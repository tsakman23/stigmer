//! The TLS mode and CA bundle for connections to Postgres, from `--db-tls`, `--db-tls-ca` and the
//! URL's `sslmode` and `sslrootcert`.

use std::path::{Path, PathBuf};

use clap::ValueEnum;
use stigmer_store_postgres::{CaBundle, PgTls};

use crate::Failure;

/// `--db-tls` and the URL's `sslmode`.
///
/// The variants carry no doc comments on purpose: clap would list them as a "Possible values"
/// section, which switches all of `--help` to its long layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum DbTls {
    // Plain connections; only for a loopback host unless chosen explicitly.
    Disable,
    // TLS without checking the server's certificate.
    Require,
    // TLS with the certificate checked against the trusted roots and the host name.
    VerifyFull,
}

impl DbTls {
    pub(crate) fn from_sslmode(value: &str) -> Result<DbTls, String> {
        match value {
            "disable" => Ok(DbTls::Disable),
            "require" => Ok(DbTls::Require),
            "verify-full" => Ok(DbTls::VerifyFull),
            other => Err(format!(
                "sslmode={other} in the database URL is not supported: use disable, require or \
                 verify-full (or --db-tls)"
            )),
        }
    }

    fn name(self) -> &'static str {
        match self {
            DbTls::Disable => "disable",
            DbTls::Require => "require",
            DbTls::VerifyFull => "verify-full",
        }
    }

    fn pg(self) -> PgTls {
        match self {
            DbTls::Disable => PgTls::Disable,
            DbTls::Require => PgTls::Require,
            DbTls::VerifyFull => PgTls::VerifyFull,
        }
    }
}

/// The CA bundle file from `--db-tls-ca` or the URL's `sslrootcert`; both must name the same.
pub(crate) fn choose_ca(
    flag: Option<&Path>,
    in_url: Option<&str>,
) -> Result<Option<PathBuf>, Failure> {
    match (flag, in_url) {
        (Some(flag), Some(in_url)) if flag != Path::new(in_url) => Err(Failure::Config(format!(
            "--db-tls-ca {} and sslrootcert={in_url} in the database URL disagree; give one",
            flag.display()
        ))),
        (Some(flag), _) => Ok(Some(flag.to_owned())),
        (None, in_url) => Ok(in_url.map(PathBuf::from)),
    }
}

/// The TLS mode: `--db-tls` and the URL's `sslmode` must agree; without either, verify-full
/// with a CA bundle, a plain connection to a loopback host and `require` to any other. So a
/// plain connection leaves this machine only when `disable` was asked for by name.
pub(crate) fn choose_tls(
    flag: Option<DbTls>,
    in_url: Option<DbTls>,
    ca_bundle: bool,
    loopback: bool,
) -> Result<PgTls, String> {
    let explicit = match (flag, in_url) {
        (Some(flag), Some(in_url)) if flag != in_url => {
            return Err(format!(
                "--db-tls {} and sslmode={} in the database URL disagree; give one",
                flag.name(),
                in_url.name()
            ));
        }
        (flag, in_url) => flag.or(in_url),
    };
    let chosen = match explicit {
        Some(mode) => mode,
        None if ca_bundle => DbTls::VerifyFull,
        None if loopback => DbTls::Disable,
        None => DbTls::Require,
    };
    if ca_bundle && chosen != DbTls::VerifyFull {
        return Err(format!(
            "a CA bundle (--db-tls-ca or sslrootcert) is used only with verify-full, not with {}",
            chosen.name()
        ));
    }
    Ok(chosen.pg())
}

pub(crate) fn read_ca_bundle(path: &Path) -> Result<CaBundle, Failure> {
    let pem = std::fs::read(path).map_err(|e| {
        Failure::Config(format!("cannot read the CA bundle {}: {e}", path.display()))
    })?;
    CaBundle::from_pem(&pem).map_err(|e| Failure::Config(format!("{}: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::url;
    use DbTls::{Disable, Require, VerifyFull};

    #[test]
    fn each_sslmode_selects_its_tls_mode_and_is_not_passed_on() {
        for (sslmode, loopback, expected) in [
            ("disable", true, PgTls::Disable),
            ("disable", false, PgTls::Disable),
            ("require", true, PgTls::Require),
            ("require", false, PgTls::Require),
            ("verify-full", true, PgTls::VerifyFull),
            ("verify-full", false, PgTls::VerifyFull),
        ] {
            let host = if loopback { "localhost" } else { "db.example" };
            let raw = format!("postgres://u@{host}/app?sslmode={sslmode}&application_name=x");
            let parsed = url::parse(&raw).unwrap();
            assert!(!parsed.url.contains("sslmode"), "{}", parsed.url);
            assert_eq!(
                parsed.url,
                format!("postgres://u@{host}/app?application_name=x")
            );
            let in_url = DbTls::from_sslmode(parsed.sslmode.as_deref().unwrap()).unwrap();
            assert_eq!(
                choose_tls(None, Some(in_url), false, parsed.loopback),
                Ok(expected),
                "{raw}"
            );
        }
        for unsupported in ["prefer", "allow", "verify-ca", "VERIFY-FULL", ""] {
            let err = DbTls::from_sslmode(unsupported).unwrap_err();
            assert!(err.contains("not supported"), "{err}");
        }
    }

    #[test]
    fn without_a_choice_tls_depends_on_the_host_and_the_ca_bundle() {
        assert_eq!(choose_tls(None, None, false, true), Ok(PgTls::Disable));
        assert_eq!(choose_tls(None, None, false, false), Ok(PgTls::Require));
        assert_eq!(choose_tls(None, None, true, true), Ok(PgTls::VerifyFull));
        assert_eq!(choose_tls(None, None, true, false), Ok(PgTls::VerifyFull));
    }

    #[test]
    fn a_plain_connection_to_another_host_needs_disable_by_name() {
        // Asked for by name, through either route: allowed.
        assert_eq!(
            choose_tls(Some(Disable), None, false, false),
            Ok(PgTls::Disable)
        );
        assert_eq!(
            choose_tls(None, Some(Disable), false, false),
            Ok(PgTls::Disable)
        );
        // Otherwise a remote host never gets a plain connection.
        for flag in [None, Some(Require), Some(VerifyFull)] {
            for in_url in [None, Some(Require), Some(VerifyFull)] {
                if let Ok(tls) = choose_tls(flag, in_url, false, false) {
                    assert_ne!(tls, PgTls::Disable, "{flag:?} {in_url:?}");
                }
            }
        }
    }

    #[test]
    fn the_flag_and_the_url_must_agree() {
        for (flag, in_url) in [
            (Disable, Require),
            (Require, VerifyFull),
            (VerifyFull, Disable),
        ] {
            let err = choose_tls(Some(flag), Some(in_url), false, true).unwrap_err();
            assert!(err.contains("disagree"), "{err}");
        }
        assert_eq!(
            choose_tls(Some(Require), Some(Require), false, false),
            Ok(PgTls::Require)
        );
    }

    #[test]
    fn a_ca_bundle_needs_verify_full() {
        for mode in [Disable, Require] {
            let err = choose_tls(Some(mode), None, true, true).unwrap_err();
            assert!(err.contains("verify-full"), "{err}");
        }
        assert_eq!(
            choose_tls(Some(VerifyFull), None, true, false),
            Ok(PgTls::VerifyFull)
        );
    }

    #[test]
    fn the_ca_flag_and_sslrootcert_must_name_the_same_file() {
        let flag = Path::new("/etc/ca.pem");
        assert!(choose_ca(Some(flag), Some("/etc/other.pem")).is_err());
        assert_eq!(
            choose_ca(Some(flag), Some("/etc/ca.pem")).ok().flatten(),
            Some(flag.to_owned())
        );
        assert_eq!(
            choose_ca(None, Some("/etc/ca.pem")).ok().flatten(),
            Some(flag.to_owned())
        );
        assert_eq!(choose_ca(None, None).ok().flatten(), None);
    }
}
