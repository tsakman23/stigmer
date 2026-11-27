//! Which store the server and the admin commands use: SQLite in a data directory (the default,
//! unchanged) or Postgres at a database URL. Both are generic over the store traits past this
//! point; only opening, the schema check and `admin migrate` differ.
//!
//! The database URL comes from `--database-url`, `--database-url-file` or
//! `STIGMER_DATABASE_URL`, in that order. One with a password is refused as a command-line
//! argument, where every user of the machine can read it in the process listing. The password
//! is never printed: errors from here name files and settings, and the store's errors name the
//! host, port and database only.

mod url;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use clap::{Args, ValueEnum};
use stigmer_store_postgres::{
    CaBundle, PgOptions, PgStore, PgTls, PollErrorHook, SchemaState, DEFAULT_POLL_INTERVAL,
};
use stigmer_store_sqlite::SqliteStore;

use crate::lock::DataDir;
use crate::serve::Throttle;
use crate::Failure;

/// The variable the database URL is read from when no flag names one.
pub(crate) const DATABASE_URL_VAR: &str = "STIGMER_DATABASE_URL";

const DEFAULT_DATA_DIR: &str = "./.stigmer";
const DEFAULT_DB_MAX_CONNECTIONS: u32 = 16;

/// At most one warning about failing safety polls per this period.
const POLL_WARN_EVERY: Duration = Duration::from_secs(60);

/// Where the data lives: the flags `serve` and every `admin` subcommand share.
///
/// No `Debug`: the database URL may hold a password.
#[derive(Args)]
pub struct StoreArgs {
    /// Directory holding the SQLite database, created if missing [default: ./.stigmer]. Ignored,
    /// with a warning, when a Postgres database URL is given.
    #[arg(long, value_name = "DIR")]
    data_dir: Option<PathBuf>,
    /// Use the Postgres database at this URL instead of SQLite (also read from
    /// STIGMER_DATABASE_URL). A URL with a password is refused here, where process listings
    /// show it: put it in STIGMER_DATABASE_URL or a file named by --database-url-file.
    #[arg(long, value_name = "URL", conflicts_with = "database_url_file")]
    database_url: Option<String>,
    /// Read the Postgres database URL from this file (keep it private: chmod 600).
    #[arg(long, value_name = "PATH")]
    database_url_file: Option<PathBuf>,
    /// Most connections to Postgres at once, per process [default: 16].
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u32).range(1..=500))]
    db_max_connections: Option<u32>,
    /// How often the heads of boards with waiters are re-read from Postgres, in ms, behind its
    /// notifications [default: 2000].
    #[arg(long, hide = true, value_parser = clap::value_parser!(u64).range(100..=60_000))]
    db_poll_interval_ms: Option<u64>,
    /// How connections to Postgres are secured, as sslmode in the URL: disable (plain), require
    /// (TLS, certificate not checked) or verify-full (certificate and host name checked)
    /// [default: verify-full with a CA bundle, otherwise disable for a loopback host and require
    /// for any other].
    #[arg(long, value_enum)]
    db_tls: Option<DbTls>,
    /// Trust only the CA certificates in this PEM file to verify the Postgres server (as
    /// sslrootcert in the URL); implies --db-tls verify-full.
    #[arg(long, value_name = "PEM")]
    db_tls_ca: Option<PathBuf>,
}

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
    fn from_sslmode(value: &str) -> Result<DbTls, String> {
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

/// Where a database URL came from.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Source {
    Argument,
    File,
    Environment,
}

/// The store to open, decided from the flags before anything is touched.
pub(crate) enum Plan {
    Sqlite { data_dir: PathBuf },
    Postgres(PgPlan),
}

/// A Postgres store to connect to. No `Debug`: the URL may hold a password.
pub(crate) struct PgPlan {
    url: String,
    options: PgOptions,
    target: String,
}

/// An open store.
pub(crate) enum Backend {
    /// SQLite, with the data directory locked for as long as this lives.
    Sqlite {
        store: SqliteStore,
        data_dir: PathBuf,
        lock: DataDir,
    },
    Postgres {
        store: Box<PgStore>,
        target: String,
    },
}

impl StoreArgs {
    /// Decides the store from the flags and the environment. A wrong setting is a usage error
    /// (exit 2) found before any file or connection is opened. Warns once when `--data-dir` is
    /// ignored.
    pub(crate) fn plan(&self) -> Result<Plan, Failure> {
        let Some((raw, source)) = self.database_url()? else {
            if let Some(flag) = self.database_flag() {
                return Err(Failure::Config(format!(
                    "{flag} applies only to a Postgres database: give one with --database-url, \
                     --database-url-file or {DATABASE_URL_VAR}"
                )));
            }
            let data_dir = self
                .data_dir
                .clone()
                .unwrap_or_else(|| PathBuf::from(DEFAULT_DATA_DIR));
            return Ok(Plan::Sqlite { data_dir });
        };
        if self.data_dir.is_some() {
            eprintln!(
                "stigmerd: warning: --data-dir is ignored: the database is Postgres, at the \
                 database URL"
            );
        }
        let parsed = url::parse(&raw).map_err(Failure::Config)?;
        if source == Source::Argument && parsed.has_password {
            return Err(Failure::Config(format!(
                "refusing a database URL with a password on the command line, where process \
                 listings show it: put the URL in {DATABASE_URL_VAR} or a file named by \
                 --database-url-file"
            )));
        }
        let ca_file = choose_ca(self.db_tls_ca.as_deref(), parsed.sslrootcert.as_deref())?;
        let url_tls = parsed
            .sslmode
            .as_deref()
            .map(DbTls::from_sslmode)
            .transpose()
            .map_err(Failure::Config)?;
        let tls = choose_tls(self.db_tls, url_tls, ca_file.is_some(), parsed.loopback)
            .map_err(Failure::Config)?;
        let ca_bundle = ca_file.as_deref().map(read_ca_bundle).transpose()?;
        let max_connections = self
            .db_max_connections
            .unwrap_or(DEFAULT_DB_MAX_CONNECTIONS);
        let options = PgOptions {
            // u32 always fits a usize on the platforms Rust supports for this server.
            max_connections: usize::try_from(max_connections).unwrap_or(usize::MAX),
            tls,
            poll_interval: self
                .db_poll_interval_ms
                .map_or(DEFAULT_POLL_INTERVAL, Duration::from_millis),
            ca_bundle,
            on_poll_error: Some(poll_warning()),
        };
        Ok(Plan::Postgres(PgPlan {
            url: parsed.url,
            options,
            target: parsed.target,
        }))
    }

    /// The database URL and where it came from: the flag, else the file, else the environment.
    fn database_url(&self) -> Result<Option<(String, Source)>, Failure> {
        if let Some(url) = &self.database_url {
            return Ok(Some((url.clone(), Source::Argument)));
        }
        if let Some(path) = &self.database_url_file {
            return read_url_file(path).map(|url| Some((url, Source::File)));
        }
        Ok(std::env::var(DATABASE_URL_VAR)
            .ok()
            .filter(|url| !url.trim().is_empty())
            .map(|url| (url.trim().to_owned(), Source::Environment)))
    }

    /// The first Postgres-only flag given, if any.
    fn database_flag(&self) -> Option<&'static str> {
        [
            (self.db_max_connections.is_some(), "--db-max-connections"),
            (self.db_poll_interval_ms.is_some(), "--db-poll-interval-ms"),
            (self.db_tls.is_some(), "--db-tls"),
            (self.db_tls_ca.is_some(), "--db-tls-ca"),
        ]
        .into_iter()
        .find_map(|(given, flag)| given.then_some(flag))
    }
}

/// The URL in `path`, without surrounding whitespace (such as the final newline).
fn read_url_file(path: &Path) -> Result<String, Failure> {
    crate::tls::warn_if_exposed(path, "database URL file");
    let text = std::fs::read_to_string(path).map_err(|e| {
        Failure::Config(format!(
            "cannot read the database URL file {}: {}",
            path.display(),
            e.kind()
        ))
    })?;
    let url = text.trim();
    if url.is_empty() {
        return Err(Failure::Config(format!(
            "the database URL file {} is empty",
            path.display()
        )));
    }
    Ok(url.to_owned())
}

/// The CA bundle file from `--db-tls-ca` or the URL's `sslrootcert`; both must name the same.
fn choose_ca(flag: Option<&Path>, in_url: Option<&str>) -> Result<Option<PathBuf>, Failure> {
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

fn read_ca_bundle(path: &Path) -> Result<CaBundle, Failure> {
    let pem = std::fs::read(path).map_err(|e| {
        Failure::Config(format!("cannot read the CA bundle {}: {e}", path.display()))
    })?;
    CaBundle::from_pem(&pem)
        .map_err(|e| Failure::Config(format!("CA bundle {}: {e}", path.display())))
}

/// A warning on stderr when a safety-poll round fails, at most once per `POLL_WARN_EVERY`.
fn poll_warning() -> PollErrorHook {
    let throttle = Mutex::new(Throttle::new(POLL_WARN_EVERY));
    Arc::new(move |e| {
        // A throttle is changed in one step, so a panicking holder cannot leave it half-done.
        let due = throttle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .allow(Instant::now());
        if due {
            eprintln!(
                "stigmerd: warning: re-reading board heads from the database failed ({e}); \
                 waits still wake on notifications, and the read is retried"
            );
        }
    })
}

impl Plan {
    /// Opens the store: locks the data directory and opens (and migrates) SQLite, or connects
    /// to Postgres. Does not check a Postgres schema; see [`Backend::check_schema`].
    pub(crate) async fn open(self) -> Result<Backend, Failure> {
        match self {
            Plan::Sqlite { data_dir } => {
                let lock = DataDir::open(&data_dir)?;
                let db_path = lock.db_path();
                let store = SqliteStore::open(&db_path).await.map_err(|e| {
                    Failure::Runtime(format!("cannot open database {}: {e}", db_path.display()))
                })?;
                Ok(Backend::Sqlite {
                    store,
                    data_dir,
                    lock,
                })
            }
            Plan::Postgres(plan) => {
                let store = PgStore::connect(&plan.url, plan.options)
                    .await
                    .map_err(|e| Failure::Runtime(e.to_string()))?;
                Ok(Backend::Postgres {
                    store: Box::new(store),
                    target: plan.target,
                })
            }
        }
    }
}

impl Backend {
    /// Where the data is, for the listening line: the data directory or the Postgres target.
    pub(crate) fn describe(&self) -> String {
        match self {
            Backend::Sqlite { data_dir, .. } => data_dir.display().to_string(),
            Backend::Postgres { target, .. } => target.clone(),
        }
    }

    /// Refuses (exit 1) a Postgres schema this build does not write: an older one needs
    /// `stigmerd admin migrate`, a newer one a newer server. SQLite migrates itself on open.
    pub(crate) async fn check_schema(&self) -> Result<(), Failure> {
        let Backend::Postgres { store, .. } = self else {
            return Ok(());
        };
        let state = store
            .schema_state()
            .await
            .map_err(|e| Failure::Runtime(format!("cannot read the database schema: {e}")))?;
        match state {
            SchemaState::Current => Ok(()),
            SchemaState::Behind { have, need } => Err(Failure::Runtime(format!(
                "the database schema is at version {have} and this server needs version {need}: \
                 run stigmerd admin migrate (stop servers of an older version first)"
            ))),
            SchemaState::Ahead { have, need } => Err(Failure::Runtime(format!(
                "the database schema is at version {have}, newer than this server supports \
                 ({need}): this server is older than the database; run a newer stigmerd"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
