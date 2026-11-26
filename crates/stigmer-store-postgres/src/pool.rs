//! The connection pool, and the one place a connection string is at hand.
//!
//! Errors from here name the host, port and database only. Anything that could echo the URL
//! goes through [`Redactor`], which removes its password, raw and decoded, from the message.

use std::time::Duration;

use deadpool_postgres::{Manager, ManagerConfig, Object, Pool, RecyclingMethod, Runtime};
use stigmer_store::StoreError;
use tokio_postgres::config::{Config, Host, SslMode};
use tokio_postgres::NoTls;

use crate::error::backend;
use crate::{tls, PgOptions, PgTls};

/// How long opening one new connection may take.
const CREATE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a caller may wait for a free connection when the pool is busy.
const WAIT_TIMEOUT: Duration = Duration::from_secs(30);

/// A checked pool on the database `url` names, its parsed configuration and a description of
/// the target without credentials.
pub(crate) struct Connected {
    pub(crate) pool: Pool,
    pub(crate) config: Config,
    pub(crate) target: String,
}

/// Parses `url`, builds the pool and opens one connection, so a wrong address, password or TLS
/// setting fails here rather than on the first request.
pub(crate) async fn connect(url: &str, options: PgOptions) -> Result<Connected, StoreError> {
    let mut secrets = Redactor::from_url(url);
    let mut config: Config = url.parse().map_err(|e| {
        let hint = if url.contains("sslmode=verify") {
            " (sslmode verify-ca and verify-full are not read from the connection string: \
             remove sslmode and choose the TLS mode in the options)"
        } else {
            ""
        };
        StoreError::Backend(
            secrets.redact(&format!("invalid Postgres connection string: {e}{hint}")),
        )
    })?;
    if let Some(password) = config.get_password() {
        secrets.add(String::from_utf8_lossy(password).into_owned());
    }
    check_ssl_mode(config.get_ssl_mode(), options.tls)?;
    config.ssl_mode(match options.tls {
        PgTls::Disable => SslMode::Disable,
        PgTls::Require | PgTls::VerifyFull => SslMode::Require,
    });
    let target = target(&config);
    let pool = build(&config, options)?;
    let first = pool.get().await.map_err(|e| {
        StoreError::Backend(secrets.redact(&format!("cannot connect to {target}: {e}")))
    })?;
    drop(first);
    Ok(Connected {
        pool,
        config,
        target,
    })
}

/// Refuses a connection string whose `sslmode` disagrees with `tls`, rather than letting one
/// silently override the other (a `require` in the URL must never become a plain connection).
/// `prefer`, which is also what an absent `sslmode` parses to, defers to `tls`.
fn check_ssl_mode(in_url: SslMode, tls: PgTls) -> Result<(), StoreError> {
    let agrees = match in_url {
        SslMode::Disable => tls == PgTls::Disable,
        SslMode::Require => tls != PgTls::Disable,
        _ => true,
    };
    if agrees {
        return Ok(());
    }
    let named = if in_url == SslMode::Disable {
        "disable"
    } else {
        "require"
    };
    Err(StoreError::Backend(format!(
        "the connection string's sslmode={named} conflicts with the TLS option ({tls:?}): \
         remove sslmode from the connection string or choose a matching TLS option"
    )))
}

/// A pool of up to `options.max_connections` connections made from `config`.
pub(crate) fn build(config: &Config, options: PgOptions) -> Result<Pool, StoreError> {
    if options.max_connections == 0 {
        return Err(StoreError::Backend(
            "max_connections must be at least 1".into(),
        ));
    }
    let manager_config = ManagerConfig {
        recycling_method: RecyclingMethod::Fast,
    };
    let manager = match tls::connector(options.tls)? {
        None => Manager::from_config(config.clone(), NoTls, manager_config),
        Some(tls) => Manager::from_config(config.clone(), tls, manager_config),
    };
    Pool::builder(manager)
        .max_size(options.max_connections)
        .runtime(Runtime::Tokio1)
        .create_timeout(Some(CREATE_TIMEOUT))
        .wait_timeout(Some(WAIT_TIMEOUT))
        .build()
        .map_err(backend)
}

/// A connection from `pool`.
pub(crate) async fn client(pool: &Pool) -> Result<Object, StoreError> {
    pool.get().await.map_err(backend)
}

/// `database <db> on <host>:<port>`, without user or password.
fn target(config: &Config) -> String {
    let hosts: Vec<String> = config
        .get_hosts()
        .iter()
        .map(|host| match host {
            Host::Tcp(name) => name.clone(),
            #[cfg(unix)]
            Host::Unix(path) => path.display().to_string(),
        })
        .collect();
    let port = config.get_ports().first().copied().unwrap_or(5432);
    let database = config.get_dbname().or(config.get_user()).unwrap_or("?");
    format!("database {database} on {}:{port}", hosts.join(","))
}

/// Removes known secrets from messages.
#[derive(Default)]
pub(crate) struct Redactor(Vec<String>);

impl Redactor {
    /// Knows the password of `url` as written in it (URL or key-value form) and decoded,
    /// whether or not the driver can parse the rest.
    pub(crate) fn from_url(url: &str) -> Redactor {
        let mut secrets = Redactor::default();
        if let Some((_, rest)) = url.split_once("://") {
            let before_query = rest.split('?').next().unwrap_or(rest);
            let password = before_query
                .rsplit_once('@')
                .and_then(|(userinfo, _)| userinfo.split_once(':'))
                .map(|(_, password)| password);
            if let Some(password) = password {
                secrets.add(password.to_owned());
                secrets.add(percent_decode(password));
            }
        }
        for word in url.split_whitespace() {
            if let Some(value) = word.strip_prefix("password=") {
                secrets.add(value.trim_matches('\'').to_owned());
            }
        }
        secrets
    }

    pub(crate) fn add(&mut self, secret: String) {
        if !secret.is_empty() && !self.0.contains(&secret) {
            self.0.push(secret);
            // Longest first, so a secret that contains another is removed whole.
            self.0.sort_by_key(|s| std::cmp::Reverse(s.len()));
        }
    }

    pub(crate) fn redact(&self, text: &str) -> String {
        self.0
            .iter()
            .fold(text.to_owned(), |text, secret| text.replace(secret, "***"))
    }
}

/// Decodes `%XX` escapes; anything else is kept as written.
fn percent_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let escaped = bytes
            .get(i + 1..i + 3)
            .filter(|_| bytes[i] == b'%')
            .and_then(|hex| std::str::from_utf8(hex).ok())
            .and_then(|hex| u8::from_str_radix(hex, 16).ok());
        match escaped {
            Some(byte) => {
                out.push(byte);
                i += 3;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redactor_finds_the_password_in_every_form() {
        let url = "postgres://bob:p%40ss/w0rd@db.example:5433/app?sslmode=disable";
        let secrets = Redactor::from_url(url);
        assert_eq!(
            secrets.redact("x p%40ss/w0rd y p@ss/w0rd z"),
            "x *** y *** z"
        );
        let kv = Redactor::from_url("host=db password='hunter2' dbname=app");
        assert_eq!(kv.redact("said hunter2"), "said ***");
        let none = Redactor::from_url("postgres://bob@db/app");
        assert_eq!(none.redact("bob@db"), "bob@db");
    }

    #[test]
    fn target_names_host_port_and_database_only() {
        let config: Config = "postgres://bob:secret@db.example:5433/app".parse().unwrap();
        assert_eq!(target(&config), "database app on db.example:5433");
    }

    #[test]
    fn a_url_sslmode_that_conflicts_with_the_tls_option_is_refused() {
        use PgTls::{Disable, Require, VerifyFull};
        for (mode, tls) in [
            (SslMode::Require, Disable),
            (SslMode::Disable, Require),
            (SslMode::Disable, VerifyFull),
        ] {
            let err = check_ssl_mode(mode, tls).unwrap_err();
            assert!(
                err.to_string().contains("conflicts with the TLS option"),
                "{err}"
            );
        }
        for (mode, tls) in [
            (SslMode::Require, Require),
            (SslMode::Require, VerifyFull),
            (SslMode::Disable, Disable),
            (SslMode::Prefer, Disable),
            (SslMode::Prefer, VerifyFull),
        ] {
            assert_eq!(check_ssl_mode(mode, tls), Ok(()), "{mode:?} with {tls:?}");
        }
    }

    #[tokio::test]
    async fn connect_refuses_a_conflicting_sslmode_before_connecting() {
        let options = PgOptions {
            max_connections: 1,
            tls: PgTls::Disable,
        };
        // Port 1: were the conflict not caught first, this would be a refused connection.
        let url = "postgres://u:hunter2@127.0.0.1:1/db?sslmode=require";
        let Err(StoreError::Backend(text)) = connect(url, options).await else {
            panic!("a conflicting sslmode is refused");
        };
        assert!(text.contains("sslmode=require conflicts"), "{text}");
        assert!(!text.contains("hunter2"), "{text}");

        let url = "postgres://u:hunter2@127.0.0.1:1/db?sslmode=verify-full";
        let Err(StoreError::Backend(text)) = connect(url, options).await else {
            panic!("verify-full in the URL is refused");
        };
        assert!(
            text.contains("choose the TLS mode in the options"),
            "{text}"
        );
        assert!(!text.contains("hunter2"), "{text}");
    }

    #[test]
    fn a_pool_needs_at_least_one_connection() {
        let config: Config = "postgres://localhost/app".parse().unwrap();
        let options = PgOptions {
            max_connections: 0,
            tls: PgTls::Disable,
        };
        assert!(matches!(
            build(&config, options),
            Err(StoreError::Backend(_))
        ));
    }
}
