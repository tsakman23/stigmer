//! Which store the server and the admin commands use: SQLite in a data directory (the default,
//! unchanged) or Postgres at a database URL. Both are generic over the store traits past this
//! point; only opening, the schema check and `admin migrate` differ.
//!
//! The database URL comes from `--database-url`, `--database-url-file` or
//! `STIGMER_DATABASE_URL`, in that order. One with a password is refused as a command-line
//! argument, where every user of the machine can read it in the process listing. The password
//! is never printed: errors from here name files and settings, and the store's errors name the
//! host, port and database only.

mod db_tls;
mod url;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use clap::Args;
use db_tls::{choose_ca, choose_tls, read_ca_bundle, DbTls};
use stigmer_store_postgres::{
    PgOptions, PgStore, PollErrorHook, SchemaState, DEFAULT_POLL_INTERVAL,
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
    #[arg(long, value_enum, value_name = "MODE")]
    db_tls: Option<DbTls>,
    /// Trust only the CA certificates in this PEM file to verify the Postgres server (as
    /// sslrootcert in the URL); implies --db-tls verify-full.
    #[arg(long, value_name = "PEM")]
    db_tls_ca: Option<PathBuf>,
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
            if url.trim().is_empty() {
                return Err(Failure::Config("--database-url is empty".into()));
            }
            return Ok(Some((url.trim().to_owned(), Source::Argument)));
        }
        if let Some(path) = &self.database_url_file {
            return read_url_file(path).map(|url| Some((url, Source::File)));
        }
        // Unset means SQLite; set but empty is a mistake, not a choice of SQLite.
        let Some(value) = std::env::var_os(DATABASE_URL_VAR) else {
            return Ok(None);
        };
        let url = value
            .into_string()
            .map_err(|_| Failure::Config(format!("{DATABASE_URL_VAR} is not valid UTF-8")))?;
        if url.trim().is_empty() {
            return Err(Failure::Config(format!(
                "{DATABASE_URL_VAR} is set but empty: unset it to use SQLite, or set it to a \
                 database URL"
            )));
        }
        Ok(Some((url.trim().to_owned(), Source::Environment)))
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
    if path.is_dir() {
        return Err(Failure::Config(format!(
            "the database URL file {} is a directory",
            path.display()
        )));
    }
    let text = std::fs::read_to_string(path).map_err(|e| {
        Failure::Config(format!(
            "cannot read the database URL file {}: {}",
            path.display(),
            e.kind()
        ))
    })?;
    crate::tls::warn_if_exposed(path, "database URL file");
    let url = text.trim();
    if url.is_empty() {
        return Err(Failure::Config(format!(
            "the database URL file {} is empty",
            path.display()
        )));
    }
    Ok(url.to_owned())
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
                let (store, target) = plan.connect().await?;
                Ok(Backend::Postgres {
                    store: Box::new(store),
                    target,
                })
            }
        }
    }
}

impl PgPlan {
    /// Connects to the database (opening no listener connection) and returns the store with a
    /// description of its target for messages. Does not check the schema.
    pub(crate) async fn connect(self) -> Result<(PgStore, String), Failure> {
        let store = PgStore::connect(&self.url, self.options)
            .await
            .map_err(|e| Failure::Runtime(e.to_string()))?;
        Ok((store, self.target))
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
