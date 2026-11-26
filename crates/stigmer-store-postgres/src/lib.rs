//! stigmer-store-postgres: the Postgres backend for `Store`.
//!
//! `IdentityStore` is not implemented yet (Task 5 of the M2 plan). `wait_past` polls the board
//! head every 100 ms for now; Task 6 replaces the polling with LISTEN/NOTIFY wake-ups.
//!
//! A pool of connections (deadpool) to one database, shared by every replica of the server.
//! Writes to one board serialise on that board's row (`SELECT ... FOR UPDATE`), so its event
//! sequence stays gapless across processes; different boards proceed in parallel. The schema is
//! migrated explicitly ([`PgStore::migrate`]), never on connect.
//!
//! A connection string's password never appears in an error, a log line or `Debug` output:
//! errors name the host, port and database only.

mod audit;
mod boards;
mod chain;
mod error;
mod events;
mod hash;
mod migrate;
mod pool;
mod posts;
mod reads;
mod schema;
mod second_handle;
mod store;
mod threads;
mod tls;
mod wait;

#[doc(hidden)]
pub mod testing;

use std::fmt;
use std::sync::Arc;

use deadpool_postgres::Pool;
use stigmer_store::StoreError;

pub use schema::{MigrationReport, SchemaState};

/// How to secure connections to Postgres.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PgTls {
    /// Plain connections (`sslmode=disable`).
    Disable,
    /// TLS without checking the server's certificate (`sslmode=require`).
    Require,
    /// TLS with the certificate checked against the platform's trusted roots and the host name
    /// (`sslmode=verify-full`).
    VerifyFull,
}

/// Connection options for [`PgStore::connect`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PgOptions {
    /// The most connections the pool opens (at least 1).
    pub max_connections: usize,
    /// How connections are secured; this, not the URL's `sslmode`, decides.
    pub tls: PgTls,
}

/// A `Store` backed by a Postgres database.
pub struct PgStore {
    pool: Pool,
    /// Kept for second handles in tests; never printed.
    config: tokio_postgres::Config,
    options: PgOptions,
    target: String,
    waiters: Arc<wait::Waiters>,
}

impl fmt::Debug for PgStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PgStore")
            .field("target", &self.target)
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

impl PgStore {
    /// Connects to the database `url` names (a `postgres://` URL or key-value string) and
    /// checks that one connection opens. Neither this nor any later error contains the URL's
    /// password; errors name the host, port and database only. Does not touch the schema: see
    /// [`PgStore::schema_state`] and [`PgStore::migrate`].
    pub async fn connect(url: &str, options: PgOptions) -> Result<PgStore, StoreError> {
        let connected = pool::connect(url, options).await?;
        Ok(PgStore {
            pool: connected.pool,
            config: connected.config,
            options,
            target: connected.target,
            waiters: Arc::default(),
        })
    }

    /// Applies every pending migration in one transaction under an advisory lock, records them
    /// in `schema_version` and makes sure board `main` exists. Running it again changes
    /// nothing. A schema newer than this build is an error and is left untouched.
    pub async fn migrate(&self) -> Result<MigrationReport, StoreError> {
        migrate::migrate(&self.pool).await
    }

    /// Where the database's schema stands relative to this build.
    pub async fn schema_state(&self) -> Result<SchemaState, StoreError> {
        let mut client = pool::client(&self.pool).await?;
        let tx = client
            .build_transaction()
            .read_only(true)
            .start()
            .await
            .map_err(error::db)?;
        let have = schema::version(&tx).await?;
        tx.commit().await.map_err(error::db)?;
        Ok(schema::state(have))
    }
}
