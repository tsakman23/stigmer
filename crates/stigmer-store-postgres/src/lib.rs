//! stigmer-store-postgres: the Postgres backend for `Store` and `IdentityStore`.
//!
//! A pool of connections (deadpool) to one database, shared by every replica of the server.
//! Writes to one board serialise on that board's row (`SELECT ... FOR UPDATE`), so its event
//! sequence stays gapless across processes; different boards proceed in parallel. The schema is
//! migrated explicitly ([`PgStore::migrate`]), never on connect.
//!
//! Lock order: a write that touches more than one row of a board (a post, an archive, a member,
//! invite or credential change, a join) locks the board row first and only then the rows behind
//! it, so two such writers queue on the board row. `revoke_credential` and `touch_credential`
//! lock only their single credential row, which cannot form a cycle. `enable_network` locks the
//! instance row, then the board row of its invite; nothing locks them the other way round.
//!
//! A post wakes waits on every replica through LISTEN/NOTIFY: each store handle keeps one
//! listener connection outside the pool, opened by its first wait that has to sleep, and a slow
//! safety poll covers it while it reconnects (see `listener`, `wakeups` and ADR 0013).
//!
//! Methods named `*_for_tests` on [`PgStore`] are hidden test support, not API, as is the
//! [`testing`] module.
//!
//! A connection string's password never appears in an error, a log line or `Debug` output:
//! errors name the host, port and database only.

mod audit;
mod boards;
mod chain;
mod error;
mod events;
mod hash;
mod identity;
mod identity_credentials;
mod identity_invites;
mod identity_members;
mod identity_security;
mod listener;
mod migrate;
mod notify;
mod pool;
mod posts;
mod reads;
mod schema;
mod second_handle;
mod store;
mod threads;
mod tls;
mod wait;
mod wakeups;

#[doc(hidden)]
pub mod testing;

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use deadpool_postgres::Pool;
use stigmer_store::StoreError;

pub use schema::{MigrationReport, SchemaState};
pub use tls::{CaBundle, CaBundleError};

/// How to secure connections to Postgres.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PgTls {
    /// Plain connections (`sslmode=disable`).
    Disable,
    /// TLS without checking the server's certificate (`sslmode=require`).
    Require,
    /// TLS with the certificate checked against the trusted roots and the host name
    /// (`sslmode=verify-full`). The roots are [`PgOptions::ca_bundle`] when set, else the
    /// platform's.
    VerifyFull,
}

/// Called with the error of each failed safety-poll round (see [`PgOptions::on_poll_error`]).
pub type PollErrorHook = Arc<dyn Fn(&StoreError) + Send + Sync>;

/// Connection options for [`PgStore::connect`].
#[derive(Clone)]
pub struct PgOptions {
    /// The most connections the pool opens (at least 1).
    pub max_connections: usize,
    /// How connections are secured. A connection string's `sslmode` may only repeat it
    /// (`disable` or `require`); one that disagrees is refused by [`PgStore::connect`].
    pub tls: PgTls,
    /// How often the heads of boards with waiters are re-read, the safety net behind
    /// LISTEN/NOTIFY wake-ups. [`DEFAULT_POLL_INTERVAL`] unless there is a reason to change it;
    /// [`PgStore::connect`] refuses anything outside [`MIN_POLL_INTERVAL`] to
    /// [`MAX_POLL_INTERVAL`].
    pub poll_interval: Duration,
    /// The only roots trusted with [`PgTls::VerifyFull`], for a server certificate from a private
    /// CA; `None` trusts the platform's roots. [`PgStore::connect`] refuses a bundle with any
    /// other TLS mode.
    pub ca_bundle: Option<CaBundle>,
    /// Told about every safety-poll round that fails (the round is retried at the next
    /// interval). The safety poll starts with the listener, on the first wait that sleeps. The
    /// store logs nothing itself; the server decides how to report it. The error never contains
    /// the connection string's password.
    pub on_poll_error: Option<PollErrorHook>,
}

impl fmt::Debug for PgOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PgOptions")
            .field("max_connections", &self.max_connections)
            .field("tls", &self.tls)
            .field("poll_interval", &self.poll_interval)
            .field("ca_bundle", &self.ca_bundle)
            .field("on_poll_error", &self.on_poll_error.is_some())
            .finish()
    }
}

/// The default [`PgOptions::poll_interval`]: 2 s.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(2000);

/// The shortest [`PgOptions::poll_interval`] [`PgStore::connect`] accepts: 100 ms.
pub const MIN_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// The longest [`PgOptions::poll_interval`] [`PgStore::connect`] accepts: 60 s.
pub const MAX_POLL_INTERVAL: Duration = Duration::from_millis(60_000);

/// A `Store` backed by a Postgres database.
pub struct PgStore {
    pool: Pool,
    options: PgOptions,
    /// The notifier, and the listener and safety poll once a wait has started them; dropping
    /// the store stops them.
    wakeups: Arc<wakeups::Wakeups>,
}

impl fmt::Debug for PgStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PgStore")
            .field("target", &self.wakeups.setup().target)
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

impl PgStore {
    /// Connects to the database `url` names (a `postgres://` URL or key-value string) and
    /// checks that one connection opens. Neither this nor any later error contains the URL's
    /// password; errors name the host, port and database only. Does not touch the schema: see
    /// [`PgStore::schema_state`] and [`PgStore::migrate`].
    ///
    /// Opens no listener connection: the first wait that has to sleep starts the store's
    /// listener (outside the pool) and its safety poll. [`PgOptions::poll_interval`] must lie
    /// within [`MIN_POLL_INTERVAL`] and [`MAX_POLL_INTERVAL`].
    pub async fn connect(url: &str, options: PgOptions) -> Result<PgStore, StoreError> {
        let poll_interval = options.poll_interval;
        check_poll_interval(poll_interval)?;
        PgStore::open(url, options, poll_interval).await
    }

    /// Test support, not API: [`PgStore::connect`] with a safety poll of `poll_interval`,
    /// unchecked, so a test can set it to an hour and prove a wake came through NOTIFY.
    #[doc(hidden)]
    pub async fn connect_with_poll_for_tests(
        url: &str,
        options: PgOptions,
        poll_interval: Duration,
    ) -> Result<PgStore, StoreError> {
        PgStore::open(url, options, poll_interval).await
    }

    async fn open(
        url: &str,
        options: PgOptions,
        poll_interval: Duration,
    ) -> Result<PgStore, StoreError> {
        let connected = pool::connect(url, &options).await?;
        let setup = listener::ListenerSetup {
            config: connected.config,
            tls: options.tls,
            ca_bundle: options.ca_bundle.clone(),
            target: connected.target,
            pool: connected.pool.clone(),
            poll_interval,
            on_poll_error: options.on_poll_error.clone(),
        };
        Ok(PgStore::with_setup(connected.pool, options, setup))
    }

    /// A store on `pool` whose listener, once a wait starts it, is described by `setup`.
    fn with_setup(pool: Pool, options: PgOptions, setup: listener::ListenerSetup) -> PgStore {
        PgStore {
            pool,
            options,
            wakeups: Arc::new(wakeups::Wakeups::new(setup)),
        }
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

/// Refuses a safety poll interval outside [`MIN_POLL_INTERVAL`]..=[`MAX_POLL_INTERVAL`].
fn check_poll_interval(interval: Duration) -> Result<(), StoreError> {
    if (MIN_POLL_INTERVAL..=MAX_POLL_INTERVAL).contains(&interval) {
        return Ok(());
    }
    Err(StoreError::Backend(format!(
        "the database poll interval must be between {} and {} ms, not {} ms",
        MIN_POLL_INTERVAL.as_millis(),
        MAX_POLL_INTERVAL.as_millis(),
        interval.as_millis()
    )))
}
