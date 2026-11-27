//! Test support for the conformance suites and the wake-up tests: a second handle on a store's
//! database, and a view of the handle's notifier, listener and pool.

use stigmer_core::BoardId;
use stigmer_store::StoreError;

use crate::error::backend;
use crate::{listener, pool, PgStore};

impl PgStore {
    /// Test support, not API: a new pool on the SAME database (and schema) as this store, with
    /// a (lazily started) listener, safety poll and notifier of its own, as a second server
    /// process would have.
    /// Opens one connection to check it, as [`PgStore::connect`] does.
    #[doc(hidden)]
    pub async fn second_handle_for_tests(&self) -> Result<PgStore, StoreError> {
        let pool = pool::build(&self.wakeups.setup().config, &self.options)?;
        drop(pool.get().await.map_err(backend)?);
        let setup = listener::ListenerSetup {
            config: self.wakeups.setup().config.clone(),
            tls: self.wakeups.setup().tls,
            ca_bundle: self.wakeups.setup().ca_bundle.clone(),
            target: self.wakeups.setup().target.clone(),
            pool: pool.clone(),
            poll_interval: self.wakeups.setup().poll_interval,
            on_poll_error: self.wakeups.setup().on_poll_error.clone(),
        };
        Ok(PgStore::with_setup(pool, self.options.clone(), setup))
    }

    /// Test support, not API: the number of `wait_past` callers currently subscribed to
    /// `board`'s entry in this handle's notifier.
    #[doc(hidden)]
    pub fn waiters_for_tests(&self, board: &BoardId) -> usize {
        self.wakeups.notifier().receiver_count(board)
    }

    /// Test support, not API: the number of boards with a wake-up entry on this handle.
    #[doc(hidden)]
    pub fn notifier_entries_for_tests(&self) -> usize {
        self.wakeups.notifier().entry_count()
    }

    /// Test support, not API: the number of notifications for this store's schema that this
    /// handle's listener has handled.
    #[doc(hidden)]
    pub fn notifications_handled_for_tests(&self) -> u64 {
        self.wakeups.notifier().handled()
    }

    /// Test support, not API: the backend process id of this handle's listener connection,
    /// `None` while it is reconnecting.
    #[doc(hidden)]
    pub fn listener_pid_for_tests(&self) -> Option<i32> {
        self.wakeups.listener_pid()
    }

    /// Test support, not API: starts this handle's listener now, as its first sleeping wait
    /// would.
    #[doc(hidden)]
    pub async fn start_listener_for_tests(&self) -> Result<(), StoreError> {
        self.wakeups.ensure_started().await
    }

    /// Test support, not API: how many times this handle has started its listener.
    #[doc(hidden)]
    pub fn listener_starts_for_tests(&self) -> u64 {
        self.wakeups.starts()
    }

    /// Test support, not API: the number of pooled connections in use right now.
    #[doc(hidden)]
    pub fn pool_in_use_for_tests(&self) -> usize {
        let status = self.pool.status();
        status.size.saturating_sub(status.available)
    }
}
