//! Test support for the conformance suites and the wake-up tests: a second handle on a store's
//! database, and a view of the handle's notifier, listener and pool.

use std::sync::Arc;

use stigmer_core::BoardId;
use stigmer_store::StoreError;

use crate::error::backend;
use crate::{listener, pool, PgStore};

impl PgStore {
    /// Test support, not API: a new pool on the SAME database (and schema) as this store, with
    /// a listener, safety poll and notifier of its own, as a second server process would have.
    /// Opens one connection to check it, as [`PgStore::connect`] does.
    #[doc(hidden)]
    pub async fn second_handle_for_tests(&self) -> Result<PgStore, StoreError> {
        let pool = pool::build(&self.config, self.options)?;
        drop(pool.get().await.map_err(backend)?);
        let notifier = Arc::default();
        let background = listener::start(
            &self.config,
            self.options.tls,
            &self.target,
            pool.clone(),
            Arc::clone(&notifier),
            self.poll_interval,
        )
        .await?;
        Ok(PgStore {
            pool,
            config: self.config.clone(),
            options: self.options,
            target: self.target.clone(),
            notifier,
            background,
            poll_interval: self.poll_interval,
        })
    }

    /// Test support, not API: the number of `wait_past` callers currently subscribed to
    /// `board`'s entry in this handle's notifier.
    #[doc(hidden)]
    pub fn waiters_for_tests(&self, board: &BoardId) -> usize {
        self.notifier.receiver_count(board)
    }

    /// Test support, not API: the number of boards with a wake-up entry on this handle.
    #[doc(hidden)]
    pub fn notifier_entries_for_tests(&self) -> usize {
        self.notifier.entry_count()
    }

    /// Test support, not API: the number of notifications for this store's schema that this
    /// handle's listener has handled.
    #[doc(hidden)]
    pub fn notifications_handled_for_tests(&self) -> u64 {
        self.notifier.handled()
    }

    /// Test support, not API: the backend process id of this handle's listener connection,
    /// `None` while it is reconnecting.
    #[doc(hidden)]
    pub fn listener_pid_for_tests(&self) -> Option<i32> {
        self.background.listener_pid()
    }

    /// Test support, not API: the number of pooled connections in use right now.
    #[doc(hidden)]
    pub fn pool_in_use_for_tests(&self) -> usize {
        let status = self.pool.status();
        status.size.saturating_sub(status.available)
    }
}
