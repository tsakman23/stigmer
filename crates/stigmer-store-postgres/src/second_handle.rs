//! Test support for the conformance suites: a second handle on a store's database, and the
//! number of waiters on a board.

use std::sync::Arc;

use stigmer_core::BoardId;
use stigmer_store::StoreError;

use crate::error::backend;
use crate::{pool, PgStore};

impl PgStore {
    /// Test support, not API: a new pool on the SAME database (and schema) as this store, with
    /// waiters of its own, as a second server process would have. Opens one connection to
    /// check it, as [`PgStore::connect`] does.
    #[doc(hidden)]
    pub async fn second_handle_for_tests(&self) -> Result<PgStore, StoreError> {
        let pool = pool::build(&self.config, self.options)?;
        drop(pool.get().await.map_err(backend)?);
        Ok(PgStore {
            pool,
            config: self.config.clone(),
            options: self.options,
            target: self.target.clone(),
            waiters: Arc::default(),
        })
    }

    /// Test support, not API: the number of `wait_past` callers currently blocked on `board`
    /// through this handle.
    #[doc(hidden)]
    pub fn waiters_for_tests(&self, board: &BoardId) -> usize {
        self.waiters.count(board)
    }
}
