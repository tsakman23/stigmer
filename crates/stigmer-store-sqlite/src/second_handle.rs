//! Test support for the conformance suites: a second handle on a store's database file, and
//! the number of waiters subscribed to a board.

use std::path::PathBuf;
use std::sync::Arc;

use stigmer_core::BoardId;
use stigmer_store::StoreError;

use crate::SqliteStore;

impl SqliteStore {
    /// Test support, not API: a new connection to the SAME database file as this store,
    /// sharing its in-process notifier, so a post through either handle wakes waiters on
    /// either. Like [`SqliteStore::open`] it checks the schema (already current) and takes no
    /// lock file. An in-memory store has no file to share and is a backend error.
    #[doc(hidden)]
    pub async fn second_handle_for_tests(&self) -> Result<SqliteStore, StoreError> {
        let path = self
            .run(|conn| {
                conn.path()
                    .filter(|path| !path.is_empty())
                    .map(PathBuf::from)
                    .ok_or_else(|| {
                        StoreError::Backend("an in-memory store has no file to share".into())
                    })
            })
            .await?;
        let mut second = Self::open(&path).await?;
        second.notifier = Arc::clone(&self.notifier);
        Ok(second)
    }

    /// Test support, not API: the number of `wait_past` callers currently subscribed to
    /// `board`'s wake-up channel through this handle's notifier (shared with its second
    /// handles); 0 when the board has no entry.
    #[doc(hidden)]
    pub fn waiters_for_tests(&self, board: &BoardId) -> usize {
        self.notifier.receiver_count(board)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_in_memory_store_has_no_second_handle() {
        let store = SqliteStore::open_memory().await.unwrap();
        let err = store.second_handle_for_tests().await.err().unwrap();
        assert!(matches!(err, StoreError::Backend(_)), "{err:?}");
    }
}
