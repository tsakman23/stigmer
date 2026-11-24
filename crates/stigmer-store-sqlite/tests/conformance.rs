//! Runs the shared conformance suites against SQLite, on file-backed stores.

use std::sync::{Mutex, PoisonError};

use stigmer_store_conformance::Fixture;
use stigmer_store_sqlite::SqliteStore;
use tempfile::TempDir;

/// Makes each store in its own temporary directory, and owns those directories for its whole
/// life, so no store outlives its file.
#[derive(Default)]
struct SqliteFixture {
    dirs: Mutex<Vec<TempDir>>,
}

impl Fixture for SqliteFixture {
    type Store = SqliteStore;

    /// SQLite is single-process: a second handle is another connection in the same process,
    /// sharing the first handle's in-process notifier.
    const CROSS_PROCESS_WAKE: bool = false;

    async fn fresh(&self) -> SqliteStore {
        let dir = tempfile::tempdir().expect("temporary directory");
        let path = dir.path().join("board.db");
        self.dirs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(dir);
        SqliteStore::open(&path).await.expect("file store opens")
    }

    async fn second_handle(&self, store: &SqliteStore) -> SqliteStore {
        store
            .second_handle_for_tests()
            .await
            .expect("second handle opens")
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sqlite_store_passes_conformance_suite() {
    stigmer_store_conformance::run_all(&SqliteFixture::default()).await;
}
