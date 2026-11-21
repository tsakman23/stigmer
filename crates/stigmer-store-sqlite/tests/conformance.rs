//! Runs the shared `Store` conformance suite against SQLite.

use stigmer_store_sqlite::SqliteStore;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sqlite_store_passes_conformance_suite() {
    stigmer_store_conformance::run_all(|| async {
        SqliteStore::open_memory()
            .await
            .expect("in-memory store opens")
    })
    .await;
}
