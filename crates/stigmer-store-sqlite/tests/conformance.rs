//! Runs the shared `Store` and `IdentityStore` conformance suites against SQLite.

use stigmer_store_sqlite::SqliteStore;

async fn fresh_store() -> SqliteStore {
    SqliteStore::open_memory()
        .await
        .expect("in-memory store opens")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sqlite_store_passes_conformance_suite() {
    stigmer_store_conformance::run_all(fresh_store).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sqlite_store_passes_identity_conformance_suite() {
    stigmer_store_conformance::run_identity_all(fresh_store).await;
}
