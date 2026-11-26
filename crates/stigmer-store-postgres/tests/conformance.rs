//! Runs the shared `Store` conformance suites against Postgres, each store in a schema of its
//! own on the test database (`STIGMER_TEST_DATABASE_URL`).
//!
//! Only the `Store` half runs: `PgStore` does not implement `IdentityStore` yet (Task 5 adds it
//! and switches this test to `run_all`).

use std::sync::{Mutex, PoisonError};

use stigmer_core::BoardId;
use stigmer_store_conformance::Fixture;
use stigmer_store_postgres::testing::{database_url, TestSchema};
use stigmer_store_postgres::PgStore;

/// Makes each store on a new schema and owns the schemas for its whole life, so every schema
/// outlives its stores and is dropped, with everything in it, when the fixture is.
struct PgFixture {
    url: String,
    schemas: Mutex<Vec<TestSchema>>,
}

impl Fixture for PgFixture {
    type Store = PgStore;

    /// Two handles are two pools with their own waiters. Until LISTEN/NOTIFY (Task 6) a wait
    /// sees another handle's post by polling the head in the database, not through a notifier.
    const CROSS_PROCESS_WAKE: bool = false;

    async fn fresh(&self) -> PgStore {
        let schema = TestSchema::create(&self.url).await.expect("test schema");
        let store = PgStore::connect(schema.url(), schema.options())
            .await
            .expect("store connects");
        store.migrate().await.expect("schema migrates");
        self.schemas
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(schema);
        store
    }

    async fn second_handle(&self, store: &PgStore) -> PgStore {
        store
            .second_handle_for_tests()
            .await
            .expect("second handle connects")
    }

    fn waiters(&self, store: &PgStore, board: &BoardId) -> usize {
        store.waiters_for_tests(board)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_store_passes_store_conformance_suites() {
    const TEST: &str = "postgres_store_passes_store_conformance_suites";
    let Some(url) = database_url(TEST).unwrap() else {
        return;
    };
    let fixture = PgFixture {
        url,
        schemas: Mutex::default(),
    };
    stigmer_store_conformance::run_store_suites(&fixture).await;
}
