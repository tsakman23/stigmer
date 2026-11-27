//! Runs the shared conformance suites (store, identity and cross-instance) against Postgres,
//! each store in a schema of its own on the test database (`STIGMER_TEST_DATABASE_URL`).

use std::sync::{Mutex, PoisonError};

use stigmer_core::BoardId;
use stigmer_store_conformance::Fixture;
use stigmer_store_postgres::testing::{database_url, TestSchema, HOURLY_POLL};
use stigmer_store_postgres::PgStore;

/// Makes each store on a new schema and owns the schemas for its whole life, so every schema
/// outlives its stores and is dropped, with everything in it, when the fixture is.
struct PgFixture {
    url: String,
    schemas: Mutex<Vec<TestSchema>>,
}

impl Fixture for PgFixture {
    type Store = PgStore;

    /// Two handles are two pools, each with its own notifier and its own listener connection
    /// (started by its first wait that sleeps), as two server processes would have: a wait on one handle wakes for a post through the other
    /// only by LISTEN/NOTIFY, since every store here polls the heads once an hour.
    const CROSS_PROCESS_WAKE: bool = true;

    async fn fresh(&self) -> PgStore {
        let schema = TestSchema::create(&self.url).await.expect("test schema");
        let store =
            PgStore::connect_with_poll_for_tests(schema.url(), schema.options(), HOURLY_POLL)
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

    /// The waits on `board` that have read the head and sleep on the handle's notifier, so a
    /// post after this reaches them only through a wake-up (not their own head read).
    fn waiters(&self, store: &PgStore, board: &BoardId) -> usize {
        store.sleeping_waiters_for_tests(board)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_store_passes_conformance_suite() {
    const TEST: &str = "postgres_store_passes_conformance_suite";
    let Some(url) = database_url(TEST).unwrap() else {
        return;
    };
    let fixture = PgFixture {
        url,
        schemas: Mutex::default(),
    };
    stigmer_store_conformance::run_all(&fixture).await;
}
