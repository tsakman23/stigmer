//! Shared helpers for the wake-up tests (the crate's own and its integration tests). Nothing
//! here sleeps to synchronise: every wait is on a condition, bounded only so a broken build
//! fails instead of hanging. Errors come back as values; the tests decide what fails.

use std::sync::Arc;
use std::time::Duration;

use stigmer_core::{BoardId, ChannelPath, Cursor, NewMessage, Principal, Target};
use stigmer_store::{Store, StoreError};
use tokio::task::JoinHandle;

use crate::error::backend;
use crate::testing::TestSchema;
use crate::PgStore;

/// A safety poll so slow that, within a test, only NOTIFY (or a reconnect re-read) can wake.
pub const HOURLY_POLL: Duration = Duration::from_secs(3600);

/// Upper bound for a condition a test waits on.
pub const CONDITION_BOUND: Duration = Duration::from_secs(30);

/// Timeout of a wait that must end early; ending by timing out fails the test.
pub const WAIT_TIMEOUT: Duration = Duration::from_secs(10);

/// The most yields an interleaving-exhaustive test tries: every count in `0..=YIELDS`.
pub const YIELDS: usize = 20;

/// A migrated store on `schema` whose safety poll runs every `poll`. Its listener starts on
/// its first wait, as in production.
pub async fn store_with_poll(schema: &TestSchema, poll: Duration) -> Result<PgStore, StoreError> {
    let store = PgStore::connect_with_poll_for_tests(schema.url(), schema.options(), poll).await?;
    store.migrate().await?;
    Ok(store)
}

/// [`store_with_poll`], with its listener started up front, for tests that count the
/// notifications it handles from the first post on.
pub async fn listening_store(schema: &TestSchema, poll: Duration) -> Result<PgStore, StoreError> {
    let store = store_with_poll(schema, poll).await?;
    store.start_listener_for_tests().await?;
    Ok(store)
}

/// A new thread in `eng` on board `main`.
pub fn new_thread(text: &str) -> Result<NewMessage, StoreError> {
    new_thread_on(&BoardId::main(), text)
}

/// A new thread in `eng` on `board`.
pub fn new_thread_on(board: &BoardId, text: &str) -> Result<NewMessage, StoreError> {
    let channel = ChannelPath::new("eng").map_err(backend)?;
    let author = Principal::new("alice").map_err(backend)?;
    let target = Target::NewThread { channel };
    NewMessage::new(board.clone(), target, author, text.to_owned(), vec![], None).map_err(backend)
}

/// Starts `store.wait_past(board, after, timeout)` on a task of its own.
pub fn spawn_wait(
    store: &Arc<PgStore>,
    board: &BoardId,
    after: Option<&Cursor>,
    timeout: Duration,
) -> JoinHandle<Result<bool, StoreError>> {
    let (store, board, after) = (Arc::clone(store), board.clone(), after.cloned());
    tokio::spawn(async move { store.wait_past(&board, after.as_ref(), timeout).await })
}

/// Yields to the runtime `n` times: one interleaving of a spawned task with this one.
pub async fn yield_times(n: usize) {
    for _ in 0..n {
        tokio::task::yield_now().await;
    }
}

/// Whether `reached` came to hold within [`CONDITION_BOUND`], checked between yields.
pub async fn until(mut reached: impl FnMut() -> bool) -> bool {
    tokio::time::timeout(CONDITION_BOUND, async {
        while !reached() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .is_ok()
}

/// Sends a notification in `client`'s schema for a board that does not exist and reports
/// whether `store` then handled at least `expected` notifications in all. Notifications are
/// delivered in commit order, so once the marker is handled every notification committed
/// before it has been handled too.
pub async fn flush_notifications(
    store: &PgStore,
    client: &tokio_postgres::Client,
    expected: u64,
) -> Result<bool, StoreError> {
    client
        .execute(
            "SELECT pg_notify('stigmer_events', current_schema() || ':no-such-board:1')",
            &[],
        )
        .await
        .map_err(crate::error::db)?;
    Ok(until(|| store.notifications_handled_for_tests() >= expected).await)
}
