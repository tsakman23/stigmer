//! Helpers shared by the wake-up tests. Nothing here sleeps to synchronise: every wait is on a
//! condition, bounded by `LONG` only so a broken build fails instead of hanging.

#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;

use stigmer_core::{BoardId, ChannelPath, Cursor, NewMessage, Principal, Target};
use stigmer_store::{Store, StoreError};
use stigmer_store_postgres::testing::TestSchema;
use stigmer_store_postgres::PgStore;
use tokio::task::JoinHandle;

/// A safety poll so slow that, within a test, only NOTIFY (or a reconnect re-read) can wake.
pub const HOUR: Duration = Duration::from_secs(3600);

/// Upper bound for a condition wait or a wait that must end early.
pub const LONG: Duration = Duration::from_secs(30);

/// The most yields an interleaving-exhaustive test tries: every count in `0..=YIELDS`.
pub const YIELDS: usize = 20;

/// A migrated store on `schema` whose safety poll runs every `poll`.
pub async fn store(schema: &TestSchema, poll: Duration) -> PgStore {
    let store = PgStore::connect_with_poll_for_tests(schema.url(), schema.options(), poll)
        .await
        .expect("store connects");
    store.migrate().await.expect("schema migrates");
    store
}

/// A new thread in `eng` on board `main`.
pub fn new_thread(text: &str) -> NewMessage {
    new_thread_on(&BoardId::main(), text)
}

/// A new thread in `eng` on `board`.
pub fn new_thread_on(board: &BoardId, text: &str) -> NewMessage {
    let channel = ChannelPath::new("eng").unwrap();
    let target = Target::NewThread { channel };
    let author = Principal::new("alice").unwrap();
    NewMessage::new(board.clone(), target, author, text.to_owned(), vec![], None).unwrap()
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

/// Yields to the runtime `n` times.
pub async fn yield_times(n: usize) {
    for _ in 0..n {
        tokio::task::yield_now().await;
    }
}

/// Returns once `reached` holds; fails the test if it does not within `LONG`.
pub async fn until(what: &str, mut reached: impl FnMut() -> bool) {
    let held = tokio::time::timeout(LONG, async {
        while !reached() {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(held.is_ok(), "never reached: {what}");
}

/// Sends a notification in `client`'s schema for a board that does not exist and returns once
/// `store` has handled at least `expected` notifications in all. Notifications are delivered
/// in commit order, so once the marker is handled every notification committed before it has
/// been handled too.
pub async fn flush_notifications(store: &PgStore, client: &tokio_postgres::Client, expected: u64) {
    client
        .execute(
            "SELECT pg_notify('stigmer_events', current_schema() || ':no-such-board:1')",
            &[],
        )
        .await
        .expect("marker notification");
    until("the marker notification is handled", || {
        store.notifications_handled_for_tests() >= expected
    })
    .await;
}
