//! Long-poll waits on the board head.

use std::sync::Arc;
use std::time::Duration;

use stigmer_core::{BoardId, Cursor};
use stigmer_store::{Store, StoreError};

use crate::support::{keyed, new_thread, ok, post_ok};

/// Generous upper bound for waits that must end early; tests assert on the outcome, not the time.
const LONG: Duration = Duration::from_secs(10);
const SHORT: Duration = Duration::from_millis(150);

pub(crate) async fn wait_past_returns_true_when_a_post_lands_during_the_wait<S: Store>(store: S) {
    const SCENARIO: &str = "wait_past_returns_true_when_a_post_lands_during_the_wait";
    let store = Arc::new(store);
    let first = post_ok(&*store, new_thread("eng", "alice", "one"), SCENARIO).await;
    let cursor = first.event.cursor.clone();

    let waiter = {
        let store = Arc::clone(&store);
        tokio::spawn(async move { store.wait_past(&BoardId::main(), Some(&cursor), LONG).await })
    };
    // Give the waiter time to start waiting; correctness does not depend on it.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!waiter.is_finished(), "{SCENARIO}: nothing posted yet");
    post_ok(&*store, new_thread("eng", "bob", "two"), SCENARIO).await;

    let result = ok(waiter.await, format_args!("{SCENARIO}: waiter task failed"));
    assert_eq!(result, Ok(true), "{SCENARIO}");
}

pub(crate) async fn wait_past_returns_false_on_timeout<S: Store>(store: S) {
    const SCENARIO: &str = "wait_past_returns_false_on_timeout";
    let first = post_ok(&store, new_thread("eng", "alice", "one"), SCENARIO).await;
    let result = store
        .wait_past(&BoardId::main(), Some(&first.event.cursor), SHORT)
        .await;
    assert_eq!(result, Ok(false), "{SCENARIO}: with a cursor at the head");
    let from_start = store.wait_past(&BoardId::main(), None, SHORT).await;
    assert_eq!(
        from_start,
        Ok(true),
        "{SCENARIO}: None counts as seq 0, and seq 1 exists"
    );
}

pub(crate) async fn wait_past_does_not_wake_for_events_before_the_cursor<S: Store>(store: S) {
    const SCENARIO: &str = "wait_past_does_not_wake_for_events_before_the_cursor";
    let store = Arc::new(store);
    post_ok(&*store, new_thread("eng", "alice", "one"), SCENARIO).await;
    let second = post_ok(&*store, new_thread("eng", "alice", "two"), SCENARIO).await;
    let cursor = second.event.cursor.clone();

    // Nothing new after seq 2: events 1 and 2 must not count.
    let result = store
        .wait_past(&BoardId::main(), Some(&cursor), SHORT)
        .await;
    assert_eq!(
        result,
        Ok(false),
        "{SCENARIO}: old events do not wake the wait"
    );

    // A waiter on the head cursor wakes for the next post.
    let fresh_waiter = {
        let store = Arc::clone(&store);
        tokio::spawn(async move {
            store
                .wait_past(&BoardId::main(), Some(&Cursor::from_seq(2)), LONG)
                .await
        })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    post_ok(&*store, new_thread("eng", "alice", "three"), SCENARIO).await;
    let result = ok(
        fresh_waiter.await,
        format_args!("{SCENARIO}: waiter task failed"),
    );
    assert_eq!(result, Ok(true), "{SCENARIO}: seq 3 is past cursor 2");
}

pub(crate) async fn wait_past_returns_true_at_once_when_head_is_already_past<S: Store>(store: S) {
    const SCENARIO: &str = "wait_past_returns_true_at_once_when_head_is_already_past";
    let first = post_ok(&store, new_thread("eng", "alice", "one"), SCENARIO).await;
    post_ok(&store, new_thread("eng", "alice", "two"), SCENARIO).await;
    // A long timeout: if the head check is skipped this test would hang, not pass.
    let result = store
        .wait_past(&BoardId::main(), Some(&first.event.cursor), LONG)
        .await;
    assert_eq!(result, Ok(true), "{SCENARIO}");
}

pub(crate) async fn wait_past_future_cursor_is_invalid_cursor_without_waiting<S: Store>(store: S) {
    const SCENARIO: &str = "wait_past_future_cursor_is_invalid_cursor_without_waiting";
    post_ok(&store, new_thread("eng", "alice", "one"), SCENARIO).await;
    let result = store
        .wait_past(&BoardId::main(), Some(&Cursor::from_seq(5)), LONG)
        .await;
    assert_eq!(result, Err(StoreError::InvalidCursor), "{SCENARIO}");
}

pub(crate) async fn wait_past_is_not_woken_by_an_idempotent_replay<S: Store>(store: S) {
    const SCENARIO: &str = "wait_past_is_not_woken_by_an_idempotent_replay";
    let store = Arc::new(store);
    let msg = keyed(new_thread("eng", "alice", "deploy"), "req-1");
    let first = post_ok(&*store, msg.clone(), SCENARIO).await;
    let cursor = first.event.cursor.clone();

    let waiter = {
        let store = Arc::clone(&store);
        tokio::spawn(async move {
            store
                .wait_past(&BoardId::main(), Some(&cursor), Duration::from_millis(300))
                .await
        })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    let retry = post_ok(&*store, msg, SCENARIO).await;
    assert!(retry.replayed, "{SCENARIO}: the retry is a replay");

    let result = ok(waiter.await, format_args!("{SCENARIO}: waiter task failed"));
    assert_eq!(result, Ok(false), "{SCENARIO}: a replay adds no event");
}
