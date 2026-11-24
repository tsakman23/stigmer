//! Long-poll waits on the board head.
//!
//! No scenario sleeps to let a waiter start: a wake must hold whether the post lands before,
//! during or after the waiter subscribes, so each wake scenario repeats for every number of
//! yields in `0..=YIELDS` between starting the waiter and posting.

use std::sync::Arc;
use std::time::Duration;

use stigmer_core::{BoardId, Cursor};
use stigmer_store::{Store, StoreError};

use crate::support::{keyed, new_thread, ok, post_ok, yield_times, LONG, YIELDS};

const SHORT: Duration = Duration::from_millis(150);

pub(crate) async fn wait_past_returns_true_when_a_post_lands_during_the_wait<S: Store>(store: S) {
    const SCENARIO: &str = "wait_past_returns_true_when_a_post_lands_during_the_wait";
    let store = Arc::new(store);
    let first = post_ok(&*store, new_thread("eng", "alice", "one"), SCENARIO).await;
    let mut cursor = first.event.cursor;

    for yields in 0..=YIELDS {
        let waiter = {
            let (store, cursor) = (Arc::clone(&store), cursor.clone());
            tokio::spawn(
                async move { store.wait_past(&BoardId::main(), Some(&cursor), LONG).await },
            )
        };
        yield_times(yields).await;
        assert!(
            !waiter.is_finished(),
            "{SCENARIO}: nothing posted yet ({yields} yields)"
        );
        let posted = post_ok(&*store, new_thread("eng", "bob", "two"), SCENARIO).await;

        let result = ok(waiter.await, format_args!("{SCENARIO}: waiter task failed"));
        assert_eq!(result, Ok(true), "{SCENARIO} ({yields} yields)");
        cursor = posted.event.cursor;
    }
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
    for (head, yields) in (2..).zip(0..=YIELDS) {
        let fresh_waiter = {
            let store = Arc::clone(&store);
            tokio::spawn(async move {
                store
                    .wait_past(&BoardId::main(), Some(&Cursor::from_seq(head)), LONG)
                    .await
            })
        };
        yield_times(yields).await;
        post_ok(&*store, new_thread("eng", "alice", "three"), SCENARIO).await;
        let result = ok(
            fresh_waiter.await,
            format_args!("{SCENARIO}: waiter task failed"),
        );
        assert_eq!(
            result,
            Ok(true),
            "{SCENARIO}: seq {} is past cursor {head} ({yields} yields)",
            head + 1
        );
    }
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
    let cursor = first.event.cursor;

    // A replay adds no event, so the rounds cannot disturb each other: they overlap, and each
    // waiter sees its own replay and the later ones.
    let mut waiters = Vec::new();
    for yields in 0..=YIELDS {
        let waiter = {
            let (store, cursor) = (Arc::clone(&store), cursor.clone());
            tokio::spawn(async move {
                store
                    .wait_past(&BoardId::main(), Some(&cursor), Duration::from_millis(300))
                    .await
            })
        };
        yield_times(yields).await;
        let retry = post_ok(&*store, msg.clone(), SCENARIO).await;
        assert!(retry.replayed, "{SCENARIO}: the retry is a replay");
        waiters.push((yields, waiter));
    }

    for (yields, waiter) in waiters {
        let result = ok(waiter.await, format_args!("{SCENARIO}: waiter task failed"));
        assert_eq!(
            result,
            Ok(false),
            "{SCENARIO}: a replay adds no event ({yields} yields)"
        );
    }
}
