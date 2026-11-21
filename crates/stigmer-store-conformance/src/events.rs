//! The event feed: head, events_after, filters and cursors.

use std::future::Future;
use std::panic::Location;
use std::time::Duration;

use stigmer_core::{BoardId, Cursor, Event, EventFilter, NewMessage, Target};
use stigmer_store::{Entity, Store, StoreError};

use crate::support::{channel, label, message, new_thread, ok, ok_from, post_ok, reply};

fn labelled(channel_path: &str, text: &str, key: &str, value: &str) -> NewMessage {
    message(
        BoardId::main(),
        Target::NewThread {
            channel: channel(channel_path),
        },
        "alice",
        text,
        vec![label(key, value)],
    )
}

/// Reads main-board events, panicking with `scenario` and the caller's line on error.
#[track_caller]
fn events_ok<'a, S: Store>(
    store: &'a S,
    after: Option<&'a Cursor>,
    filter: &'a EventFilter,
    limit: u32,
    scenario: &'a str,
) -> impl Future<Output = Vec<Event>> + 'a {
    let caller = Location::caller();
    async move {
        ok_from(
            caller,
            store
                .events_after(&BoardId::main(), after, filter, limit)
                .await,
            format_args!("{scenario}: events_after failed"),
        )
    }
}

fn seqs(events: &[Event]) -> Vec<u64> {
    events.iter().map(|e| e.seq).collect()
}

pub(crate) async fn head_is_none_on_an_empty_board_then_the_latest_cursor<S: Store>(store: S) {
    const SCENARIO: &str = "head_is_none_on_an_empty_board_then_the_latest_cursor";
    let board = BoardId::main();
    assert_eq!(
        store.head(&board).await,
        Ok(None),
        "{SCENARIO}: empty board has no head"
    );
    post_ok(&store, new_thread("eng", "alice", "one"), SCENARIO).await;
    let second = post_ok(&store, new_thread("eng", "alice", "two"), SCENARIO).await;
    assert_eq!(
        store.head(&board).await,
        Ok(Some(second.event.cursor)),
        "{SCENARIO}"
    );
    let nowhere = ok(BoardId::new("nowhere"), SCENARIO);
    assert!(
        matches!(
            store.head(&nowhere).await,
            Err(StoreError::NotFound {
                entity: Entity::Board,
                ..
            })
        ),
        "{SCENARIO}: unknown board"
    );
}

pub(crate) async fn events_after_none_returns_from_start<S: Store>(store: S) {
    const SCENARIO: &str = "events_after_none_returns_from_start";
    let none = events_ok(&store, None, &EventFilter::default(), 10, SCENARIO).await;
    assert!(none.is_empty(), "{SCENARIO}: empty board has no events");

    let root = post_ok(&store, new_thread("eng", "alice", "root"), SCENARIO).await;
    let answer = post_ok(&store, reply(&root.message.id, "bob", "answer"), SCENARIO).await;
    post_ok(&store, new_thread("ops", "carol", "third"), SCENARIO).await;

    let events = events_ok(&store, None, &EventFilter::default(), 10, SCENARIO).await;
    assert_eq!(seqs(&events), vec![1, 2, 3], "{SCENARIO}: ascending from 1");
    assert_eq!(events[0], root.event, "{SCENARIO}: full first event");
    assert_eq!(events[1], answer.event, "{SCENARIO}: full second event");
}

pub(crate) async fn events_after_resumes_after_a_cursor_and_clamps_limit<S: Store>(store: S) {
    const SCENARIO: &str = "events_after_resumes_after_a_cursor_and_clamps_limit";
    for i in 0..4 {
        post_ok(
            &store,
            new_thread("eng", "alice", &format!("t{i}")),
            SCENARIO,
        )
        .await;
    }
    let filter = EventFilter::default();
    let after_1 = events_ok(&store, Some(&Cursor::from_seq(1)), &filter, 10, SCENARIO).await;
    assert_eq!(seqs(&after_1), vec![2, 3, 4], "{SCENARIO}: strictly after");
    let at_head = events_ok(&store, Some(&Cursor::from_seq(4)), &filter, 10, SCENARIO).await;
    assert!(
        at_head.is_empty(),
        "{SCENARIO}: the head cursor has nothing new"
    );
    let limited = events_ok(&store, None, &filter, 2, SCENARIO).await;
    assert_eq!(seqs(&limited), vec![1, 2], "{SCENARIO}: limit");
    let zero = events_ok(&store, None, &filter, 0, SCENARIO).await;
    assert_eq!(
        seqs(&zero),
        vec![1],
        "{SCENARIO}: limit 0 is clamped up to 1"
    );

    for i in 4..504 {
        post_ok(
            &store,
            new_thread("many", "alice", &format!("t{i}")),
            SCENARIO,
        )
        .await;
    }
    let huge = events_ok(&store, None, &filter, u32::MAX, SCENARIO).await;
    assert_eq!(huge.len(), 500, "{SCENARIO}: limit is clamped to 500");
}

pub(crate) async fn events_after_filters_by_channel_thread_and_label<S: Store>(store: S) {
    const SCENARIO: &str = "events_after_filters_by_channel_thread_and_label";
    let a = post_ok(&store, labelled("research", "a", "kind", "bug"), SCENARIO).await; // 1
    let b = post_ok(
        &store,
        labelled("research/tls", "b", "kind", "idea"),
        SCENARIO,
    )
    .await; // 2
    post_ok(&store, labelled("research2", "c", "kind", "bug"), SCENARIO).await; // 3
    let a_reply = post_ok(&store, reply(&a.message.id, "bob", "a reply"), SCENARIO).await; // 4
    let b_reply = post_ok(
        &store,
        message(
            BoardId::main(),
            Target::Reply {
                thread: b.message.id.clone(),
            },
            "bob",
            "b reply",
            vec![label("kind", "bug")],
        ),
        SCENARIO,
    )
    .await; // 5

    let by_channel = EventFilter {
        channel_prefix: Some(channel("research")),
        ..EventFilter::default()
    };
    let got = events_ok(&store, None, &by_channel, 50, SCENARIO).await;
    assert_eq!(
        seqs(&got),
        vec![1, 2, 4, 5],
        "{SCENARIO}: whole segments, so research2 is out"
    );

    let by_thread = EventFilter {
        thread: Some(a.message.id.clone()),
        ..EventFilter::default()
    };
    let got = events_ok(&store, None, &by_thread, 50, SCENARIO).await;
    assert_eq!(
        seqs(&got),
        vec![1, 4],
        "{SCENARIO}: the root and its replies"
    );
    assert_eq!(got[1], a_reply.event, "{SCENARIO}");

    let by_label = EventFilter {
        label: Some(label("kind", "bug")),
        ..EventFilter::default()
    };
    let got = events_ok(&store, None, &by_label, 50, SCENARIO).await;
    assert_eq!(
        seqs(&got),
        vec![1, 3, 5],
        "{SCENARIO}: events whose message carries kind=bug"
    );
    assert_eq!(got[2], b_reply.event, "{SCENARIO}");

    let wrong_value = EventFilter {
        label: Some(label("kind", "bu")),
        ..EventFilter::default()
    };
    let got = events_ok(&store, None, &wrong_value, 50, SCENARIO).await;
    assert!(got.is_empty(), "{SCENARIO}: label value must match exactly");

    let combined = EventFilter {
        channel_prefix: Some(channel("research")),
        thread: Some(b.message.id.clone()),
        label: Some(label("kind", "bug")),
    };
    let got = events_ok(&store, None, &combined, 50, SCENARIO).await;
    assert_eq!(seqs(&got), vec![5], "{SCENARIO}: filters combine with AND");

    let after_2 = events_ok(
        &store,
        Some(&Cursor::from_seq(2)),
        &by_channel,
        50,
        SCENARIO,
    )
    .await;
    assert_eq!(seqs(&after_2), vec![4, 5], "{SCENARIO}: cursor plus filter");
}

pub(crate) async fn events_after_future_cursor_is_invalid_cursor<S: Store>(store: S) {
    const SCENARIO: &str = "events_after_future_cursor_is_invalid_cursor";
    let filter = EventFilter::default();
    let result = store
        .events_after(&BoardId::main(), Some(&Cursor::from_seq(1)), &filter, 10)
        .await;
    assert_eq!(
        result,
        Err(StoreError::InvalidCursor),
        "{SCENARIO}: any cursor on an empty board is ahead of the head"
    );
    post_ok(&store, new_thread("eng", "alice", "one"), SCENARIO).await;
    let result = store
        .events_after(&BoardId::main(), Some(&Cursor::from_seq(2)), &filter, 10)
        .await;
    assert_eq!(result, Err(StoreError::InvalidCursor), "{SCENARIO}: head+1");
    let result = store
        .events_after(
            &BoardId::main(),
            Some(&Cursor::from_seq(u64::MAX)),
            &filter,
            10,
        )
        .await;
    assert_eq!(
        result,
        Err(StoreError::InvalidCursor),
        "{SCENARIO}: u64::MAX"
    );
}

pub(crate) async fn events_after_malformed_cursor_is_invalid_cursor<S: Store>(store: S) {
    const SCENARIO: &str = "events_after_malformed_cursor_is_invalid_cursor";
    post_ok(&store, new_thread("eng", "alice", "one"), SCENARIO).await;
    // Sequences start at 1, so a cursor for seq 0 is well formed on the wire but does not decode.
    let malformed = Cursor::from_seq(0);
    assert!(
        malformed.seq().is_err(),
        "{SCENARIO}: test cursor must be bad"
    );
    let result = store
        .events_after(
            &BoardId::main(),
            Some(&malformed),
            &EventFilter::default(),
            10,
        )
        .await;
    assert_eq!(result, Err(StoreError::InvalidCursor), "{SCENARIO}");
    let result = store
        .wait_past(
            &BoardId::main(),
            Some(&malformed),
            Duration::from_millis(50),
        )
        .await;
    assert_eq!(
        result,
        Err(StoreError::InvalidCursor),
        "{SCENARIO}: wait_past"
    );
}

pub(crate) async fn events_after_unknown_board_is_not_found<S: Store>(store: S) {
    const SCENARIO: &str = "events_after_unknown_board_is_not_found";
    let nowhere = ok(BoardId::new("nowhere"), SCENARIO);
    let result = store
        .events_after(&nowhere, None, &EventFilter::default(), 10)
        .await;
    assert!(
        matches!(
            result,
            Err(StoreError::NotFound {
                entity: Entity::Board,
                ..
            })
        ),
        "{SCENARIO}: got {result:?}"
    );
}
