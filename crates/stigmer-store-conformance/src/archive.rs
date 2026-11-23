//! Archived boards: they refuse posts and stay readable.

use std::time::Duration;

use stigmer_core::{BoardId, BoardInfo, EventFilter};
use stigmer_store::{ConflictKind, Store, StoreError};

use crate::support::{
    all_channels, board, channel, fail, keyed, new_thread_on, ok, post_ok, principal, reply_on,
    tick, valid_chain,
};

const SHORT: Duration = Duration::from_millis(150);

pub(crate) async fn archive_main_is_refused_and_main_stays_writable<S: Store>(store: S) {
    const SCENARIO: &str = "archive_main_is_refused_and_main_stays_writable";
    let main = BoardId::main();
    assert_eq!(
        store.archive_board(&main).await.map(|_| ()),
        Err(StoreError::Conflict(ConflictKind::BoardProtected)),
        "{SCENARIO}: archive main"
    );
    let info = ok(store.get_board(&main).await, SCENARIO);
    assert_eq!(
        info.archived_at_ms, None,
        "{SCENARIO}: main is not archived"
    );
    let posted = post_ok(
        &store,
        new_thread_on(&main, "eng", "alice", "still open"),
        SCENARIO,
    )
    .await;
    assert_eq!(posted.event.seq, 1, "{SCENARIO}: main takes posts");
}

pub(crate) async fn post_to_archived_board_is_board_archived_and_uses_no_sequence_number<
    S: Store,
>(
    store: S,
) {
    const SCENARIO: &str = "post_to_archived_board_is_board_archived_and_uses_no_sequence_number";
    let old = board("old");
    ok(
        store.create_board(&old, None).await,
        format_args!("{SCENARIO}: create"),
    );
    let keyed_root = keyed(new_thread_on(&old, "eng", "alice", "root"), "req-1");
    let root = post_ok(&store, keyed_root.clone(), SCENARIO).await;
    ok(
        store.archive_board(&old).await,
        format_args!("{SCENARIO}: archive"),
    );

    let archived = Err(StoreError::Conflict(ConflictKind::BoardArchived));
    let thread = store.post(new_thread_on(&old, "eng", "bob", "late")).await;
    assert_eq!(thread.map(|_| ()), archived, "{SCENARIO}: new thread");
    let answer = store
        .post(reply_on(&old, &root.message.id, "bob", "late reply"))
        .await;
    assert_eq!(answer.map(|_| ()), archived, "{SCENARIO}: reply");
    let retry = store.post(keyed_root).await;
    assert_eq!(retry.map(|_| ()), archived, "{SCENARIO}: keyed retry");

    assert_eq!(
        store.head(&old).await,
        Ok(Some(root.event.cursor.clone())),
        "{SCENARIO}: the head did not move"
    );
    assert_eq!(
        store.verify_chain(&old).await,
        Ok(valid_chain(1)),
        "{SCENARIO}: no sequence number was consumed"
    );
    // Other boards still take posts.
    let on_main = post_ok(
        &store,
        new_thread_on(&BoardId::main(), "eng", "alice", "fine"),
        SCENARIO,
    )
    .await;
    assert_eq!(on_main.event.seq, 1, "{SCENARIO}");
}

pub(crate) async fn archived_board_is_still_readable<S: Store>(store: S) {
    const SCENARIO: &str = "archived_board_is_still_readable";
    let old = board("old");
    ok(
        store.create_board(&old, None).await,
        format_args!("{SCENARIO}: create"),
    );
    let root = post_ok(
        &store,
        new_thread_on(&old, "eng", "alice", "root"),
        SCENARIO,
    )
    .await;
    let answer = post_ok(
        &store,
        reply_on(&old, &root.message.id, "bob", "answer"),
        SCENARIO,
    )
    .await;
    ok(
        store.archive_board(&old).await,
        format_args!("{SCENARIO}: archive"),
    );

    let threads = ok(
        store
            .read_channel(&old, &channel("eng"), all_channels())
            .await,
        format_args!("{SCENARIO}: read_channel"),
    );
    assert_eq!(threads.len(), 1, "{SCENARIO}");
    assert_eq!(threads[0].reply_count, 1, "{SCENARIO}");
    let thread = ok(
        store.read_thread(&old, &root.message.id).await,
        format_args!("{SCENARIO}: read_thread"),
    );
    assert_eq!(thread.root, root.message, "{SCENARIO}");
    assert_eq!(thread.replies, vec![answer.message.clone()], "{SCENARIO}");
    let events = ok(
        store
            .events_after(&old, None, &EventFilter::default(), 50)
            .await,
        format_args!("{SCENARIO}: events_after"),
    );
    assert_eq!(events.len(), 2, "{SCENARIO}");
    assert_eq!(
        store.head(&old).await,
        Ok(Some(answer.event.cursor.clone())),
        "{SCENARIO}: head"
    );
    assert_eq!(
        store.verify_chain(&old).await,
        Ok(valid_chain(2)),
        "{SCENARIO}: verify_chain"
    );
    assert_eq!(
        store.wait_past(&old, None, SHORT).await,
        Ok(true),
        "{SCENARIO}: wait_past from the start"
    );
    assert_eq!(
        store
            .wait_past(&old, Some(&answer.event.cursor), SHORT)
            .await,
        Ok(false),
        "{SCENARIO}: wait_past at the head times out"
    );
}

pub(crate) async fn archive_is_idempotent_and_keeps_first_timestamp<S: Store>(store: S) {
    const SCENARIO: &str = "archive_is_idempotent_and_keeps_first_timestamp";
    let old = board("old");
    let created = ok(
        store.create_board(&old, Some(&principal("alice"))).await,
        format_args!("{SCENARIO}: create"),
    );
    let first = ok(
        store.archive_board(&old).await,
        format_args!("{SCENARIO}: first archive"),
    );
    let Some(archived_at) = first.archived_at_ms else {
        fail(format_args!("{SCENARIO}: archive sets archived_at_ms"));
    };
    assert!(archived_at >= created.created_at_ms, "{SCENARIO}");
    assert_eq!(
        first,
        BoardInfo {
            archived_at_ms: Some(archived_at),
            ..created
        },
        "{SCENARIO}: only the archive time changes"
    );
    tick().await;
    assert_eq!(
        store.archive_board(&old).await,
        Ok(first.clone()),
        "{SCENARIO}: a second archive is a no-op"
    );
    assert_eq!(store.get_board(&old).await, Ok(first.clone()), "{SCENARIO}");
    let listed = ok(store.list_boards().await, format_args!("{SCENARIO}: list"));
    assert!(
        listed.contains(&first),
        "{SCENARIO}: archived boards are still listed"
    );
}
