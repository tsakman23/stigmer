//! Board lifecycle: creating, listing and archiving boards, and keeping boards apart.

use std::time::Duration;

use stigmer_core::{BoardId, BoardInfo, EventFilter, Page};
use stigmer_store::{ConflictKind, Store, StoreError};

use crate::support::{
    board, keyed, new_thread_on, ok, post_ok, principal, reply_on, tick, valid_chain,
};

const SHORT: Duration = Duration::from_millis(150);

fn ids(boards: &[BoardInfo]) -> Vec<&str> {
    boards.iter().map(|b| b.id.as_str()).collect()
}

fn all_channels() -> Page {
    Page {
        limit: 50,
        before: None,
    }
}

pub(crate) async fn create_board_then_get_and_list<S: Store>(store: S) {
    const SCENARIO: &str = "create_board_then_get_and_list";
    let alice = principal("alice");
    tick().await;
    let research = ok(
        store.create_board(&board("research"), Some(&alice)).await,
        format_args!("{SCENARIO}: create research"),
    );
    assert_eq!(research.id, board("research"), "{SCENARIO}");
    assert_eq!(research.created_by, Some(alice), "{SCENARIO}: creator");
    assert_eq!(research.archived_at_ms, None, "{SCENARIO}: not archived");
    assert!(
        research.created_at_ms > 0,
        "{SCENARIO}: creation time is set"
    );
    assert_eq!(
        store.get_board(&board("research")).await,
        Ok(research.clone()),
        "{SCENARIO}: get returns what create returned"
    );

    tick().await;
    // Created later but sorting first by id: the list must order by creation time.
    let alpha = ok(
        store.create_board(&board("alpha"), None).await,
        format_args!("{SCENARIO}: create alpha"),
    );
    assert_eq!(alpha.created_by, None, "{SCENARIO}: no creator");
    assert!(alpha.created_at_ms > research.created_at_ms, "{SCENARIO}");

    let listed = ok(store.list_boards().await, format_args!("{SCENARIO}: list"));
    assert_eq!(
        ids(&listed),
        vec!["main", "research", "alpha"],
        "{SCENARIO}: oldest first"
    );
    assert_eq!(listed[1], research, "{SCENARIO}");
    assert_eq!(listed[2], alpha, "{SCENARIO}");
}

pub(crate) async fn create_duplicate_board_is_board_exists<S: Store>(store: S) {
    const SCENARIO: &str = "create_duplicate_board_is_board_exists";
    let first = ok(
        store.create_board(&board("research"), None).await,
        format_args!("{SCENARIO}: first create"),
    );
    let again = store
        .create_board(&board("research"), Some(&principal("bob")))
        .await;
    assert_eq!(
        again,
        Err(StoreError::Conflict(ConflictKind::BoardExists)),
        "{SCENARIO}: second create"
    );
    let main = store.create_board(&BoardId::main(), None).await;
    assert_eq!(
        main,
        Err(StoreError::Conflict(ConflictKind::BoardExists)),
        "{SCENARIO}: main always exists"
    );
    assert_eq!(
        store.get_board(&board("research")).await,
        Ok(first),
        "{SCENARIO}: the original board is untouched"
    );
}

pub(crate) async fn main_exists_on_a_fresh_store<S: Store>(store: S) {
    const SCENARIO: &str = "main_exists_on_a_fresh_store";
    let main = ok(
        store.get_board(&BoardId::main()).await,
        format_args!("{SCENARIO}: get main"),
    );
    assert_eq!(main.id, BoardId::main(), "{SCENARIO}");
    assert_eq!(main.created_by, None, "{SCENARIO}: made by the store");
    assert_eq!(main.archived_at_ms, None, "{SCENARIO}");
    let listed = ok(store.list_boards().await, format_args!("{SCENARIO}: list"));
    assert_eq!(listed, vec![main], "{SCENARIO}: main is the only board");
}

pub(crate) async fn boards_are_isolated_sequences_start_at_1_per_board<S: Store>(store: S) {
    const SCENARIO: &str = "boards_are_isolated_sequences_start_at_1_per_board";
    let (main, other) = (BoardId::main(), board("other"));
    ok(
        store.create_board(&other, None).await,
        format_args!("{SCENARIO}: create other"),
    );
    let on_main = post_ok(&store, new_thread_on(&main, "eng", "alice", "m1"), SCENARIO).await;
    let first = post_ok(&store, new_thread_on(&other, "eng", "bob", "o1"), SCENARIO).await;
    let second = post_ok(
        &store,
        reply_on(&other, &first.message.id, "carol", "o2"),
        SCENARIO,
    )
    .await;
    assert_eq!(on_main.event.seq, 1, "{SCENARIO}: main starts at 1");
    assert_eq!(first.event.seq, 1, "{SCENARIO}: other starts at 1 too");
    assert_eq!(second.event.seq, 2, "{SCENARIO}");
    assert_eq!(first.message.board, other, "{SCENARIO}");

    for (id, events) in [(&main, 1), (&other, 2)] {
        let report = ok(
            store.verify_chain(id).await,
            format_args!("{SCENARIO}: verify {id}"),
        );
        assert_eq!(report, valid_chain(events), "{SCENARIO}: chain of {id}");
    }
    let other_events = ok(
        store
            .events_after(&other, None, &EventFilter::default(), 50)
            .await,
        format_args!("{SCENARIO}: events of other"),
    );
    let message_ids: Vec<_> = other_events.iter().map(|e| &e.message_id).collect();
    assert_eq!(
        message_ids,
        vec![&first.message.id, &second.message.id],
        "{SCENARIO}: only the other board's events"
    );
    let main_threads = ok(
        store
            .read_channel(&main, &crate::support::channel("eng"), all_channels())
            .await,
        format_args!("{SCENARIO}: read main"),
    );
    assert_eq!(main_threads.len(), 1, "{SCENARIO}: only main's thread");
    assert_eq!(main_threads[0].thread_id, on_main.message.id, "{SCENARIO}");
    let cross = store
        .post(reply_on(&main, &first.message.id, "dave", "x"))
        .await;
    assert!(
        matches!(cross, Err(StoreError::NotFound { .. })),
        "{SCENARIO}: a thread on another board cannot be replied to, got {cross:?}"
    );
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
            .read_channel(&old, &crate::support::channel("eng"), all_channels())
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
        crate::support::fail(format_args!("{SCENARIO}: archive sets archived_at_ms"));
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
