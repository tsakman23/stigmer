//! Board lifecycle: creating, listing and archiving boards, and keeping boards apart.

use std::time::Duration;

use stigmer_core::{BoardId, BoardInfo, Cursor, EventFilter, MessageId};
use stigmer_store::{ConflictKind, Entity, Store, StoreError};

use crate::support::{
    all_channels, board, channel, new_thread_on, ok, post_ok, principal, reply_on, valid_chain,
};
use crate::support::{board_archived, board_created, NOW};

fn ids(boards: &[BoardInfo]) -> Vec<&str> {
    boards.iter().map(|b| b.id.as_str()).collect()
}

pub(crate) async fn create_board_then_get_and_list<S: Store>(store: S) {
    const SCENARIO: &str = "create_board_then_get_and_list";
    let alice = principal("alice");
    // After main, which the store stamped with the real clock when it opened.
    let at = stigmer_core::now_ms() + 1_000;
    let research = ok(
        store
            .create_board(
                &board("research"),
                Some(&alice),
                at,
                board_created(&board("research"), at),
            )
            .await,
        format_args!("{SCENARIO}: create research"),
    );
    assert_eq!(research.id, board("research"), "{SCENARIO}");
    assert_eq!(research.created_by, Some(alice), "{SCENARIO}: creator");
    assert_eq!(research.archived_at_ms, None, "{SCENARIO}: not archived");
    assert_eq!(
        research.created_at_ms, at,
        "{SCENARIO}: creation time is the caller's"
    );
    assert_eq!(
        store.get_board(&board("research")).await,
        Ok(research.clone()),
        "{SCENARIO}: get returns what create returned"
    );

    // Created later but sorting first by id: the list must order by creation time.
    let alpha = ok(
        store
            .create_board(
                &board("alpha"),
                None,
                at + 1,
                board_created(&board("alpha"), at + 1),
            )
            .await,
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
        store
            .create_board(
                &board("research"),
                None,
                NOW,
                board_created(&board("research"), NOW),
            )
            .await,
        format_args!("{SCENARIO}: first create"),
    );
    let again = store
        .create_board(
            &board("research"),
            Some(&principal("bob")),
            NOW,
            board_created(&board("research"), NOW),
        )
        .await;
    assert_eq!(
        again,
        Err(StoreError::Conflict(ConflictKind::BoardExists)),
        "{SCENARIO}: second create"
    );
    let main = store
        .create_board(
            &BoardId::main(),
            None,
            NOW,
            board_created(&BoardId::main(), NOW),
        )
        .await;
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
        store
            .create_board(&other, None, NOW, board_created(&other, NOW))
            .await,
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
            .read_channel(&main, &channel("eng"), all_channels())
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

pub(crate) async fn unknown_board_is_not_found_from_every_method<S: Store>(store: S) {
    const SCENARIO: &str = "unknown_board_is_not_found_from_every_method";
    let nowhere = board("nowhere");
    let not_found = |result: Result<(), StoreError>, method: &str| {
        assert_eq!(
            result,
            Err(StoreError::NotFound {
                entity: Entity::Board,
                id: "nowhere".to_owned(),
            }),
            "{SCENARIO}: {method}"
        );
    };
    not_found(
        store
            .read_channel(&nowhere, &channel("eng"), all_channels())
            .await
            .map(drop),
        "read_channel",
    );
    not_found(store.verify_chain(&nowhere).await.map(drop), "verify_chain");
    // A long timeout: an unknown board must fail at once, not wait.
    let wait = store
        .wait_past(&nowhere, None, Duration::from_secs(10))
        .await;
    not_found(wait.map(drop), "wait_past");
    let at_one = Cursor::from_seq(1);
    let wait_cursor = store
        .wait_past(&nowhere, Some(&at_one), Duration::ZERO)
        .await;
    not_found(wait_cursor.map(drop), "wait_past with a cursor");
    let events = store
        .events_after(&nowhere, None, &EventFilter::default(), 10)
        .await;
    not_found(events.map(drop), "events_after");
    not_found(store.head(&nowhere).await.map(drop), "head");
    let post = store
        .post(new_thread_on(&nowhere, "eng", "alice", "hi"))
        .await;
    not_found(post.map(drop), "post");
    not_found(store.get_board(&nowhere).await.map(drop), "get_board");
    not_found(
        store
            .archive_board(&nowhere, NOW, board_archived(&nowhere, NOW))
            .await
            .map(drop),
        "archive_board",
    );

    // read_thread names the thread, not the board (see the trait docs).
    let thread = ok(MessageId::new("msg_0123456789abcdef01234567"), SCENARIO);
    let read = store.read_thread(&nowhere, &thread).await;
    assert!(
        matches!(
            read,
            Err(StoreError::NotFound {
                entity: Entity::Thread,
                ..
            })
        ),
        "{SCENARIO}: read_thread, got {read:?}"
    );
    let listed = ok(store.list_boards().await, format_args!("{SCENARIO}: list"));
    assert_eq!(
        listed.len(),
        1,
        "{SCENARIO}: no board was created on the way"
    );
}
