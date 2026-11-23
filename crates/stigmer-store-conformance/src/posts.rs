//! Posting threads and replies, and the hash chain they extend.

use std::sync::Arc;

use stigmer_core::{
    event_hash, BoardId, Cursor, EventKind, HashInput, MessageId, Target, GENESIS_HASH,
};
use stigmer_store::{Entity, Posted, Store, StoreError};

use crate::support::{
    channel, label, message, new_thread, ok, post_ok, principal, reply, valid_chain, verify_main,
};

/// The hash this event must carry when `prev` is the hash before it.
fn expected_hash(prev: &str, posted: &Posted) -> String {
    let e = &posted.event;
    event_hash(&HashInput {
        prev,
        seq: e.seq,
        kind: e.kind,
        actor: &e.actor,
        message_id: &e.message_id,
        thread_id: &e.thread_id,
        channel: &e.channel,
        at_ms: e.at_ms,
    })
}

pub(crate) async fn first_post_creates_thread_with_event_seq_1<S: Store>(store: S) {
    const SCENARIO: &str = "first_post_creates_thread_with_event_seq_1";
    assert_eq!(
        verify_main(&store, SCENARIO).await,
        valid_chain(0),
        "{SCENARIO}: empty board"
    );

    let labels = vec![label("kind", "bug"), label("prio", "high")];
    let msg = message(
        BoardId::main(),
        Target::NewThread {
            channel: channel("eng/ops"),
        },
        "alice",
        "deploy is red",
        labels.clone(),
    );
    let posted = post_ok(&store, msg, SCENARIO).await;

    let m = &posted.message;
    assert_eq!(m.board, BoardId::main(), "{SCENARIO}: board");
    assert_eq!(m.channel, channel("eng/ops"), "{SCENARIO}: channel");
    assert_eq!(
        m.thread_id, m.id,
        "{SCENARIO}: a thread root is its own thread"
    );
    assert_eq!(m.author, principal("alice"), "{SCENARIO}: author");
    assert_eq!(m.text, "deploy is red", "{SCENARIO}: text");
    assert_eq!(m.labels, labels, "{SCENARIO}: labels");
    assert!(m.at_ms > 0, "{SCENARIO}: at_ms is a real timestamp");
    assert!(!posted.replayed, "{SCENARIO}: a first post is not a replay");

    let e = &posted.event;
    assert_eq!(e.seq, 1, "{SCENARIO}: seq");
    assert_eq!(e.cursor, Cursor::from_seq(1), "{SCENARIO}: cursor");
    assert_eq!(e.kind, EventKind::ThreadCreated, "{SCENARIO}: kind");
    assert_eq!(e.actor, m.author, "{SCENARIO}: actor");
    assert_eq!(e.message_id, m.id, "{SCENARIO}: message_id");
    assert_eq!(e.thread_id, m.id, "{SCENARIO}: thread_id");
    assert_eq!(e.channel, m.channel, "{SCENARIO}: event channel");
    assert_eq!(e.at_ms, m.at_ms, "{SCENARIO}: event at_ms");
    assert_eq!(
        e.hash,
        expected_hash(GENESIS_HASH, &posted),
        "{SCENARIO}: first event chains from genesis"
    );

    assert_eq!(
        verify_main(&store, SCENARIO).await,
        valid_chain(1),
        "{SCENARIO}"
    );
}

pub(crate) async fn reply_appends_event_seq_2_and_keeps_thread_id<S: Store>(store: S) {
    const SCENARIO: &str = "reply_appends_event_seq_2_and_keeps_thread_id";
    let root = post_ok(&store, new_thread("eng/ops", "alice", "question"), SCENARIO).await;
    let answer = post_ok(&store, reply(&root.message.id, "bot", "answer"), SCENARIO).await;

    let m = &answer.message;
    assert_ne!(m.id, root.message.id, "{SCENARIO}: a reply gets its own id");
    assert_eq!(m.thread_id, root.message.id, "{SCENARIO}: thread_id");
    assert_eq!(m.channel, root.message.channel, "{SCENARIO}: channel");
    assert_eq!(m.author, principal("bot"), "{SCENARIO}: author");
    assert_eq!(m.text, "answer", "{SCENARIO}: text");
    assert!(!answer.replayed, "{SCENARIO}: replayed");

    let e = &answer.event;
    assert_eq!(e.seq, 2, "{SCENARIO}: seq");
    assert_eq!(e.cursor, Cursor::from_seq(2), "{SCENARIO}: cursor");
    assert_eq!(e.kind, EventKind::MessageReplied, "{SCENARIO}: kind");
    assert_eq!(e.message_id, m.id, "{SCENARIO}: message_id");
    assert_eq!(e.thread_id, root.message.id, "{SCENARIO}: event thread_id");
    assert_eq!(e.channel, root.message.channel, "{SCENARIO}: event channel");
    assert_eq!(
        e.hash,
        expected_hash(&root.event.hash, &answer),
        "{SCENARIO}: reply chains from the root's event"
    );

    assert_eq!(
        verify_main(&store, SCENARIO).await,
        valid_chain(2),
        "{SCENARIO}"
    );
}

pub(crate) async fn sequence_is_gapless_under_50_concurrent_posts<S: Store>(store: S) {
    const SCENARIO: &str = "sequence_is_gapless_under_50_concurrent_posts";
    const POSTS: u64 = 50;
    let store = Arc::new(store);
    let handles: Vec<_> = (0..POSTS)
        .map(|i| {
            let store = Arc::clone(&store);
            tokio::spawn(async move {
                store
                    .post(new_thread("load", "agent", &format!("post {i}")))
                    .await
            })
        })
        .collect();

    let mut seqs = Vec::new();
    for handle in handles {
        let joined = ok(handle.await, format_args!("{SCENARIO}: task failed"));
        let posted = ok(joined, format_args!("{SCENARIO}: post failed"));
        seqs.push(posted.event.seq);
    }
    seqs.sort_unstable();
    assert_eq!(
        seqs,
        (1..=POSTS).collect::<Vec<_>>(),
        "{SCENARIO}: seqs are exactly 1..={POSTS}"
    );
    assert_eq!(
        verify_main(store.as_ref(), SCENARIO).await,
        valid_chain(POSTS),
        "{SCENARIO}"
    );
}

pub(crate) async fn reply_to_unknown_thread_is_not_found<S: Store>(store: S) {
    const SCENARIO: &str = "reply_to_unknown_thread_is_not_found";
    let unknown = ok(MessageId::new("msg_0123456789abcdef01234567"), SCENARIO);
    let result = store.post(reply(&unknown, "alice", "hello?")).await;
    assert!(
        matches!(
            result,
            Err(StoreError::NotFound {
                entity: Entity::Thread,
                ..
            })
        ),
        "{SCENARIO}: got {result:?}"
    );

    // A rejected post must not use up a sequence number.
    let first = post_ok(&store, new_thread("eng", "alice", "first"), SCENARIO).await;
    assert_eq!(
        first.event.seq, 1,
        "{SCENARIO}: no gap after a rejected post"
    );
    assert_eq!(
        verify_main(&store, SCENARIO).await,
        valid_chain(1),
        "{SCENARIO}"
    );
}

pub(crate) async fn reply_to_a_reply_is_not_found<S: Store>(store: S) {
    const SCENARIO: &str = "reply_to_a_reply_is_not_found";
    let root = post_ok(&store, new_thread("eng", "alice", "root"), SCENARIO).await;
    let answer = post_ok(&store, reply(&root.message.id, "bob", "answer"), SCENARIO).await;
    let result = store
        .post(reply(&answer.message.id, "carol", "nested"))
        .await;
    assert!(
        matches!(
            result,
            Err(StoreError::NotFound {
                entity: Entity::Thread,
                ..
            })
        ),
        "{SCENARIO}: replies attach to thread roots only, got {result:?}"
    );
    assert_eq!(
        verify_main(&store, SCENARIO).await,
        valid_chain(2),
        "{SCENARIO}"
    );
}

pub(crate) async fn post_to_unknown_board_is_not_found<S: Store>(store: S) {
    const SCENARIO: &str = "post_to_unknown_board_is_not_found";
    let board = ok(BoardId::new("nowhere"), SCENARIO);
    let msg = message(
        board,
        Target::NewThread {
            channel: channel("eng"),
        },
        "alice",
        "hello",
        vec![],
    );
    let result = store.post(msg).await;
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
    assert_eq!(
        verify_main(&store, SCENARIO).await,
        valid_chain(0),
        "{SCENARIO}"
    );
}
