//! stigmer-store-conformance: the behaviour every `Store` backend must show.
//!
//! A backend's test calls [`run_all`] with a factory for fresh, empty stores. Each scenario
//! panics with its name when the backend gets something wrong. Run it on a multi-thread
//! tokio runtime: the concurrency scenario spawns tasks.

use std::future::Future;
use std::sync::Arc;

use stigmer_core::{
    event_hash, BoardId, ChannelPath, Cursor, EventKind, Label, MessageId, NewMessage, Principal,
    Target, GENESIS_HASH,
};
use stigmer_store::{ChainReport, Posted, Store, StoreError};

/// Runs every scenario, each against a fresh store from `factory`.
pub async fn run_all<S, F, Fut>(factory: F)
where
    S: Store,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    first_post_creates_thread_with_event_seq_1(factory().await).await;
    reply_appends_event_seq_2_and_keeps_thread_id(factory().await).await;
    sequence_is_gapless_under_50_concurrent_posts(factory().await).await;
    reply_to_unknown_thread_is_not_found(factory().await).await;
    reply_to_a_reply_is_not_found(factory().await).await;
    post_to_unknown_board_is_not_found(factory().await).await;
    same_key_same_author_returns_original_and_replayed_true(factory().await).await;
    same_key_writes_exactly_one_event(factory().await).await;
    same_key_different_author_is_a_new_message(factory().await).await;
    same_key_different_text_is_conflict(factory().await).await;
}

fn channel(raw: &str) -> ChannelPath {
    ChannelPath::new(raw).unwrap_or_else(|e| panic!("test channel {raw:?}: {e}"))
}

fn principal(raw: &str) -> Principal {
    Principal::new(raw).unwrap_or_else(|e| panic!("test principal {raw:?}: {e}"))
}

fn message(
    board: BoardId,
    target: Target,
    author: &str,
    text: &str,
    labels: Vec<Label>,
) -> NewMessage {
    NewMessage::new(
        board,
        target,
        principal(author),
        text.to_owned(),
        labels,
        None,
    )
    .unwrap_or_else(|e| panic!("test message: {e}"))
}

fn new_thread(channel_path: &str, author: &str, text: &str) -> NewMessage {
    message(
        BoardId::main(),
        Target::NewThread {
            channel: channel(channel_path),
        },
        author,
        text,
        vec![],
    )
}

fn reply(thread: &MessageId, author: &str, text: &str) -> NewMessage {
    message(
        BoardId::main(),
        Target::Reply {
            thread: thread.clone(),
        },
        author,
        text,
        vec![],
    )
}

fn keyed(mut msg: NewMessage, key: &str) -> NewMessage {
    msg.idempotency_key = Some(key.to_owned());
    msg
}

async fn post_ok<S: Store>(store: &S, msg: NewMessage, scenario: &str) -> Posted {
    match store.post(msg).await {
        Ok(posted) => posted,
        Err(e) => panic!("{scenario}: post failed: {e}"),
    }
}

async fn verify_main<S: Store>(store: &S, scenario: &str) -> ChainReport {
    match store.verify_chain(&BoardId::main()).await {
        Ok(report) => report,
        Err(e) => panic!("{scenario}: verify_chain failed: {e}"),
    }
}

fn valid_chain(checked: u64) -> ChainReport {
    ChainReport {
        valid: true,
        checked,
        first_bad_seq: None,
    }
}

/// The hash this event must carry when `prev` is the hash before it.
fn expected_hash(prev: &str, posted: &Posted) -> String {
    let e = &posted.event;
    event_hash(
        prev,
        e.seq,
        e.kind,
        &e.actor,
        &e.message_id,
        &e.channel,
        e.at_ms,
    )
}

async fn first_post_creates_thread_with_event_seq_1<S: Store>(store: S) {
    const SCENARIO: &str = "first_post_creates_thread_with_event_seq_1";
    assert_eq!(
        verify_main(&store, SCENARIO).await,
        valid_chain(0),
        "{SCENARIO}: empty board"
    );

    let labels = vec![
        Label::new("kind", "bug").unwrap_or_else(|e| panic!("{e}")),
        Label::new("prio", "high").unwrap_or_else(|e| panic!("{e}")),
    ];
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

async fn reply_appends_event_seq_2_and_keeps_thread_id<S: Store>(store: S) {
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

async fn sequence_is_gapless_under_50_concurrent_posts<S: Store>(store: S) {
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
        let posted = match handle.await {
            Ok(Ok(posted)) => posted,
            Ok(Err(e)) => panic!("{SCENARIO}: post failed: {e}"),
            Err(e) => panic!("{SCENARIO}: task failed: {e}"),
        };
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

async fn reply_to_unknown_thread_is_not_found<S: Store>(store: S) {
    const SCENARIO: &str = "reply_to_unknown_thread_is_not_found";
    let unknown = MessageId::new("msg_0123456789abcdef01234567")
        .unwrap_or_else(|e| panic!("{SCENARIO}: {e}"));
    let result = store.post(reply(&unknown, "alice", "hello?")).await;
    assert!(
        matches!(result, Err(StoreError::NotFound(_))),
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

async fn reply_to_a_reply_is_not_found<S: Store>(store: S) {
    const SCENARIO: &str = "reply_to_a_reply_is_not_found";
    let root = post_ok(&store, new_thread("eng", "alice", "root"), SCENARIO).await;
    let answer = post_ok(&store, reply(&root.message.id, "bob", "answer"), SCENARIO).await;
    let result = store
        .post(reply(&answer.message.id, "carol", "nested"))
        .await;
    assert!(
        matches!(result, Err(StoreError::NotFound(_))),
        "{SCENARIO}: replies attach to thread roots only, got {result:?}"
    );
    assert_eq!(
        verify_main(&store, SCENARIO).await,
        valid_chain(2),
        "{SCENARIO}"
    );
}

async fn post_to_unknown_board_is_not_found<S: Store>(store: S) {
    const SCENARIO: &str = "post_to_unknown_board_is_not_found";
    let board = BoardId::new("nowhere").unwrap_or_else(|e| panic!("{SCENARIO}: {e}"));
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
        matches!(result, Err(StoreError::NotFound(_))),
        "{SCENARIO}: got {result:?}"
    );
    assert_eq!(
        verify_main(&store, SCENARIO).await,
        valid_chain(0),
        "{SCENARIO}"
    );
}

async fn same_key_same_author_returns_original_and_replayed_true<S: Store>(store: S) {
    const SCENARIO: &str = "same_key_same_author_returns_original_and_replayed_true";
    let msg = keyed(new_thread("eng", "alice", "deploy"), "req-1");
    let first = post_ok(&store, msg.clone(), SCENARIO).await;
    assert!(!first.replayed, "{SCENARIO}: first post is not a replay");
    let second = post_ok(&store, msg, SCENARIO).await;
    assert!(second.replayed, "{SCENARIO}: retry must be flagged");
    assert_eq!(second.message, first.message, "{SCENARIO}");
    assert_eq!(second.event, first.event, "{SCENARIO}");
}

async fn same_key_writes_exactly_one_event<S: Store>(store: S) {
    const SCENARIO: &str = "same_key_writes_exactly_one_event";
    let msg = keyed(new_thread("eng", "alice", "deploy"), "req-1");
    for _ in 0..3 {
        post_ok(&store, msg.clone(), SCENARIO).await;
    }
    assert_eq!(
        verify_main(&store, SCENARIO).await,
        valid_chain(1),
        "{SCENARIO}"
    );
}

async fn same_key_different_author_is_a_new_message<S: Store>(store: S) {
    const SCENARIO: &str = "same_key_different_author_is_a_new_message";
    let alice = post_ok(
        &store,
        keyed(new_thread("eng", "alice", "deploy"), "req-1"),
        SCENARIO,
    )
    .await;
    let bob = post_ok(
        &store,
        keyed(new_thread("eng", "bob", "deploy"), "req-1"),
        SCENARIO,
    )
    .await;
    assert!(!bob.replayed, "{SCENARIO}: keys are scoped per author");
    assert_ne!(bob.message.id, alice.message.id, "{SCENARIO}");
    assert_eq!(bob.event.seq, 2, "{SCENARIO}");
    assert_eq!(
        verify_main(&store, SCENARIO).await,
        valid_chain(2),
        "{SCENARIO}"
    );
}

async fn same_key_different_text_is_conflict<S: Store>(store: S) {
    const SCENARIO: &str = "same_key_different_text_is_conflict";
    post_ok(
        &store,
        keyed(new_thread("eng", "alice", "deploy"), "req-1"),
        SCENARIO,
    )
    .await;
    let result = store
        .post(keyed(new_thread("eng", "alice", "something else"), "req-1"))
        .await;
    assert!(
        matches!(result, Err(StoreError::Conflict(_))),
        "{SCENARIO}: got {result:?}"
    );
    assert_eq!(
        verify_main(&store, SCENARIO).await,
        valid_chain(1),
        "{SCENARIO}"
    );
}
