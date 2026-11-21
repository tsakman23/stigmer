//! stigmer-store-conformance: the behaviour every `Store` backend must show.
//!
//! A backend's test calls [`run_all`] with a factory for fresh, empty stores. Each scenario
//! panics with its name when the backend gets something wrong. Run it on a multi-thread
//! tokio runtime: the concurrency scenario spawns tasks.

use std::future::Future;
use std::sync::Arc;

use stigmer_core::{
    event_hash, BoardId, ChannelPath, Cursor, EventKind, Label, MessageId, NewMessage, Page,
    Principal, Target, ThreadSummary, GENESIS_HASH,
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
    read_channel_lists_threads_newest_first_and_filters_by_prefix(factory().await).await;
    read_channel_matches_whole_path_segments_only(factory().await).await;
    read_channel_paginates_with_before_and_clamps_limit(factory().await).await;
    read_channel_preview_is_200_chars_not_bytes(factory().await).await;
    read_thread_returns_root_and_replies_in_order(factory().await).await;
    read_thread_of_unknown_id_reply_or_other_board_is_not_found(factory().await).await;
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

/// Waits long enough that the next post gets a later millisecond timestamp.
async fn tick() {
    tokio::time::sleep(std::time::Duration::from_millis(3)).await;
}

fn page(limit: u32, before: Option<&MessageId>) -> Page {
    Page {
        limit,
        before: before.cloned(),
    }
}

async fn read_channel_ok<S: Store>(
    store: &S,
    prefix: &str,
    page: Page,
    scenario: &str,
) -> Vec<ThreadSummary> {
    match store
        .read_channel(&BoardId::main(), &channel(prefix), page)
        .await
    {
        Ok(threads) => threads,
        Err(e) => panic!("{scenario}: read_channel({prefix}) failed: {e}"),
    }
}

fn ids(threads: &[ThreadSummary]) -> Vec<&MessageId> {
    threads.iter().map(|t| &t.thread_id).collect()
}

async fn read_channel_lists_threads_newest_first_and_filters_by_prefix<S: Store>(store: S) {
    const SCENARIO: &str = "read_channel_lists_threads_newest_first_and_filters_by_prefix";
    let t1 = post_ok(&store, new_thread("research", "alice", "first"), SCENARIO).await;
    tick().await;
    let t2 = post_ok(
        &store,
        new_thread("research/tls", "bob", "second"),
        SCENARIO,
    )
    .await;
    tick().await;
    let t3 = post_ok(&store, new_thread("research2", "carol", "other"), SCENARIO).await;
    tick().await;
    let t4 = post_ok(&store, new_thread("eng", "dave", "eng thread"), SCENARIO).await;
    tick().await;

    let before_reply = read_channel_ok(&store, "research", page(50, None), SCENARIO).await;
    assert_eq!(
        ids(&before_reply),
        vec![&t2.message.id, &t1.message.id],
        "{SCENARIO}: newest thread first"
    );

    let answer = post_ok(&store, reply(&t1.message.id, "bob", "answer"), SCENARIO).await;
    let listed = read_channel_ok(&store, "research", page(50, None), SCENARIO).await;
    assert_eq!(
        ids(&listed),
        vec![&t1.message.id, &t2.message.id],
        "{SCENARIO}: a reply makes its thread the newest"
    );
    assert_eq!(listed[0].channel, channel("research"), "{SCENARIO}");
    assert_eq!(listed[0].root_text_preview, "first", "{SCENARIO}");
    assert_eq!(listed[0].reply_count, 1, "{SCENARIO}: replies only");
    assert_eq!(
        listed[0].last_at_ms, answer.message.at_ms,
        "{SCENARIO}: activity includes replies"
    );
    assert_eq!(listed[1].channel, channel("research/tls"), "{SCENARIO}");
    assert_eq!(listed[1].reply_count, 0, "{SCENARIO}");
    assert_eq!(listed[1].last_at_ms, t2.message.at_ms, "{SCENARIO}");

    let tls = read_channel_ok(&store, "research/tls", page(50, None), SCENARIO).await;
    assert_eq!(
        ids(&tls),
        vec![&t2.message.id],
        "{SCENARIO}: narrower prefix"
    );
    let eng = read_channel_ok(&store, "eng", page(50, None), SCENARIO).await;
    assert_eq!(ids(&eng), vec![&t4.message.id], "{SCENARIO}: other channel");
    let r2 = read_channel_ok(&store, "research2", page(50, None), SCENARIO).await;
    assert_eq!(ids(&r2), vec![&t3.message.id], "{SCENARIO}");
    let none = read_channel_ok(&store, "nothing", page(50, None), SCENARIO).await;
    assert!(none.is_empty(), "{SCENARIO}: unknown channel is empty");
}

async fn read_channel_matches_whole_path_segments_only<S: Store>(store: S) {
    const SCENARIO: &str = "read_channel_matches_whole_path_segments_only";
    let under = post_ok(&store, new_thread("a_b/c", "alice", "under"), SCENARIO).await;
    tick().await;
    let exact = post_ok(&store, new_thread("a_b", "alice", "exact"), SCENARIO).await;
    tick().await;
    post_ok(
        &store,
        new_thread("axb", "alice", "wildcard bait"),
        SCENARIO,
    )
    .await;
    tick().await;
    post_ok(&store, new_thread("a_bc", "alice", "longer name"), SCENARIO).await;
    tick().await;
    post_ok(&store, new_thread("a.b", "alice", "dot bait"), SCENARIO).await;

    let listed = read_channel_ok(&store, "a_b", page(50, None), SCENARIO).await;
    assert_eq!(
        ids(&listed),
        vec![&exact.message.id, &under.message.id],
        "{SCENARIO}: only a_b and a_b/..."
    );
}

async fn read_channel_paginates_with_before_and_clamps_limit<S: Store>(store: S) {
    const SCENARIO: &str = "read_channel_paginates_with_before_and_clamps_limit";
    let mut roots = Vec::new();
    for i in 0..5 {
        roots.push(
            post_ok(
                &store,
                new_thread("page", "alice", &format!("t{i}")),
                SCENARIO,
            )
            .await,
        );
        tick().await;
    }
    let newest_first: Vec<&MessageId> = roots.iter().rev().map(|p| &p.message.id).collect();

    let first = read_channel_ok(&store, "page", page(2, None), SCENARIO).await;
    assert_eq!(ids(&first), newest_first[0..2], "{SCENARIO}: first page");
    let second =
        read_channel_ok(&store, "page", page(2, Some(&first[1].thread_id)), SCENARIO).await;
    assert_eq!(ids(&second), newest_first[2..4], "{SCENARIO}: second page");
    let third = read_channel_ok(
        &store,
        "page",
        page(2, Some(&second[1].thread_id)),
        SCENARIO,
    )
    .await;
    assert_eq!(ids(&third), newest_first[4..5], "{SCENARIO}: last page");
    let end = read_channel_ok(&store, "page", page(2, Some(&third[0].thread_id)), SCENARIO).await;
    assert!(end.is_empty(), "{SCENARIO}: nothing past the end");

    let zero = read_channel_ok(&store, "page", page(0, None), SCENARIO).await;
    assert_eq!(zero.len(), 1, "{SCENARIO}: limit 0 is clamped up to 1");

    for i in 5..205 {
        post_ok(
            &store,
            new_thread("many", "alice", &format!("t{i}")),
            SCENARIO,
        )
        .await;
    }
    let huge = read_channel_ok(&store, "many", page(u32::MAX, None), SCENARIO).await;
    assert_eq!(huge.len(), 200, "{SCENARIO}: limit is clamped to 200");
}

async fn read_channel_preview_is_200_chars_not_bytes<S: Store>(store: S) {
    const SCENARIO: &str = "read_channel_preview_is_200_chars_not_bytes";
    let text: String = "\u{e9}".repeat(250);
    post_ok(&store, new_thread("eng", "alice", &text), SCENARIO).await;
    post_ok(&store, new_thread("short", "alice", "tiny"), SCENARIO).await;
    let listed = read_channel_ok(&store, "eng", page(10, None), SCENARIO).await;
    assert_eq!(
        listed[0].root_text_preview,
        "\u{e9}".repeat(200),
        "{SCENARIO}: first 200 characters"
    );
    let short = read_channel_ok(&store, "short", page(10, None), SCENARIO).await;
    assert_eq!(short[0].root_text_preview, "tiny", "{SCENARIO}");
}

async fn read_thread_returns_root_and_replies_in_order<S: Store>(store: S) {
    const SCENARIO: &str = "read_thread_returns_root_and_replies_in_order";
    let labels = vec![Label::new("kind", "bug").unwrap_or_else(|e| panic!("{e}"))];
    let root = post_ok(
        &store,
        message(
            BoardId::main(),
            Target::NewThread {
                channel: channel("eng"),
            },
            "alice",
            "root",
            labels,
        ),
        SCENARIO,
    )
    .await;
    let other = post_ok(&store, new_thread("eng", "alice", "other thread"), SCENARIO).await;
    let r1 = post_ok(&store, reply(&root.message.id, "bob", "one"), SCENARIO).await;
    post_ok(
        &store,
        reply(&other.message.id, "bob", "elsewhere"),
        SCENARIO,
    )
    .await;
    let r2 = post_ok(&store, reply(&root.message.id, "carol", "two"), SCENARIO).await;

    let thread = match store.read_thread(&BoardId::main(), &root.message.id).await {
        Ok(thread) => thread,
        Err(e) => panic!("{SCENARIO}: read_thread failed: {e}"),
    };
    assert_eq!(thread.root, root.message, "{SCENARIO}: root with labels");
    assert_eq!(
        thread.replies,
        vec![r1.message, r2.message],
        "{SCENARIO}: replies in event order, this thread only"
    );
}

async fn read_thread_of_unknown_id_reply_or_other_board_is_not_found<S: Store>(store: S) {
    const SCENARIO: &str = "read_thread_of_unknown_id_reply_or_other_board_is_not_found";
    let root = post_ok(&store, new_thread("eng", "alice", "root"), SCENARIO).await;
    let answer = post_ok(&store, reply(&root.message.id, "bob", "answer"), SCENARIO).await;
    let unknown = MessageId::new("msg_0123456789abcdef01234567")
        .unwrap_or_else(|e| panic!("{SCENARIO}: {e}"));
    let nowhere = BoardId::new("nowhere").unwrap_or_else(|e| panic!("{SCENARIO}: {e}"));

    let cases = [
        (BoardId::main(), unknown),
        (BoardId::main(), answer.message.id),
        (nowhere, root.message.id),
    ];
    for (board, id) in cases {
        let result = store.read_thread(&board, &id).await;
        assert!(
            matches!(result, Err(StoreError::NotFound(_))),
            "{SCENARIO}: {board} {id} gave {result:?}"
        );
    }
}
