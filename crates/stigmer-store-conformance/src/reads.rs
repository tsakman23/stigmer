//! Channel listings, pagination and thread reads.

use std::future::Future;
use std::panic::Location;

use stigmer_core::{BoardId, MessageId, Page, Target, ThreadSummary};
use stigmer_store::{Entity, Store, StoreError};

use crate::support::{channel, label, message, new_thread, ok, ok_from, post_ok, reply, tick};

fn page(limit: u32, before: Option<&MessageId>) -> Page {
    Page {
        limit,
        before: before.cloned(),
    }
}

/// Lists `prefix` on the main board, panicking with `scenario` and the caller's line on error.
#[track_caller]
fn read_channel_ok<'a, S: Store>(
    store: &'a S,
    prefix: &'a str,
    page: Page,
    scenario: &'a str,
) -> impl Future<Output = Vec<ThreadSummary>> + 'a {
    let caller = Location::caller();
    async move {
        ok_from(
            caller,
            store
                .read_channel(&BoardId::main(), &channel(prefix), page)
                .await,
            format_args!("{scenario}: read_channel({prefix}) failed"),
        )
    }
}

fn ids(threads: &[ThreadSummary]) -> Vec<&MessageId> {
    threads.iter().map(|t| &t.thread_id).collect()
}

pub(crate) async fn read_channel_lists_threads_newest_first_and_filters_by_prefix<S: Store>(
    store: S,
) {
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

pub(crate) async fn read_channel_matches_whole_path_segments_only<S: Store>(store: S) {
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

pub(crate) async fn read_channel_paginates_with_before_and_clamps_limit<S: Store>(store: S) {
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

pub(crate) async fn read_channel_preview_is_200_chars_not_bytes<S: Store>(store: S) {
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

pub(crate) async fn read_thread_returns_root_and_replies_in_order<S: Store>(store: S) {
    const SCENARIO: &str = "read_thread_returns_root_and_replies_in_order";
    let labels = vec![label("kind", "bug")];
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

    let thread = ok(
        store.read_thread(&BoardId::main(), &root.message.id).await,
        format_args!("{SCENARIO}: read_thread failed"),
    );
    assert_eq!(thread.root, root.message, "{SCENARIO}: root with labels");
    assert_eq!(
        thread.replies,
        vec![r1.message, r2.message],
        "{SCENARIO}: replies in event order, this thread only"
    );
}

pub(crate) async fn read_thread_of_unknown_id_reply_or_other_board_is_not_found<S: Store>(
    store: S,
) {
    const SCENARIO: &str = "read_thread_of_unknown_id_reply_or_other_board_is_not_found";
    let root = post_ok(&store, new_thread("eng", "alice", "root"), SCENARIO).await;
    let answer = post_ok(&store, reply(&root.message.id, "bob", "answer"), SCENARIO).await;
    let unknown = ok(MessageId::new("msg_0123456789abcdef01234567"), SCENARIO);
    let nowhere = ok(BoardId::new("nowhere"), SCENARIO);

    let cases = [
        (BoardId::main(), unknown),
        (BoardId::main(), answer.message.id),
        (nowhere, root.message.id),
    ];
    for (board, id) in cases {
        let result = store.read_thread(&board, &id).await;
        assert!(
            matches!(
                result,
                Err(StoreError::NotFound {
                    entity: Entity::Thread,
                    ..
                })
            ),
            "{SCENARIO}: {board} {id} gave {result:?}"
        );
    }
}
