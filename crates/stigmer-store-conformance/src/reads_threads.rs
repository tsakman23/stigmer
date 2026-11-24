//! Channel listings against a reference model: ordering by the last event sequence, deep
//! pagination, and summaries that agree with the threads they describe (ADR 0015).

use std::collections::HashMap;

use stigmer_core::{
    BoardId, ChannelPath, Cursor, EventFilter, MessageId, NewMessage, Page, ThreadSummary,
};
use stigmer_store::Store;

use crate::support::{channel, fail, keyed, new_thread, ok, post_ok, reply, Rng};

/// Every thread under `prefix` on the main board, walking pages of `size` with `before`.
pub(crate) async fn list_all<S: Store>(
    store: &S,
    prefix: &str,
    size: u32,
    scenario: &str,
) -> Vec<ThreadSummary> {
    let mut all: Vec<ThreadSummary> = Vec::new();
    loop {
        let page = Page {
            limit: size,
            before: all.last().map(|t| t.thread_id.clone()),
        };
        let listed = ok(
            store
                .read_channel(&BoardId::main(), &channel(prefix), page)
                .await,
            format_args!("{scenario}: read_channel({prefix})"),
        );
        assert!(
            listed.len() <= size as usize,
            "{scenario}: a page holds at most {size}"
        );
        if listed.is_empty() {
            return all;
        }
        all.extend(listed);
    }
}

/// The sequence number of each thread's latest event on the main board.
async fn last_seqs<S: Store>(store: &S, scenario: &str) -> HashMap<MessageId, u64> {
    let mut last = HashMap::new();
    let mut after: Option<Cursor> = None;
    loop {
        let events = ok(
            store
                .events_after(
                    &BoardId::main(),
                    after.as_ref(),
                    &EventFilter::default(),
                    500,
                )
                .await,
            format_args!("{scenario}: events_after"),
        );
        let Some(tail) = events.last() else {
            return last;
        };
        after = Some(tail.cursor.clone());
        for event in &events {
            last.insert(event.thread_id.clone(), event.seq);
        }
    }
}

/// What `read_channel` must list for `roots`, built from `read_thread` and the event log:
/// latest event first, replies counted, the latest message's time, the root's first 200 chars.
pub(crate) async fn model<S: Store>(
    store: &S,
    roots: &[MessageId],
    scenario: &str,
) -> Vec<ThreadSummary> {
    let last = last_seqs(store, scenario).await;
    let mut rows = Vec::new();
    for root in roots {
        let thread = ok(
            store.read_thread(&BoardId::main(), root).await,
            format_args!("{scenario}: read_thread({root})"),
        );
        let latest = thread.replies.last().unwrap_or(&thread.root);
        let Some(seq) = last.get(root) else {
            fail(format_args!("{scenario}: thread {root} has no event"))
        };
        rows.push((
            *seq,
            ThreadSummary {
                thread_id: root.clone(),
                channel: thread.root.channel.clone(),
                root_text_preview: thread.root.text.chars().take(200).collect(),
                reply_count: ok(u32::try_from(thread.replies.len()), scenario),
                last_at_ms: latest.at_ms,
            },
        ));
    }
    rows.sort_by_key(|row| std::cmp::Reverse(row.0));
    rows.into_iter().map(|(_, summary)| summary).collect()
}

/// Threads ordered by their last touch in `touches` (a post or reply), latest first.
fn by_last_touch(touches: &[MessageId]) -> Vec<MessageId> {
    let mut order: Vec<MessageId> = Vec::new();
    for thread in touches.iter().rev() {
        if !order.contains(thread) {
            order.push(thread.clone());
        }
    }
    order
}

fn ids(threads: &[ThreadSummary]) -> Vec<MessageId> {
    threads.iter().map(|t| t.thread_id.clone()).collect()
}

pub(crate) async fn read_channel_orders_by_last_event_sequence_not_wall_clock<S: Store>(store: S) {
    const SCENARIO: &str = "read_channel_orders_by_last_event_sequence_not_wall_clock";
    // No pause between posts: many share a millisecond, so only the sequence can order them.
    let mut touches = Vec::new();
    for i in 0..30 {
        let posted = post_ok(
            &store,
            new_thread("tied", "alice", &format!("t{i}")),
            SCENARIO,
        )
        .await;
        touches.push(posted.message.id);
    }
    let roots = touches.clone();
    for i in [3, 17, 0, 29, 3] {
        post_ok(&store, reply(&roots[i], "bob", "bump"), SCENARIO).await;
        touches.push(roots[i].clone());
    }
    let listed = list_all(&store, "tied", 50, SCENARIO).await;
    assert_eq!(
        ids(&listed),
        by_last_touch(&touches),
        "{SCENARIO}: latest event first, whatever the timestamps"
    );
    assert_eq!(
        ids(&listed[..4]),
        vec![
            roots[3].clone(),
            roots[29].clone(),
            roots[0].clone(),
            roots[17].clone()
        ],
        "{SCENARIO}"
    );
    assert_eq!(listed, model(&store, &roots, SCENARIO).await, "{SCENARIO}");
}

pub(crate) async fn reply_moves_its_thread_to_the_top_and_updates_count_and_preview_stays_the_root<
    S: Store,
>(
    store: S,
) {
    const SCENARIO: &str =
        "reply_moves_its_thread_to_the_top_and_updates_count_and_preview_stays_the_root";
    let long = "\u{e9}".repeat(250);
    let first = post_ok(&store, new_thread("top/a", "alice", &long), SCENARIO).await;
    let second = post_ok(&store, new_thread("top/b", "alice", "second"), SCENARIO).await;
    let third = post_ok(&store, new_thread("top", "alice", "third"), SCENARIO).await;
    let listed = list_all(&store, "top", 50, SCENARIO).await;
    assert_eq!(
        ids(&listed),
        vec![
            third.message.id.clone(),
            second.message.id.clone(),
            first.message.id.clone()
        ],
        "{SCENARIO}: newest thread first"
    );

    let answer = post_ok(
        &store,
        reply(&first.message.id, "bob", "short answer"),
        SCENARIO,
    )
    .await;
    let listed = list_all(&store, "top", 50, SCENARIO).await;
    assert_eq!(
        listed[0],
        ThreadSummary {
            thread_id: first.message.id.clone(),
            channel: channel("top/a"),
            root_text_preview: "\u{e9}".repeat(200),
            reply_count: 1,
            last_at_ms: answer.message.at_ms,
        },
        "{SCENARIO}: the replied thread leads, the preview is still the root's"
    );
    assert_eq!(
        ids(&listed[1..]),
        vec![third.message.id.clone(), second.message.id.clone()],
        "{SCENARIO}: the others keep their order"
    );

    post_ok(&store, reply(&second.message.id, "bob", "one"), SCENARIO).await;
    let last = post_ok(&store, reply(&second.message.id, "carol", "two"), SCENARIO).await;
    let listed = list_all(&store, "top", 50, SCENARIO).await;
    assert_eq!(listed[0].thread_id, second.message.id, "{SCENARIO}");
    assert_eq!(listed[0].reply_count, 2, "{SCENARIO}");
    assert_eq!(listed[0].root_text_preview, "second", "{SCENARIO}");
    assert_eq!(listed[0].last_at_ms, last.message.at_ms, "{SCENARIO}");
    let only_b = list_all(&store, "top/b", 50, SCENARIO).await;
    assert_eq!(
        only_b,
        listed[..1],
        "{SCENARIO}: the prefix filter still applies"
    );
}

pub(crate) async fn pagination_returns_every_thread_exactly_once_across_pages_with_tied_times<
    S: Store,
>(
    store: S,
) {
    const SCENARIO: &str =
        "pagination_returns_every_thread_exactly_once_across_pages_with_tied_times";
    let mut touches = Vec::new();
    for i in 0..200 {
        let posted = post_ok(
            &store,
            new_thread("deep", "alice", &format!("t{i}")),
            SCENARIO,
        )
        .await;
        touches.push(posted.message.id);
    }
    let roots = touches.clone();
    for i in (0..200).rev().step_by(13) {
        post_ok(&store, reply(&roots[i], "bob", "bump"), SCENARIO).await;
        touches.push(roots[i].clone());
    }
    let listed = list_all(&store, "deep", 7, SCENARIO).await;
    assert_eq!(listed.len(), 200, "{SCENARIO}: every thread");
    assert_eq!(
        ids(&listed),
        by_last_touch(&touches),
        "{SCENARIO}: each exactly once, in order"
    );
    assert_eq!(listed, model(&store, &roots, SCENARIO).await, "{SCENARIO}");
}

pub(crate) async fn summaries_are_consistent_after_random_operations<S: Store>(store: S) {
    const SCENARIO: &str = "summaries_are_consistent_after_random_operations";
    const CHANNELS: [&str; 3] = ["rand/a", "rand/b", "rand/c"];
    let mut rng = Rng::new(0x5eed_0015);
    let mut roots: Vec<MessageId> = Vec::new();
    let mut sent: Vec<NewMessage> = Vec::new();
    for op in 0..150 {
        let roll = rng.below(10);
        if roll >= 8 && !sent.is_empty() {
            let again = sent[rng.below(sent.len())].clone();
            let replay = post_ok(&store, again, SCENARIO).await;
            assert!(replay.replayed, "{SCENARIO}: op {op} is a replay");
            continue;
        }
        let msg = if roll < 3 || roots.is_empty() {
            let path = CHANNELS[rng.below(CHANNELS.len())];
            new_thread(
                path,
                "alice",
                &format!("op {op} {}", "x".repeat(rng.below(300))),
            )
        } else {
            reply(&roots[rng.below(roots.len())], "bob", &format!("op {op}"))
        };
        let msg = if rng.below(2) == 0 {
            keyed(msg, &format!("key-{op}"))
        } else {
            msg
        };
        let posted = post_ok(&store, msg.clone(), SCENARIO).await;
        if posted.message.thread_id == posted.message.id {
            roots.push(posted.message.id.clone());
        }
        if msg.idempotency_key.is_some() {
            sent.push(msg);
        }
    }

    let expected = model(&store, &roots, SCENARIO).await;
    assert_eq!(
        list_all(&store, "rand", 7, SCENARIO).await,
        expected,
        "{SCENARIO}: all channels"
    );
    for path in CHANNELS {
        let only: Vec<ThreadSummary> = expected
            .iter()
            .filter(|t| t.channel == ChannelPath::new(path).unwrap_or_else(|e| fail(e)))
            .cloned()
            .collect();
        assert_eq!(
            list_all(&store, path, 5, SCENARIO).await,
            only,
            "{SCENARIO}: {path}"
        );
    }
}
