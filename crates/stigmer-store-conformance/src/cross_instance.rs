//! Two handles on one database: what one handle writes, the other sees and builds on. Every
//! scenario takes handle `a` and handle `b` from [`Fixture::second_handle`]. On a backend
//! whose handles share one notifier the wake scenario passes for that reason; the summary line
//! of [`run_all`](crate::run_all) reports [`Fixture::CROSS_PROCESS_WAKE`] so that is never
//! read as proof of cross-process wakes.

use std::sync::Arc;

use stigmer_core::{BoardId, Cursor};
use stigmer_store::{ConflictKind, Store, StoreError};

use crate::cross_instance_identity::{
    credential_issued_on_one_handle_is_valid_on_the_other_and_revocable_from_either,
    invite_redeemed_once_across_handles,
};
use crate::fixture::Fixture;
use crate::support::{
    board, board_created, new_thread, ok, post_ok, valid_chain, verify_main, yield_times, LONG,
    NOW, YIELDS,
};

/// Runs every cross-instance scenario, each against a fresh store and a second handle on it.
pub(crate) async fn run_cross_instance_suite<X: Fixture>(fixture: &X) {
    let (a, b) = pair(fixture).await;
    wake_across_handles(a, b).await;
    let (a, b) = pair(fixture).await;
    credential_issued_on_one_handle_is_valid_on_the_other_and_revocable_from_either(a, b).await;
    let (a, b) = pair(fixture).await;
    concurrent_create_board_across_handles_has_one_winner_and_one_board_exists(a, b).await;
    let (a, b) = pair(fixture).await;
    invite_redeemed_once_across_handles(a, b).await;
    let (a, b) = pair(fixture).await;
    sequence_is_gapless_with_concurrent_posts_from_both_handles(a, b).await;
}

async fn pair<X: Fixture>(fixture: &X) -> (X::Store, X::Store) {
    let a = fixture.fresh().await;
    let b = fixture.second_handle(&a).await;
    (a, b)
}

async fn wake_across_handles<S: Store>(a: S, b: S) {
    const SCENARIO: &str = "wake_across_handles";
    let (a, b) = (Arc::new(a), Arc::new(b));
    let first = post_ok(&*b, new_thread("eng", "alice", "start"), SCENARIO).await;
    let mut cursor = first.event.cursor;
    // The wake must hold whether the post lands before, during or after the waiter subscribes,
    // so try every number of yields up to YIELDS instead of sleeping for one interleaving.
    for yields in 0..=YIELDS {
        let waiter = {
            let (a, cursor) = (Arc::clone(&a), cursor.clone());
            tokio::spawn(async move { a.wait_past(&BoardId::main(), Some(&cursor), LONG).await })
        };
        yield_times(yields).await;
        assert!(
            !waiter.is_finished(),
            "{SCENARIO}: nothing posted yet ({yields} yields)"
        );
        let text = format!("post after {yields} yields");
        let posted = post_ok(&*b, new_thread("eng", "bob", &text), SCENARIO).await;
        let result = ok(waiter.await, format_args!("{SCENARIO}: waiter task failed"));
        assert_eq!(
            result,
            Ok(true),
            "{SCENARIO}: a post through b wakes a waiter on a ({yields} yields)"
        );
        cursor = posted.event.cursor;
    }
}

async fn concurrent_create_board_across_handles_has_one_winner_and_one_board_exists<S: Store>(
    a: S,
    b: S,
) {
    const SCENARIO: &str =
        "concurrent_create_board_across_handles_has_one_winner_and_one_board_exists";
    create_board_race(&[Arc::new(a), Arc::new(b)], SCENARIO).await;
}

/// Twenty tasks, spread over `handles` in turn, create the same board at once: exactly one
/// wins, the rest are `BoardExists`, and every handle lists the board once.
pub(crate) async fn create_board_race<S: Store>(handles: &[Arc<S>], scenario: &str) {
    const TASKS: usize = 20;
    let research = board("research");
    let tasks: Vec<_> = handles
        .iter()
        .cycle()
        .take(TASKS)
        .map(|store| {
            let (store, research) = (Arc::clone(store), research.clone());
            tokio::spawn(async move {
                store
                    .create_board(&research, None, board_created(&research, NOW))
                    .await
            })
        })
        .collect();

    let mut winners = 0;
    for task in tasks {
        match ok(task.await, format_args!("{scenario}: task failed")) {
            Ok(info) => {
                winners += 1;
                assert_eq!(info.id, research, "{scenario}: the winner's board");
            }
            Err(e) => assert_eq!(
                e,
                StoreError::Conflict(ConflictKind::BoardExists),
                "{scenario}: a losing create"
            ),
        }
    }
    assert_eq!(winners, 1, "{scenario}: exactly one winner");
    for (n, store) in handles.iter().enumerate() {
        let listed = ok(store.list_boards().await, format_args!("{scenario}: list"));
        let found = listed.iter().filter(|info| info.id == research).count();
        assert_eq!(found, 1, "{scenario}: listed once through handle {n}");
    }
}

async fn sequence_is_gapless_with_concurrent_posts_from_both_handles<S: Store>(a: S, b: S) {
    const SCENARIO: &str = "sequence_is_gapless_with_concurrent_posts_from_both_handles";
    const POSTS: u64 = 50;
    let handles = [Arc::new(a), Arc::new(b)];
    let tasks: Vec<_> = (0..POSTS)
        .zip(handles.iter().cycle())
        .map(|(i, store)| {
            let store = Arc::clone(store);
            tokio::spawn(async move {
                store
                    .post(new_thread("load", "agent", &format!("post {i}")))
                    .await
            })
        })
        .collect();

    let mut seqs = Vec::new();
    for task in tasks {
        let joined = ok(task.await, format_args!("{SCENARIO}: task failed"));
        let posted = ok(joined, format_args!("{SCENARIO}: post failed"));
        seqs.push(posted.event.seq);
    }
    seqs.sort_unstable();
    assert_eq!(
        seqs,
        (1..=POSTS).collect::<Vec<_>>(),
        "{SCENARIO}: seqs are exactly 1..={POSTS}"
    );
    for (n, store) in handles.iter().enumerate() {
        assert_eq!(
            verify_main(store.as_ref(), SCENARIO).await,
            valid_chain(POSTS),
            "{SCENARIO}: chain through handle {n}"
        );
        assert_eq!(
            store.head(&BoardId::main()).await,
            Ok(Some(Cursor::from_seq(POSTS))),
            "{SCENARIO}: head through handle {n}"
        );
    }
}
