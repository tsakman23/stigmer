//! Two handles on one database: what one handle writes, the other sees and builds on. Every
//! scenario takes handle `a` and handle `b` from [`Fixture::second_handle`]. On a backend
//! whose handles share one notifier the wake scenario passes for that reason; the summary line
//! of [`run_all`](crate::run_all) reports [`Fixture::CROSS_PROCESS_WAKE`] so that is never
//! read as proof of cross-process wakes.

use std::sync::Arc;
use std::time::Instant;

use stigmer_core::{BoardId, Cursor};
use stigmer_store::{IdentityStore, Store};

use crate::cross_instance_identity::{
    credential_issued_on_one_handle_is_valid_on_the_other_and_revocable_from_either,
    invite_redeemed_once_across_handles,
};
use crate::fixture::Fixture;
use crate::support::{
    create_board_race, fail, new_thread, ok, post_ok, spawn_across, valid_chain, verify_main,
    yield_times, LONG, YIELDS,
};

/// Runs every cross-instance scenario that needs only `Store`, each against a fresh store and a
/// second handle on it.
pub(crate) async fn run_cross_instance_suite<X: Fixture>(fixture: &X) {
    let (a, b) = pair(fixture).await;
    wake_across_handles(a, b).await;
    let (a, b) = pair(fixture).await;
    wake_reaches_a_blocked_waiter_on_the_other_handle(fixture, a, b).await;
    let (a, b) = pair(fixture).await;
    concurrent_create_board_across_handles_has_one_winner_and_one_board_exists(a, b).await;
    let (a, b) = pair(fixture).await;
    sequence_is_gapless_with_concurrent_posts_from_both_handles(a, b).await;
}

/// Runs the cross-instance scenarios that need `IdentityStore`, likewise.
pub(crate) async fn run_cross_instance_identity_suite<X>(fixture: &X)
where
    X: Fixture,
    X::Store: IdentityStore,
{
    let (a, b) = pair(fixture).await;
    credential_issued_on_one_handle_is_valid_on_the_other_and_revocable_from_either(a, b).await;
    let (a, b) = pair(fixture).await;
    invite_redeemed_once_across_handles(a, b).await;
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

/// The blocked-then-woken path, forced: the post goes through `b` only once the waiter on
/// `a` is subscribed and still pending. (`wake_across_handles` covers the other orders.)
async fn wake_reaches_a_blocked_waiter_on_the_other_handle<X: Fixture>(
    fixture: &X,
    a: X::Store,
    b: X::Store,
) {
    const SCENARIO: &str = "wake_reaches_a_blocked_waiter_on_the_other_handle";
    let main = BoardId::main();
    let (a, b) = (Arc::new(a), Arc::new(b));
    let head = post_ok(&*b, new_thread("eng", "alice", "start"), SCENARIO).await;
    let waiter = {
        let (a, cursor) = (Arc::clone(&a), head.event.cursor);
        tokio::spawn(async move { a.wait_past(&BoardId::main(), Some(&cursor), LONG).await })
    };

    // A condition wait, not a sleep: LONG is only an upper bound.
    let blocked = tokio::time::timeout(LONG, async {
        while fixture.waiters(&a, &main) == 0 {
            if waiter.is_finished() {
                fail(format_args!("{SCENARIO}: the waiter ended before any post"));
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(blocked.is_ok(), "{SCENARIO}: the waiter on a subscribed");
    assert!(
        !waiter.is_finished(),
        "{SCENARIO}: the waiter is blocked before the post"
    );

    let posted_at = Instant::now();
    post_ok(&*b, new_thread("eng", "bob", "wake"), SCENARIO).await;
    let result = ok(waiter.await, format_args!("{SCENARIO}: waiter task failed"));
    let woke_after = posted_at.elapsed();
    assert_eq!(
        result,
        Ok(true),
        "{SCENARIO}: a post through b wakes the blocked waiter on a"
    );
    assert!(
        woke_after < LONG / 2,
        "{SCENARIO}: woken well before the timeout, after {woke_after:?}"
    );
}

async fn concurrent_create_board_across_handles_has_one_winner_and_one_board_exists<S: Store>(
    a: S,
    b: S,
) {
    const SCENARIO: &str =
        "concurrent_create_board_across_handles_has_one_winner_and_one_board_exists";
    create_board_race(&[Arc::new(a), Arc::new(b)], SCENARIO).await;
}

async fn sequence_is_gapless_with_concurrent_posts_from_both_handles<S: Store>(a: S, b: S) {
    const SCENARIO: &str = "sequence_is_gapless_with_concurrent_posts_from_both_handles";
    const POSTS: u64 = 50;
    let handles = [Arc::new(a), Arc::new(b)];
    let results = spawn_across(&handles, POSTS as usize, SCENARIO, |store, i| async move {
        store
            .post(new_thread("load", "agent", &format!("post {i}")))
            .await
    })
    .await;

    let mut seqs = Vec::new();
    for result in results {
        let posted = ok(result, format_args!("{SCENARIO}: post failed"));
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
