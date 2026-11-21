//! Idempotency keys: replays, scoping per author, and conflicts.

use stigmer_store::{ConflictKind, Store, StoreError};

use crate::support::{keyed, new_thread, post_ok, valid_chain, verify_main};

pub(crate) async fn same_key_same_author_returns_original_and_replayed_true<S: Store>(store: S) {
    const SCENARIO: &str = "same_key_same_author_returns_original_and_replayed_true";
    let msg = keyed(new_thread("eng", "alice", "deploy"), "req-1");
    let first = post_ok(&store, msg.clone(), SCENARIO).await;
    assert!(!first.replayed, "{SCENARIO}: first post is not a replay");
    let second = post_ok(&store, msg, SCENARIO).await;
    assert!(second.replayed, "{SCENARIO}: retry must be flagged");
    assert_eq!(second.message, first.message, "{SCENARIO}");
    assert_eq!(second.event, first.event, "{SCENARIO}");
}

pub(crate) async fn same_key_writes_exactly_one_event<S: Store>(store: S) {
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

pub(crate) async fn same_key_different_author_is_a_new_message<S: Store>(store: S) {
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

pub(crate) async fn same_key_different_text_is_conflict<S: Store>(store: S) {
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
        matches!(
            result,
            Err(StoreError::Conflict(ConflictKind::IdempotencyKeyReused))
        ),
        "{SCENARIO}: got {result:?}"
    );
    assert_eq!(
        verify_main(&store, SCENARIO).await,
        valid_chain(1),
        "{SCENARIO}"
    );
}
