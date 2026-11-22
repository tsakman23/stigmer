//! Invites: single use, generic refusal, and atomic consumption.

use std::sync::Arc;

use stigmer_core::{BoardId, PrincipalKind, Role};
use stigmer_store::{ConflictKind, Consumed, Entity, IdentityStore, Store, StoreError};

use crate::identity::{hash_of, invite, member, not_found, token_id, HOUR, NOW};
use crate::support::{board, ok, principal};

pub(crate) async fn invite_consumes_once<S: Store + IdentityStore>(store: S) {
    const SCENARIO: &str = "invite_consumes_once";
    let research = board("research");
    ok(store.create_board(&research, None).await, SCENARIO);
    let new = invite(1, &research, Role::Member, PrincipalKind::Agent);
    let hash = new.secret_hash;
    ok(store.create_invite(new, NOW).await, SCENARIO);

    let dave = member(
        &research,
        "dave",
        PrincipalKind::Agent,
        Role::Member,
        NOW + 1,
    );
    assert_eq!(
        store
            .consume_invite(&token_id(1), &hash, &principal("dave"), NOW + 1)
            .await,
        Ok(Consumed {
            board: research.clone(),
            role: Role::Member,
            kind: PrincipalKind::Agent,
            member: dave.clone(),
        }),
        "{SCENARIO}: first use"
    );
    assert_eq!(
        store.get_member(&research, &principal("dave")).await,
        Ok(Some(dave.clone())),
        "{SCENARIO}: dave joined"
    );
    assert_eq!(
        store
            .consume_invite(&token_id(1), &hash, &principal("erin"), NOW + 2)
            .await,
        Err(not_found(Entity::Invite, token_id(1))),
        "{SCENARIO}: second use"
    );
    assert_eq!(
        store.list_members(&research).await,
        Ok(vec![dave]),
        "{SCENARIO}: only dave"
    );
}

pub(crate) async fn invite_expired_is_not_found<S: IdentityStore>(store: S) {
    const SCENARIO: &str = "invite_expired_is_not_found";
    let main = BoardId::main();
    let new = invite(1, &main, Role::Member, PrincipalKind::Human);
    let (hash, expires) = (new.secret_hash, new.expires_at_ms);
    ok(store.create_invite(new, NOW).await, SCENARIO);
    assert_eq!(expires, NOW + HOUR, "{SCENARIO}");

    for at_ms in [expires, expires + HOUR] {
        let late = store
            .consume_invite(&token_id(1), &hash, &principal("dave"), at_ms)
            .await;
        assert_eq!(
            late,
            Err(not_found(Entity::Invite, token_id(1))),
            "{SCENARIO}: at {at_ms}"
        );
    }
    assert_eq!(
        store.list_members(&main).await,
        Ok(vec![]),
        "{SCENARIO}: no member"
    );
    // The refusals did not use it: just before expiry it still works.
    let in_time = store
        .consume_invite(&token_id(1), &hash, &principal("dave"), expires - 1)
        .await;
    assert!(in_time.is_ok(), "{SCENARIO}: in time, got {in_time:?}");
}

pub(crate) async fn invite_wrong_hash_is_not_found_and_not_consumed<S: IdentityStore>(store: S) {
    const SCENARIO: &str = "invite_wrong_hash_is_not_found_and_not_consumed";
    let main = BoardId::main();
    let new = invite(1, &main, Role::Member, PrincipalKind::Human);
    let hash = new.secret_hash;
    ok(store.create_invite(new, NOW).await, SCENARIO);
    let mut one_bit_off = hash;
    one_bit_off[31] ^= 1;

    for wrong in [hash_of("guess"), one_bit_off] {
        assert_eq!(
            store
                .consume_invite(&token_id(1), &wrong, &principal("dave"), NOW)
                .await,
            Err(not_found(Entity::Invite, token_id(1))),
            "{SCENARIO}: wrong hash"
        );
    }
    assert_eq!(
        store
            .consume_invite(&token_id(2), &hash, &principal("dave"), NOW)
            .await,
        Err(not_found(Entity::Invite, token_id(2))),
        "{SCENARIO}: unknown id looks the same"
    );
    assert_eq!(
        store.list_members(&main).await,
        Ok(vec![]),
        "{SCENARIO}: no member"
    );
    let right = store
        .consume_invite(&token_id(1), &hash, &principal("dave"), NOW)
        .await;
    assert!(right.is_ok(), "{SCENARIO}: still usable, got {right:?}");
}

pub(crate) async fn invite_with_taken_name_conflicts_and_stays_unconsumed<S: IdentityStore>(
    store: S,
) {
    const SCENARIO: &str = "invite_with_taken_name_conflicts_and_stays_unconsumed";
    let main = BoardId::main();
    let alice = ok(
        store
            .add_member(
                &main,
                &principal("alice"),
                PrincipalKind::Human,
                Role::Admin,
                NOW,
            )
            .await,
        SCENARIO,
    );
    let new = invite(1, &main, Role::Bridge, PrincipalKind::Bridge);
    let hash = new.secret_hash;
    ok(store.create_invite(new, NOW).await, SCENARIO);

    assert_eq!(
        store
            .consume_invite(&token_id(1), &hash, &principal("alice"), NOW + 1)
            .await,
        Err(StoreError::Conflict(ConflictKind::NameTaken)),
        "{SCENARIO}: taken name"
    );
    assert_eq!(
        store.get_member(&main, &principal("alice")).await,
        Ok(Some(alice)),
        "{SCENARIO}: alice keeps her role"
    );
    let bob = store
        .consume_invite(&token_id(1), &hash, &principal("bob"), NOW + 2)
        .await;
    assert_eq!(
        bob.map(|c| c.member),
        Ok(member(
            &main,
            "bob",
            PrincipalKind::Bridge,
            Role::Bridge,
            NOW + 2
        )),
        "{SCENARIO}: the invite was still unused"
    );
}

pub(crate) async fn concurrent_consumes_of_one_invite_create_exactly_one_member<
    S: IdentityStore,
>(
    store: S,
) {
    const SCENARIO: &str = "concurrent_consumes_of_one_invite_create_exactly_one_member";
    const TASKS: usize = 20;
    let main = BoardId::main();
    let new = invite(1, &main, Role::Member, PrincipalKind::Agent);
    let hash = new.secret_hash;
    ok(store.create_invite(new, NOW).await, SCENARIO);
    let store = Arc::new(store);
    let handles: Vec<_> = (0..TASKS)
        .map(|i| {
            let store = Arc::clone(&store);
            tokio::spawn(async move {
                let name = principal(&format!("agent-{i}"));
                store.consume_invite(&token_id(1), &hash, &name, NOW).await
            })
        })
        .collect();

    let mut joined = Vec::new();
    for handle in handles {
        match ok(handle.await, format_args!("{SCENARIO}: task failed")) {
            Ok(consumed) => joined.push(consumed.member),
            Err(e) => assert_eq!(
                e,
                not_found(Entity::Invite, token_id(1)),
                "{SCENARIO}: a losing consume"
            ),
        }
    }
    assert_eq!(joined.len(), 1, "{SCENARIO}: exactly one winner");
    assert_eq!(
        store.list_members(&main).await,
        Ok(joined),
        "{SCENARIO}: exactly one member"
    );
}
