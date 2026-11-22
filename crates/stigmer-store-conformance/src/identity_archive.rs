//! Archived boards: identity writes are refused, the archive flow's own calls still work.

use stigmer_core::{PrincipalKind, Role};
use stigmer_store::{
    Adoption, ConflictKind, CredentialScope, Entity, IdentityStore, Store, StoreError,
};

use crate::identity::{credential, invite, not_found, token_id, NOW};
use crate::support::{board, new_thread_on, ok, post_ok, principal};

const ARCHIVED: StoreError = StoreError::Conflict(ConflictKind::BoardArchived);

pub(crate) async fn add_member_on_archived_board_is_board_archived<S: Store + IdentityStore>(
    store: S,
) {
    const SCENARIO: &str = "add_member_on_archived_board_is_board_archived";
    let old = board("old");
    ok(store.create_board(&old, None).await, SCENARIO);
    ok(store.archive_board(&old).await, SCENARIO);
    let added = store
        .add_member(
            &old,
            &principal("alice"),
            PrincipalKind::Human,
            Role::Admin,
            NOW,
        )
        .await;
    assert_eq!(added, Err(ARCHIVED), "{SCENARIO}");
    assert_eq!(
        store.list_members(&old).await,
        Ok(vec![]),
        "{SCENARIO}: no member"
    );
}

pub(crate) async fn create_invite_on_archived_board_is_board_archived<S: Store + IdentityStore>(
    store: S,
) {
    const SCENARIO: &str = "create_invite_on_archived_board_is_board_archived";
    let old = board("old");
    ok(store.create_board(&old, None).await, SCENARIO);
    ok(store.archive_board(&old).await, SCENARIO);
    let new = invite(1, &old, Role::Member, PrincipalKind::Agent);
    let hash = new.secret_hash;
    assert_eq!(
        store.create_invite(new, NOW).await,
        Err(ARCHIVED),
        "{SCENARIO}"
    );
    assert_eq!(
        store
            .consume_invite(&token_id(1), &hash, &principal("dave"), NOW)
            .await,
        Err(not_found(Entity::Invite, token_id(1))),
        "{SCENARIO}: nothing was stored"
    );
}

pub(crate) async fn adopt_local_authors_on_archived_board_is_board_archived<
    S: Store + IdentityStore,
>(
    store: S,
) {
    const SCENARIO: &str = "adopt_local_authors_on_archived_board_is_board_archived";
    let old = board("old");
    ok(store.create_board(&old, None).await, SCENARIO);
    post_ok(&store, new_thread_on(&old, "eng", "alice", "hi"), SCENARIO).await;
    ok(store.archive_board(&old).await, SCENARIO);
    let adoptions = [Adoption {
        name: principal("alice"),
        kind: PrincipalKind::Human,
        role: Role::Admin,
    }];
    assert_eq!(
        store.adopt_local_authors(&old, &adoptions, NOW).await,
        Err(ARCHIVED),
        "{SCENARIO}"
    );
    assert_eq!(
        store.list_members(&old).await,
        Ok(vec![]),
        "{SCENARIO}: no member"
    );
    assert_eq!(
        store.list_local_authors(&old).await,
        Ok(vec![principal("alice")]),
        "{SCENARIO}: alice is still local"
    );
}

pub(crate) async fn consume_invite_for_archived_board_is_the_generic_not_found<
    S: Store + IdentityStore,
>(
    store: S,
) {
    const SCENARIO: &str = "consume_invite_for_archived_board_is_the_generic_not_found";
    let old = board("old");
    ok(store.create_board(&old, None).await, SCENARIO);
    let new = invite(1, &old, Role::Member, PrincipalKind::Agent);
    let hash = new.secret_hash;
    ok(store.create_invite(new, NOW).await, SCENARIO);
    ok(store.archive_board(&old).await, SCENARIO);
    for name in ["dave", "erin"] {
        assert_eq!(
            store
                .consume_invite(&token_id(1), &hash, &principal(name), NOW + 1)
                .await,
            Err(not_found(Entity::Invite, token_id(1))),
            "{SCENARIO}: {name}, and the first refusal did not use the invite"
        );
    }
    assert_eq!(
        store.list_members(&old).await,
        Ok(vec![]),
        "{SCENARIO}: no member"
    );
}

pub(crate) async fn remove_member_and_revoke_still_work_on_archived_board<
    S: Store + IdentityStore,
>(
    store: S,
) {
    const SCENARIO: &str = "remove_member_and_revoke_still_work_on_archived_board";
    let old = board("old");
    ok(store.create_board(&old, None).await, SCENARIO);
    for (name, role) in [
        ("ann", Role::Admin),
        ("bob", Role::Member),
        ("cat", Role::Member),
    ] {
        let added = store
            .add_member(&old, &principal(name), PrincipalKind::Human, role, NOW)
            .await;
        ok(added, format_args!("{SCENARIO}: add {name}"));
    }
    for (n, name) in [(1, "ann"), (2, "bob"), (3, "cat")] {
        let c = credential(n, CredentialScope::Board(old.clone()), name);
        ok(store.create_credential(c, NOW).await, SCENARIO);
    }
    ok(store.archive_board(&old).await, SCENARIO);

    assert_eq!(
        store.revoke_board_credentials(&old, true, NOW + 1).await,
        Ok(2),
        "{SCENARIO}: revoke all but the admin"
    );
    assert_eq!(
        store.remove_member(&old, &principal("ann"), NOW + 2).await,
        Ok(()),
        "{SCENARIO}: remove the admin"
    );
    let ann = ok(store.find_credential(&token_id(1)).await, SCENARIO);
    assert_eq!(
        ann.and_then(|c| c.revoked_at_ms),
        Some(NOW + 2),
        "{SCENARIO}: ann's credential revoked on removal"
    );
    let members = ok(store.list_members(&old).await, SCENARIO);
    let names: Vec<_> = members.iter().map(|m| m.name.as_str()).collect();
    assert_eq!(names, vec!["bob", "cat"], "{SCENARIO}: reads still work");
    let listed = ok(store.list_credentials(&old).await, SCENARIO);
    assert_eq!(listed.len(), 3, "{SCENARIO}: list credentials still works");
    assert!(
        matches!(store.get_member(&old, &principal("bob")).await, Ok(Some(_))),
        "{SCENARIO}: get_member still works"
    );
}
