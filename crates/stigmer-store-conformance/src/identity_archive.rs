//! Archived boards: identity writes are refused, the archive flow's own calls still work, and
//! `archive_board_revoking` archives and revokes in one transaction.

use stigmer_core::{BoardId, PrincipalKind, Role};
use stigmer_store::{
    Adoption, ConflictKind, CredentialScope, Entity, IdentityStore, Store, StoreError,
};

use crate::identity::{credential, invite, join_credential, not_found, token_id, NOW};
use crate::support::{board, log_of, new_thread_on, ok, post_ok, principal};
use crate::support::{board_archived, board_created, invite_created, member_removed, token_issued};

const ARCHIVED: StoreError = StoreError::Conflict(ConflictKind::BoardArchived);

pub(crate) async fn add_member_on_archived_board_is_board_archived<S: Store + IdentityStore>(
    store: S,
) {
    const SCENARIO: &str = "add_member_on_archived_board_is_board_archived";
    let old = board("old");
    ok(
        store
            .create_board(&old, None, board_created(&old, NOW))
            .await,
        SCENARIO,
    );
    ok(
        store.archive_board(&old, board_archived(&old, NOW)).await,
        SCENARIO,
    );
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
    ok(
        store
            .create_board(&old, None, board_created(&old, NOW))
            .await,
        SCENARIO,
    );
    ok(
        store.archive_board(&old, board_archived(&old, NOW)).await,
        SCENARIO,
    );
    let new = invite(1, &old, Role::Member, PrincipalKind::Agent);
    let hash = new.secret_hash;
    assert_eq!(
        store.create_invite(new, invite_created(NOW)).await,
        Err(ARCHIVED),
        "{SCENARIO}"
    );
    assert_eq!(
        store
            .consume_invite(
                &token_id(1),
                &hash,
                &principal("dave"),
                NOW,
                join_credential(100)
            )
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
    ok(
        store
            .create_board(&old, None, board_created(&old, NOW))
            .await,
        SCENARIO,
    );
    post_ok(&store, new_thread_on(&old, "eng", "alice", "hi"), SCENARIO).await;
    ok(
        store.archive_board(&old, board_archived(&old, NOW)).await,
        SCENARIO,
    );
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
    ok(
        store
            .create_board(&old, None, board_created(&old, NOW))
            .await,
        SCENARIO,
    );
    let new = invite(1, &old, Role::Member, PrincipalKind::Agent);
    let hash = new.secret_hash;
    ok(
        store.create_invite(new, invite_created(NOW)).await,
        SCENARIO,
    );
    ok(
        store.archive_board(&old, board_archived(&old, NOW)).await,
        SCENARIO,
    );
    for name in ["dave", "erin"] {
        assert_eq!(
            store
                .consume_invite(
                    &token_id(1),
                    &hash,
                    &principal(name),
                    NOW + 1,
                    join_credential(100)
                )
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
    ok(
        store
            .create_board(&old, None, board_created(&old, NOW))
            .await,
        SCENARIO,
    );
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
        ok(
            store.create_credential(c, token_issued(NOW)).await,
            SCENARIO,
        );
    }
    ok(
        store.archive_board(&old, board_archived(&old, NOW)).await,
        SCENARIO,
    );

    assert_eq!(
        store.revoke_board_credentials(&old, true, NOW + 1).await,
        Ok(2),
        "{SCENARIO}: revoke all but the admin"
    );
    assert_eq!(
        store
            .remove_member(&old, &principal("ann"), member_removed(&old, NOW + 2))
            .await,
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

pub(crate) async fn archive_board_revoking_archives_revokes_non_admin_credentials_and_keeps_admins_in_one_transaction<
    S: Store + IdentityStore,
>(
    store: S,
) {
    const SCENARIO: &str = "archive_board_revoking_archives_revokes_non_admin_credentials_and_keeps_admins_in_one_transaction";
    let (ops, main) = (board("ops"), BoardId::main());
    ok(
        store
            .create_board(&ops, None, board_created(&ops, NOW))
            .await,
        SCENARIO,
    );
    for (on, name, role) in [
        (&ops, "ann", Role::Admin),
        (&ops, "bob", Role::Member),
        (&main, "cat", Role::Member),
    ] {
        let added = store
            .add_member(on, &principal(name), PrincipalKind::Human, role, NOW)
            .await;
        ok(added, format_args!("{SCENARIO}: add {name}"));
    }
    for (n, on, name) in [(1, &ops, "ann"), (2, &ops, "bob"), (3, &main, "cat")] {
        let c = credential(n, CredentialScope::Board(on.clone()), name);
        ok(
            store.create_credential(c, token_issued(NOW)).await,
            SCENARIO,
        );
    }
    let instance = credential(4, CredentialScope::Instance, "instance-admin");
    ok(
        store.create_credential(instance, token_issued(NOW)).await,
        SCENARIO,
    );
    let before = log_of(&store, SCENARIO).await;

    // main is protected: refused, nothing revoked, no row.
    assert_eq!(
        store
            .archive_board_revoking(&main, board_archived(&main, NOW + 1))
            .await,
        Err(StoreError::Conflict(ConflictKind::BoardProtected)),
        "{SCENARIO}: main"
    );
    let unknown = board("nowhere");
    assert_eq!(
        store
            .archive_board_revoking(&unknown, board_archived(&unknown, NOW + 1))
            .await,
        Err(not_found(Entity::Board, "nowhere")),
        "{SCENARIO}: unknown board"
    );
    let revoked_at = |n: u8| {
        let store = &store;
        async move {
            ok(store.find_credential(&token_id(n)).await, SCENARIO).and_then(|c| c.revoked_at_ms)
        }
    };
    assert_eq!(revoked_at(3).await, None, "{SCENARIO}: main untouched");
    assert_eq!(
        log_of(&store, SCENARIO).await,
        before,
        "{SCENARIO}: no row yet"
    );

    let row = board_archived(&ops, NOW + 2);
    let info = ok(
        store.archive_board_revoking(&ops, row.clone()).await,
        SCENARIO,
    );
    assert_eq!(info.archived_at_ms, Some(NOW + 2), "{SCENARIO}: archived");
    assert_eq!(store.get_board(&ops).await, Ok(info.clone()), "{SCENARIO}");
    assert_eq!(
        revoked_at(1).await,
        None,
        "{SCENARIO}: the admin keeps hers"
    );
    assert_eq!(
        revoked_at(2).await,
        Some(NOW + 2),
        "{SCENARIO}: bob revoked"
    );
    assert_eq!(
        revoked_at(3).await,
        None,
        "{SCENARIO}: other boards untouched"
    );
    assert_eq!(revoked_at(4).await, None, "{SCENARIO}: instance untouched");
    let mut expected = before.clone();
    expected.push(row);
    assert_eq!(
        log_of(&store, SCENARIO).await,
        expected,
        "{SCENARIO}: one row"
    );

    // A repeat: nothing left to change, so no row and the first time kept.
    let again = store
        .archive_board_revoking(&ops, board_archived(&ops, NOW + 3))
        .await;
    assert_eq!(again, Ok(info), "{SCENARIO}: repeat");
    assert_eq!(
        revoked_at(2).await,
        Some(NOW + 2),
        "{SCENARIO}: first time kept"
    );
    assert_eq!(
        log_of(&store, SCENARIO).await,
        expected,
        "{SCENARIO}: no new row"
    );
}
