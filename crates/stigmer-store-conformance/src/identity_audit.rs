//! Audited mutations write their security log row in the same transaction: exactly one row per
//! change, none for an idempotent repeat, none for a failure.

use stigmer_core::{BoardId, PrincipalKind, Role};
use stigmer_store::{ConflictKind, CredentialScope, Entity, IdentityStore, Store, StoreError};

use crate::identity::{credential, invite, not_found, token_id, NOW};
use crate::support::{
    board, board_archived, board_created, instance_token_issued, invite_created, log_of,
    member_removed, mode_enabled, ok, principal, token_issued, token_revoked,
};

pub(crate) async fn create_board_writes_exactly_one_board_created_row<S: Store + IdentityStore>(
    store: S,
) {
    const SCENARIO: &str = "create_board_writes_exactly_one_board_created_row";
    let ops = board("ops");
    let row = board_created(&ops, NOW + 7);
    let info = ok(
        store
            .create_board(&ops, Some(&principal("root")), NOW + 7, row.clone())
            .await,
        SCENARIO,
    );
    assert_eq!(info.created_at_ms, NOW + 7, "{SCENARIO}: the caller's time");
    assert_eq!(log_of(&store, SCENARIO).await, vec![row], "{SCENARIO}");
}

pub(crate) async fn duplicate_create_board_writes_no_row<S: Store + IdentityStore>(store: S) {
    const SCENARIO: &str = "duplicate_create_board_writes_no_row";
    let ops = board("ops");
    let first = board_created(&ops, NOW);
    ok(
        store.create_board(&ops, None, NOW, first.clone()).await,
        SCENARIO,
    );
    for on in [&ops, &BoardId::main()] {
        assert_eq!(
            store
                .create_board(on, None, NOW + 1, board_created(on, NOW + 1))
                .await,
            Err(StoreError::Conflict(ConflictKind::BoardExists)),
            "{SCENARIO}: {on}"
        );
    }
    assert_eq!(log_of(&store, SCENARIO).await, vec![first], "{SCENARIO}");
}

pub(crate) async fn archive_board_writes_one_row_and_a_second_archive_writes_none<
    S: Store + IdentityStore,
>(
    store: S,
) {
    const SCENARIO: &str = "archive_board_writes_one_row_and_a_second_archive_writes_none";
    let ops = board("ops");
    let created = board_created(&ops, NOW);
    ok(
        store.create_board(&ops, None, NOW, created.clone()).await,
        SCENARIO,
    );
    let archived = board_archived(&ops, NOW + 1);
    let info = ok(
        store.archive_board(&ops, NOW + 1, archived.clone()).await,
        SCENARIO,
    );
    assert_eq!(info.archived_at_ms, Some(NOW + 1), "{SCENARIO}");
    let again = store
        .archive_board(&ops, NOW + 2, board_archived(&ops, NOW + 2))
        .await;
    assert_eq!(again, Ok(info), "{SCENARIO}: a repeat changes nothing");
    assert_eq!(
        log_of(&store, SCENARIO).await,
        vec![created, archived],
        "{SCENARIO}"
    );
}

pub(crate) async fn revoke_credential_writes_one_row_and_a_repeat_writes_none<
    S: Store + IdentityStore,
>(
    store: S,
) {
    const SCENARIO: &str = "revoke_credential_writes_one_row_and_a_repeat_writes_none";
    let c = credential(1, CredentialScope::Board(BoardId::main()), "alice");
    let issued = token_issued(NOW);
    ok(
        store.create_credential(c, NOW, issued.clone()).await,
        SCENARIO,
    );
    let revoked = token_revoked(NOW + 1);
    ok(
        store
            .revoke_credential(&token_id(1), NOW + 1, revoked.clone())
            .await,
        SCENARIO,
    );
    assert_eq!(
        store
            .revoke_credential(&token_id(1), NOW + 2, token_revoked(NOW + 2))
            .await,
        Ok(()),
        "{SCENARIO}: a repeat is allowed"
    );
    let found = ok(store.find_credential(&token_id(1)).await, SCENARIO);
    assert_eq!(
        found.and_then(|c| c.revoked_at_ms),
        Some(NOW + 1),
        "{SCENARIO}"
    );
    assert_eq!(
        log_of(&store, SCENARIO).await,
        vec![issued, revoked],
        "{SCENARIO}"
    );
}

pub(crate) async fn remove_member_revokes_credentials_and_writes_one_row<
    S: Store + IdentityStore,
>(
    store: S,
) {
    const SCENARIO: &str = "remove_member_revokes_credentials_and_writes_one_row";
    let main = BoardId::main();
    let alice = principal("alice");
    let added = store
        .add_member(&main, &alice, PrincipalKind::Human, Role::Member, NOW)
        .await;
    ok(added, SCENARIO);
    let c = credential(1, CredentialScope::Board(main.clone()), "alice");
    let issued = token_issued(NOW);
    ok(
        store.create_credential(c, NOW, issued.clone()).await,
        SCENARIO,
    );
    let removed = member_removed(&main, NOW + 1);
    ok(
        store
            .remove_member(&main, &alice, NOW + 1, removed.clone())
            .await,
        SCENARIO,
    );
    let found = ok(store.find_credential(&token_id(1)).await, SCENARIO);
    assert_eq!(
        found.and_then(|c| c.revoked_at_ms),
        Some(NOW + 1),
        "{SCENARIO}"
    );
    assert_eq!(
        store
            .remove_member(&main, &alice, NOW + 2, member_removed(&main, NOW + 2))
            .await,
        Err(not_found(Entity::Member, "alice")),
        "{SCENARIO}: remove again"
    );
    assert_eq!(
        log_of(&store, SCENARIO).await,
        vec![issued, removed],
        "{SCENARIO}"
    );
}

pub(crate) async fn create_invite_and_create_credential_and_replace_instance_credential_each_write_one_row<
    S: Store + IdentityStore,
>(
    store: S,
) {
    const SCENARIO: &str =
        "create_invite_and_create_credential_and_replace_instance_credential_each_write_one_row";
    let main = BoardId::main();
    let rows = [
        invite_created(NOW),
        token_issued(NOW + 1),
        instance_token_issued(NOW + 2),
        instance_token_issued(NOW + 3),
    ];
    let into = invite(1, &main, Role::Member, PrincipalKind::Agent);
    ok(
        store.create_invite(into, NOW, rows[0].clone()).await,
        SCENARIO,
    );
    let c = credential(2, CredentialScope::Board(main.clone()), "alice");
    ok(
        store.create_credential(c, NOW + 1, rows[1].clone()).await,
        SCENARIO,
    );
    let old = credential(3, CredentialScope::Instance, "instance-admin");
    ok(
        store.create_credential(old, NOW + 2, rows[2].clone()).await,
        SCENARIO,
    );
    let new = credential(4, CredentialScope::Instance, "instance-admin");
    assert_eq!(
        store
            .replace_instance_credential(new, NOW + 3, rows[3].clone())
            .await,
        Ok(1),
        "{SCENARIO}: replace"
    );
    assert_eq!(log_of(&store, SCENARIO).await, rows.to_vec(), "{SCENARIO}");
}

pub(crate) async fn enable_network_mode_writes_one_row_and_a_second_call_none<
    S: Store + IdentityStore,
>(
    store: S,
) {
    const SCENARIO: &str = "enable_network_mode_writes_one_row_and_a_second_call_none";
    let row = mode_enabled(NOW);
    ok(store.enable_network_mode(row.clone()).await, SCENARIO);
    assert_eq!(
        store.enable_network_mode(mode_enabled(NOW + 1)).await,
        Err(StoreError::Conflict(ConflictKind::AlreadyNetwork)),
        "{SCENARIO}: second call"
    );
    assert_eq!(log_of(&store, SCENARIO).await, vec![row], "{SCENARIO}");
}
