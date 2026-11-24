//! Audited mutations write their security log row in the same transaction: exactly one row per
//! change, none for an idempotent repeat, none for a failure.

use stigmer_core::{BoardId, PrincipalKind, Role};
use stigmer_store::{
    ConflictKind, CredentialScope, Entity, IdentityStore, SecurityEvent, SecurityEventKind, Store,
    StoreError,
};

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
            .create_board(&ops, Some(&principal("root")), row.clone())
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
        store.create_board(&ops, None, first.clone()).await,
        SCENARIO,
    );
    for on in [&ops, &BoardId::main()] {
        assert_eq!(
            store
                .create_board(on, None, board_created(on, NOW + 1))
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
        store.create_board(&ops, None, created.clone()).await,
        SCENARIO,
    );
    let archived = board_archived(&ops, NOW + 1);
    let info = ok(store.archive_board(&ops, archived.clone()).await, SCENARIO);
    assert_eq!(info.archived_at_ms, Some(NOW + 1), "{SCENARIO}");
    let again = store
        .archive_board(&ops, board_archived(&ops, NOW + 2))
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
    ok(store.create_credential(c, issued.clone()).await, SCENARIO);
    let revoked = token_revoked(NOW + 1);
    ok(
        store.revoke_credential(&token_id(1), revoked.clone()).await,
        SCENARIO,
    );
    assert_eq!(
        store
            .revoke_credential(&token_id(1), token_revoked(NOW + 2))
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
    ok(store.create_credential(c, issued.clone()).await, SCENARIO);
    let removed = member_removed(&main, NOW + 1);
    ok(
        store.remove_member(&main, &alice, removed.clone()).await,
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
            .remove_member(&main, &alice, member_removed(&main, NOW + 2))
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
    ok(store.create_invite(into, rows[0].clone()).await, SCENARIO);
    let c = credential(2, CredentialScope::Board(main.clone()), "alice");
    ok(store.create_credential(c, rows[1].clone()).await, SCENARIO);
    // A board credential: the replacement below has no other instance credential to revoke,
    // so it writes only its own row (revoking ones are the next two scenarios).
    let other = credential(3, CredentialScope::Board(main.clone()), "bob");
    ok(
        store.create_credential(other, rows[2].clone()).await,
        SCENARIO,
    );
    let new = credential(4, CredentialScope::Instance, "instance-admin");
    assert_eq!(
        store
            .replace_instance_credential(new, rows[3].clone())
            .await,
        Ok(0),
        "{SCENARIO}: replace"
    );
    assert_eq!(log_of(&store, SCENARIO).await, rows.to_vec(), "{SCENARIO}");
}

pub(crate) async fn replace_instance_credential_writes_a_token_revoked_row_with_the_count_when_it_revokes_others<
    S: Store + IdentityStore,
>(
    store: S,
) {
    const SCENARIO: &str = "replace_instance_credential_writes_a_token_revoked_row_with_the_count_when_it_revokes_others";
    for n in [1, 2] {
        let old = credential(n, CredentialScope::Instance, "instance-admin");
        ok(
            store
                .create_credential(old, instance_token_issued(NOW))
                .await,
            SCENARIO,
        );
    }
    let before = log_of(&store, SCENARIO).await;
    let issued = instance_token_issued(NOW + 1);
    let new = credential(3, CredentialScope::Instance, "instance-admin");
    assert_eq!(
        store.replace_instance_credential(new, issued.clone()).await,
        Ok(2),
        "{SCENARIO}: replace"
    );
    let revoked = SecurityEvent {
        at_ms: issued.at_ms,
        kind: SecurityEventKind::TokenRevoked,
        board: None,
        principal: issued.principal.clone(),
        detail: "revoked 2 other instance credentials".to_owned(),
    };
    let mut expected = before;
    expected.extend([issued, revoked]);
    assert_eq!(
        log_of(&store, SCENARIO).await,
        expected,
        "{SCENARIO}: the caller's row, then the store's count row"
    );
}

pub(crate) async fn replace_instance_credential_writes_no_extra_row_when_nothing_is_revoked<
    S: Store + IdentityStore,
>(
    store: S,
) {
    const SCENARIO: &str =
        "replace_instance_credential_writes_no_extra_row_when_nothing_is_revoked";
    let issued = instance_token_issued(NOW);
    let new = credential(1, CredentialScope::Instance, "instance-admin");
    assert_eq!(
        store.replace_instance_credential(new, issued.clone()).await,
        Ok(0),
        "{SCENARIO}: replace"
    );
    assert_eq!(
        log_of(&store, SCENARIO).await,
        vec![issued],
        "{SCENARIO}: only the caller's row"
    );
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

/// Every audited mutation takes its instant from its audit event: the times it stores and the
/// row's `at_ms` are that one instant. A credential's and an invite's creation times are not
/// readable through the trait; the SQLite tests read those columns.
pub(crate) async fn audited_mutations_stamp_state_and_row_with_the_audit_instant<
    S: Store + IdentityStore,
>(
    store: S,
) {
    const SCENARIO: &str = "audited_mutations_stamp_state_and_row_with_the_audit_instant";
    let (ops, main) = (board("ops"), BoardId::main());
    let created = board_created(&ops, NOW + 11);
    let info = ok(
        store.create_board(&ops, None, created.clone()).await,
        SCENARIO,
    );
    assert_eq!(info.created_at_ms, NOW + 11, "{SCENARIO}: board created_at");
    let archived = board_archived(&ops, NOW + 12);
    let info = ok(store.archive_board(&ops, archived.clone()).await, SCENARIO);
    assert_eq!(
        info.archived_at_ms,
        Some(NOW + 12),
        "{SCENARIO}: board archived_at"
    );
    let invited = invite_created(NOW + 13);
    let into = invite(1, &main, Role::Member, PrincipalKind::Agent);
    ok(store.create_invite(into, invited.clone()).await, SCENARIO);
    let issued = token_issued(NOW + 14);
    let c = credential(2, CredentialScope::Board(main.clone()), "alice");
    ok(store.create_credential(c, issued.clone()).await, SCENARIO);
    let revoked = token_revoked(NOW + 15);
    ok(
        store.revoke_credential(&token_id(2), revoked.clone()).await,
        SCENARIO,
    );
    let found = ok(store.find_credential(&token_id(2)).await, SCENARIO);
    assert_eq!(
        found.and_then(|c| c.revoked_at_ms),
        Some(NOW + 15),
        "{SCENARIO}: revoked_at"
    );
    let rows = vec![created, archived, invited, issued, revoked];
    let instants: Vec<i64> = rows.iter().map(|r| r.at_ms).collect();
    assert_eq!(
        instants,
        [NOW + 11, NOW + 12, NOW + 13, NOW + 14, NOW + 15],
        "{SCENARIO}"
    );
    assert_eq!(
        log_of(&store, SCENARIO).await,
        rows,
        "{SCENARIO}: rows as given"
    );
}
