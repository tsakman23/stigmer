//! Audited mutations write their security log row in the same transaction: exactly one row per
//! change, none for an idempotent repeat, none for a failure.

use stigmer_core::{BoardId, PrincipalKind, Role};
use stigmer_store::{
    ConflictKind, CredentialScope, EnableAudits, Entity, IdentityStore, Mode, SecurityEvent,
    SecurityEventKind, Store, StoreError,
};

use crate::identity::{credential, invite, join_credential, not_found, token_id, NOW};
use crate::support::{
    audit, board, board_archived, board_created, instance_token_issued, invite_created,
    member_removed, mode_enabled, ok, principal, token_issued, token_revoked,
};

/// The whole security log, oldest first.
async fn log_of<S: IdentityStore>(store: &S, scenario: &str) -> Vec<SecurityEvent> {
    let mut rows = ok(
        store.security_log(1_000).await,
        format_args!("{scenario}: log"),
    );
    rows.reverse();
    rows
}

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

pub(crate) async fn archive_board_revoking_archives_revokes_non_admin_credentials_and_keeps_admins_in_one_transaction<
    S: Store + IdentityStore,
>(
    store: S,
) {
    const SCENARIO: &str = "archive_board_revoking_archives_revokes_non_admin_credentials_and_keeps_admins_in_one_transaction";
    let (ops, main) = (board("ops"), BoardId::main());
    ok(
        store
            .create_board(&ops, None, NOW, board_created(&ops, NOW))
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
            store.create_credential(c, NOW, token_issued(NOW)).await,
            SCENARIO,
        );
    }
    let instance = credential(4, CredentialScope::Instance, "instance-admin");
    ok(
        store
            .create_credential(instance, NOW, token_issued(NOW))
            .await,
        SCENARIO,
    );
    let before = log_of(&store, SCENARIO).await;

    // main is protected: refused, nothing revoked, no row.
    assert_eq!(
        store
            .archive_board_revoking(&main, NOW + 1, board_archived(&main, NOW + 1))
            .await,
        Err(StoreError::Conflict(ConflictKind::BoardProtected)),
        "{SCENARIO}: main"
    );
    let unknown = board("nowhere");
    assert_eq!(
        store
            .archive_board_revoking(&unknown, NOW + 1, board_archived(&unknown, NOW + 1))
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
        store
            .archive_board_revoking(&ops, NOW + 2, row.clone())
            .await,
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
        .archive_board_revoking(&ops, NOW + 3, board_archived(&ops, NOW + 3))
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

pub(crate) async fn failed_mutations_write_no_rows<S: Store + IdentityStore>(store: S) {
    const SCENARIO: &str = "failed_mutations_write_no_rows";
    let (nowhere, old, main) = (board("nowhere"), board("old"), BoardId::main());
    ok(
        store
            .create_board(&old, None, NOW, board_created(&old, NOW))
            .await,
        SCENARIO,
    );
    ok(
        store
            .archive_board(&old, NOW, board_archived(&old, NOW))
            .await,
        SCENARIO,
    );
    let existing = credential(9, CredentialScope::Board(main.clone()), "zed");
    ok(
        store
            .create_credential(existing, NOW, token_issued(NOW))
            .await,
        SCENARIO,
    );
    let into_main = invite(8, &main, Role::Member, PrincipalKind::Agent);
    let main_hash = into_main.secret_hash;
    ok(
        store
            .create_invite(into_main, NOW, invite_created(NOW))
            .await,
        SCENARIO,
    );
    let added = store
        .add_member(
            &main,
            &principal("taken"),
            PrincipalKind::Agent,
            Role::Member,
            NOW,
        )
        .await;
    ok(added, SCENARIO);
    let before = log_of(&store, SCENARIO).await;
    let at = NOW + 1;

    let mut failures: Vec<(&str, bool)> = Vec::new();
    // Unknown board.
    failures.push((
        "create_invite unknown board",
        store
            .create_invite(
                invite(1, &nowhere, Role::Member, PrincipalKind::Agent),
                at,
                invite_created(at),
            )
            .await
            .is_err(),
    ));
    failures.push((
        "create_credential unknown board",
        store
            .create_credential(
                credential(2, CredentialScope::Board(nowhere.clone()), "a"),
                at,
                token_issued(at),
            )
            .await
            .is_err(),
    ));
    failures.push((
        "remove_member unknown board",
        store
            .remove_member(&nowhere, &principal("a"), at, member_removed(&nowhere, at))
            .await
            .is_err(),
    ));
    failures.push((
        "archive_board unknown board",
        store
            .archive_board(&nowhere, at, board_archived(&nowhere, at))
            .await
            .is_err(),
    ));
    failures.push((
        "archive_board main",
        store
            .archive_board(&main, at, board_archived(&main, at))
            .await
            .is_err(),
    ));
    // Archived board.
    failures.push((
        "create_invite archived board",
        store
            .create_invite(
                invite(3, &old, Role::Member, PrincipalKind::Agent),
                at,
                invite_created(at),
            )
            .await
            .is_err(),
    ));
    failures.push((
        "create_credential archived board",
        store
            .create_credential(
                credential(4, CredentialScope::Board(old.clone()), "a"),
                at,
                token_issued(at),
            )
            .await
            .is_err(),
    ));
    // Taken names and ids.
    failures.push((
        "create_board taken id",
        store
            .create_board(&old, None, at, board_created(&old, at))
            .await
            .is_err(),
    ));
    failures.push((
        "create_credential taken id",
        store
            .create_credential(
                credential(9, CredentialScope::Board(main.clone()), "zed"),
                at,
                token_issued(at),
            )
            .await
            .is_err(),
    ));
    failures.push((
        "consume_invite taken name",
        store
            .consume_invite(
                &token_id(8),
                &main_hash,
                &principal("taken"),
                at,
                join_credential(100),
            )
            .await
            .is_err(),
    ));
    // Unknown member and credential.
    failures.push((
        "remove_member unknown member",
        store
            .remove_member(&main, &principal("nobody"), at, member_removed(&main, at))
            .await
            .is_err(),
    ));
    failures.push((
        "revoke_credential unknown id",
        store
            .revoke_credential(&token_id(77), at, token_revoked(at))
            .await
            .is_err(),
    ));
    failures.push((
        "replace_instance_credential board scope",
        store
            .replace_instance_credential(
                credential(5, CredentialScope::Board(main.clone()), "a"),
                at,
                instance_token_issued(at),
            )
            .await
            .is_err(),
    ));
    for (what, failed) in failures {
        assert!(failed, "{SCENARIO}: {what} should fail");
    }
    assert_eq!(
        log_of(&store, SCENARIO).await,
        before,
        "{SCENARIO}: no failed mutation wrote a row"
    );
    for n in [1, 2, 3, 4, 5] {
        assert_eq!(
            store
                .find_credential(&token_id(n))
                .await
                .map(|c| c.is_some()),
            Ok(false),
            "{SCENARIO}: credential {n} not stored"
        );
    }
}

/// The three rows `enable_network` is given, at `at_ms`, the invite's when `with_invite`.
fn enable_audits(at_ms: i64, with_invite: bool) -> EnableAudits {
    EnableAudits {
        mode: mode_enabled(at_ms),
        token: instance_token_issued(at_ms),
        invite: with_invite.then(|| {
            audit(
                SecurityEventKind::InviteCreated,
                Some(&BoardId::main()),
                at_ms,
            )
        }),
    }
}

pub(crate) async fn enable_network_writes_its_rows_in_order<S: Store + IdentityStore>(store: S) {
    const SCENARIO: &str = "enable_network_writes_its_rows_in_order";
    let audits = enable_audits(NOW, true);
    let main_invite = invite(2, &BoardId::main(), Role::Admin, PrincipalKind::Human);
    let main_hash = main_invite.secret_hash;
    ok(
        store
            .enable_network(
                credential(1, CredentialScope::Instance, "instance-admin"),
                Some(main_invite),
                NOW,
                audits.clone(),
            )
            .await,
        SCENARIO,
    );
    assert_eq!(store.mode().await, Ok(Mode::Network), "{SCENARIO}");
    let found = ok(store.find_credential(&token_id(1)).await, SCENARIO);
    assert_eq!(
        found.map(|c| c.scope),
        Some(CredentialScope::Instance),
        "{SCENARIO}: the instance credential"
    );
    let mut expected = vec![audits.mode, audits.token];
    expected.extend(audits.invite);
    assert_eq!(log_of(&store, SCENARIO).await, expected, "{SCENARIO}");
    // The invite was stored: it can be used.
    let joined = store
        .consume_invite(
            &token_id(2),
            &main_hash,
            &principal("ann"),
            NOW + 1,
            join_credential(100),
        )
        .await;
    assert!(joined.is_ok(), "{SCENARIO}: the invite works: {joined:?}");
}

pub(crate) async fn enable_network_without_invite_writes_two_rows<S: Store + IdentityStore>(
    store: S,
) {
    const SCENARIO: &str = "enable_network_without_invite_writes_two_rows";
    let audits = enable_audits(NOW, false);
    ok(
        store
            .enable_network(
                credential(1, CredentialScope::Instance, "instance-admin"),
                None,
                NOW,
                audits.clone(),
            )
            .await,
        SCENARIO,
    );
    assert_eq!(store.mode().await, Ok(Mode::Network), "{SCENARIO}");
    assert_eq!(
        log_of(&store, SCENARIO).await,
        vec![audits.mode, audits.token],
        "{SCENARIO}"
    );
}

pub(crate) async fn enable_network_twice_is_already_network_and_writes_nothing<
    S: Store + IdentityStore,
>(
    store: S,
) {
    const SCENARIO: &str = "enable_network_twice_is_already_network_and_writes_nothing";
    ok(
        store
            .enable_network(
                credential(1, CredentialScope::Instance, "instance-admin"),
                None,
                NOW,
                enable_audits(NOW, false),
            )
            .await,
        SCENARIO,
    );
    let before = log_of(&store, SCENARIO).await;
    assert_eq!(
        store
            .enable_network(
                credential(2, CredentialScope::Instance, "instance-admin"),
                Some(invite(
                    3,
                    &BoardId::main(),
                    Role::Admin,
                    PrincipalKind::Human
                )),
                NOW + 1,
                enable_audits(NOW + 1, true),
            )
            .await,
        Err(StoreError::Conflict(ConflictKind::AlreadyNetwork)),
        "{SCENARIO}: second call"
    );
    assert_eq!(
        store.find_credential(&token_id(2)).await,
        Ok(None),
        "{SCENARIO}: no credential stored"
    );
    assert_eq!(log_of(&store, SCENARIO).await, before, "{SCENARIO}: no row");
}

pub(crate) async fn enable_network_is_atomic_all_or_nothing<S: Store + IdentityStore>(store: S) {
    const SCENARIO: &str = "enable_network_is_atomic_all_or_nothing";
    let old = board("old");
    ok(
        store
            .create_board(&old, None, NOW, board_created(&old, NOW))
            .await,
        SCENARIO,
    );
    ok(
        store
            .archive_board(&old, NOW, board_archived(&old, NOW))
            .await,
        SCENARIO,
    );
    let before = log_of(&store, SCENARIO).await;
    let attempts = [
        (
            "invite into an archived board",
            credential(1, CredentialScope::Instance, "instance-admin"),
            Some(invite(2, &old, Role::Admin, PrincipalKind::Human)),
        ),
        (
            "invite into an unknown board",
            credential(1, CredentialScope::Instance, "instance-admin"),
            Some(invite(
                2,
                &board("nowhere"),
                Role::Admin,
                PrincipalKind::Human,
            )),
        ),
        (
            "a board-scoped credential",
            credential(1, CredentialScope::Board(BoardId::main()), "instance-admin"),
            None,
        ),
    ];
    for (what, c, into) in attempts {
        let with_invite = into.is_some();
        let result = store
            .enable_network(c, into, NOW + 1, enable_audits(NOW + 1, with_invite))
            .await;
        assert!(result.is_err(), "{SCENARIO}: {what} must fail");
        assert_eq!(
            store.mode().await,
            Ok(Mode::Local),
            "{SCENARIO}: {what}: still local"
        );
        assert_eq!(
            store.find_credential(&token_id(1)).await,
            Ok(None),
            "{SCENARIO}: {what}: no credential"
        );
        assert_eq!(
            log_of(&store, SCENARIO).await,
            before,
            "{SCENARIO}: {what}: no row"
        );
    }
    // Nothing was half-done: a correct call still works.
    ok(
        store
            .enable_network(
                credential(1, CredentialScope::Instance, "instance-admin"),
                None,
                NOW + 2,
                enable_audits(NOW + 2, false),
            )
            .await,
        format_args!("{SCENARIO}: retry"),
    );
}
