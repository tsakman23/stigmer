//! `enable_network`: the instance credential, the optional main invite, the switch to network
//! mode and their security log rows, all in one transaction or none of it.

use stigmer_core::{BoardId, PrincipalKind, Role};
use stigmer_store::{
    ConflictKind, CredentialScope, EnableAudits, Entity, IdentityStore, Mode, NewInvite,
    SecurityEvent, SecurityEventKind, Store, StoreError,
};

use crate::identity::{credential, hash_of, invite, join_credential, not_found, token_id, NOW};
use crate::support::{
    audit, board, board_archived, board_created, instance_token_issued, log_of, mode_enabled, ok,
    principal,
};

/// The mode and token rows `enable_network` is given, at `at_ms`.
fn enable_audits(at_ms: i64) -> EnableAudits {
    EnableAudits {
        mode: mode_enabled(at_ms),
        token: instance_token_issued(at_ms),
    }
}

/// `into` with the `InviteCreated` row that comes with it, at `at_ms`.
fn with_row(into: NewInvite, at_ms: i64) -> (NewInvite, SecurityEvent) {
    let row = audit(SecurityEventKind::InviteCreated, Some(&into.board), at_ms);
    (into, row)
}

pub(crate) async fn enable_network_writes_its_rows_in_order<S: Store + IdentityStore>(store: S) {
    const SCENARIO: &str = "enable_network_writes_its_rows_in_order";
    let audits = enable_audits(NOW);
    let main_invite = invite(2, &BoardId::main(), Role::Admin, PrincipalKind::Human);
    let main_hash = main_invite.secret_hash;
    let (main_invite, invite_row) = with_row(main_invite, NOW);
    ok(
        store
            .enable_network(
                credential(1, CredentialScope::Instance, "instance-admin"),
                Some((main_invite, invite_row.clone())),
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
    let expected: Vec<_> = audits.rows(Some(&invite_row)).cloned().collect();
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
    let audits = enable_audits(NOW);
    ok(
        store
            .enable_network(
                credential(1, CredentialScope::Instance, "instance-admin"),
                None,
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
                enable_audits(NOW),
            )
            .await,
        SCENARIO,
    );
    let before = log_of(&store, SCENARIO).await;
    assert_eq!(
        store
            .enable_network(
                credential(2, CredentialScope::Instance, "instance-admin"),
                Some(with_row(
                    invite(3, &BoardId::main(), Role::Admin, PrincipalKind::Human),
                    NOW + 1
                )),
                enable_audits(NOW + 1)
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
    assert_no_invite(&store, 3, SCENARIO).await;
    assert_eq!(log_of(&store, SCENARIO).await, before, "{SCENARIO}: no row");
}

pub(crate) async fn enable_network_is_atomic_all_or_nothing<S: Store + IdentityStore>(store: S) {
    const SCENARIO: &str = "enable_network_is_atomic_all_or_nothing";
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
        (
            "a board-scoped credential with a valid main invite",
            credential(1, CredentialScope::Board(BoardId::main()), "instance-admin"),
            Some(invite(
                2,
                &BoardId::main(),
                Role::Admin,
                PrincipalKind::Human,
            )),
        ),
    ];
    for (what, c, into) in attempts {
        let into = into.map(|i| with_row(i, NOW + 1));
        let result = store.enable_network(c, into, enable_audits(NOW + 1)).await;
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
        assert_no_invite(&store, 2, SCENARIO).await;
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
                enable_audits(NOW + 2),
            )
            .await,
        format_args!("{SCENARIO}: retry"),
    );
}

/// Checks that invite `n` (as built by `invite`, so its secret is known) was never stored: using
/// it is the generic `NotFound`, and the attempt changes nothing either way.
async fn assert_no_invite<S: Store + IdentityStore>(store: &S, n: u8, scenario: &str) {
    let used = store
        .consume_invite(
            &token_id(n),
            &hash_of(&format!("invite-{n}")),
            &principal("probe"),
            NOW,
            join_credential(200),
        )
        .await;
    assert_eq!(
        used,
        Err(not_found(Entity::Invite, token_id(n))),
        "{scenario}: invite {n} was not stored"
    );
}
