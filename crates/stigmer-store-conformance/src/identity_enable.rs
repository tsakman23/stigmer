//! `enable_network`: the instance credential, the optional main invite, the switch to network
//! mode and their security log rows, all in one transaction or none of it.

use stigmer_core::{BoardId, PrincipalKind, Role};
use stigmer_store::{
    ConflictKind, CredentialScope, EnableAudits, IdentityStore, Mode, SecurityEventKind, Store,
    StoreError,
};

use crate::identity::{credential, invite, join_credential, token_id, NOW};
use crate::support::{
    audit, board, board_archived, board_created, instance_token_issued, log_of, mode_enabled, ok,
    principal,
};

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
