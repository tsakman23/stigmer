//! Credentials: storing, finding, touching and revoking them.

use stigmer_core::{BoardId, PrincipalKind, Role};
use stigmer_store::{Credential, CredentialScope, Entity, IdentityStore, NewCredential, Store};

use crate::identity::{credential, not_found, token_id, NOW};
use crate::support::{board, ok, principal};

/// The credential `new` as freshly stored: never revoked or seen.
fn stored(new: &NewCredential) -> Credential {
    Credential {
        id: new.id.clone(),
        secret_hash: new.secret_hash,
        scope: new.scope.clone(),
        principal: new.principal.clone(),
        expires_at_ms: new.expires_at_ms,
        revoked_at_ms: None,
        last_seen_ms: None,
    }
}

pub(crate) async fn credential_roundtrip_and_find_unknown_is_none<S: IdentityStore>(store: S) {
    const SCENARIO: &str = "credential_roundtrip_and_find_unknown_is_none";
    let main = BoardId::main();
    // Created out of id order: listing goes by creation time.
    let later = credential(1, CredentialScope::Board(main.clone()), "alice");
    let earlier = credential(2, CredentialScope::Board(main.clone()), "bob");
    let instance = credential(3, CredentialScope::Instance, "root");
    for (c, at_ms) in [(&earlier, NOW), (&later, NOW + 1), (&instance, NOW + 2)] {
        ok(store.create_credential(c.clone(), at_ms).await, SCENARIO);
    }
    for c in [&later, &earlier, &instance] {
        assert_eq!(
            store.find_credential(&c.id).await,
            Ok(Some(stored(c))),
            "{SCENARIO}: find {}",
            c.id
        );
    }
    assert_eq!(
        store.find_credential(&token_id(9)).await,
        Ok(None),
        "{SCENARIO}: unknown id"
    );

    assert_eq!(
        store.touch_credential(&later.id, NOW + 10).await,
        Ok(()),
        "{SCENARIO}"
    );
    let touched = Credential {
        last_seen_ms: Some(NOW + 10),
        ..stored(&later)
    };
    assert_eq!(
        store.find_credential(&later.id).await,
        Ok(Some(touched.clone())),
        "{SCENARIO}: touch records last use"
    );
    assert_eq!(
        store.touch_credential(&token_id(9), NOW).await,
        Err(not_found(Entity::Credential, token_id(9))),
        "{SCENARIO}: touch unknown"
    );
    assert_eq!(
        store.list_credentials(&main).await,
        Ok(vec![stored(&earlier), touched]),
        "{SCENARIO}: the board's credentials, oldest first, no instance credential"
    );
}

pub(crate) async fn revoke_credential_is_idempotent<S: IdentityStore>(store: S) {
    const SCENARIO: &str = "revoke_credential_is_idempotent";
    let c = credential(1, CredentialScope::Board(BoardId::main()), "alice");
    ok(store.create_credential(c.clone(), NOW).await, SCENARIO);
    for at_ms in [NOW + 1, NOW + 2] {
        let revoked = store.revoke_credential(&c.id, at_ms).await;
        assert_eq!(revoked, Ok(()), "{SCENARIO}: revoke at {at_ms}");
    }
    let found = ok(store.find_credential(&c.id).await, SCENARIO);
    assert_eq!(
        found.and_then(|f| f.revoked_at_ms),
        Some(NOW + 1),
        "{SCENARIO}: the first revocation time is kept"
    );
    assert_eq!(
        store.revoke_credential(&token_id(9), NOW).await,
        Err(not_found(Entity::Credential, token_id(9))),
        "{SCENARIO}: revoke unknown"
    );
}

pub(crate) async fn archive_style_revoke_keeps_admins_when_asked<S: Store + IdentityStore>(
    store: S,
) {
    const SCENARIO: &str = "archive_style_revoke_keeps_admins_when_asked";
    let (main, research) = (BoardId::main(), board("research"));
    ok(store.create_board(&research, None).await, SCENARIO);
    let members = [
        (&main, "ann", Role::Admin),
        (&main, "bob", Role::Member),
        (&main, "cat", Role::Bridge),
        (&research, "bob", Role::Admin),
    ];
    for (on, name, role) in members {
        let added = store
            .add_member(on, &principal(name), PrincipalKind::Human, role, NOW)
            .await;
        ok(added, format_args!("{SCENARIO}: add {name} on {on}"));
    }
    let creds = [
        credential(1, CredentialScope::Board(main.clone()), "ann"),
        credential(2, CredentialScope::Board(main.clone()), "bob"),
        credential(3, CredentialScope::Board(main.clone()), "cat"),
        credential(4, CredentialScope::Board(research.clone()), "bob"),
        credential(5, CredentialScope::Instance, "ann"),
    ];
    for c in creds {
        ok(store.create_credential(c, NOW).await, SCENARIO);
    }
    let revoked_at = |n: u8| {
        let store = &store;
        async move {
            let found = ok(store.find_credential(&token_id(n)).await, SCENARIO);
            found.and_then(|c| c.revoked_at_ms)
        }
    };

    assert_eq!(
        store.revoke_board_credentials(&main, true, NOW + 1).await,
        Ok(2),
        "{SCENARIO}: bob and cat revoked, admin ann kept"
    );
    for (n, expected) in [
        (1, None),
        (2, Some(NOW + 1)),
        (3, Some(NOW + 1)),
        (4, None),
        (5, None),
    ] {
        assert_eq!(revoked_at(n).await, expected, "{SCENARIO}: credential {n}");
    }

    assert_eq!(
        store.revoke_board_credentials(&main, false, NOW + 2).await,
        Ok(1),
        "{SCENARIO}: then ann too"
    );
    for (n, expected) in [(1, Some(NOW + 2)), (2, Some(NOW + 1)), (4, None), (5, None)] {
        assert_eq!(
            revoked_at(n).await,
            expected,
            "{SCENARIO}: credential {n} after all"
        );
    }
}
