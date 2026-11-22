//! Board members: adding, listing and removing them.

use stigmer_core::{BoardId, PrincipalKind, Role};
use stigmer_store::{ConflictKind, CredentialScope, Entity, IdentityStore, Store, StoreError};

use crate::identity::{credential, member, not_found, token_id, NOW};
use crate::support::{board, fail, ok, principal};

pub(crate) async fn add_member_then_list_and_name_taken_conflict<S: IdentityStore>(store: S) {
    const SCENARIO: &str = "add_member_then_list_and_name_taken_conflict";
    let main = BoardId::main();
    let bob = member(&main, "bob", PrincipalKind::Agent, Role::Member, NOW);
    let alice = member(&main, "alice", PrincipalKind::Human, Role::Admin, NOW + 1);
    for m in [&bob, &alice] {
        let added = store
            .add_member(&main, &m.name, m.kind, m.role, m.created_at_ms)
            .await;
        assert_eq!(added.as_ref(), Ok(m), "{SCENARIO}: add {}", m.name);
    }
    assert_eq!(
        store.list_members(&main).await,
        Ok(vec![alice.clone(), bob.clone()]),
        "{SCENARIO}: listed by name"
    );
    assert_eq!(
        store.get_member(&main, &principal("alice")).await,
        Ok(Some(alice.clone())),
        "{SCENARIO}: get"
    );
    assert_eq!(
        store.get_member(&main, &principal("carol")).await,
        Ok(None),
        "{SCENARIO}: get an unknown name"
    );
    let again = store
        .add_member(
            &main,
            &principal("alice"),
            PrincipalKind::Bridge,
            Role::Bridge,
            NOW + 2,
        )
        .await;
    assert_eq!(
        again,
        Err(StoreError::Conflict(ConflictKind::NameTaken)),
        "{SCENARIO}: second add"
    );
    assert_eq!(
        store.get_member(&main, &principal("alice")).await,
        Ok(Some(alice)),
        "{SCENARIO}: the first alice is untouched"
    );
}

pub(crate) async fn member_names_are_unique_per_board_not_globally<S: Store + IdentityStore>(
    store: S,
) {
    const SCENARIO: &str = "member_names_are_unique_per_board_not_globally";
    let (main, research) = (BoardId::main(), board("research"));
    ok(store.create_board(&research, None).await, SCENARIO);
    let on_main = member(&main, "alice", PrincipalKind::Human, Role::Admin, NOW);
    let on_research = member(
        &research,
        "alice",
        PrincipalKind::Agent,
        Role::Member,
        NOW + 1,
    );
    for m in [&on_main, &on_research] {
        let added = store
            .add_member(&m.board, &m.name, m.kind, m.role, m.created_at_ms)
            .await;
        assert_eq!(added.as_ref(), Ok(m), "{SCENARIO}: add on {}", m.board);
    }
    assert_eq!(
        store.list_members(&main).await,
        Ok(vec![on_main]),
        "{SCENARIO}: main"
    );
    assert_eq!(
        store.list_members(&research).await,
        Ok(vec![on_research]),
        "{SCENARIO}: research"
    );
}

pub(crate) async fn remove_member_revokes_their_credentials<S: Store + IdentityStore>(store: S) {
    const SCENARIO: &str = "remove_member_revokes_their_credentials";
    let (main, research) = (BoardId::main(), board("research"));
    ok(store.create_board(&research, None).await, SCENARIO);
    for (on, name) in [(&main, "alice"), (&main, "bob"), (&research, "alice")] {
        let added = store
            .add_member(
                on,
                &principal(name),
                PrincipalKind::Human,
                Role::Member,
                NOW,
            )
            .await;
        ok(added, format_args!("{SCENARIO}: add {name} on {on}"));
    }
    let creds = [
        credential(1, CredentialScope::Board(main.clone()), "alice"),
        credential(2, CredentialScope::Board(main.clone()), "alice"),
        credential(3, CredentialScope::Board(research.clone()), "alice"),
        credential(4, CredentialScope::Board(main.clone()), "bob"),
        credential(5, CredentialScope::Instance, "alice"),
    ];
    for c in creds {
        ok(store.create_credential(c, NOW).await, SCENARIO);
    }

    let removed = store
        .remove_member(&main, &principal("alice"), NOW + 5)
        .await;
    assert_eq!(removed, Ok(()), "{SCENARIO}: remove");
    assert_eq!(
        store.get_member(&main, &principal("alice")).await,
        Ok(None),
        "{SCENARIO}: gone from main"
    );
    assert!(
        matches!(
            store.get_member(&research, &principal("alice")).await,
            Ok(Some(_))
        ),
        "{SCENARIO}: still on research"
    );
    for (n, revoked) in [
        (1, Some(NOW + 5)),
        (2, Some(NOW + 5)),
        (3, None),
        (4, None),
        (5, None),
    ] {
        let found = ok(store.find_credential(&token_id(n)).await, SCENARIO);
        let Some(found) = found else {
            fail(format_args!("{SCENARIO}: credential {n} disappeared"));
        };
        assert_eq!(found.revoked_at_ms, revoked, "{SCENARIO}: credential {n}");
    }
    assert_eq!(
        store
            .remove_member(&main, &principal("alice"), NOW + 6)
            .await,
        Err(not_found(Entity::Member, "alice")),
        "{SCENARIO}: remove again"
    );
}
