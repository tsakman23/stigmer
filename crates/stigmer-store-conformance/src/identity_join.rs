//! Joining: the member, their credential, the used invite and the audit row happen together.

use std::sync::Arc;

use stigmer_core::{BoardId, PrincipalKind, Role};
use stigmer_store::{
    ConflictKind, Credential, CredentialScope, Entity, IdentityStore, SecurityEvent,
    SecurityEventKind, Store, StoreError,
};

use crate::identity::{credential, hash_of, invite, join_credential, not_found, token_id, NOW};
use crate::support::{board, ok, principal};

const JOIN_CREDENTIAL: u8 = 100;

/// The join rows in the log, oldest first.
async fn joins<S: IdentityStore>(store: &S, scenario: &str) -> Vec<SecurityEvent> {
    let mut log = ok(store.security_log(100).await, scenario);
    log.retain(|e| e.kind == SecurityEventKind::Join);
    log.reverse();
    log
}

pub(crate) async fn join_creates_member_credential_and_audit_row_atomically<
    S: Store + IdentityStore,
>(
    store: S,
) {
    const SCENARIO: &str = "join_creates_member_credential_and_audit_row_atomically";
    let research = board("research");
    ok(store.create_board(&research, None).await, SCENARIO);
    let new = invite(1, &research, Role::Member, PrincipalKind::Agent);
    let hash = new.secret_hash;
    ok(store.create_invite(new, NOW).await, SCENARIO);

    let joined = ok(
        store
            .consume_invite(
                &token_id(1),
                &hash,
                &principal("dave"),
                NOW + 1,
                join_credential(JOIN_CREDENTIAL),
            )
            .await,
        SCENARIO,
    );
    assert_eq!(joined.member.name, principal("dave"), "{SCENARIO}");
    let stored = ok(
        store.find_credential(&token_id(JOIN_CREDENTIAL)).await,
        SCENARIO,
    );
    let expected = join_credential(JOIN_CREDENTIAL);
    assert_eq!(
        stored,
        Some(Credential {
            id: expected.id,
            secret_hash: expected.secret_hash,
            scope: CredentialScope::Board(research.clone()),
            principal: principal("dave"),
            expires_at_ms: expected.expires_at_ms,
            revoked_at_ms: None,
            last_seen_ms: None,
        }),
        "{SCENARIO}: credential"
    );
    assert_eq!(
        joins(&store, SCENARIO).await,
        vec![SecurityEvent {
            at_ms: NOW + 1,
            kind: SecurityEventKind::Join,
            board: Some(research.clone()),
            principal: Some("dave".to_owned()),
            // Public ids only; never a secret or a hash.
            detail: format!(
                "joined as agent/member via invite {} token {}",
                token_id(1),
                token_id(JOIN_CREDENTIAL)
            ),
        }],
        "{SCENARIO}: audit row"
    );
    assert_eq!(
        store
            .consume_invite(
                &token_id(1),
                &hash,
                &principal("erin"),
                NOW + 2,
                join_credential(101)
            )
            .await,
        Err(not_found(Entity::Invite, token_id(1))),
        "{SCENARIO}: the invite is used"
    );
}

pub(crate) async fn join_failure_leaves_no_member_credential_or_audit_row<
    S: Store + IdentityStore,
>(
    store: S,
) {
    const SCENARIO: &str = "join_failure_leaves_no_member_credential_or_audit_row";
    let main = BoardId::main();
    let old = board("old");
    ok(store.create_board(&old, None).await, SCENARIO);
    ok(
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
    let taken = invite(1, &main, Role::Member, PrincipalKind::Agent);
    let archived = invite(2, &old, Role::Member, PrincipalKind::Agent);
    let (taken_hash, archived_hash) = (taken.secret_hash, archived.secret_hash);
    ok(store.create_invite(taken, NOW).await, SCENARIO);
    ok(store.create_invite(archived, NOW).await, SCENARIO);
    ok(store.archive_board(&old).await, SCENARIO);

    let attempts = [
        (
            token_id(1),
            taken_hash,
            "alice",
            StoreError::Conflict(ConflictKind::NameTaken),
        ),
        (
            token_id(1),
            hash_of("wrong"),
            "dave",
            not_found(Entity::Invite, token_id(1)),
        ),
        (
            token_id(2),
            archived_hash,
            "dave",
            not_found(Entity::Invite, token_id(2)),
        ),
    ];
    for (id, hash, name, refusal) in attempts {
        let result = store
            .consume_invite(
                &id,
                &hash,
                &principal(name),
                NOW + 1,
                join_credential(JOIN_CREDENTIAL),
            )
            .await;
        assert_eq!(result, Err(refusal), "{SCENARIO}: {name} with {id}");
        assert_eq!(
            store.find_credential(&token_id(JOIN_CREDENTIAL)).await,
            Ok(None),
            "{SCENARIO}: no credential after {name} with {id}"
        );
        assert_eq!(joins(&store, SCENARIO).await, vec![], "{SCENARIO}: no row");
    }
    assert_eq!(store.list_members(&main).await.map(|m| m.len()), Ok(1));
    assert_eq!(store.list_members(&old).await, Ok(vec![]));
    // None of the refusals used the first invite.
    let ok_join = store
        .consume_invite(
            &token_id(1),
            &taken_hash,
            &principal("dave"),
            NOW + 2,
            join_credential(JOIN_CREDENTIAL),
        )
        .await;
    assert!(ok_join.is_ok(), "{SCENARIO}: still usable, got {ok_join:?}");
}

pub(crate) async fn create_credential_on_archived_board_is_board_archived<
    S: Store + IdentityStore,
>(
    store: S,
) {
    const SCENARIO: &str = "create_credential_on_archived_board_is_board_archived";
    let old = board("old");
    ok(store.create_board(&old, None).await, SCENARIO);
    ok(store.archive_board(&old).await, SCENARIO);
    assert_eq!(
        store
            .create_credential(
                credential(1, CredentialScope::Board(old.clone()), "ann"),
                NOW
            )
            .await,
        Err(StoreError::Conflict(ConflictKind::BoardArchived)),
        "{SCENARIO}"
    );
    assert_eq!(
        store.find_credential(&token_id(1)).await,
        Ok(None),
        "{SCENARIO}"
    );
    // The instance scope is not tied to a board.
    let instance = store
        .create_credential(credential(2, CredentialScope::Instance, "root"), NOW)
        .await;
    assert_eq!(instance, Ok(()), "{SCENARIO}: instance scope");
}

pub(crate) async fn concurrent_joins_with_one_invite_create_exactly_one_member_and_one_credential<
    S: IdentityStore,
>(
    store: S,
) {
    const SCENARIO: &str =
        "concurrent_joins_with_one_invite_create_exactly_one_member_and_one_credential";
    const TASKS: u8 = 20;
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
                let credential = join_credential(JOIN_CREDENTIAL + i);
                store
                    .consume_invite(&token_id(1), &hash, &name, NOW, credential)
                    .await
            })
        })
        .collect();
    let mut winners = Vec::new();
    for handle in handles {
        if let Ok(consumed) = ok(handle.await, SCENARIO) {
            winners.push(consumed.member.name);
        }
    }
    assert_eq!(winners.len(), 1, "{SCENARIO}: exactly one winner");
    let members = ok(store.list_members(&main).await, SCENARIO);
    assert_eq!(
        members.iter().map(|m| m.name.clone()).collect::<Vec<_>>(),
        winners,
        "{SCENARIO}: one member"
    );
    let credentials = ok(store.list_credentials(&main).await, SCENARIO);
    assert_eq!(credentials.len(), 1, "{SCENARIO}: one credential");
    assert_eq!(credentials[0].principal, winners[0], "{SCENARIO}");
    assert_eq!(
        joins(&*store, SCENARIO).await.len(),
        1,
        "{SCENARIO}: one row"
    );
}
