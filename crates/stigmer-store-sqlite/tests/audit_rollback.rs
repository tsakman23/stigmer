//! A failing audit write rolls its whole mutation back: with a trigger that refuses every
//! security log insert, each audited mutation fails as a backend error and changes nothing.

use std::path::Path;

use rusqlite::Connection;
use stigmer_core::{BoardId, Principal, PrincipalKind, Role, TokenId};
use stigmer_store::{
    CredentialScope, EnableAudits, IdentityStore, Mode, NewCredential, NewInvite, SecurityEvent,
    SecurityEventKind, Store, StoreError,
};
use stigmer_store_sqlite::SqliteStore;

const NOW: i64 = 1_700_000_000_000;

fn audit(kind: SecurityEventKind) -> SecurityEvent {
    SecurityEvent {
        at_ms: NOW,
        kind,
        board: None,
        principal: Some("root".to_owned()),
        detail: format!("{kind}"),
    }
}

fn id(n: u8) -> TokenId {
    TokenId::new(&format!("{n:016x}")).unwrap()
}

fn name(raw: &str) -> Principal {
    Principal::new(raw).unwrap()
}

fn credential(n: u8, scope: CredentialScope, who: &str) -> NewCredential {
    NewCredential {
        id: id(n),
        secret_hash: [n; 32],
        scope,
        principal: name(who),
        expires_at_ms: NOW + 1_000_000,
    }
}

fn invite(n: u8, into: &BoardId) -> NewInvite {
    NewInvite {
        id: id(n),
        secret_hash: [n; 32],
        board: into.clone(),
        role: Role::Member,
        kind: PrincipalKind::Agent,
        created_by: name("root"),
        expires_at_ms: NOW + 1_000_000,
    }
}

fn set_audit_trigger(path: &Path, on: bool) {
    let db = Connection::open(path).unwrap();
    let sql = if on {
        "CREATE TRIGGER refuse_audit BEFORE INSERT ON security_log
         BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END;"
    } else {
        "DROP TRIGGER refuse_audit;"
    };
    db.execute_batch(sql).unwrap();
}

fn count(path: &Path, table: &str) -> i64 {
    let db = Connection::open(path).unwrap();
    db.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
        row.get(0)
    })
    .unwrap()
}

fn is_backend<T: std::fmt::Debug>(result: Result<T, StoreError>, what: &str) {
    assert!(
        matches!(result, Err(StoreError::Backend(_))),
        "{what}: {result:?}"
    );
}

async fn revoked(store: &SqliteStore, n: u8) -> bool {
    let found = store.find_credential(&id(n)).await.unwrap().unwrap();
    found.revoked_at_ms.is_some()
}

#[tokio::test]
async fn a_failing_audit_write_rolls_back_every_audited_mutation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("board.db");
    let store = SqliteStore::open(&path).await.unwrap();
    let (ops, main) = (BoardId::new("ops").unwrap(), BoardId::main());
    store
        .create_board(&ops, None, NOW, audit(SecurityEventKind::BoardCreated))
        .await
        .unwrap();
    for (who, role) in [("ann", Role::Admin), ("bob", Role::Member)] {
        store
            .add_member(&ops, &name(who), PrincipalKind::Human, role, NOW)
            .await
            .unwrap();
    }
    for (n, scope, who) in [
        (1, CredentialScope::Board(ops.clone()), "ann"),
        (2, CredentialScope::Board(ops.clone()), "bob"),
        (3, CredentialScope::Instance, "instance-admin"),
    ] {
        let issued = audit(SecurityEventKind::MemberTokenIssued);
        store
            .create_credential(credential(n, scope, who), NOW, issued)
            .await
            .unwrap();
    }
    let rows = count(&path, "security_log");
    let invites = count(&path, "invites");
    set_audit_trigger(&path, true);

    let new = BoardId::new("new").unwrap();
    is_backend(
        store
            .create_board(&new, None, NOW, audit(SecurityEventKind::BoardCreated))
            .await,
        "create_board",
    );
    assert!(store.get_board(&new).await.is_err(), "board not created");

    is_backend(
        store
            .archive_board(&ops, NOW, audit(SecurityEventKind::BoardArchived))
            .await,
        "archive_board",
    );
    is_backend(
        store
            .archive_board_revoking(&ops, NOW, audit(SecurityEventKind::BoardArchived))
            .await,
        "archive_board_revoking",
    );
    let info = store.get_board(&ops).await.unwrap();
    assert_eq!(info.archived_at_ms, None, "board not archived");
    assert!(!revoked(&store, 2).await, "bob's credential not revoked");

    let board_token = credential(4, CredentialScope::Board(main.clone()), "zed");
    is_backend(
        store
            .create_credential(
                board_token,
                NOW,
                audit(SecurityEventKind::MemberTokenIssued),
            )
            .await,
        "create_credential",
    );
    assert_eq!(store.find_credential(&id(4)).await, Ok(None), "not stored");

    is_backend(
        store
            .revoke_credential(&id(2), NOW, audit(SecurityEventKind::TokenRevoked))
            .await,
        "revoke_credential",
    );
    assert!(!revoked(&store, 2).await, "credential not revoked");

    is_backend(
        store
            .remove_member(
                &ops,
                &name("bob"),
                NOW,
                audit(SecurityEventKind::MemberRemoved),
            )
            .await,
        "remove_member",
    );
    let bob = store.get_member(&ops, &name("bob")).await.unwrap();
    assert!(bob.is_some(), "member not removed");
    assert!(!revoked(&store, 2).await, "member's credential not revoked");

    is_backend(
        store
            .create_invite(
                invite(5, &main),
                NOW,
                audit(SecurityEventKind::InviteCreated),
            )
            .await,
        "create_invite",
    );
    assert_eq!(count(&path, "invites"), invites, "invite not created");

    let replacement = credential(6, CredentialScope::Instance, "instance-admin");
    is_backend(
        store
            .replace_instance_credential(
                replacement,
                NOW,
                audit(SecurityEventKind::InstanceTokenIssued),
            )
            .await,
        "replace_instance_credential",
    );
    assert_eq!(store.find_credential(&id(6)).await, Ok(None), "not stored");
    assert!(!revoked(&store, 3).await, "old instance credential kept");

    is_backend(
        store
            .enable_network_mode(audit(SecurityEventKind::ModeEnabled))
            .await,
        "enable_network_mode",
    );
    let audits = EnableAudits {
        mode: audit(SecurityEventKind::ModeEnabled),
        token: audit(SecurityEventKind::InstanceTokenIssued),
        invite: Some(audit(SecurityEventKind::InviteCreated)),
    };
    is_backend(
        store
            .enable_network(
                credential(7, CredentialScope::Instance, "instance-admin"),
                Some(invite(8, &main)),
                NOW,
                audits,
            )
            .await,
        "enable_network",
    );
    assert_eq!(store.mode().await, Ok(Mode::Local), "mode still local");
    assert_eq!(store.find_credential(&id(7)).await, Ok(None), "not stored");
    assert_eq!(count(&path, "invites"), invites, "invite not created");
    assert_eq!(count(&path, "security_log"), rows, "no row written");

    // Nothing was half-done, so once the log works again a retry succeeds.
    set_audit_trigger(&path, false);
    store
        .archive_board_revoking(&ops, NOW, audit(SecurityEventKind::BoardArchived))
        .await
        .unwrap();
    assert!(revoked(&store, 2).await, "the retry revoked bob");
    assert!(!revoked(&store, 1).await, "the admin keeps hers");
    assert_eq!(count(&path, "security_log"), rows + 1);
}
