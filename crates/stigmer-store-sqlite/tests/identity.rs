//! SQLite-only identity checks: what the database file actually holds.

use rusqlite::Connection;
use stigmer_core::{generate_secret, BoardId, PrincipalKind, Role, SecretKind};
use stigmer_store::{
    CredentialScope, Entity, IdentityStore, NewCredential, NewInvite, NewJoinCredential,
    SecurityEvent, SecurityEventKind, StoreError,
};
use stigmer_store_sqlite::SqliteStore;

const NOW: i64 = 1_700_000_000_000;

fn join_credential() -> NewJoinCredential {
    let secret = generate_secret(SecretKind::Token).unwrap();
    NewJoinCredential {
        id: secret.id,
        secret_hash: secret.hash,
        expires_at_ms: NOW + 1,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Every value in `table`, each rendered as text (blobs as hex), one string per cell.
fn cells(conn: &Connection, table: &str) -> Vec<String> {
    let mut stmt = conn.prepare(&format!("SELECT * FROM {table}")).unwrap();
    let columns = stmt.column_count();
    let mut rows = stmt.query([]).unwrap();
    let mut out = Vec::new();
    while let Some(row) = rows.next().unwrap() {
        for i in 0..columns {
            out.push(match row.get_ref(i).unwrap() {
                rusqlite::types::ValueRef::Null => String::new(),
                rusqlite::types::ValueRef::Integer(n) => n.to_string(),
                rusqlite::types::ValueRef::Real(r) => r.to_string(),
                rusqlite::types::ValueRef::Text(t) => String::from_utf8_lossy(t).into_owned(),
                rusqlite::types::ValueRef::Blob(b) => hex(b),
            });
        }
    }
    out
}

#[tokio::test]
async fn secret_hashes_not_stored_in_plain_text() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("board.db");
    let store = SqliteStore::open(&path).await.unwrap();
    let token = generate_secret(SecretKind::Token).unwrap();
    let invite = generate_secret(SecretKind::Invite).unwrap();
    store
        .create_credential(
            NewCredential {
                id: token.id.clone(),
                secret_hash: token.hash,
                scope: CredentialScope::Board(BoardId::main()),
                principal: stigmer_core::Principal::new("alice").unwrap(),
                expires_at_ms: NOW + 1,
            },
            NOW,
        )
        .await
        .unwrap();
    store
        .create_invite(
            NewInvite {
                id: invite.id.clone(),
                secret_hash: invite.hash,
                board: BoardId::main(),
                role: Role::Member,
                kind: PrincipalKind::Agent,
                created_by: stigmer_core::Principal::new("root").unwrap(),
                expires_at_ms: NOW + 1,
            },
            NOW,
        )
        .await
        .unwrap();
    store
        .log_security(SecurityEvent {
            at_ms: NOW,
            kind: SecurityEventKind::Join,
            board: Some(BoardId::main()),
            principal: Some("alice".to_owned()),
            detail: format!("joined with invite {}", invite.id),
        })
        .await
        .unwrap();

    let conn = Connection::open(&path).unwrap();
    for table in ["credentials", "invites"] {
        let (kind, length): (String, i64) = conn
            .query_row(
                &format!("SELECT typeof(secret_hash), length(secret_hash) FROM {table}"),
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((kind.as_str(), length), ("blob", 32), "{table}");
    }
    let stored_hashes: Vec<Vec<u8>> = ["credentials", "invites"]
        .iter()
        .map(|table| {
            conn.query_row(&format!("SELECT secret_hash FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap()
        })
        .collect();
    assert_eq!(
        stored_hashes,
        vec![token.hash.to_vec(), invite.hash.to_vec()]
    );

    for secret in [&token, &invite] {
        let secret_part = secret.full.rsplit('_').next().unwrap();
        for table in ["credentials", "invites", "security_log", "principals"] {
            for cell in cells(&conn, table) {
                assert!(!cell.contains(&secret.full), "full secret in {table}");
                assert!(!cell.contains(secret_part), "secret part in {table}");
            }
        }
        for cell in cells(&conn, "security_log") {
            assert!(!cell.contains(&hex(&secret.hash)), "a hash in security_log");
        }
    }
}

#[tokio::test]
async fn unknown_invite_id_is_refused_exactly_like_a_wrong_secret() {
    let store = SqliteStore::open_memory().await.unwrap();
    let invite = generate_secret(SecretKind::Invite).unwrap();
    store
        .create_invite(
            NewInvite {
                id: invite.id.clone(),
                secret_hash: invite.hash,
                board: BoardId::main(),
                role: Role::Member,
                kind: PrincipalKind::Agent,
                created_by: stigmer_core::Principal::new("root").unwrap(),
                expires_at_ms: NOW + 1,
            },
            NOW,
        )
        .await
        .unwrap();
    let unknown = generate_secret(SecretKind::Invite).unwrap();
    let dave = stigmer_core::Principal::new("dave").unwrap();
    let refused = |id: &stigmer_core::TokenId| StoreError::NotFound {
        entity: Entity::Invite,
        id: id.to_string(),
    };

    // An unknown id, including with the all-zero hash the store compares unknown ids against.
    for hash in [unknown.hash, [0u8; 32], invite.hash] {
        let result = store
            .consume_invite(&unknown.id, &hash, &dave, NOW, join_credential())
            .await;
        assert_eq!(result, Err(refused(&unknown.id)));
    }
    let wrong = store
        .consume_invite(&invite.id, &unknown.hash, &dave, NOW, join_credential())
        .await;
    assert_eq!(wrong, Err(refused(&invite.id)));
    assert!(store
        .list_members(&BoardId::main())
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn refused_join_leaves_no_credential_member_or_join_row_in_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("board.db");
    let store = SqliteStore::open(&path).await.unwrap();
    let main = BoardId::main();
    let alice = stigmer_core::Principal::new("alice").unwrap();
    store
        .add_member(&main, &alice, PrincipalKind::Human, Role::Admin, NOW)
        .await
        .unwrap();
    let invite = generate_secret(SecretKind::Invite).unwrap();
    let new = NewInvite {
        id: invite.id.clone(),
        secret_hash: invite.hash,
        board: main,
        role: Role::Member,
        kind: PrincipalKind::Agent,
        created_by: alice.clone(),
        expires_at_ms: NOW + 1,
    };
    store.create_invite(new, NOW).await.unwrap();

    let refused = store
        .consume_invite(&invite.id, &invite.hash, &alice, NOW, join_credential())
        .await;
    assert!(
        matches!(refused, Err(StoreError::Conflict(_))),
        "{refused:?}"
    );

    let conn = Connection::open(&path).unwrap();
    let count = |sql: &str| -> i64 { conn.query_row(sql, [], |row| row.get(0)).unwrap() };
    assert_eq!(count("SELECT count(*) FROM credentials"), 0);
    assert_eq!(count("SELECT count(*) FROM principals"), 1);
    assert_eq!(
        count("SELECT count(*) FROM security_log WHERE kind = 'join'"),
        0
    );
    assert_eq!(
        count("SELECT count(*) FROM invites WHERE used_at_ms IS NOT NULL"),
        0
    );
}

#[tokio::test]
async fn join_row_holds_public_ids_but_no_secret_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("board.db");
    let store = SqliteStore::open(&path).await.unwrap();
    let invite = generate_secret(SecretKind::Invite).unwrap();
    let token = generate_secret(SecretKind::Token).unwrap();
    let new = NewInvite {
        id: invite.id.clone(),
        secret_hash: invite.hash,
        board: BoardId::main(),
        role: Role::Member,
        kind: PrincipalKind::Agent,
        created_by: stigmer_core::Principal::new("root").unwrap(),
        expires_at_ms: NOW + 1,
    };
    store.create_invite(new, NOW).await.unwrap();
    let join = NewJoinCredential {
        id: token.id.clone(),
        secret_hash: token.hash,
        expires_at_ms: NOW + 1,
    };
    let dave = stigmer_core::Principal::new("dave").unwrap();
    store
        .consume_invite(&invite.id, &invite.hash, &dave, NOW, join)
        .await
        .unwrap();

    let conn = Connection::open(&path).unwrap();
    let row: String = conn
        .query_row(
            "SELECT detail FROM security_log WHERE kind = 'join'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        row,
        format!(
            "joined as agent/member via invite {} token {}",
            invite.id, token.id
        )
    );
    for secret in [&invite, &token] {
        let secret_part = secret.full.rsplit('_').next().unwrap();
        for cell in cells(&conn, "security_log") {
            assert!(!cell.contains(&secret.full) && !cell.contains(secret_part));
            assert!(!cell.contains(&hex(&secret.hash)));
        }
    }
}
