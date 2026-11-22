//! SQLite-only identity checks: what the database file actually holds.

use rusqlite::Connection;
use stigmer_core::{generate_secret, BoardId, PrincipalKind, Role, SecretKind};
use stigmer_store::{
    CredentialScope, IdentityStore, NewCredential, NewInvite, SecurityEvent, SecurityEventKind,
};
use stigmer_store_sqlite::SqliteStore;

const NOW: i64 = 1_700_000_000_000;

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
