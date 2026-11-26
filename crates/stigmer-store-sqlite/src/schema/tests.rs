use rusqlite::Connection;
use stigmer_core::{
    event_hash, BoardId, ChannelPath, EventKind, HashInput, MessageId, NewMessage, Principal,
    Target, GENESIS_HASH,
};
use stigmer_store::Store;

use super::MIGRATIONS;
use crate::SqliteStore;

/// Builds a real database at schema `version` holding one message and its valid event.
fn write_old_database(path: &std::path::Path, version: usize) {
    let conn = Connection::open(path).unwrap();
    for sql in &MIGRATIONS[..version] {
        conn.execute_batch(sql).unwrap();
    }
    conn.pragma_update(None, "user_version", version as i64)
        .unwrap();

    let id = MessageId::generate().unwrap();
    let author = Principal::new("alice").unwrap();
    let channel = ChannelPath::new("eng").unwrap();
    let hash = event_hash(&HashInput {
        prev: GENESIS_HASH,
        seq: 1,
        kind: EventKind::ThreadCreated,
        actor: &author,
        message_id: &id,
        thread_id: &id,
        channel: &channel,
        at_ms: 1_000,
    });
    conn.execute(
        "INSERT INTO boards (id, head_seq, head_hash) VALUES ('main', 1, ?1)",
        [&hash],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO messages (id, board_id, channel, thread_id, author, text, at_ms)
         VALUES (?1, 'main', 'eng', ?1, 'alice', 'old message', 1000)",
        [id.as_str()],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO events (board_id, seq, kind, actor, message_id, thread_id, channel, at_ms, hash)
         VALUES ('main', 1, ?2, 'alice', ?1, ?1, 'eng', 1000, ?3)",
        (id.as_str(), EventKind::ThreadCreated.as_str(), &hash),
    )
    .unwrap();
}

#[tokio::test]
async fn v1_database_upgrades_to_v2_and_keeps_working() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("board.db");
    write_old_database(&path, 1);

    let store = SqliteStore::open(&path).await.unwrap();

    let conn = Connection::open(&path).unwrap();
    let version: i64 = conn
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, MIGRATIONS.len() as i64);
    for index in ["messages_thread", "labels_message", "events_message"] {
        let found: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?1",
                [index],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(found, 1, "index {index}");
    }
    let old_key: Option<String> = conn
        .query_row(
            "SELECT idempotency_key FROM messages WHERE text = 'old message'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(old_key, None);
    let index_sql: String = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'messages_idempotency'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(index_sql.contains("UNIQUE") && index_sql.contains("WHERE"));

    let keyed = || {
        NewMessage::new(
            BoardId::main(),
            Target::NewThread {
                channel: ChannelPath::new("eng").unwrap(),
            },
            Principal::new("alice").unwrap(),
            "new message".to_owned(),
            vec![],
            Some("req-1".to_owned()),
        )
        .unwrap()
    };
    let first = store.post(keyed()).await.unwrap();
    assert!(!first.replayed);
    assert_eq!(first.event.seq, 2);
    let retry = store.post(keyed()).await.unwrap();
    assert!(retry.replayed);
    assert_eq!(retry.message, first.message);

    let report = store.verify_chain(&BoardId::main()).await.unwrap();
    assert!(report.valid);
    assert_eq!(report.checked, 2);
}

#[tokio::test]
async fn v4_database_upgrades_to_v5_and_keeps_main_as_it_was() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("board.db");
    write_old_database(&path, 4);

    let store = SqliteStore::open(&path).await.unwrap();

    let conn = Connection::open(&path).unwrap();
    let version: i64 = conn
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, MIGRATIONS.len() as i64);
    let main = store.get_board(&BoardId::main()).await.unwrap();
    assert_eq!(main.created_at_ms, 0, "a board older than migration 5");
    assert_eq!(main.created_by, None);
    assert_eq!(main.archived_at_ms, None);
    assert_eq!(store.list_boards().await.unwrap(), vec![main]);

    let other = BoardId::new("other").unwrap();
    let created = store
        .create_board(
            &other,
            None,
            crate::tests::audit(stigmer_store::SecurityEventKind::BoardCreated, 1),
        )
        .await
        .unwrap();
    assert!(created.created_at_ms > 0);
    let report = store.verify_chain(&BoardId::main()).await.unwrap();
    assert!(report.valid);
    assert_eq!(report.checked, 1);
}

#[tokio::test]
async fn v3_database_upgrades_to_v4_and_marks_authors_local() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("board.db");
    write_old_database(&path, 3);

    let store = SqliteStore::open(&path).await.unwrap();

    let conn = Connection::open(&path).unwrap();
    let version: i64 = conn
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, MIGRATIONS.len() as i64);
    let old_kind: String = conn
        .query_row(
            "SELECT author_kind FROM messages WHERE text = 'old message'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(old_kind, "local");

    let keyed = || {
        NewMessage::new(
            BoardId::main(),
            Target::NewThread {
                channel: ChannelPath::new("eng").unwrap(),
            },
            Principal::new("alice").unwrap(),
            "new message".to_owned(),
            vec![],
            Some("req-1".to_owned()),
        )
        .unwrap()
    };
    let first = store.post(keyed()).await.unwrap();
    assert!(!first.replayed);
    assert_eq!(first.event.seq, 2);
    assert!(store.post(keyed()).await.unwrap().replayed);
    let new_kind: String = conn
        .query_row(
            "SELECT author_kind FROM messages WHERE id = ?1",
            [first.message.id.as_str()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(new_kind, "local");

    let report = store.verify_chain(&BoardId::main()).await.unwrap();
    assert!(report.valid);
    assert_eq!(report.checked, 2);
}

#[tokio::test]
async fn v5_database_upgrades_to_v7_in_local_mode_with_identity_tables() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("board.db");
    write_old_database(&path, 5);

    let store = SqliteStore::open(&path).await.unwrap();

    let conn = Connection::open(&path).unwrap();
    let version: i64 = conn
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, MIGRATIONS.len() as i64);
    let mode: String = conn
        .query_row("SELECT mode FROM instance", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        mode, "local",
        "an upgraded data directory stays in local mode"
    );
    let found = |kind: &str, name: &str| -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = ?1 AND name = ?2",
            [kind, name],
            |row| row.get(0),
        )
        .unwrap()
    };
    for table in [
        "instance",
        "principals",
        "credentials",
        "invites",
        "security_log",
    ] {
        assert_eq!(found("table", table), 1, "table {table}");
        let rows: i64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(rows, i64::from(table == "instance"), "rows in {table}");
    }
    for index in ["credentials_board", "principals_board"] {
        assert_eq!(found("index", index), 1, "index {index}");
    }
    let second_row = conn.execute("INSERT INTO instance (id, mode) VALUES (2, 'local')", []);
    assert!(second_row.is_err(), "instance holds a single row");
    let short_hash = conn.execute(
        "INSERT INTO credentials (id, secret_hash, principal, created_at_ms, expires_at_ms)
         VALUES ('0123456789abcdef', x'00', 'root', 1, 2)",
        [],
    );
    assert!(short_hash.is_err(), "a secret hash is exactly 32 bytes");
    let insert_invite = |hash: Vec<u8>| {
        conn.execute(
            "INSERT INTO invites
                 (id, secret_hash, board_id, role, kind, created_by, created_at_ms,
                  expires_at_ms)
             VALUES ('0123456789abcdef', ?1, 'main', 'member', 'agent', 'root', 1, 2)",
            [hash],
        )
    };
    assert!(
        insert_invite(vec![7; 31]).is_err(),
        "an invite hash is exactly 32 bytes"
    );
    assert_eq!(insert_invite(vec![7; 32]).unwrap(), 1, "32 bytes fit");

    let old_kind: String = conn
        .query_row(
            "SELECT author_kind FROM messages WHERE text = 'old message'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(old_kind, "local");
    let report = store.verify_chain(&BoardId::main()).await.unwrap();
    assert!(report.valid);
    assert_eq!(report.checked, 1);
}
