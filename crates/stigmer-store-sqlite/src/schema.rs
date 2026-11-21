//! Schema migrations, tracked with `PRAGMA user_version`.
//!
//! `MIGRATIONS[i]` takes the schema from version `i` to `i + 1`. Append new migrations;
//! never edit one that has shipped.

use rusqlite::{Connection, TransactionBehavior};
use stigmer_core::{BoardId, GENESIS_HASH};
use stigmer_store::StoreError;

use crate::backend;

/// Ordered migration scripts, each applied in its own transaction.
pub(crate) const MIGRATIONS: &[&str] = &[
    // 1: boards, messages, labels and the event log.
    "CREATE TABLE boards (
        id TEXT PRIMARY KEY,
        head_seq INTEGER NOT NULL,
        head_hash TEXT NOT NULL
    );
    CREATE TABLE messages (
        id TEXT PRIMARY KEY,
        board_id TEXT NOT NULL REFERENCES boards(id),
        channel TEXT NOT NULL,
        thread_id TEXT NOT NULL,
        author TEXT NOT NULL,
        text TEXT NOT NULL,
        at_ms INTEGER NOT NULL
    );
    CREATE TABLE labels (
        message_id TEXT NOT NULL REFERENCES messages(id),
        key TEXT NOT NULL,
        value TEXT NOT NULL
    );
    CREATE TABLE events (
        board_id TEXT NOT NULL REFERENCES boards(id),
        seq INTEGER NOT NULL,
        kind TEXT NOT NULL,
        actor TEXT NOT NULL,
        message_id TEXT NOT NULL,
        thread_id TEXT NOT NULL,
        channel TEXT NOT NULL,
        at_ms INTEGER NOT NULL,
        hash TEXT NOT NULL,
        PRIMARY KEY (board_id, seq)
    );",
    // 2: idempotency keys, unique per board and author.
    "ALTER TABLE messages ADD COLUMN idempotency_key TEXT;
    CREATE UNIQUE INDEX messages_idempotency
        ON messages (board_id, author, idempotency_key)
        WHERE idempotency_key IS NOT NULL;",
];

/// Brings the database up to the latest schema and makes sure board `main` exists.
pub(crate) fn migrate(conn: &mut Connection) -> Result<(), StoreError> {
    loop {
        // Read the version inside the write transaction so two processes cannot both apply a step.
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(backend)?;
        let version: i64 = tx
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(backend)?;
        let applied = usize::try_from(version)
            .map_err(|_| StoreError::Backend(format!("invalid schema version {version}")))?;
        if applied > MIGRATIONS.len() {
            return Err(StoreError::Backend(format!(
                "database schema version {applied} is newer than this build supports ({})",
                MIGRATIONS.len()
            )));
        }
        let Some(sql) = MIGRATIONS.get(applied) else {
            break;
        };
        tx.execute_batch(sql).map_err(backend)?;
        tx.pragma_update(None, "user_version", version + 1)
            .map_err(backend)?;
        tx.commit().map_err(backend)?;
    }
    conn.execute(
        "INSERT OR IGNORE INTO boards (id, head_seq, head_hash) VALUES (?1, 0, ?2)",
        (BoardId::main().as_str(), GENESIS_HASH),
    )
    .map_err(backend)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;
    use stigmer_core::{
        event_hash, BoardId, ChannelPath, EventKind, MessageId, NewMessage, Principal, Target,
        GENESIS_HASH,
    };
    use stigmer_store::Store;

    use super::MIGRATIONS;
    use crate::SqliteStore;

    /// Builds a real version 1 database holding one message and its valid event.
    fn write_v1_database(path: &std::path::Path) {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(MIGRATIONS[0]).unwrap();
        conn.pragma_update(None, "user_version", 1).unwrap();

        let id = MessageId::generate().unwrap();
        let author = Principal::new("alice").unwrap();
        let channel = ChannelPath::new("eng").unwrap();
        let hash = event_hash(
            GENESIS_HASH,
            1,
            EventKind::ThreadCreated,
            &author,
            &id,
            &channel,
            1_000,
        );
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
        write_v1_database(&path);

        let store = SqliteStore::open(&path).await.unwrap();

        let conn = Connection::open(&path).unwrap();
        let version: i64 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, 2);
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
}
