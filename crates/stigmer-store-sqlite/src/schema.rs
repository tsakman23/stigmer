//! Schema migrations, tracked with `PRAGMA user_version`.
//!
//! `MIGRATIONS[i]` takes the schema from version `i` to `i + 1`. Append new migrations;
//! never edit one that has shipped.

use rusqlite::{Connection, TransactionBehavior};
use stigmer_core::{BoardId, GENESIS_HASH};
use stigmer_store::StoreError;

use crate::{backend, now_ms};

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
    // 3: indexes for thread reads and the event feed.
    "CREATE INDEX messages_thread ON messages (board_id, thread_id);
    CREATE INDEX labels_message ON labels (message_id);
    CREATE INDEX events_message ON events (board_id, message_id);",
    // 4: the kind of principal that wrote each message. Every M0 author is a self-declared
    // local name, so existing rows and new posts are 'local'. See docs/design.md section 12,
    // call 8: M1 maps local principals to real principals with an explicit migration command.
    // Kept out of the wire format and the core types.
    "ALTER TABLE messages ADD COLUMN author_kind TEXT NOT NULL DEFAULT 'local';",
    // 5: board lifecycle. Boards that predate it (only `main`) keep created_at_ms 0 and no
    // creator; a board made from now on is stamped when it is created.
    "ALTER TABLE boards ADD COLUMN created_at_ms INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE boards ADD COLUMN created_by TEXT;
    ALTER TABLE boards ADD COLUMN archived_at_ms INTEGER;",
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
        "INSERT OR IGNORE INTO boards (id, head_seq, head_hash, created_at_ms)
         VALUES (?1, 0, ?2, ?3)",
        (BoardId::main().as_str(), GENESIS_HASH, now_ms()?),
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
        let hash = event_hash(
            GENESIS_HASH,
            1,
            EventKind::ThreadCreated,
            &author,
            &id,
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
        let created = store.create_board(&other, None).await.unwrap();
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
}
