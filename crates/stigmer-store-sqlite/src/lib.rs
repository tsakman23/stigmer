//! stigmer-store-sqlite: the SQLite backend for `Store`.
//!
//! One connection behind a mutex; every database call runs on tokio's blocking pool.

mod posts;
mod reads;
mod schema;

use std::fmt::Display;
use std::future::Future;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rusqlite::Connection;
use stigmer_core::{BoardId, ChannelPath, MessageId, NewMessage};
use stigmer_store::{ChainReport, Page, Posted, Store, StoreError, Thread, ThreadSummary};

/// A `Store` backed by one SQLite database.
pub struct SqliteStore {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteStore {
    /// Opens (creating if needed) the database file at `path` and migrates it.
    pub async fn open(path: &Path) -> Result<Self, StoreError> {
        let path = path.to_owned();
        Self::open_with(move || {
            let conn = Connection::open(&path).map_err(backend)?;
            let mode: String = conn
                .pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))
                .map_err(backend)?;
            if !mode.eq_ignore_ascii_case("wal") {
                return Err(StoreError::Backend(format!(
                    "could not enable WAL mode (journal_mode is {mode})"
                )));
            }
            Ok(conn)
        })
        .await
    }

    /// Opens a private in-memory database, for tests.
    pub async fn open_memory() -> Result<Self, StoreError> {
        Self::open_with(|| Connection::open_in_memory().map_err(backend)).await
    }

    async fn open_with<F>(connect: F) -> Result<Self, StoreError>
    where
        F: FnOnce() -> Result<Connection, StoreError> + Send + 'static,
    {
        let conn = tokio::task::spawn_blocking(move || {
            let mut conn = connect()?;
            conn.pragma_update(None, "foreign_keys", "ON")
                .map_err(backend)?;
            conn.busy_timeout(Duration::from_millis(5000))
                .map_err(backend)?;
            conn.pragma_update(None, "synchronous", "FULL")
                .map_err(backend)?;
            schema::migrate(&mut conn)?;
            Ok::<_, StoreError>(conn)
        })
        .await
        .map_err(backend)??;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Runs `work` on the blocking pool with exclusive use of the connection.
    fn run<T, F>(&self, work: F) -> impl Future<Output = Result<T, StoreError>> + Send + 'static
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T, StoreError> + Send + 'static,
    {
        let conn = Arc::clone(&self.conn);
        async move {
            tokio::task::spawn_blocking(move || {
                let mut conn = conn.lock().map_err(|_| {
                    StoreError::Backend("database connection mutex poisoned".into())
                })?;
                work(&mut conn)
            })
            .await
            .map_err(backend)?
        }
    }
}

impl Store for SqliteStore {
    fn post(&self, msg: NewMessage) -> impl Future<Output = Result<Posted, StoreError>> + Send {
        self.run(move |conn| posts::post(conn, msg))
    }

    fn verify_chain(
        &self,
        board: &BoardId,
    ) -> impl Future<Output = Result<ChainReport, StoreError>> + Send {
        let board = board.clone();
        self.run(move |conn| posts::verify_chain(conn, &board))
    }

    fn read_channel(
        &self,
        board: &BoardId,
        prefix: &ChannelPath,
        page: Page,
    ) -> impl Future<Output = Result<Vec<ThreadSummary>, StoreError>> + Send {
        let (board, prefix) = (board.clone(), prefix.clone());
        self.run(move |conn| reads::read_channel(conn, &board, &prefix, &page))
    }

    fn read_thread(
        &self,
        board: &BoardId,
        thread: &MessageId,
    ) -> impl Future<Output = Result<Thread, StoreError>> + Send {
        let (board, thread) = (board.clone(), thread.clone());
        self.run(move |conn| reads::read_thread(conn, &board, &thread))
    }
}

/// Wraps a database or runtime failure as a backend error.
pub(crate) fn backend(err: impl Display) -> StoreError {
    StoreError::Backend(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use stigmer_core::GENESIS_HASH;

    fn query<T: rusqlite::types::FromSql>(store: &SqliteStore, sql: &str) -> T {
        let conn = store.conn.lock().unwrap();
        conn.query_row(sql, [], |row| row.get(0)).unwrap()
    }

    fn board_head(store: &SqliteStore) -> (i64, String) {
        let conn = store.conn.lock().unwrap();
        conn.query_row(
            "SELECT head_seq, head_hash FROM boards WHERE id = ?1",
            [BoardId::main().as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn open_memory_migrates_and_creates_main_board() {
        let store = SqliteStore::open_memory().await.unwrap();
        let version: i64 = query(&store, "PRAGMA user_version");
        assert_eq!(version, schema::MIGRATIONS.len() as i64);
        assert_eq!(board_head(&store), (0, GENESIS_HASH.to_owned()));
        let foreign_keys: i64 = query(&store, "PRAGMA foreign_keys");
        assert_eq!(foreign_keys, 1);
    }

    #[tokio::test]
    async fn reopening_a_file_keeps_schema_and_single_main_board() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("board.db");
        drop(SqliteStore::open(&path).await.unwrap());
        let store = SqliteStore::open(&path).await.unwrap();
        let version: i64 = query(&store, "PRAGMA user_version");
        assert_eq!(version, schema::MIGRATIONS.len() as i64);
        let boards: i64 = query(&store, "SELECT COUNT(*) FROM boards");
        assert_eq!(boards, 1);
        assert_eq!(board_head(&store), (0, GENESIS_HASH.to_owned()));
        let mode: String = query(&store, "PRAGMA journal_mode");
        assert_eq!(mode, "wal");
        let synchronous: i64 = query(&store, "PRAGMA synchronous");
        assert_eq!(synchronous, 2, "FULL");
        let busy: i64 = query(&store, "PRAGMA busy_timeout");
        assert_eq!(busy, 5000);
    }

    #[tokio::test]
    async fn open_refuses_a_schema_newer_than_this_build() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("board.db");
        drop(SqliteStore::open(&path).await.unwrap());
        rusqlite::Connection::open(&path)
            .unwrap()
            .pragma_update(None, "user_version", 99)
            .unwrap();
        let err = SqliteStore::open(&path).await.err().unwrap();
        assert!(matches!(err, StoreError::Backend(_)), "{err:?}");
    }
}
