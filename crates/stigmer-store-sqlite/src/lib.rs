//! stigmer-store-sqlite: the SQLite backend for `Store`.
//!
//! One connection behind a mutex; every database call runs on tokio's blocking pool.

mod boards;
mod credentials;
mod events;
mod identity;
mod members;
mod notify;
mod posts;
mod reads;
mod schema;

use std::fmt::Display;
use std::future::Future;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::Connection;
use stigmer_core::{BoardId, ChannelPath, Cursor, Event, MessageId, NewMessage, Principal};
use stigmer_store::{
    BoardInfo, ChainReport, Entity, EventFilter, Page, Posted, Store, StoreError, Thread,
    ThreadSummary,
};

/// A `Store` backed by one SQLite database.
pub struct SqliteStore {
    conn: Arc<Mutex<Connection>>,
    notifier: Arc<notify::Notifier>,
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
            notifier: Arc::new(notify::Notifier::default()),
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
    fn create_board(
        &self,
        id: &BoardId,
        created_by: Option<&Principal>,
    ) -> impl Future<Output = Result<BoardInfo, StoreError>> + Send {
        let (id, created_by) = (id.clone(), created_by.cloned());
        self.run(move |conn| boards::create(conn, &id, created_by.as_ref()))
    }

    fn get_board(
        &self,
        id: &BoardId,
    ) -> impl Future<Output = Result<BoardInfo, StoreError>> + Send {
        let id = id.clone();
        self.run(move |conn| boards::get(conn, &id))
    }

    fn list_boards(&self) -> impl Future<Output = Result<Vec<BoardInfo>, StoreError>> + Send {
        self.run(boards::list)
    }

    fn archive_board(
        &self,
        id: &BoardId,
    ) -> impl Future<Output = Result<BoardInfo, StoreError>> + Send {
        let id = id.clone();
        let notifier = Arc::clone(&self.notifier);
        self.run(move |conn| {
            let info = boards::archive(conn, &id)?;
            // Under the connection lock, like the subscription in `wait_past`.
            notifier.forget(&id);
            Ok(info)
        })
    }

    fn post(&self, msg: NewMessage) -> impl Future<Output = Result<Posted, StoreError>> + Send {
        let notifier = Arc::clone(&self.notifier);
        self.run(move |conn| {
            let posted = posts::post(conn, msg)?;
            // Only a new event moves the head; a replay wrote nothing.
            if !posted.replayed {
                notifier.bump(&posted.message.board, posted.event.seq);
            }
            Ok(posted)
        })
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

    fn events_after(
        &self,
        board: &BoardId,
        after: Option<&Cursor>,
        filter: &EventFilter,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<Event>, StoreError>> + Send {
        let (board, after, filter) = (board.clone(), after.cloned(), filter.clone());
        self.run(move |conn| events::events_after(conn, &board, after.as_ref(), &filter, limit))
    }

    fn head(
        &self,
        board: &BoardId,
    ) -> impl Future<Output = Result<Option<Cursor>, StoreError>> + Send {
        let board = board.clone();
        self.run(move |conn| events::head(conn, &board))
    }

    fn wait_past(
        &self,
        board: &BoardId,
        after: Option<&Cursor>,
        timeout: Duration,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send {
        let (board, after) = (board.clone(), after.cloned());
        let notifier = Arc::clone(&self.notifier);
        // Lazy: the database read starts only when polled, after the cursor has been decoded.
        let read_and_subscribe = self.run(move |conn| {
            let (head, archived) = events::head_state(conn, &board)?;
            // Still holding the connection: `post` commits and bumps under the same lock, so no
            // commit can land between this read and the subscription. Only a live board gets an
            // entry: an unknown board failed above, and an archived board's head cannot move.
            let head_rx = (!archived).then(|| notifier.subscribe(&board));
            Ok((head, head_rx))
        });
        async move {
            let after_seq = events::cursor_seq(after.as_ref())?;
            let (head, head_rx) = read_and_subscribe.await?;
            if after_seq > head {
                return Err(StoreError::InvalidCursor);
            }
            if head > after_seq {
                return Ok(true);
            }
            let moved_past = async {
                let Some(mut head_rx) = head_rx else {
                    return std::future::pending().await;
                };
                loop {
                    if *head_rx.borrow_and_update() > after_seq {
                        return true;
                    }
                    if head_rx.changed().await.is_err() {
                        // The board was archived during the wait: its head can no longer move.
                        return std::future::pending().await;
                    }
                }
            };
            // No spawned task: dropping this future drops the receiver and the timer with it.
            Ok(tokio::time::timeout(timeout, moved_past)
                .await
                .unwrap_or(false))
        }
    }
}

/// A `NotFound` error for the `entity` named by `id`.
pub(crate) fn not_found(entity: Entity, id: impl Display) -> StoreError {
    StoreError::NotFound {
        entity,
        id: id.to_string(),
    }
}

/// Wall-clock time in milliseconds since the Unix epoch: the one clock for post and board times.
pub(crate) fn now_ms() -> Result<i64, StoreError> {
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(backend)?;
    i64::try_from(since_epoch.as_millis()).map_err(backend)
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
        let main = store.get_board(&BoardId::main()).await.unwrap();
        assert!(
            main.created_at_ms > 0,
            "main is stamped when the store opens"
        );
        assert_eq!(main.created_by, None);
    }

    #[tokio::test]
    async fn wait_past_on_unknown_board_leaves_no_notifier_entry() {
        let store = SqliteStore::open_memory().await.unwrap();
        let nowhere = BoardId::new("nowhere").unwrap();
        let result = store
            .wait_past(&nowhere, None, Duration::from_secs(10))
            .await;
        assert!(matches!(
            result,
            Err(StoreError::NotFound {
                entity: Entity::Board,
                ..
            })
        ));
        assert_eq!(store.notifier.entry_count(), 0);
    }

    #[tokio::test]
    async fn archive_drops_the_notifier_entry_and_waits_on_it_time_out() {
        let store = Arc::new(SqliteStore::open_memory().await.unwrap());
        let old = BoardId::new("old").unwrap();
        store.create_board(&old, None).await.unwrap();
        let waiter = {
            let (store, old) = (Arc::clone(&store), old.clone());
            tokio::spawn(async move {
                store
                    .wait_past(&old, None, Duration::from_millis(300))
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(store.notifier.entry_count(), 1, "the waiter subscribed");

        store.archive_board(&old).await.unwrap();
        assert_eq!(store.notifier.entry_count(), 0, "archive drops the entry");
        assert_eq!(
            waiter.await.unwrap(),
            Ok(false),
            "a wait cut short by archive times out as usual"
        );

        let again = store.wait_past(&old, None, Duration::from_millis(20)).await;
        assert_eq!(again, Ok(false));
        assert_eq!(
            store.notifier.entry_count(),
            0,
            "waiting on an archived board subscribes to nothing"
        );
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
    async fn new_posts_are_stored_with_author_kind_local() {
        // alice is not a member of main, so she is a local author.
        let store = SqliteStore::open_memory().await.unwrap();
        let msg = NewMessage::new(
            BoardId::main(),
            stigmer_core::Target::NewThread {
                channel: ChannelPath::new("eng").unwrap(),
            },
            stigmer_core::Principal::new("alice").unwrap(),
            "hello".to_owned(),
            vec![],
            None,
        )
        .unwrap();
        store.post(msg).await.unwrap();
        let kind: String = query(&store, "SELECT author_kind FROM messages");
        assert_eq!(kind, "local");
    }

    #[tokio::test]
    async fn members_posts_are_stored_with_author_kind_principal() {
        use stigmer_store::IdentityStore;
        let store = SqliteStore::open_memory().await.unwrap();
        let alice = stigmer_core::Principal::new("alice").unwrap();
        store
            .add_member(
                &BoardId::main(),
                &alice,
                stigmer_core::PrincipalKind::Agent,
                stigmer_core::Role::Member,
                1,
            )
            .await
            .unwrap();
        for author in [alice.clone(), stigmer_core::Principal::new("zed").unwrap()] {
            let msg = NewMessage::new(
                BoardId::main(),
                stigmer_core::Target::NewThread {
                    channel: ChannelPath::new("eng").unwrap(),
                },
                author,
                "hello".to_owned(),
                vec![],
                None,
            )
            .unwrap();
            store.post(msg).await.unwrap();
        }
        let kind: String = query(
            &store,
            "SELECT author_kind FROM messages WHERE author = 'alice'",
        );
        assert_eq!(kind, "principal");
        let kind: String = query(
            &store,
            "SELECT author_kind FROM messages WHERE author = 'zed'",
        );
        assert_eq!(kind, "local", "a non-member is still a local author");
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
