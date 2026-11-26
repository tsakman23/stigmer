//! Migration 8: the thread summary table, its backfill and the write path that maintains it.

use rusqlite::Connection;
use stigmer_core::{
    event_hash, BoardId, ChannelPath, EventKind, HashInput, MessageId, NewMessage, Principal,
    Target, GENESIS_HASH,
};
use stigmer_store::Store;

use super::{insert_thread, record_reply};
use crate::schema::MIGRATIONS;
use crate::SqliteStore;

/// One summary row, every column, in table order.
type Row = (String, String, String, String, i64, i64, i64, i64);

/// One message of a test history, posted with the given time.
struct Post {
    board: &'static str,
    /// The channel of a new thread; ignored for a reply.
    channel: &'static str,
    /// The index (in the history) of the thread root this replies to.
    reply_to: Option<usize>,
    text: String,
    at_ms: i64,
}

fn post(board: &'static str, channel: &'static str, text: &str, at_ms: i64) -> Post {
    Post {
        board,
        channel,
        reply_to: None,
        text: text.to_owned(),
        at_ms,
    }
}

fn reply(board: &'static str, to: usize, text: &str, at_ms: i64) -> Post {
    Post {
        board,
        channel: "",
        reply_to: Some(to),
        text: text.to_owned(),
        at_ms,
    }
}

/// Three boards (one archived once its messages are in), tied and backwards clocks, a long multi-byte root and a thread with no replies.
fn history() -> Vec<Post> {
    vec![
        post("main", "eng", &"\u{e9}".repeat(250), 1_000),
        post("main", "eng/ops", "tied with the first", 1_000),
        reply("main", 0, "the clock stepped back", 900),
        post("other", "eng", "other board", 1_100),
        post("main", "sales", "never answered", 1_200),
        reply("main", 1, "tied again", 1_000),
        reply("other", 3, "answer on other", 1_300),
        reply("main", 0, "latest", 1_500),
        reply("main", 0, "earlier than the one before", 1_400),
        post("old", "eng", "on a board archived later", 1_600),
        reply("old", 9, "last word before the archive", 1_700),
    ]
}

/// Writes `posts` as the post path stores them: message row, event row and board head, with a
/// valid hash chain per board. With `summaries`, also calls the summary write path, as the
/// current `post` does; without, the rows are exactly what a v7 `post` wrote.
fn write_history(conn: &Connection, posts: &[Post], ids: &[MessageId], summaries: bool) {
    let author = Principal::new("alice").unwrap();
    for (i, p) in posts.iter().enumerate() {
        let board = BoardId::new(p.board).unwrap();
        let id = &ids[i];
        let (thread_id, channel, kind) = match p.reply_to {
            None => (
                id.clone(),
                ChannelPath::new(p.channel).unwrap(),
                EventKind::ThreadCreated,
            ),
            Some(root) => (
                ids[root].clone(),
                ChannelPath::new(posts[root].channel).unwrap(),
                EventKind::MessageReplied,
            ),
        };
        let (head_seq, head_hash): (i64, String) = conn
            .query_row(
                "SELECT head_seq, head_hash FROM boards WHERE id = ?1",
                [p.board],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let seq = head_seq + 1;
        let hash = event_hash(&HashInput {
            prev: &head_hash,
            seq: u64::try_from(seq).unwrap(),
            kind,
            actor: &author,
            message_id: id,
            thread_id: &thread_id,
            channel: &channel,
            at_ms: p.at_ms,
        });
        conn.execute(
            "INSERT INTO messages (id, board_id, channel, thread_id, author, text, at_ms)
             VALUES (?1, ?2, ?3, ?4, 'alice', ?5, ?6)",
            (
                id.as_str(),
                p.board,
                channel.as_str(),
                thread_id.as_str(),
                &p.text,
                p.at_ms,
            ),
        )
        .unwrap();
        conn.execute(
            "INSERT INTO events
                 (board_id, seq, kind, actor, message_id, thread_id, channel, at_ms, hash)
             VALUES (?1, ?2, ?3, 'alice', ?4, ?5, ?6, ?7, ?8)",
            (
                p.board,
                seq,
                kind.as_str(),
                id.as_str(),
                thread_id.as_str(),
                channel.as_str(),
                p.at_ms,
                &hash,
            ),
        )
        .unwrap();
        if summaries {
            match p.reply_to {
                None => {
                    insert_thread(conn, &board, id, &channel, &p.text, seq, p.at_ms).unwrap();
                }
                Some(_) => record_reply(conn, &board, &thread_id, seq, p.at_ms).unwrap(),
            }
        }
        conn.execute(
            "UPDATE boards SET head_seq = ?1, head_hash = ?2 WHERE id = ?3",
            (seq, &hash, p.board),
        )
        .unwrap();
    }
}

fn add_boards(conn: &Connection) {
    for board in ["main", "other", "old"] {
        conn.execute(
            "INSERT INTO boards (id, head_seq, head_hash) VALUES (?1, 0, ?2)",
            (board, GENESIS_HASH),
        )
        .unwrap();
    }
}

/// Archives board `old`, after its messages were written (a post cannot reach it once archived).
fn archive_old(conn: &Connection) {
    conn.execute(
        "UPDATE boards SET archived_at_ms = 2000 WHERE id = 'old'",
        [],
    )
    .unwrap();
}

fn summaries(conn: &Connection) -> Vec<Row> {
    let mut stmt = conn
        .prepare(
            "SELECT board_id, thread_id, channel, preview, reply_count, first_seq, last_seq,
                    last_at_ms
               FROM threads ORDER BY board_id, thread_id",
        )
        .unwrap();
    stmt.query_map([], |r| {
        Ok((
            r.get(0)?,
            r.get(1)?,
            r.get(2)?,
            r.get(3)?,
            r.get(4)?,
            r.get(5)?,
            r.get(6)?,
            r.get(7)?,
        ))
    })
    .unwrap()
    .collect::<Result<_, _>>()
    .unwrap()
}

#[tokio::test]
async fn v7_database_backfills_threads_and_matches_the_new_write_path() {
    let posts = history();
    let ids: Vec<MessageId> = posts
        .iter()
        .map(|_| MessageId::generate().unwrap())
        .collect();

    // A v7 database built by the real migrations 1 to 7, holding what v7 `post` wrote.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("board.db");
    {
        let conn = Connection::open(&path).unwrap();
        for sql in &MIGRATIONS[..7] {
            conn.execute_batch(sql).unwrap();
        }
        conn.pragma_update(None, "user_version", 7).unwrap();
        add_boards(&conn);
        write_history(&conn, &posts, &ids, false);
        archive_old(&conn);
    }
    let store = SqliteStore::open(&path).await.unwrap();
    let upgraded = summaries(&Connection::open(&path).unwrap());

    // The same messages, with the same ids and times, written by the new path.
    let fresh = Connection::open_in_memory().unwrap();
    for sql in MIGRATIONS {
        fresh.execute_batch(sql).unwrap();
    }
    add_boards(&fresh);
    write_history(&fresh, &posts, &ids, true);
    archive_old(&fresh);
    let replayed = summaries(&fresh);

    assert_eq!(upgraded, replayed);
    assert_eq!(upgraded.len(), 5, "one row per thread root");
    let archived = upgraded
        .iter()
        .find(|row| row.1 == ids[9].as_str())
        .unwrap();
    assert_eq!(
        (
            archived.0.as_str(),
            archived.4,
            archived.5,
            archived.6,
            archived.7
        ),
        ("old", 1, 1, 2, 1_700),
        "an archived board's threads are backfilled too"
    );
    let first = upgraded
        .iter()
        .find(|row| row.1 == ids[0].as_str())
        .unwrap();
    let expected = (
        "main".to_owned(),
        ids[0].as_str().to_owned(),
        "eng".to_owned(),
        "\u{e9}".repeat(200),
        3,
        1,
        7,
        1_400,
    );
    assert_eq!(
        *first, expected,
        "last_at_ms is the time of the latest message by sequence, even when it is earlier"
    );

    // The upgraded store keeps posting into the backfilled summaries.
    let answer = store
        .post(
            NewMessage::new(
                BoardId::main(),
                Target::Reply {
                    thread: ids[4].clone(),
                },
                Principal::new("bob").unwrap(),
                "finally".to_owned(),
                vec![],
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let after = summaries(&Connection::open(&path).unwrap());
    let sales = after.iter().find(|row| row.1 == ids[4].as_str()).unwrap();
    assert_eq!((sales.4, sales.5, sales.6), (1, 4, 8));
    assert_eq!(sales.7, answer.message.at_ms);
}

#[tokio::test]
async fn backfill_of_posted_messages_equals_what_post_wrote() {
    let store = SqliteStore::open_memory().await.unwrap();
    let alice = Principal::new("alice").unwrap();
    let message = |target: Target, text: &str, key: Option<&str>| {
        NewMessage::new(
            BoardId::main(),
            target,
            alice.clone(),
            text.to_owned(),
            vec![],
            key.map(str::to_owned),
        )
        .unwrap()
    };
    let new_thread = |channel: &str| Target::NewThread {
        channel: ChannelPath::new(channel).unwrap(),
    };
    let to = |thread: &MessageId| Target::Reply {
        thread: thread.clone(),
    };
    let a = store
        .post(message(new_thread("eng"), &"x".repeat(300), None))
        .await
        .unwrap();
    let b = store
        .post(message(new_thread("eng/ops"), "b", Some("k1")))
        .await
        .unwrap();
    store
        .post(message(to(&a.message.id), "r1", Some("k2")))
        .await
        .unwrap();
    let replay = store
        .post(message(to(&a.message.id), "r1", Some("k2")))
        .await
        .unwrap();
    assert!(replay.replayed);
    assert!(
        store
            .post(message(new_thread("eng/ops"), "b", Some("k1")))
            .await
            .unwrap()
            .replayed
    );
    store
        .post(message(to(&b.message.id), "r2", None))
        .await
        .unwrap();
    store
        .post(message(to(&a.message.id), "r3", None))
        .await
        .unwrap();
    let unknown = MessageId::generate().unwrap();
    assert!(store
        .post(message(to(&unknown), "lost", None))
        .await
        .is_err());

    let conn = store.conn.lock().unwrap();
    let written = summaries(&conn);
    conn.execute_batch("DROP TABLE threads").unwrap();
    conn.execute_batch(MIGRATIONS[7]).unwrap();
    assert_eq!(summaries(&conn), written);
    let replies: i64 = written.iter().map(|row| row.4).sum();
    assert_eq!(replies, 3, "replays and refusals add nothing");
}

#[tokio::test]
async fn read_channel_orders_by_sequence_when_the_clock_steps_back() {
    let store = SqliteStore::open_memory().await.unwrap();
    let post = |text: &str| {
        NewMessage::new(
            BoardId::main(),
            Target::NewThread {
                channel: ChannelPath::new("eng").unwrap(),
            },
            Principal::new("alice").unwrap(),
            text.to_owned(),
            vec![],
            None,
        )
        .unwrap()
    };
    let older = store.post(post("older")).await.unwrap().message.id;
    let newer = store.post(post("newer")).await.unwrap().message.id;
    {
        // The second post was stamped by a clock that had stepped back an hour.
        let conn = store.conn.lock().unwrap();
        conn.execute(
            "UPDATE messages SET at_ms = at_ms - 3600000 WHERE id = ?1",
            [newer.as_str()],
        )
        .unwrap();
        conn.execute(
            "UPDATE threads SET last_at_ms = last_at_ms - 3600000 WHERE thread_id = ?1",
            [newer.as_str()],
        )
        .unwrap();
    }
    let page = stigmer_store::Page {
        limit: 10,
        before: None,
    };
    let listed = store
        .read_channel(&BoardId::main(), &ChannelPath::new("eng").unwrap(), page)
        .await
        .unwrap();
    let ids: Vec<&MessageId> = listed.iter().map(|t| &t.thread_id).collect();
    assert_eq!(ids, vec![&newer, &older], "the later event leads");
    assert!(listed[0].last_at_ms < listed[1].last_at_ms);
}

/// FNV-1a over the shipped migrations, so an edit to any of them fails this test.
fn fingerprint(migrations: &[&str]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in migrations.join("\u{0}").bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

#[test]
fn migration_8_is_appended_not_edited() {
    assert_eq!(MIGRATIONS.len(), 8);
    assert_eq!(
        fingerprint(&MIGRATIONS[..7]),
        SHIPPED_V7_FINGERPRINT,
        "migrations 1 to 7 shipped in v0.2.0 and must not change"
    );
    assert!(MIGRATIONS[7].contains("CREATE TABLE threads"));
}

#[test]
fn migration_files_are_byte_identical_to_the_shipped_sql() {
    assert_eq!(
        fingerprint(MIGRATIONS),
        SHIPPED_V8_FINGERPRINT,
        "migrations 1 to 8 are frozen; add a numbered file instead of editing one"
    );
}

/// `fingerprint(&MIGRATIONS[..7])` as of v0.2.0.
const SHIPPED_V7_FINGERPRINT: u64 = 12_864_702_251_451_237_187;

/// `fingerprint(MIGRATIONS)` when migration 8 was still an inline string; the move to
/// `migrations/*.sql` files left every byte unchanged.
const SHIPPED_V8_FINGERPRINT: u64 = 13_089_949_527_898_416_318;
