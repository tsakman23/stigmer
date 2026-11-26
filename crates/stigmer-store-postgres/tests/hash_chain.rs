//! The hash chain is backend-independent: the events Postgres stores verify on SQLite, and both
//! backends return the very same events for them.

use stigmer_core::{
    event_hash, BoardId, ChannelPath, EventFilter, HashInput, Label, NewMessage, Principal, Target,
    GENESIS_HASH,
};
use stigmer_store::{ChainReport, Store};
use stigmer_store_postgres::testing::{database_url, TestSchema};
use stigmer_store_postgres::PgStore;
use stigmer_store_sqlite::SqliteStore;

fn message(target: Target, author: &str, text: &str, labels: Vec<Label>) -> NewMessage {
    let author = Principal::new(author).unwrap();
    NewMessage::new(
        BoardId::main(),
        target,
        author,
        text.to_owned(),
        labels,
        None,
    )
    .unwrap()
}

fn thread_in(channel: &str) -> Target {
    Target::NewThread {
        channel: ChannelPath::new(channel).unwrap(),
    }
}

#[tokio::test]
async fn pg_hash_chain_matches_sqlite_for_the_same_messages() {
    let Some(url) = database_url("pg_hash_chain_matches_sqlite_for_the_same_messages").unwrap()
    else {
        return;
    };
    let schema = TestSchema::create(&url).await.unwrap();
    let pg = PgStore::connect(schema.url(), schema.options())
        .await
        .unwrap();
    pg.migrate().await.unwrap();
    let main = BoardId::main();

    let label = Label::new("kind", "deploy").unwrap();
    let first = pg
        .post(message(thread_in("eng"), "alice", "first", vec![label]))
        .await
        .unwrap();
    let reply = Target::Reply {
        thread: first.message.id.clone(),
    };
    pg.post(message(reply, "bob", "a reply", vec![]))
        .await
        .unwrap();
    let unicode = message(thread_in("ops/deploy"), "carol", "héllo 🚀", vec![]);
    pg.post(unicode).await.unwrap();

    let events = pg
        .events_after(&main, None, &EventFilter::default(), 500)
        .await
        .unwrap();
    assert_eq!(events.len(), 3);
    let valid = ChainReport {
        valid: true,
        checked: 3,
        first_bad_seq: None,
    };
    assert_eq!(pg.verify_chain(&main).await.unwrap(), valid);

    // The stored hashes are the ones the shared hash function gives for the stored fields.
    let mut prev = GENESIS_HASH.to_owned();
    for event in &events {
        let expected = event_hash(&HashInput {
            prev: &prev,
            seq: event.seq,
            kind: event.kind,
            actor: &event.actor,
            message_id: &event.message_id,
            thread_id: &event.thread_id,
            channel: &event.channel,
            at_ms: event.at_ms,
        });
        assert_eq!(event.hash, expected, "event {}", event.seq);
        prev = expected;
    }

    // The same events, written into a SQLite database as they are, verify there too.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("board.db");
    drop(SqliteStore::open(&path).await.unwrap());
    {
        let db = rusqlite::Connection::open(&path).unwrap();
        for e in &events {
            db.execute(
                "INSERT INTO events
                     (board_id, seq, kind, actor, message_id, thread_id, channel, at_ms, hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                (
                    main.as_str(),
                    i64::try_from(e.seq).unwrap(),
                    e.kind.as_str(),
                    e.actor.as_str(),
                    e.message_id.as_str(),
                    e.thread_id.as_str(),
                    e.channel.as_str(),
                    e.at_ms,
                    &e.hash,
                ),
            )
            .unwrap();
        }
        db.execute(
            "UPDATE boards SET head_seq = 3, head_hash = ?1 WHERE id = 'main'",
            [&prev],
        )
        .unwrap();
    }
    let sqlite = SqliteStore::open(&path).await.unwrap();
    assert_eq!(sqlite.verify_chain(&main).await.unwrap(), valid);
    let on_sqlite = sqlite
        .events_after(&main, None, &EventFilter::default(), 500)
        .await
        .unwrap();
    assert_eq!(on_sqlite, events, "both backends return the same events");
    assert_eq!(sqlite.head(&main).await, pg.head(&main).await);
}
