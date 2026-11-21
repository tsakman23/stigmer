//! The hash chain catches edits made behind the store's back.

use stigmer_core::{BoardId, ChannelPath, NewMessage, Principal, Target};
use stigmer_store::{ChainReport, Store};
use stigmer_store_sqlite::SqliteStore;

fn new_thread(text: &str) -> NewMessage {
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
}

/// Opens a file-backed store in `dir` holding four valid events.
async fn store_with_four_events(dir: &tempfile::TempDir) -> SqliteStore {
    let store = SqliteStore::open(&dir.path().join("board.db"))
        .await
        .unwrap();
    for text in ["one", "two", "three", "four"] {
        store.post(new_thread(text)).await.unwrap();
    }
    assert!(store.verify_chain(&BoardId::main()).await.unwrap().valid);
    store
}

/// Edits the database directly, behind the store's back.
fn tamper(dir: &tempfile::TempDir, sql: &str, params: impl rusqlite::Params) -> usize {
    rusqlite::Connection::open(dir.path().join("board.db"))
        .unwrap()
        .execute(sql, params)
        .unwrap()
}

#[tokio::test]
async fn chain_detects_tampering() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_with_four_events(&dir).await;
    let board = BoardId::main();

    let changed = tamper(
        &dir,
        "UPDATE events SET hash = ?1 WHERE board_id = 'main' AND seq = 3",
        ["f".repeat(64)],
    );
    assert_eq!(changed, 1);

    assert_eq!(
        store.verify_chain(&board).await.unwrap(),
        ChainReport {
            valid: false,
            checked: 3,
            first_bad_seq: Some(3),
        }
    );
}

#[tokio::test]
async fn chain_detects_a_deleted_last_event() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_with_four_events(&dir).await;

    let changed = tamper(
        &dir,
        "DELETE FROM events WHERE board_id = 'main' AND seq = 4",
        [],
    );
    assert_eq!(changed, 1);

    assert_eq!(
        store.verify_chain(&BoardId::main()).await.unwrap(),
        ChainReport {
            valid: false,
            checked: 3,
            first_bad_seq: Some(4),
        }
    );
}
