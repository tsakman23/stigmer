//! An idempotency key outlives the process: a retry after reopening the file is a replay.

use stigmer_core::{BoardId, ChannelPath, NewMessage, Principal, Target};
use stigmer_store::Store;
use stigmer_store_sqlite::SqliteStore;

fn keyed_thread() -> NewMessage {
    NewMessage::new(
        BoardId::main(),
        Target::NewThread {
            channel: ChannelPath::new("eng").unwrap(),
        },
        Principal::new("alice").unwrap(),
        "deploy".to_owned(),
        vec![],
        Some("req-1".to_owned()),
    )
    .unwrap()
}

#[tokio::test]
async fn key_survives_reopen_of_the_database() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("board.db");

    let store = SqliteStore::open(&path).await.unwrap();
    let first = store.post(keyed_thread()).await.unwrap();
    assert!(!first.replayed);
    drop(store);

    let store = SqliteStore::open(&path).await.unwrap();
    let retry = store.post(keyed_thread()).await.unwrap();
    assert!(retry.replayed);
    assert_eq!(retry.message, first.message);
    assert_eq!(retry.event, first.event);
    assert_eq!(
        store.verify_chain(&BoardId::main()).await.unwrap().checked,
        1
    );
}
