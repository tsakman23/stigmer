use stigmer_core::{ChannelPath, Principal, Target};
use stigmer_store::ChainReport;

use super::*;
use crate::testing::{database_url, TestSchema};
use crate::PgStore;

fn new_thread(text: &str) -> NewMessage {
    let channel = ChannelPath::new("eng").unwrap();
    let author = Principal::new("alice").unwrap();
    let target = Target::NewThread { channel };
    NewMessage::new(
        BoardId::main(),
        target,
        author,
        text.to_owned(),
        vec![],
        None,
    )
    .unwrap()
}

async fn count(client: &tokio_postgres::Client, table: &str) -> i64 {
    let sql = format!("SELECT COUNT(*) FROM {table}");
    client.query_one(&sql, &[]).await.unwrap().get(0)
}

#[tokio::test]
async fn rolled_back_post_consumes_no_sequence_number() {
    let Some(url) = database_url("rolled_back_post_consumes_no_sequence_number").unwrap() else {
        return;
    };
    let schema = TestSchema::create(&url).await.unwrap();
    let store = PgStore::connect(schema.url(), schema.options())
        .await
        .unwrap();
    store.migrate().await.unwrap();
    let client = schema.client().await.unwrap();
    let main = BoardId::main();

    let first = post(&store.pool, new_thread("one")).await.unwrap();
    assert_eq!(first.event.seq, 1);

    // The head update is the post's last write: fail the transaction right after it.
    client
        .batch_execute(
            "CREATE FUNCTION refuse_head() RETURNS trigger LANGUAGE plpgsql AS $$
             BEGIN RAISE EXCEPTION 'injected failure after the head update'; END $$;
             CREATE TRIGGER refuse_head AFTER UPDATE OF head_seq ON boards
             FOR EACH ROW EXECUTE FUNCTION refuse_head();",
        )
        .await
        .unwrap();
    let failed = post(&store.pool, new_thread("two")).await;
    let Err(StoreError::Backend(text)) = failed else {
        panic!("the injected failure fails the post: {failed:?}");
    };
    assert!(text.contains("injected failure"), "{text}");
    for table in ["messages", "events", "threads"] {
        assert_eq!(count(&client, table).await, 1, "{table}: nothing kept");
    }
    let head: i64 = client
        .query_one("SELECT head_seq FROM boards WHERE id = 'main'", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(head, 1, "the head did not move");

    client
        .batch_execute("DROP TRIGGER refuse_head ON boards")
        .await
        .unwrap();
    let next = post(&store.pool, new_thread("three")).await.unwrap();
    assert_eq!(next.event.seq, 2, "the failed post used no sequence number");
    let report = crate::chain::verify_chain(&store.pool, &main)
        .await
        .unwrap();
    assert_eq!(
        report,
        ChainReport {
            valid: true,
            checked: 2,
            first_bad_seq: None,
        }
    );
}
