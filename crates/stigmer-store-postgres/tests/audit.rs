//! Board mutations write their security log row in their own transaction (ADR 0014). The
//! identity conformance suite checks this through `security_log`, which `PgStore` does not
//! offer until it implements `IdentityStore`; until then this test reads the table directly.

use stigmer_core::{BoardId, Principal};
use stigmer_store::{SecurityEvent, SecurityEventKind, Store, StoreError};
use stigmer_store_postgres::testing::{database_url, TestSchema};
use stigmer_store_postgres::PgStore;

const NOW: i64 = 1_700_000_000_000;

fn audit(kind: SecurityEventKind, on: &BoardId, at_ms: i64) -> SecurityEvent {
    SecurityEvent {
        at_ms,
        kind,
        board: Some(on.clone()),
        principal: Some("root".to_owned()),
        detail: format!("{kind} at {at_ms}"),
    }
}

async fn rows(client: &tokio_postgres::Client) -> Vec<SecurityEvent> {
    let rows = client
        .query(
            "SELECT at_ms, kind, board_id, principal, detail FROM security_log ORDER BY id",
            &[],
        )
        .await
        .unwrap();
    rows.iter()
        .map(|row| {
            let kind: &str = row.get(1);
            let board: Option<&str> = row.get(2);
            SecurityEvent {
                at_ms: row.get(0),
                kind: SecurityEventKind::parse(kind).unwrap(),
                board: board.map(|b| BoardId::new(b).unwrap()),
                principal: row.get(3),
                detail: row.get(4),
            }
        })
        .collect()
}

#[tokio::test]
async fn board_mutations_write_their_row_in_their_transaction() {
    let Some(url) = database_url("board_mutations_write_their_row_in_their_transaction").unwrap()
    else {
        return;
    };
    let schema = TestSchema::create(&url).await.unwrap();
    let store = PgStore::connect(schema.url(), schema.options())
        .await
        .unwrap();
    store.migrate().await.unwrap();
    let client = schema.client().await.unwrap();
    let ops = BoardId::new("ops").unwrap();
    let alice = Principal::new("alice").unwrap();

    let created = audit(SecurityEventKind::BoardCreated, &ops, NOW);
    let info = store
        .create_board(&ops, Some(&alice), created.clone())
        .await
        .unwrap();
    assert_eq!(info.created_at_ms, NOW, "stamped with the audit instant");
    let again = audit(SecurityEventKind::BoardCreated, &ops, NOW + 1);
    assert!(store.create_board(&ops, None, again).await.is_err());
    let archived = audit(SecurityEventKind::BoardArchived, &ops, NOW + 2);
    let info = store.archive_board(&ops, archived.clone()).await.unwrap();
    assert_eq!(info.archived_at_ms, Some(NOW + 2));
    let twice = audit(SecurityEventKind::BoardArchived, &ops, NOW + 3);
    let info = store.archive_board(&ops, twice).await.unwrap();
    assert_eq!(
        info.archived_at_ms,
        Some(NOW + 2),
        "first archive time kept"
    );
    assert_eq!(
        rows(&client).await,
        vec![created, archived],
        "one row per change, none for the duplicate or the repeat"
    );

    // A row that cannot be written fails the mutation, which then changes nothing.
    client
        .batch_execute(
            "CREATE FUNCTION refuse_audit() RETURNS trigger LANGUAGE plpgsql AS $$
             BEGIN RAISE EXCEPTION 'injected audit failure'; END $$;
             CREATE TRIGGER refuse_audit BEFORE INSERT ON security_log
             FOR EACH ROW EXECUTE FUNCTION refuse_audit();",
        )
        .await
        .unwrap();
    let new = BoardId::new("new").unwrap();
    let created = audit(SecurityEventKind::BoardCreated, &new, NOW);
    let result = store.create_board(&new, None, created).await;
    assert!(matches!(result, Err(StoreError::Backend(_))), "{result:?}");
    assert!(store.get_board(&new).await.is_err(), "board not created");
    let research = BoardId::new("research").unwrap();
    client
        .batch_execute("DROP TRIGGER refuse_audit ON security_log")
        .await
        .unwrap();
    let created = audit(SecurityEventKind::BoardCreated, &research, NOW);
    store.create_board(&research, None, created).await.unwrap();
    client
        .batch_execute(
            "CREATE TRIGGER refuse_audit BEFORE INSERT ON security_log
             FOR EACH ROW EXECUTE FUNCTION refuse_audit();",
        )
        .await
        .unwrap();
    let archived = audit(SecurityEventKind::BoardArchived, &research, NOW + 5);
    let result = store.archive_board(&research, archived).await;
    assert!(matches!(result, Err(StoreError::Backend(_))), "{result:?}");
    let info = store.get_board(&research).await.unwrap();
    assert_eq!(info.archived_at_ms, None, "board not archived");
    assert_eq!(
        rows(&client).await.len(),
        3,
        "no row from the failed mutations"
    );
}
