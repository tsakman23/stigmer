//! Migrations: idempotent, recorded in `schema_version`, and the schema state they leave.

use stigmer_store_postgres::testing::{database_url, TestSchema};
use stigmer_store_postgres::{MigrationReport, PgStore, SchemaState};

const LATEST: u32 = 8;

async fn versions(schema: &TestSchema) -> Vec<i32> {
    let client = schema.client().await.unwrap();
    let rows = client
        .query("SELECT version FROM schema_version ORDER BY version", &[])
        .await
        .unwrap();
    rows.iter().map(|row| row.get(0)).collect()
}

#[tokio::test]
async fn migrate_is_idempotent_and_records_schema_version() {
    let Some(url) = database_url("migrate_is_idempotent_and_records_schema_version").unwrap()
    else {
        return;
    };
    let schema = TestSchema::create(&url).await.unwrap();
    let store = PgStore::connect(schema.url(), schema.options())
        .await
        .unwrap();

    let first = store.migrate().await.unwrap();
    assert_eq!(
        first,
        MigrationReport {
            from: 0,
            to: LATEST
        }
    );
    assert_eq!(first.applied(), LATEST);
    assert_eq!(versions(&schema).await, (1..=8).collect::<Vec<i32>>());

    let again = store.migrate().await.unwrap();
    assert_eq!(
        again,
        MigrationReport {
            from: LATEST,
            to: LATEST
        }
    );
    assert_eq!(again.applied(), 0);
    assert_eq!(versions(&schema).await, (1..=8).collect::<Vec<i32>>());

    let client = schema.client().await.unwrap();
    let boards: i64 = client
        .query_one("SELECT COUNT(*) FROM boards WHERE id = 'main'", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(boards, 1, "main exists once");
    let tables: i64 = client
        .query_one(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = $1",
            &[&schema.name()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        tables, 11,
        "ten tables and schema_version, all in the test schema"
    );

    // Two handles migrating at once: one applies, neither fails, nothing is applied twice.
    let fresh = TestSchema::create(&url).await.unwrap();
    let (a, b) = (
        PgStore::connect(fresh.url(), fresh.options())
            .await
            .unwrap(),
        PgStore::connect(fresh.url(), fresh.options())
            .await
            .unwrap(),
    );
    let (ra, rb) = tokio::join!(a.migrate(), b.migrate());
    let mut applied = [ra.unwrap().applied(), rb.unwrap().applied()];
    applied.sort_unstable();
    assert_eq!(applied, [0, LATEST]);
    assert_eq!(versions(&fresh).await, (1..=8).collect::<Vec<i32>>());
}

#[tokio::test]
async fn schema_state_reports_behind_and_ahead() {
    let Some(url) = database_url("schema_state_reports_behind_and_ahead").unwrap() else {
        return;
    };
    let schema = TestSchema::create(&url).await.unwrap();
    let store = PgStore::connect(schema.url(), schema.options())
        .await
        .unwrap();
    assert_eq!(
        store.schema_state().await.unwrap(),
        SchemaState::Behind {
            have: 0,
            need: LATEST
        },
        "an empty schema"
    );

    store.migrate().await.unwrap();
    assert_eq!(store.schema_state().await.unwrap(), SchemaState::Current);

    let client = schema.client().await.unwrap();
    client
        .batch_execute("INSERT INTO schema_version (version) VALUES (9), (10)")
        .await
        .unwrap();
    assert_eq!(
        store.schema_state().await.unwrap(),
        SchemaState::Ahead {
            have: 10,
            need: LATEST
        }
    );
    let err = store.migrate().await.unwrap_err();
    assert!(err.to_string().contains("older than the database"), "{err}");
    assert_eq!(
        store.schema_state().await.unwrap(),
        SchemaState::Ahead {
            have: 10,
            need: LATEST
        },
        "a refused migrate changes nothing"
    );

    client
        .batch_execute("DELETE FROM schema_version WHERE version > 5")
        .await
        .unwrap();
    assert_eq!(
        store.schema_state().await.unwrap(),
        SchemaState::Behind {
            have: 5,
            need: LATEST
        }
    );
}
