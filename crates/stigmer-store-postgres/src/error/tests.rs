use super::*;
use crate::testing::{database_url, TestSchema};

/// Runs `sql` on a fresh, migrated schema after `setup` and returns the mapped error.
async fn violation(client: &tokio_postgres::Client, setup: &str, sql: &str) -> StoreError {
    client.batch_execute(setup).await.unwrap();
    let err = client.batch_execute(sql).await.unwrap_err();
    db(err)
}

#[tokio::test]
async fn sqlstate_23505_maps_to_conflict_kinds() {
    let unique = SqlState::UNIQUE_VIOLATION;
    assert_eq!(
        conflict_kind(&unique, "boards_pkey"),
        Some(ConflictKind::BoardExists)
    );
    assert_eq!(
        conflict_kind(&unique, "principals_pkey"),
        Some(ConflictKind::NameTaken)
    );
    assert_eq!(
        conflict_kind(&unique, "messages_idempotency"),
        Some(ConflictKind::IdempotencyKeyReused)
    );
    assert_eq!(conflict_kind(&unique, "credentials_pkey"), None);
    let other = SqlState::FOREIGN_KEY_VIOLATION;
    assert_eq!(conflict_kind(&other, "boards_pkey"), None);

    // The same mapping on the errors the real schema raises.
    let Some(url) = database_url("sqlstate_23505_maps_to_conflict_kinds").unwrap() else {
        return;
    };
    let schema = TestSchema::create(&url).await.unwrap();
    let store = crate::PgStore::connect(schema.url(), schema.options())
        .await
        .unwrap();
    store.migrate().await.unwrap();
    let client = schema.client().await.unwrap();

    let main_again = "INSERT INTO boards (id, head_seq, head_hash) VALUES ('main', 0, decode(repeat('00', 32), 'hex'))";
    assert_eq!(
        violation(&client, "", main_again).await,
        StoreError::Conflict(ConflictKind::BoardExists)
    );
    let member = "INSERT INTO principals (board_id, name, kind, role, created_at_ms)
                  VALUES ('main', 'alice', 'human', 'member', 1)";
    assert_eq!(
        violation(&client, member, member).await,
        StoreError::Conflict(ConflictKind::NameTaken)
    );
    let keyed = |id: &str| {
        format!(
            "INSERT INTO messages (id, board_id, channel, thread_id, author, text, at_ms,
                                   idempotency_key)
             VALUES ('{id}', 'main', 'eng', '{id}', 'alice', 'hi', 1, 'req-1')"
        )
    };
    assert_eq!(
        violation(&client, &keyed("msg_a"), &keyed("msg_b")).await,
        StoreError::Conflict(ConflictKind::IdempotencyKeyReused)
    );
    let unmapped = "INSERT INTO instance (id, mode) VALUES (1, 'local')";
    assert!(matches!(
        violation(&client, "", unmapped).await,
        StoreError::Backend(_)
    ));
}
