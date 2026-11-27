//! Postgres-only identity checks: what the database actually holds for secrets, and how an
//! unknown invite id is refused.

use stigmer_core::{
    generate_secret, parse_secret, BoardId, Principal, PrincipalKind, Role, SecretKind, TokenId,
};
use stigmer_store::{
    CredentialScope, EnableAudits, Entity, IdentityStore, NewCredential, NewInvite,
    NewJoinCredential, SecurityEvent, SecurityEventKind, StoreError,
};
use stigmer_store_postgres::testing::{database_url, TestSchema};
use stigmer_store_postgres::PgStore;

const NOW: i64 = 1_700_000_000_000;

fn audit(kind: SecurityEventKind, at_ms: i64) -> SecurityEvent {
    SecurityEvent {
        at_ms,
        kind,
        board: None,
        principal: Some("root".to_owned()),
        detail: format!("{kind} at {at_ms}"),
    }
}

fn name(raw: &str) -> Principal {
    Principal::new(raw).unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn instance_credential() -> NewCredential {
    let secret = generate_secret(SecretKind::Token).unwrap();
    NewCredential {
        id: secret.id,
        secret_hash: secret.hash,
        scope: CredentialScope::Instance,
        principal: name("instance-admin"),
        expires_at_ms: NOW + 1_000_000,
    }
}

fn join_credential() -> NewJoinCredential {
    let secret = generate_secret(SecretKind::Token).unwrap();
    NewJoinCredential {
        id: secret.id,
        secret_hash: secret.hash,
        expires_at_ms: NOW + 1_000_000,
    }
}

fn new_invite(id: &TokenId, hash: [u8; 32]) -> NewInvite {
    NewInvite {
        id: id.clone(),
        secret_hash: hash,
        board: BoardId::main(),
        role: Role::Member,
        kind: PrincipalKind::Agent,
        created_by: name("root"),
        expires_at_ms: NOW + 1_000_000,
    }
}

async fn store_on(schema: &TestSchema) -> PgStore {
    let store = PgStore::connect(schema.url(), schema.options())
        .await
        .unwrap();
    store.migrate().await.unwrap();
    store
}

#[tokio::test]
async fn secret_hashes_stored_as_32_byte_bytea_only() {
    const TEST: &str = "secret_hashes_stored_as_32_byte_bytea_only";
    let Some(url) = database_url(TEST).unwrap() else {
        return;
    };
    let schema = TestSchema::create(&url).await.unwrap();
    let store = store_on(&schema).await;
    let client = schema.client().await.unwrap();

    // Every way a secret hash reaches the store: an instance credential and an invite through
    // enable_network, a board credential, another invite, and the credential a join creates.
    let instance = instance_credential();
    let first_invite = generate_secret(SecretKind::Invite).unwrap();
    let audits = EnableAudits {
        mode: audit(SecurityEventKind::ModeEnabled, NOW),
        token: audit(SecurityEventKind::InstanceTokenIssued, NOW),
    };
    let with_invite = (
        new_invite(&first_invite.id, first_invite.hash),
        audit(SecurityEventKind::InviteCreated, NOW),
    );
    store
        .enable_network(instance.clone(), Some(with_invite), audits)
        .await
        .unwrap();
    let token = generate_secret(SecretKind::Token).unwrap();
    store
        .create_credential(
            NewCredential {
                id: token.id.clone(),
                secret_hash: token.hash,
                scope: CredentialScope::Board(BoardId::main()),
                principal: name("alice"),
                expires_at_ms: NOW + 1_000_000,
            },
            audit(SecurityEventKind::MemberTokenIssued, NOW),
        )
        .await
        .unwrap();
    let second_invite = generate_secret(SecretKind::Invite).unwrap();
    store
        .create_invite(
            new_invite(&second_invite.id, second_invite.hash),
            audit(SecurityEventKind::InviteCreated, NOW),
        )
        .await
        .unwrap();
    let join = join_credential();
    let join_hash = join.secret_hash;
    store
        .consume_invite(
            &second_invite.id,
            &second_invite.hash,
            &name("dave"),
            NOW,
            join,
        )
        .await
        .unwrap();

    // The only secret columns are the two hashes, both bytea, both checked to 32 bytes.
    let columns = client
        .query(
            "SELECT table_name::text, column_name::text, data_type::text
               FROM information_schema.columns
              WHERE table_schema = current_schema()
                AND (column_name LIKE '%secret%' OR column_name LIKE '%token%')
              ORDER BY 1, 2",
            &[],
        )
        .await
        .unwrap();
    let columns: Vec<(String, String, String)> = columns
        .iter()
        .map(|row| (row.get(0), row.get(1), row.get(2)))
        .collect();
    let bytea = |table: &str| {
        (
            table.to_owned(),
            "secret_hash".to_owned(),
            "bytea".to_owned(),
        )
    };
    assert_eq!(columns, vec![bytea("credentials"), bytea("invites")]);

    // Each stored hash is the 32 bytes the caller gave, and nothing else.
    let mut stored = Vec::new();
    for table in ["credentials", "invites"] {
        let rows = client
            .query(
                &format!(
                    "SELECT id, secret_hash, octet_length(secret_hash) FROM {table} ORDER BY id"
                ),
                &[],
            )
            .await
            .unwrap();
        for row in rows {
            let (id, hash, length): (String, Vec<u8>, i32) = (row.get(0), row.get(1), row.get(2));
            assert_eq!(length, 32, "{table} {id}");
            stored.push((id, hash));
        }
    }
    let mut expected = vec![
        (instance.id.to_string(), instance.secret_hash.to_vec()),
        (token.id.to_string(), token.hash.to_vec()),
        (first_invite.id.to_string(), first_invite.hash.to_vec()),
        (second_invite.id.to_string(), second_invite.hash.to_vec()),
    ];
    let joined = store.list_credentials(&BoardId::main()).await.unwrap();
    let dave = joined.iter().find(|c| c.principal == name("dave")).unwrap();
    assert_eq!(dave.secret_hash, join_hash);
    expected.push((dave.id.to_string(), join_hash.to_vec()));
    stored.sort();
    expected.sort();
    assert_eq!(stored, expected);

    // The database refuses a hash of any other length.
    for table in ["credentials", "invites"] {
        let refused = client
            .execute(
                &format!("UPDATE {table} SET secret_hash = $1"),
                &[&vec![7u8; 31]],
            )
            .await;
        let code = refused.unwrap_err().code().cloned();
        assert_eq!(
            code,
            Some(tokio_postgres::error::SqlState::CHECK_VIOLATION),
            "{table}"
        );
    }

    // No secret, whole or in part, in any table; no hash in the security log.
    for (kind, secret) in [
        (SecretKind::Invite, &first_invite),
        (SecretKind::Token, &token),
        (SecretKind::Invite, &second_invite),
    ] {
        let (_, secret_part) = parse_secret(kind, &secret.full).unwrap();
        for table in ["credentials", "invites", "security_log", "principals"] {
            let rows = client
                .query(&format!("SELECT row_to_json(t)::text FROM {table} t"), &[])
                .await
                .unwrap();
            for row in rows {
                let text: String = row.get(0);
                assert!(!text.contains(&secret.full), "full secret in {table}");
                assert!(!text.contains(&secret_part), "secret part in {table}");
            }
        }
    }
    let log = client
        .query("SELECT row_to_json(t)::text FROM security_log t", &[])
        .await
        .unwrap();
    for row in log {
        let text: String = row.get(0);
        for (n, hash) in expected.iter().map(|(_, hash)| hash).enumerate() {
            assert!(
                !text.contains(&hex(hash)),
                "hash {n} in security_log: {text}"
            );
        }
    }
}

#[tokio::test]
async fn unknown_invite_id_is_refused_exactly_like_a_wrong_secret() {
    const TEST: &str = "unknown_invite_id_is_refused_exactly_like_a_wrong_secret";
    let Some(url) = database_url(TEST).unwrap() else {
        return;
    };
    let schema = TestSchema::create(&url).await.unwrap();
    let store = store_on(&schema).await;
    let invite = generate_secret(SecretKind::Invite).unwrap();
    store
        .create_invite(
            new_invite(&invite.id, invite.hash),
            audit(SecurityEventKind::InviteCreated, NOW),
        )
        .await
        .unwrap();
    let unknown = generate_secret(SecretKind::Invite).unwrap();
    let dave = name("dave");
    let refused = |id: &TokenId| StoreError::NotFound {
        entity: Entity::Invite,
        id: id.to_string(),
    };

    // An unknown id, including with the all-zero hash the store compares unknown ids against.
    for hash in [unknown.hash, [0u8; 32], invite.hash] {
        let result = store
            .consume_invite(&unknown.id, &hash, &dave, NOW, join_credential())
            .await;
        assert_eq!(result, Err(refused(&unknown.id)));
    }
    let wrong = store
        .consume_invite(&invite.id, &unknown.hash, &dave, NOW, join_credential())
        .await;
    assert_eq!(wrong, Err(refused(&invite.id)));
    assert_eq!(store.list_members(&BoardId::main()).await, Ok(Vec::new()));
}
