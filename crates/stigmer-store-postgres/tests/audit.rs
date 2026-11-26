//! A failing audit write rolls its whole mutation back (ADR 0014): with a trigger that refuses
//! security log inserts, each audited mutation fails as a backend error and changes nothing.
//!
//! The rows a successful mutation writes (one per change, none for a duplicate or an idempotent
//! repeat, stamped with the audit instant) are checked by the shared identity conformance
//! scenarios, which run on Postgres; only the injected failure needs the database itself.

use stigmer_core::{BoardId, Principal, PrincipalKind, Role, TokenId};
use stigmer_store::{
    CredentialScope, EnableAudits, IdentityStore, Mode, NewCredential, NewInvite, SecurityEvent,
    SecurityEventKind, Store, StoreError,
};
use stigmer_store_postgres::testing::{database_url, TestSchema};
use stigmer_store_postgres::PgStore;

const NOW: i64 = 1_700_000_000_000;

const REFUSE_EVERY_ROW: &str = "CREATE TRIGGER refuse_audit BEFORE INSERT ON security_log
    FOR EACH ROW EXECUTE FUNCTION refuse_audit()";

fn audit(kind: SecurityEventKind) -> SecurityEvent {
    SecurityEvent {
        at_ms: NOW,
        kind,
        board: None,
        principal: Some("root".to_owned()),
        detail: format!("{kind}"),
    }
}

fn id(n: u8) -> TokenId {
    TokenId::new(&format!("{n:016x}")).unwrap()
}

fn name(raw: &str) -> Principal {
    Principal::new(raw).unwrap()
}

fn credential(n: u8, scope: CredentialScope, who: &str) -> NewCredential {
    NewCredential {
        id: id(n),
        secret_hash: [n; 32],
        scope,
        principal: name(who),
        expires_at_ms: NOW + 1_000_000,
    }
}

fn invite(n: u8, into: &BoardId) -> NewInvite {
    NewInvite {
        id: id(n),
        secret_hash: [n; 32],
        board: into.clone(),
        role: Role::Member,
        kind: PrincipalKind::Agent,
        created_by: name("root"),
        expires_at_ms: NOW + 1_000_000,
    }
}

/// A migrated store on a schema of its own, a plain client on that schema, and the
/// `refuse_audit()` trigger function the tests attach to `security_log`.
async fn setup(url: &str) -> (TestSchema, PgStore, tokio_postgres::Client) {
    let schema = TestSchema::create(url).await.unwrap();
    let store = PgStore::connect(schema.url(), schema.options())
        .await
        .unwrap();
    store.migrate().await.unwrap();
    let client = schema.client().await.unwrap();
    client
        .batch_execute(
            "CREATE FUNCTION refuse_audit() RETURNS trigger LANGUAGE plpgsql AS $$
             BEGIN RAISE EXCEPTION 'injected audit failure'; END $$",
        )
        .await
        .unwrap();
    (schema, store, client)
}

async fn count(client: &tokio_postgres::Client, table: &str) -> i64 {
    client
        .query_one(&format!("SELECT COUNT(*) FROM {table}"), &[])
        .await
        .unwrap()
        .get(0)
}

fn is_backend<T: std::fmt::Debug>(result: Result<T, StoreError>, what: &str) {
    assert!(
        matches!(result, Err(StoreError::Backend(_))),
        "{what}: {result:?}"
    );
}

async fn revoked(store: &PgStore, n: u8) -> bool {
    let found = store.find_credential(&id(n)).await.unwrap().unwrap();
    found.revoked_at_ms.is_some()
}

#[tokio::test]
async fn a_failing_audit_write_rolls_back_every_audited_mutation() {
    const TEST: &str = "a_failing_audit_write_rolls_back_every_audited_mutation";
    let Some(url) = database_url(TEST).unwrap() else {
        return;
    };
    let (_schema, store, client) = setup(&url).await;
    let (ops, main) = (BoardId::new("ops").unwrap(), BoardId::main());
    store
        .create_board(&ops, None, audit(SecurityEventKind::BoardCreated))
        .await
        .unwrap();
    for (who, role) in [("ann", Role::Admin), ("bob", Role::Member)] {
        store
            .add_member(&ops, &name(who), PrincipalKind::Human, role, NOW)
            .await
            .unwrap();
    }
    for (n, scope, who) in [
        (1, CredentialScope::Board(ops.clone()), "ann"),
        (2, CredentialScope::Board(ops.clone()), "bob"),
        (3, CredentialScope::Instance, "instance-admin"),
    ] {
        let issued = audit(SecurityEventKind::MemberTokenIssued);
        store
            .create_credential(credential(n, scope, who), issued)
            .await
            .unwrap();
    }
    let rows = count(&client, "security_log").await;
    let invites = count(&client, "invites").await;
    client.batch_execute(REFUSE_EVERY_ROW).await.unwrap();

    let new = BoardId::new("new").unwrap();
    is_backend(
        store
            .create_board(&new, None, audit(SecurityEventKind::BoardCreated))
            .await,
        "create_board",
    );
    assert!(store.get_board(&new).await.is_err(), "board not created");

    is_backend(
        store
            .archive_board(&ops, audit(SecurityEventKind::BoardArchived))
            .await,
        "archive_board",
    );
    is_backend(
        store
            .archive_board_revoking(&ops, audit(SecurityEventKind::BoardArchived))
            .await,
        "archive_board_revoking",
    );
    let info = store.get_board(&ops).await.unwrap();
    assert_eq!(info.archived_at_ms, None, "board not archived");
    assert!(!revoked(&store, 2).await, "bob's credential not revoked");

    let board_token = credential(4, CredentialScope::Board(main.clone()), "zed");
    is_backend(
        store
            .create_credential(board_token, audit(SecurityEventKind::MemberTokenIssued))
            .await,
        "create_credential",
    );
    assert_eq!(store.find_credential(&id(4)).await, Ok(None), "not stored");

    is_backend(
        store
            .revoke_credential(&id(2), audit(SecurityEventKind::TokenRevoked))
            .await,
        "revoke_credential",
    );
    assert!(!revoked(&store, 2).await, "credential not revoked");

    is_backend(
        store
            .remove_member(&ops, &name("bob"), audit(SecurityEventKind::MemberRemoved))
            .await,
        "remove_member",
    );
    let bob = store.get_member(&ops, &name("bob")).await.unwrap();
    assert!(bob.is_some(), "member not removed");
    assert!(!revoked(&store, 2).await, "member's credential not revoked");

    is_backend(
        store
            .create_invite(invite(5, &main), audit(SecurityEventKind::InviteCreated))
            .await,
        "create_invite",
    );
    assert_eq!(
        count(&client, "invites").await,
        invites,
        "invite not created"
    );

    let replacement = credential(6, CredentialScope::Instance, "instance-admin");
    is_backend(
        store
            .replace_instance_credential(replacement, audit(SecurityEventKind::InstanceTokenIssued))
            .await,
        "replace_instance_credential",
    );
    assert_eq!(store.find_credential(&id(6)).await, Ok(None), "not stored");
    assert!(!revoked(&store, 3).await, "old instance credential kept");

    is_backend(
        store
            .enable_network_mode(audit(SecurityEventKind::ModeEnabled))
            .await,
        "enable_network_mode",
    );
    let audits = EnableAudits {
        mode: audit(SecurityEventKind::ModeEnabled),
        token: audit(SecurityEventKind::InstanceTokenIssued),
    };
    is_backend(
        store
            .enable_network(
                credential(7, CredentialScope::Instance, "instance-admin"),
                Some((invite(8, &main), audit(SecurityEventKind::InviteCreated))),
                audits,
            )
            .await,
        "enable_network",
    );
    assert_eq!(store.mode().await, Ok(Mode::Local), "mode still local");
    assert_eq!(store.find_credential(&id(7)).await, Ok(None), "not stored");
    assert_eq!(
        count(&client, "invites").await,
        invites,
        "invite not created"
    );
    assert_eq!(count(&client, "security_log").await, rows, "no row written");

    // Nothing was half-done, so once the log works again a retry succeeds.
    client
        .batch_execute("DROP TRIGGER refuse_audit ON security_log")
        .await
        .unwrap();
    store
        .archive_board_revoking(&ops, audit(SecurityEventKind::BoardArchived))
        .await
        .unwrap();
    assert!(revoked(&store, 2).await, "the retry revoked bob");
    assert!(!revoked(&store, 1).await, "the admin keeps hers");
    assert_eq!(count(&client, "security_log").await, rows + 1);
}

/// `consume_invite` and `adopt_local_authors` write their own rows (`Join`,
/// `PrincipalsAdopted`); a refused row leaves no member, credential, used mark or flipped
/// message behind.
#[tokio::test]
async fn a_failing_own_row_rolls_back_the_join_and_the_adoption() {
    const TEST: &str = "a_failing_own_row_rolls_back_the_join_and_the_adoption";
    let Some(url) = database_url(TEST).unwrap() else {
        return;
    };
    let (_schema, store, client) = setup(&url).await;
    let main = BoardId::main();
    store
        .create_invite(invite(1, &main), audit(SecurityEventKind::InviteCreated))
        .await
        .unwrap();
    let post = stigmer_core::NewMessage {
        board: main.clone(),
        target: stigmer_core::Target::NewThread {
            channel: stigmer_core::ChannelPath::new("eng").unwrap(),
        },
        author: name("carol"),
        text: "local post".to_owned(),
        labels: Vec::new(),
        idempotency_key: None,
    };
    store.post(post).await.unwrap();
    let rows = count(&client, "security_log").await;
    client.batch_execute(REFUSE_EVERY_ROW).await.unwrap();

    let join = stigmer_store::NewJoinCredential {
        id: id(2),
        secret_hash: [2; 32],
        expires_at_ms: NOW + 1_000_000,
    };
    is_backend(
        store
            .consume_invite(&id(1), &[1; 32], &name("dave"), NOW, join)
            .await,
        "consume_invite",
    );
    let adoption = stigmer_store::Adoption {
        name: name("carol"),
        kind: PrincipalKind::Human,
        role: Role::Member,
    };
    is_backend(
        store.adopt_local_authors(&main, &[adoption], NOW).await,
        "adopt_local_authors",
    );
    assert_eq!(store.list_members(&main).await, Ok(Vec::new()), "no member");
    assert_eq!(
        store.find_credential(&id(2)).await,
        Ok(None),
        "no credential"
    );
    let used: Option<i64> = client
        .query_one("SELECT used_at_ms FROM invites", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(used, None, "invite still unused");
    assert_eq!(
        store.list_local_authors(&main).await,
        Ok(vec![name("carol")]),
        "carol's post still local"
    );
    assert_eq!(count(&client, "security_log").await, rows, "no row written");
}

/// `replace_instance_credential` writes two rows when it revokes others: the caller's and the
/// store's count row. Refusing only the second still rolls back the first and the whole change.
#[tokio::test]
async fn a_failing_count_row_rolls_back_the_replacement_and_its_first_row() {
    const TEST: &str = "a_failing_count_row_rolls_back_the_replacement_and_its_first_row";
    let Some(url) = database_url(TEST).unwrap() else {
        return;
    };
    let (_schema, store, client) = setup(&url).await;
    let old = credential(1, CredentialScope::Instance, "instance-admin");
    let issued = audit(SecurityEventKind::InstanceTokenIssued);
    store.create_credential(old, issued).await.unwrap();
    let rows = count(&client, "security_log").await;
    client
        .batch_execute(
            "CREATE TRIGGER refuse_count_row BEFORE INSERT ON security_log
             FOR EACH ROW WHEN (NEW.kind = 'token_revoked') EXECUTE FUNCTION refuse_audit()",
        )
        .await
        .unwrap();

    let replacement = credential(2, CredentialScope::Instance, "instance-admin");
    is_backend(
        store
            .replace_instance_credential(replacement, audit(SecurityEventKind::InstanceTokenIssued))
            .await,
        "replace_instance_credential",
    );
    assert_eq!(store.find_credential(&id(2)).await, Ok(None), "not stored");
    assert!(!revoked(&store, 1).await, "old instance credential kept");
    assert_eq!(
        count(&client, "security_log").await,
        rows,
        "neither row written"
    );
}
