//! Archiving a board leaves no live non-admin credential, even when a join races it: the store
//! archives and revokes in one transaction.

mod common;

use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::http::{Method, StatusCode};
use axum::Router;
use common::*;
use stigmer_api::{router, ApiConfig, RoleAuthorize};
use stigmer_core::{generate_secret, hash_secret, parse_secret, Principal, Role, SecretKind};
use stigmer_store::{CredentialScope, IdentityStore, NewJoinCredential, Store};
use stigmer_store_sqlite::SqliteStore;
use tokio::sync::watch;

struct Rig {
    app: Router,
    store: Arc<LogFailingStore>,
    root: String,
    admin: String,
    _shutdown: watch::Sender<bool>,
}

/// A network router over a store with board `ops`, its admin `oda` and the instance admin.
async fn rig() -> Rig {
    let inner = SqliteStore::open_memory().await.unwrap();
    inner
        .enable_network_mode(audit(SecurityEventKind::ModeEnabled, NOW))
        .await
        .unwrap();
    let ops = board("ops");
    inner
        .create_board(&ops, None, audit(SecurityEventKind::BoardCreated, NOW))
        .await
        .unwrap();
    let root = credential(&inner, CredentialScope::Instance, "root", NOW + DAY).await;
    let admin = member_token(&inner, &ops, "oda", Role::Admin).await;
    let store = Arc::new(LogFailingStore::new(inner));
    let mut config = ApiConfig::network();
    config.limits.auth_failures_per_minute = 10_000;
    config.limits.join_per_minute = 10_000;
    config.clock = Arc::new(|| NOW);
    let (tx, rx) = watch::channel(false);
    Rig {
        app: router(Arc::clone(&store), RoleAuthorize, rx, config),
        store,
        root,
        admin,
        _shutdown: tx,
    }
}

async fn archive(rig: &Rig, token: &str) -> Reply {
    let uri = "/v1/boards/ops/archive";
    send(&rig.app, request(Method::POST, uri, Some(token), None)).await
}

async fn whoami(rig: &Rig, token: &str) -> StatusCode {
    let req = request(Method::GET, "/v1/whoami", Some(token), None);
    send(&rig.app, req).await.status
}

/// Every credential of `ops` that is neither revoked nor an admin's.
async fn live_non_admin_credentials(store: &SqliteStore) -> Vec<String> {
    let ops = board("ops");
    let mut live = Vec::new();
    for c in store.list_credentials(&ops).await.unwrap() {
        let member = store.get_member(&ops, &c.principal).await.unwrap();
        let admin = member.is_some_and(|m| m.role == Role::Admin);
        if c.revoked_at_ms.is_none() && !admin {
            live.push(c.principal.to_string());
        }
    }
    live
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn archive_leaves_no_live_member_credential_even_when_joins_race() {
    for round in 0..30 {
        let rig = rig().await;
        let invite = mint_invite(&rig.app, &rig.admin, "ops", "agent", "member").await;
        let joiner = {
            let (app, invite) = (rig.app.clone(), invite.clone());
            tokio::spawn(async move { join_as(&app, &invite, "bot").await })
        };
        let archived = archive(&rig, &rig.admin).await;
        assert_eq!(archived.status, StatusCode::OK, "round {round}");
        assert_eq!(
            live_non_admin_credentials(&rig.store.inner).await,
            Vec::<String>::new(),
            "round {round}: right after the archive response"
        );
        let joined = joiner.await.unwrap();
        // Either refused like any bad invite, or it joined before the archive, which revoked it.
        assert!(
            joined.status == StatusCode::CREATED || joined.body == UNAUTHORIZED_BODY,
            "round {round}: {} {}",
            joined.status,
            joined.body
        );
        assert_eq!(
            live_non_admin_credentials(&rig.store.inner).await,
            Vec::<String>::new(),
            "round {round}: after the join settled"
        );
        if joined.status == StatusCode::CREATED {
            let token = joined.json()["token"].as_str().unwrap().to_owned();
            assert_eq!(whoami(&rig, &token).await, StatusCode::UNAUTHORIZED);
        }
    }
}

/// The interleaving the loop above only hits by luck, forced: a join lands right after the
/// archive transaction, before the archive route returns.
#[tokio::test]
async fn join_right_after_the_archive_cannot_get_a_live_credential() {
    let rig = rig().await;
    let invite = mint_invite(&rig.app, &rig.admin, "ops", "agent", "member").await;
    let (id, secret) = parse_secret(SecretKind::Invite, &invite).unwrap();
    let token = generate_secret(SecretKind::Token).unwrap();
    *rig.store.join_after_archive.lock().unwrap() = Some(JoinAttempt {
        id,
        secret_hash: hash_secret(&secret),
        name: Principal::new("bot").unwrap(),
        credential: NewJoinCredential {
            id: token.id,
            secret_hash: token.hash,
            expires_at_ms: NOW + DAY,
        },
    });
    assert_eq!(archive(&rig, &rig.admin).await.status, StatusCode::OK);
    let raced = rig.store.join_result.lock().unwrap().take();
    assert!(raced.is_some(), "the racing join ran");
    assert_eq!(
        live_non_admin_credentials(&rig.store.inner).await,
        Vec::<String>::new()
    );
}

#[tokio::test]
async fn a_failed_archive_changes_nothing_and_a_retry_succeeds() {
    let rig = rig().await;
    let ops = board("ops");
    let member = member_token(&rig.store.inner, &ops, "mo", Role::Member).await;
    rig.store.fail_mutations.store(true, Ordering::SeqCst);

    let first = archive(&rig, &rig.root).await;
    assert_eq!(
        first.status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "{}",
        first.body
    );
    let info = rig.store.inner.get_board(&ops).await.unwrap();
    assert_eq!(info.archived_at_ms, None, "the board is not archived");
    assert_eq!(
        whoami(&rig, &member).await,
        StatusCode::OK,
        "nothing revoked"
    );

    rig.store.fail_mutations.store(false, Ordering::SeqCst);
    let retry = archive(&rig, &rig.root).await;
    assert_eq!(retry.status, StatusCode::OK, "{}", retry.body);
    assert_eq!(retry.json()["archived"], true);
    assert_eq!(whoami(&rig, &member).await, StatusCode::UNAUTHORIZED);
    assert_eq!(
        live_non_admin_credentials(&rig.store.inner).await,
        Vec::<String>::new()
    );
}
