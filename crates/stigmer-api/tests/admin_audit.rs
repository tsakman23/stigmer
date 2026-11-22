//! A failing security log never fails the mutation it records; it is reported as a warning.

mod common;

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use axum::http::{Method, StatusCode};
use common::*;
use serde_json::json;
use stigmer_api::{router, ApiConfig, RoleAuthorize};
use stigmer_core::{Principal, Role};
use stigmer_store::{CredentialScope, IdentityStore, Store};
use stigmer_store_sqlite::SqliteStore;
use tokio::sync::watch;

struct Rig {
    app: axum::Router,
    store: Arc<LogFailingStore>,
    warnings: Arc<Mutex<Vec<String>>>,
    _shutdown: watch::Sender<bool>,
}

async fn rig() -> Rig {
    let inner = SqliteStore::open_memory().await.unwrap();
    inner.enable_network_mode().await.unwrap();
    let store = Arc::new(LogFailingStore {
        inner,
        fail_log: AtomicBool::new(false),
    });
    let warnings = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&warnings);
    let now = Arc::new(AtomicI64::new(NOW));
    let mut config = ApiConfig::network();
    config.clock = Arc::new(move || now.load(Ordering::SeqCst));
    config.limits.auth_failures_per_minute = 1;
    config.warn = Arc::new(move |line| sink.lock().unwrap().push(line.to_owned()));
    let (tx, rx) = watch::channel(false);
    Rig {
        app: router(Arc::clone(&store), RoleAuthorize, rx, config),
        store,
        warnings,
        _shutdown: tx,
    }
}

#[tokio::test]
async fn failing_security_log_does_not_fail_mutations_and_is_warned_about() {
    let rig = rig().await;
    let inner = &rig.store.inner;
    let root = credential(inner, CredentialScope::Instance, "root", NOW + DAY).await;
    let ops = board("ops");
    let admin = {
        // Needs the board first, then a member.
        inner.create_board(&ops, None).await.unwrap();
        member_token(inner, &ops, "oda", Role::Admin).await
    };
    let bob = member_token(inner, &ops, "bob", Role::Member).await;
    let carol = member_token(inner, &ops, "carol", Role::Member).await;
    rig.store.fail_log.store(true, Ordering::SeqCst);

    let call = |method, uri: &str, token: &str, body: Option<serde_json::Value>| {
        send(&rig.app, request(method, uri, Some(token), body.as_ref()))
    };
    let made = call(
        Method::POST,
        "/v1/boards",
        &root,
        Some(json!({"name": "dev"})),
    )
    .await;
    assert_eq!(made.status, StatusCode::CREATED, "{}", made.body);
    let invite = call(
        Method::POST,
        "/v1/boards/ops/invites",
        &admin,
        Some(json!({"kind": "agent", "role": "member"})),
    )
    .await;
    assert_eq!(invite.status, StatusCode::CREATED);
    let invite = invite.json()["invite"].as_str().unwrap().to_owned();
    let revoke = format!("/v1/boards/ops/tokens/{}", token_id(&bob));
    let revoked = call(Method::DELETE, &revoke, &admin, None).await;
    assert_eq!(revoked.status, StatusCode::NO_CONTENT);
    let removed = call(Method::DELETE, "/v1/boards/ops/members/carol", &admin, None).await;
    assert_eq!(removed.status, StatusCode::NO_CONTENT);
    let archived = call(Method::POST, "/v1/boards/ops/archive", &root, None).await;
    assert_eq!(archived.status, StatusCode::OK);
    // The mutations really happened.
    assert!(inner.get_board(&board("dev")).await.is_ok());
    let carol_gone = inner
        .get_member(&ops, &Principal::new("carol").unwrap())
        .await;
    assert_eq!(carol_gone, Ok(None));
    assert!(inner
        .get_board(&ops)
        .await
        .unwrap()
        .archived_at_ms
        .is_some());
    // A refused request is still refused when its own log row cannot be written.
    let first = send(
        &rig.app,
        request(Method::GET, "/v1/whoami", Some("junk"), None),
    )
    .await;
    assert_eq!(first.status, StatusCode::UNAUTHORIZED);
    let limited = send(
        &rig.app,
        request(Method::GET, "/v1/whoami", Some("junk"), None),
    )
    .await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);

    let warnings = rig.warnings.lock().unwrap().clone();
    let kinds: Vec<_> = warnings
        .iter()
        .map(|w| w.split_whitespace().nth(4).unwrap().to_owned())
        .collect();
    assert_eq!(
        kinds,
        [
            "kind=board_created",
            "kind=invite_created",
            "kind=token_revoked",
            "kind=member_removed",
            "kind=board_archived",
            "kind=auth_failed",
            "kind=rate_limited",
        ],
        "{warnings:?}"
    );
    assert_eq!(
        warnings[0],
        "security log write failed: kind=board_created board=dev principal=root"
    );
    for line in &warnings {
        for secret in [&invite, &bob, &carol, &admin, &root] {
            assert!(!line.contains(secret.as_str()), "{line}");
        }
        assert!(!line.contains("source="), "{line}");
    }
}
