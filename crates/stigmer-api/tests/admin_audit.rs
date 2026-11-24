//! Admin mutations and their security log rows: the store writes each row in the mutation's
//! transaction, so a failed audit write fails the request (generic 500) and changes nothing,
//! while failed-authentication and rate-limit rows stay best effort.

mod common;

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use axum::http::{Method, StatusCode};
use common::*;
use serde_json::json;
use stigmer_api::{router, ApiConfig, RoleAuthorize};
use stigmer_core::{Principal, Role};
use stigmer_store::{CredentialScope, IdentityStore, SecurityEvent, Store};
use stigmer_store_sqlite::SqliteStore;
use tokio::sync::watch;

struct Rig {
    app: axum::Router,
    store: Arc<LogFailingStore>,
    warnings: Arc<Mutex<Vec<String>>>,
    root: String,
    admin: String,
    bob: String,
    _shutdown: watch::Sender<bool>,
}

/// A network router over a store with board `ops`: admin `oda`, members `bob` and `carol`.
async fn rig() -> Rig {
    let inner = SqliteStore::open_memory().await.unwrap();
    inner
        .enable_network_mode(audit(SecurityEventKind::ModeEnabled, NOW))
        .await
        .unwrap();
    let root = credential(&inner, CredentialScope::Instance, "root", NOW + DAY).await;
    let ops = board("ops");
    inner
        .create_board(&ops, None, NOW, audit(SecurityEventKind::BoardCreated, NOW))
        .await
        .unwrap();
    let admin = member_token(&inner, &ops, "oda", Role::Admin).await;
    let bob = member_token(&inner, &ops, "bob", Role::Member).await;
    member_token(&inner, &ops, "carol", Role::Member).await;
    let store = Arc::new(LogFailingStore::new(inner));
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
        root,
        admin,
        bob,
        _shutdown: tx,
    }
}

impl Rig {
    async fn call(
        &self,
        method: Method,
        uri: &str,
        token: &str,
        body: Option<serde_json::Value>,
    ) -> Reply {
        send(&self.app, request(method, uri, Some(token), body.as_ref())).await
    }

    /// The five audited admin mutations, each as the request and the status it gets on success.
    async fn mutations(&self) -> Vec<(&'static str, Reply, StatusCode)> {
        let revoke = format!("/v1/boards/ops/tokens/{}", token_id(&self.bob));
        let invite = json!({"kind": "agent", "role": "member"});
        vec![
            (
                "create board",
                self.call(
                    Method::POST,
                    "/v1/boards",
                    &self.root,
                    Some(json!({"name": "dev"})),
                )
                .await,
                StatusCode::CREATED,
            ),
            (
                "invite",
                self.call(
                    Method::POST,
                    "/v1/boards/ops/invites",
                    &self.admin,
                    Some(invite),
                )
                .await,
                StatusCode::CREATED,
            ),
            (
                "token revoke",
                self.call(Method::DELETE, &revoke, &self.admin, None).await,
                StatusCode::NO_CONTENT,
            ),
            (
                "member remove",
                self.call(
                    Method::DELETE,
                    "/v1/boards/ops/members/carol",
                    &self.admin,
                    None,
                )
                .await,
                StatusCode::NO_CONTENT,
            ),
            (
                "archive",
                self.call(Method::POST, "/v1/boards/ops/archive", &self.root, None)
                    .await,
                StatusCode::OK,
            ),
        ]
    }

    async fn log(&self) -> Vec<SecurityEvent> {
        let mut rows = self.store.inner.security_log(1_000).await.unwrap();
        rows.reverse();
        rows
    }

    async fn whoami(&self, token: &str) -> StatusCode {
        self.call(Method::GET, "/v1/whoami", token, None)
            .await
            .status
    }
}

/// The kinds of the rows written since `before`, oldest first.
fn new_kinds(before: &[SecurityEvent], after: &[SecurityEvent]) -> Vec<String> {
    after[before.len()..]
        .iter()
        .map(|e| e.kind.to_string())
        .collect()
}

const MUTATION_KINDS: [&str; 5] = [
    "board_created",
    "invite_created",
    "token_revoked",
    "member_removed",
    "board_archived",
];

#[tokio::test]
async fn admin_mutations_write_their_rows_through_the_store_not_the_best_effort_log() {
    let rig = rig().await;
    let before = rig.log().await;
    // The best-effort log is down; mutations do not use it, so they succeed and are recorded.
    rig.store.fail_log.store(true, Ordering::SeqCst);
    for (what, reply, ok) in rig.mutations().await {
        assert_eq!(reply.status, ok, "{what}: {}", reply.body);
    }
    let after = rig.log().await;
    assert_eq!(new_kinds(&before, &after), MUTATION_KINDS, "{after:?}");
    for row in &after[before.len()..] {
        assert_eq!(row.at_ms, NOW, "{row:?}");
        assert!(row.detail.starts_with("source="), "{row:?}");
    }
    assert_eq!(after[before.len()].principal.as_deref(), Some("root"));
    assert_eq!(after[before.len() + 1].principal.as_deref(), Some("oda"));
    assert_eq!(rig.warnings.lock().unwrap().clone(), Vec::<String>::new());
}

#[tokio::test]
async fn audit_failure_fails_the_request_with_500_and_changes_nothing() {
    let rig = rig().await;
    let inner = &rig.store.inner;
    let ops = board("ops");
    let before = rig.log().await;
    // With `fail_mutations` the wrapper answers as a failed audit write would, without ever
    // calling the inner store, so this checks the API's handling of that failure (generic 500,
    // no fallback row) and not the rollback itself. The real rollback proof is
    // crates/stigmer-store-sqlite/tests/audit_rollback.rs.
    rig.store.fail_mutations.store(true, Ordering::SeqCst);
    for (what, reply, _) in rig.mutations().await {
        assert_eq!(
            reply.status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "{what}: {}",
            reply.body
        );
        assert_eq!(
            reply.json(),
            json!({"error": {"code": "internal", "message": "internal error"}}),
            "{what}: the generic 500 body"
        );
    }
    rig.store.fail_mutations.store(false, Ordering::SeqCst);
    // Nothing happened.
    assert!(
        inner.get_board(&board("dev")).await.is_err(),
        "no board dev"
    );
    assert_eq!(
        rig.whoami(&rig.bob).await,
        StatusCode::OK,
        "bob not revoked"
    );
    let carol = inner
        .get_member(&ops, &Principal::new("carol").unwrap())
        .await;
    assert!(matches!(carol, Ok(Some(_))), "carol still a member");
    let info = inner.get_board(&ops).await.unwrap();
    assert_eq!(info.archived_at_ms, None, "ops not archived");
    assert_eq!(
        rig.log().await,
        before,
        "the API wrote no row of its own (no best-effort fallback for a failed mutation)"
    );
    assert_eq!(rig.warnings.lock().unwrap().clone(), Vec::<String>::new());
}

#[tokio::test]
async fn retry_after_an_audit_failure_succeeds() {
    let rig = rig().await;
    let before = rig.log().await;
    rig.store.fail_mutations.store(true, Ordering::SeqCst);
    for (what, reply, _) in rig.mutations().await {
        assert_eq!(reply.status, StatusCode::INTERNAL_SERVER_ERROR, "{what}");
    }
    rig.store.fail_mutations.store(false, Ordering::SeqCst);
    for (what, reply, ok) in rig.mutations().await {
        assert_eq!(reply.status, ok, "{what} retried: {}", reply.body);
    }
    // One row per mutation: the failed attempts left none behind.
    assert_eq!(new_kinds(&before, &rig.log().await), MUTATION_KINDS);
    assert_eq!(rig.whoami(&rig.bob).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rate_limited_and_auth_failed_events_stay_best_effort() {
    let rig = rig().await;
    rig.store.fail_log.store(true, Ordering::SeqCst);
    let first = rig.call(Method::GET, "/v1/whoami", "junk", None).await;
    assert_eq!(first.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        first.json(),
        json!({"error": {"code": "unauthorized", "message": "invalid or expired credentials"}}),
        "the usual 401 body"
    );
    let limited = rig.call(Method::GET, "/v1/whoami", "junk", None).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);

    let warnings = rig.warnings.lock().unwrap().clone();
    assert_eq!(
        warnings,
        [
            "security log write failed: kind=auth_failed board=- principal=-",
            "security log write failed: kind=rate_limited board=- principal=-",
        ],
        "one warning each"
    );
    for line in &warnings {
        for secret in [&rig.root, &rig.admin, &rig.bob] {
            assert!(!line.contains(secret.as_str()), "{line}");
        }
        assert!(!line.contains("source="), "{line}");
    }
}
