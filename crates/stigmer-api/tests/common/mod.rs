//! Helpers shared by the network-mode API test binaries.

// Each test binary uses a different subset of these helpers.
#![allow(dead_code)]

mod failing_log;
#[allow(unused_imports)]
pub use failing_log::{JoinAttempt, LogFailingStore};

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use stigmer_api::{router, ApiConfig, Authorize, RoleAuthorize};
use stigmer_core::{
    generate_secret, BoardId, ChannelPath, NewMessage, Principal, PrincipalKind, Role, SecretKind,
    Target, TokenId,
};
use stigmer_store::{CredentialScope, IdentityStore, NewCredential, Store};
use stigmer_store_sqlite::SqliteStore;
use tokio::sync::watch;
use tower::ServiceExt;

/// The fixed time every network test starts at, in ms.
pub const NOW: i64 = 1_800_000_000_000;
pub const DAY: i64 = 86_400_000;

pub struct Net {
    pub app: Router,
    pub store: Arc<SqliteStore>,
    pub now: Arc<AtomicI64>,
    pub _shutdown: watch::Sender<bool>,
}

/// A network-mode router over a fresh store, with a clock the test controls.
pub async fn network_with<A: Authorize>(authz: A, adjust: impl FnOnce(&mut ApiConfig)) -> Net {
    let store = Arc::new(SqliteStore::open_memory().await.unwrap());
    store.enable_network_mode().await.unwrap();
    let now = Arc::new(AtomicI64::new(NOW));
    let clock = Arc::clone(&now);
    let mut config = ApiConfig::network();
    config.clock = Arc::new(move || clock.load(Ordering::SeqCst));
    adjust(&mut config);
    let (tx, rx) = watch::channel(false);
    Net {
        app: router(Arc::clone(&store), authz, rx, config),
        store,
        now,
        _shutdown: tx,
    }
}

/// Network mode with failed-auth limiting out of the way; the limit has its own tests.
pub async fn network() -> Net {
    network_with(RoleAuthorize, |c| {
        c.limits.auth_failures_per_minute = 10_000;
        c.limits.join_per_minute = 10_000;
    })
    .await
}

pub fn board(name: &str) -> BoardId {
    BoardId::new(name).unwrap()
}

pub fn kind_for(role: Role) -> PrincipalKind {
    match role {
        Role::Bridge => PrincipalKind::Bridge,
        _ => PrincipalKind::Human,
    }
}

/// Makes `name` a member of `on` with `role` and returns a fresh token for them.
pub async fn member_token(store: &SqliteStore, on: &BoardId, name: &str, role: Role) -> String {
    let principal = Principal::new(name).unwrap();
    store
        .add_member(on, &principal, kind_for(role), role, NOW)
        .await
        .unwrap();
    credential(store, CredentialScope::Board(on.clone()), name, NOW + DAY).await
}

/// Stores a credential for `name` (membership untouched) and returns the full token.
pub async fn credential(
    store: &SqliteStore,
    scope: CredentialScope,
    name: &str,
    expires: i64,
) -> String {
    let secret = generate_secret(SecretKind::Token).unwrap();
    store
        .create_credential(
            NewCredential {
                id: secret.id.clone(),
                secret_hash: secret.hash,
                scope,
                principal: Principal::new(name).unwrap(),
                expires_at_ms: expires,
            },
            NOW,
        )
        .await
        .unwrap();
    secret.full
}

pub fn token_id(token: &str) -> TokenId {
    TokenId::new(&token["stg1_".len().."stg1_".len() + 16]).unwrap()
}

pub async fn seed_thread(store: &SqliteStore, on: &BoardId) -> String {
    let msg = NewMessage::new(
        on.clone(),
        Target::NewThread {
            channel: ChannelPath::new("eng").unwrap(),
        },
        Principal::new("seed").unwrap(),
        "seed".to_owned(),
        vec![],
        None,
    )
    .unwrap();
    store.post(msg).await.unwrap().message.id.to_string()
}

pub fn request(
    method: Method,
    uri: &str,
    token: Option<&str>,
    body: Option<&Value>,
) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    match body {
        Some(v) => b
            .header("content-type", "application/json")
            .body(Body::from(v.to_string()))
            .unwrap(),
        None => b.body(Body::empty()).unwrap(),
    }
}

pub struct Reply {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: String,
}

impl Reply {
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
}

pub async fn send(app: &Router, req: Request<Body>) -> Reply {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    Reply {
        status,
        headers,
        body: String::from_utf8(bytes.to_vec()).unwrap(),
    }
}

/// Every board route, as (method, uri, body).
pub fn board_routes(on: &str, thread: &str) -> Vec<(Method, String, Option<Value>)> {
    vec![
        (
            Method::GET,
            format!("/v1/boards/{on}/channels?prefix=eng"),
            None,
        ),
        (Method::GET, format!("/v1/boards/{on}/events"), None),
        (
            Method::GET,
            format!("/v1/boards/{on}/threads/{thread}"),
            None,
        ),
        (
            Method::POST,
            format!("/v1/boards/{on}/messages"),
            Some(json!({"channel": "eng", "text": "new"})),
        ),
        (
            Method::POST,
            format!("/v1/boards/{on}/messages"),
            Some(json!({"thread": thread, "text": "reply"})),
        ),
    ]
}

pub async fn get(net: &Net, uri: &str, token: &str) -> Reply {
    send(&net.app, request(Method::GET, uri, Some(token), None)).await
}

pub async fn delete(net: &Net, uri: &str, token: &str) -> Reply {
    send(&net.app, request(Method::DELETE, uri, Some(token), None)).await
}

/// A fresh instance-admin credential.
pub async fn instance_token(store: &SqliteStore) -> String {
    credential(store, CredentialScope::Instance, "root", NOW + DAY).await
}

/// Mints an invite with `token` and returns the invite string.
pub async fn mint_invite(app: &Router, token: &str, on: &str, kind: &str, role: &str) -> String {
    let body = json!({"kind": kind, "role": role});
    let uri = format!("/v1/boards/{on}/invites");
    let reply = send(app, request(Method::POST, &uri, Some(token), Some(&body))).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
    reply.json()["invite"].as_str().unwrap().to_owned()
}

/// Redeems `invite` as `name`, with no token.
pub async fn join_as(app: &Router, invite: &str, name: &str) -> Reply {
    let body = json!({"invite": invite, "name": name});
    send(app, request(Method::POST, "/v1/join", None, Some(&body))).await
}

/// `req`, as if it arrived from `peer`.
pub fn from_peer(mut req: Request<Body>, peer: &str) -> Request<Body> {
    req.extensions_mut()
        .insert(stigmer_api::PeerAddr(peer.parse().unwrap()));
    req
}

pub const UNAUTHORIZED_BODY: &str =
    r#"{"error":{"code":"unauthorized","message":"invalid or expired credentials"}}"#;
