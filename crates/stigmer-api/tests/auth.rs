//! Network-mode authentication, the 401/403/404 policy and request limits.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use stigmer_api::{
    router, Action, AllowAll, ApiConfig, Authenticated, Authorize, Denied, RoleAuthorize, Scope,
};
use stigmer_core::{
    generate_secret, BoardId, ChannelPath, NewMessage, Principal, PrincipalKind, Role, SecretKind,
    Target, TokenId,
};
use stigmer_store::{CredentialScope, IdentityStore, NewCredential, Store};
use stigmer_store_sqlite::SqliteStore;
use tokio::sync::watch;
use tower::ServiceExt;

/// The fixed time every network test starts at, in ms.
const NOW: i64 = 1_800_000_000_000;
const DAY: i64 = 86_400_000;

struct Net {
    app: Router,
    store: Arc<SqliteStore>,
    now: Arc<AtomicI64>,
    _shutdown: watch::Sender<bool>,
}

/// A network-mode router over a fresh store, with a clock the test controls.
async fn network_with<A: Authorize>(authz: A, adjust: impl FnOnce(&mut ApiConfig)) -> Net {
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

async fn network() -> Net {
    network_with(RoleAuthorize, |_| {}).await
}

fn board(name: &str) -> BoardId {
    BoardId::new(name).unwrap()
}

fn kind_for(role: Role) -> PrincipalKind {
    match role {
        Role::Bridge => PrincipalKind::Bridge,
        _ => PrincipalKind::Human,
    }
}

/// Makes `name` a member of `on` with `role` and returns a fresh token for them.
async fn member_token(store: &SqliteStore, on: &BoardId, name: &str, role: Role) -> String {
    let principal = Principal::new(name).unwrap();
    store
        .add_member(on, &principal, kind_for(role), role, NOW)
        .await
        .unwrap();
    credential(store, CredentialScope::Board(on.clone()), name, NOW + DAY).await
}

/// Stores a credential for `name` (membership untouched) and returns the full token.
async fn credential(
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

fn token_id(token: &str) -> TokenId {
    TokenId::new(&token["stg1_".len().."stg1_".len() + 16]).unwrap()
}

async fn seed_thread(store: &SqliteStore, on: &BoardId) -> String {
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

fn request(method: Method, uri: &str, token: Option<&str>, body: Option<&Value>) -> Request<Body> {
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

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
}

async fn send(app: &Router, req: Request<Body>) -> Reply {
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
fn board_routes(on: &str, thread: &str) -> Vec<(Method, String, Option<Value>)> {
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

const UNAUTHORIZED_BODY: &str =
    r#"{"error":{"code":"unauthorized","message":"invalid or expired credentials"}}"#;

#[tokio::test]
async fn local_mode_behaves_as_m0() {
    let store = Arc::new(SqliteStore::open_memory().await.unwrap());
    let (_tx, rx) = watch::channel(false);
    let app = router(store, AllowAll, rx, ApiConfig::local());
    let mut post = request(
        Method::POST,
        "/v1/boards/main/messages",
        Some("stg1_not_a_token"),
        Some(&json!({"channel": "eng", "text": "hi"})),
    );
    post.headers_mut()
        .insert("x-stigmer-as", "alice".parse().unwrap());
    let reply = send(&app, post).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
    assert_eq!(reply.json()["message"]["author"], "alice");
    let reply = send(
        &app,
        request(Method::GET, "/v1/boards/main/events", None, None),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.json()["events"].as_array().unwrap().len(), 1);
    let missing_author = request(
        Method::POST,
        "/v1/boards/main/messages",
        None,
        Some(&json!({"channel": "eng", "text": "hi"})),
    );
    assert_eq!(
        send(&app, missing_author).await.status,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn network_mode_requires_a_token_on_every_route_except_health_and_join() {
    let net = network().await;
    let thread = seed_thread(&net.store, &BoardId::main()).await;
    for (method, uri, body) in board_routes("main", &thread) {
        let mut req = request(method.clone(), &uri, None, body.as_ref());
        // The local-mode header must not stand in for a token.
        req.headers_mut()
            .insert("x-stigmer-as", "alice".parse().unwrap());
        let reply = send(&net.app, req).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{method} {uri}");
        assert_eq!(reply.body, UNAUTHORIZED_BODY, "{method} {uri}");
    }
    for uri in ["/healthz", "/readyz"] {
        let reply = send(&net.app, request(Method::GET, uri, None, None)).await;
        assert_eq!(reply.status, StatusCode::OK, "{uri}");
    }
}

#[tokio::test]
async fn missing_malformed_unknown_expired_revoked_tokens_return_identical_401_bodies() {
    let net = network().await;
    let main = BoardId::main();
    let good = member_token(&net.store, &main, "alice", Role::Member).await;
    let expired = credential(
        &net.store,
        CredentialScope::Board(main.clone()),
        "alice",
        NOW,
    )
    .await;
    let revoked = member_token(&net.store, &main, "bob", Role::Member).await;
    net.store
        .revoke_credential(&token_id(&revoked), NOW)
        .await
        .unwrap();
    let not_a_member = credential(
        &net.store,
        CredentialScope::Board(main.clone()),
        "carol",
        NOW + DAY,
    )
    .await;
    let unknown_id = format!("stg1_0000000000000000_{}", &good[good.len() - 43..]);
    let wrong_secret = format!("{}A{}", &good[..good.len() - 43], &good[good.len() - 42..]);
    let mut headers: Vec<Option<String>> = vec![
        None,
        Some("Basic YWxpY2U6cHc=".to_owned()),
        Some("Bearer".to_owned()),
        Some("Bearer garbage".to_owned()),
        Some(format!("Bearer stgi1_{}", &good["stg1_".len()..])),
    ];
    for token in [unknown_id, wrong_secret, expired, revoked, not_a_member] {
        headers.push(Some(format!("Bearer {token}")));
    }
    let mut first: Option<Reply> = None;
    for header in headers {
        let mut req = request(Method::GET, "/v1/boards/main/events", None, None);
        if let Some(h) = &header {
            req.headers_mut()
                .insert("authorization", h.parse().unwrap());
        }
        let reply = send(&net.app, req).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{header:?}");
        assert_eq!(reply.body, UNAUTHORIZED_BODY, "{header:?}");
        if let Some(f) = &first {
            assert_eq!(reply.headers, f.headers, "{header:?}");
        } else {
            first = Some(reply);
        }
    }
    // The good token still works: the failures above did not lock it out.
    let reply = send(
        &net.app,
        request(Method::GET, "/v1/boards/main/events", Some(&good), None),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
}

#[tokio::test]
async fn expiry_is_exclusive_of_the_expiry_instant() {
    let net = network().await;
    let main = BoardId::main();
    member_token(&net.store, &main, "alice", Role::Member).await;
    let token = credential(&net.store, CredentialScope::Board(main), "alice", NOW + 10).await;
    let get = || request(Method::GET, "/v1/boards/main/events", Some(&token), None);
    net.now.store(NOW + 9, Ordering::SeqCst);
    assert_eq!(send(&net.app, get()).await.status, StatusCode::OK);
    net.now.store(NOW + 10, Ordering::SeqCst);
    assert_eq!(send(&net.app, get()).await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn valid_token_for_another_board_gets_404_on_every_board_route() {
    let net = network().await;
    let other = board("other");
    net.store.create_board(&other, None).await.unwrap();
    let other_thread = seed_thread(&net.store, &other).await;
    let token = member_token(&net.store, &BoardId::main(), "alice", Role::Admin).await;
    let mut bodies = Vec::new();
    for on in ["other", "ghost"] {
        for (method, uri, body) in board_routes(on, &other_thread) {
            let reply = send(
                &net.app,
                request(method.clone(), &uri, Some(&token), body.as_ref()),
            )
            .await;
            assert_eq!(reply.status, StatusCode::NOT_FOUND, "{method} {uri}");
            assert_eq!(reply.json()["error"]["code"], "not_found", "{method} {uri}");
            bodies.push(reply.body);
        }
    }
    // An existing and a missing board are indistinguishable.
    assert!(bodies.windows(2).all(|w| w[0] == w[1]), "{bodies:?}");
    // Nothing was posted to the other board.
    let head = net.store.head(&other).await.unwrap().unwrap();
    assert_eq!(head.seq().unwrap(), 1);
}

#[tokio::test]
async fn unknown_board_is_404_not_a_405_or_empty_list() {
    let net = network().await;
    let instance = credential(&net.store, CredentialScope::Instance, "root", NOW + DAY).await;
    let store = Arc::new(SqliteStore::open_memory().await.unwrap());
    let (_tx, rx) = watch::channel(false);
    let local = router(store, AllowAll, rx, ApiConfig::local());
    let thread = "msg_0123456789abcdef01234567";
    for (method, uri, body) in board_routes("ghost", thread) {
        let reply = send(
            &net.app,
            request(method.clone(), &uri, Some(&instance), body.as_ref()),
        )
        .await;
        assert_eq!(
            reply.status,
            StatusCode::NOT_FOUND,
            "network {method} {uri}"
        );
        assert_eq!(reply.json()["error"]["code"], "not_found");
        let mut req = request(method.clone(), &uri, None, body.as_ref());
        req.headers_mut()
            .insert("x-stigmer-as", "alice".parse().unwrap());
        let reply = send(&local, req).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "local {method} {uri}");
        assert_eq!(reply.json()["error"]["code"], "not_found");
    }
}

fn caller(scope: CredentialScope, role: Option<Role>) -> Authenticated {
    Authenticated {
        principal: Principal::new("alice").unwrap(),
        kind: PrincipalKind::Human,
        scope,
        role,
        credential: None,
    }
}

#[tokio::test]
async fn member_cannot_manage_and_gets_403() {
    let main = BoardId::main();
    let on_main = Scope::Board {
        board: &main,
        channel: None,
    };
    for role in [Role::Member, Role::Bridge] {
        let who = caller(CredentialScope::Board(main.clone()), Some(role));
        for action in [Action::ManageMembers, Action::ManageBoards] {
            assert_eq!(
                RoleAuthorize.check(&who, action, &on_main).await,
                Err(Denied)
            );
            assert_eq!(
                RoleAuthorize.check(&who, action, &Scope::Instance).await,
                Err(Denied)
            );
        }
    }
    // Over HTTP a member reads and posts on its own board.
    let net = network().await;
    let thread = seed_thread(&net.store, &main).await;
    let token = member_token(&net.store, &main, "bot", Role::Bridge).await;
    for (method, uri, body) in board_routes("main", &thread) {
        let reply = send(
            &net.app,
            request(method.clone(), &uri, Some(&token), body.as_ref()),
        )
        .await;
        assert!(reply.status.is_success(), "{method} {uri}: {}", reply.body);
    }
}

#[tokio::test]
async fn admin_can_read_and_post_but_instance_credential_gets_403_on_content() {
    let net = network().await;
    let main = BoardId::main();
    let thread = seed_thread(&net.store, &main).await;
    let admin = member_token(&net.store, &main, "alice", Role::Admin).await;
    let instance = credential(&net.store, CredentialScope::Instance, "root", NOW + DAY).await;
    for (method, uri, body) in board_routes("main", &thread) {
        let reply = send(
            &net.app,
            request(method.clone(), &uri, Some(&admin), body.as_ref()),
        )
        .await;
        assert!(
            reply.status.is_success(),
            "admin {method} {uri}: {}",
            reply.body
        );
        let reply = send(
            &net.app,
            request(method.clone(), &uri, Some(&instance), body.as_ref()),
        )
        .await;
        assert_eq!(
            reply.status,
            StatusCode::FORBIDDEN,
            "instance {method} {uri}"
        );
        assert_eq!(reply.json()["error"]["code"], "forbidden");
    }
}

#[tokio::test]
async fn author_comes_from_the_credential_not_the_header() {
    let net = network().await;
    let token = member_token(&net.store, &BoardId::main(), "alice", Role::Member).await;
    let mut req = request(
        Method::POST,
        "/v1/boards/main/messages",
        Some(&token),
        Some(&json!({"channel": "eng", "text": "hi"})),
    );
    req.headers_mut()
        .insert("x-stigmer-as", "mallory".parse().unwrap());
    let reply = send(&net.app, req).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
    assert_eq!(reply.json()["message"]["author"], "alice");
}

/// Denies everything, but only after yielding to the runtime: proves routes await the check.
#[derive(Clone)]
struct SlowDeny;

impl Authorize for SlowDeny {
    async fn check(&self, _: &Authenticated, _: Action, _: &Scope<'_>) -> Result<(), Denied> {
        tokio::task::yield_now().await;
        Err(Denied)
    }
}

#[tokio::test]
async fn authz_check_is_async_and_denied_maps_to_403() {
    let net = network_with(SlowDeny, |_| {}).await;
    let main = BoardId::main();
    let thread = seed_thread(&net.store, &main).await;
    let token = member_token(&net.store, &main, "alice", Role::Admin).await;
    for (method, uri, body) in board_routes("main", &thread) {
        let reply = send(
            &net.app,
            request(method.clone(), &uri, Some(&token), body.as_ref()),
        )
        .await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{method} {uri}");
        assert_eq!(reply.json()["error"]["code"], "forbidden");
    }
    let head = net.store.head(&main).await.unwrap().unwrap();
    assert_eq!(head.seq().unwrap(), 1, "a denied post must not be written");
}

#[tokio::test]
async fn touch_updates_last_seen() {
    let net = network().await;
    let token = member_token(&net.store, &BoardId::main(), "alice", Role::Member).await;
    let id = token_id(&token);
    assert_eq!(
        net.store
            .find_credential(&id)
            .await
            .unwrap()
            .unwrap()
            .last_seen_ms,
        None
    );
    net.now.store(NOW + 1234, Ordering::SeqCst);
    let reply = send(
        &net.app,
        request(Method::GET, "/v1/boards/main/events", Some(&token), None),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        net.store
            .find_credential(&id)
            .await
            .unwrap()
            .unwrap()
            .last_seen_ms,
        Some(NOW + 1234)
    );
}

#[tokio::test]
async fn post_to_archived_board_is_409_board_archived() {
    let net = network().await;
    let main = BoardId::main();
    let token = member_token(&net.store, &main, "alice", Role::Admin).await;
    net.store.archive_board(&main).await.unwrap();
    let reply = send(
        &net.app,
        request(
            Method::POST,
            "/v1/boards/main/messages",
            Some(&token),
            Some(&json!({"channel": "eng", "text": "late"})),
        ),
    )
    .await;
    assert_eq!(reply.status, StatusCode::CONFLICT, "{}", reply.body);
    assert_eq!(reply.json()["error"]["code"], "board_archived");
    let reply = send(
        &net.app,
        request(Method::GET, "/v1/boards/main/events", Some(&token), None),
    )
    .await;
    assert_eq!(
        reply.status,
        StatusCode::OK,
        "archived boards stay readable"
    );
}

#[tokio::test]
async fn no_secret_in_any_error_body() {
    let net = network().await;
    let main = BoardId::main();
    let thread = seed_thread(&net.store, &main).await;
    let token = member_token(&net.store, &main, "alice", Role::Member).await;
    let secret = &token[token.len() - 43..];
    let corrupted = format!("{}{}", &token[..token.len() - 4], "AAAA");
    let corrupted_secret = &corrupted[corrupted.len() - 43..];
    let unparseable = format!("{token}!");
    let instance = credential(&net.store, CredentialScope::Instance, "root", NOW + DAY).await;
    let instance_secret = instance[instance.len() - 43..].to_owned();
    let mut probes: Vec<String> = vec![corrupted.clone(), unparseable.clone(), instance.clone()];
    probes.push(token.clone());
    for presented in &probes {
        for on in ["main", "other"] {
            for (method, uri, body) in board_routes(on, &thread) {
                let reply = send(
                    &net.app,
                    request(method.clone(), &uri, Some(presented), body.as_ref()),
                )
                .await;
                let shown = format!("{:?} {}", reply.headers, reply.body);
                for needle in [secret, corrupted_secret, instance_secret.as_str()] {
                    assert!(!shown.contains(needle), "{method} {uri} leaked: {shown}");
                }
            }
        }
    }
    for entry in net.store.security_log(100).await.unwrap() {
        for needle in [secret, corrupted_secret, instance_secret.as_str()] {
            assert!(!entry.detail.contains(needle), "{entry:?}");
        }
    }
}
