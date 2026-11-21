//! HTTP API tests against an in-memory SQLite store.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use stigmer_api::require_loopback;
use stigmer_api::{router, Action, AllowAll, Authorize, Denied};
use stigmer_core::{ChannelPath, Principal};
use stigmer_store_sqlite::SqliteStore;
use tokio::sync::watch;
use tower::ServiceExt;

struct Harness {
    app: Router,
    _shutdown: watch::Sender<bool>,
}

async fn harness() -> Harness {
    let store = Arc::new(SqliteStore::open_memory().await.unwrap());
    let (tx, rx) = watch::channel(false);
    Harness {
        app: router(store, AllowAll, rx),
        _shutdown: tx,
    }
}

async fn call(app: &Router, req: Request<Body>) -> (StatusCode, String) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

async fn call_json(app: &Router, req: Request<Body>) -> (StatusCode, Value) {
    let (status, body) = call(app, req).await;
    (status, serde_json::from_str(&body).unwrap_or(Value::Null))
}

fn post_req(as_: Option<&str>, key: Option<&str>, body: Value) -> Request<Body> {
    let mut b = Request::builder()
        .method(Method::POST)
        .uri("/v1/boards/main/messages")
        .header("content-type", "application/json");
    if let Some(a) = as_ {
        b = b.header("x-stigmer-as", a);
    }
    if let Some(k) = key {
        b = b.header("idempotency-key", k);
    }
    b.body(Body::from(body.to_string())).unwrap()
}

fn get_req(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

#[tokio::test]
async fn post_new_thread_returns_201_and_event_cursor() {
    let h = harness().await;
    let (status, body) = call_json(
        &h.app,
        post_req(Some("alice"), None, json!({"channel": "eng/ops", "text": "hello", "labels": [{"key": "kind", "value": "bug"}]})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["replayed"], false);
    assert_eq!(body["message"]["author"], "alice");
    assert_eq!(body["message"]["channel"], "eng/ops");
    assert_eq!(body["event"]["seq"], 1);
    assert!(body["event"]["cursor"].as_str().unwrap().starts_with("ev_"));
}

#[tokio::test]
async fn post_reply_lands_in_the_threads_channel() {
    let h = harness().await;
    let (_, root) = call_json(
        &h.app,
        post_req(Some("alice"), None, json!({"channel": "eng", "text": "q"})),
    )
    .await;
    let id = root["message"]["id"].as_str().unwrap().to_owned();
    let (status, reply) = call_json(
        &h.app,
        post_req(Some("bob"), None, json!({"thread": id, "text": "a"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(reply["message"]["channel"], "eng");
    assert_eq!(reply["event"]["kind"], "message.replied");
    let (status, thread) =
        call_json(&h.app, get_req(&format!("/v1/boards/main/threads/{id}"))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(thread["root"]["text"], "q");
    assert_eq!(thread["replies"][0]["text"], "a");
}

#[tokio::test]
async fn post_with_missing_as_header_is_400_invalid_input() {
    let h = harness().await;
    let (status, body) = call_json(
        &h.app,
        post_req(None, None, json!({"channel": "eng", "text": "x"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "invalid_input");
    let (status, _) = call_json(
        &h.app,
        post_req(
            Some("Not Valid"),
            None,
            json!({"channel": "eng", "text": "x"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn post_over_10000_chars_is_413_too_large() {
    let h = harness().await;
    let text = "x".repeat(10_001);
    let (status, body) = call_json(
        &h.app,
        post_req(Some("alice"), None, json!({"channel": "eng", "text": text})),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body["error"]["code"], "too_large");
}

#[tokio::test]
async fn post_body_over_256_kib_is_413_too_large() {
    let h = harness().await;
    let text = "x".repeat(300 * 1024);
    let (status, body) = call_json(
        &h.app,
        post_req(Some("alice"), None, json!({"channel": "eng", "text": text})),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body["error"]["code"], "too_large");
}

#[tokio::test]
async fn replayed_post_returns_200() {
    let h = harness().await;
    let body = json!({"channel": "eng", "text": "once"});
    let (first, a) = call_json(&h.app, post_req(Some("alice"), Some("k-1"), body.clone())).await;
    let (second, b) = call_json(&h.app, post_req(Some("alice"), Some("k-1"), body)).await;
    assert_eq!(first, StatusCode::CREATED);
    assert_eq!(second, StatusCode::OK);
    assert_eq!(b["replayed"], true);
    assert_eq!(a["message"]["id"], b["message"]["id"]);
    let (status, _) = call_json(
        &h.app,
        post_req(
            Some("alice"),
            Some("bad key"),
            json!({"channel": "eng", "text": "x"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn malformed_or_ambiguous_post_bodies_are_400_invalid_input() {
    let h = harness().await;
    let id = "msg_0123456789abcdef01234567";
    let bodies = [
        json!({"text": "no target"}),
        json!({"channel": "eng", "thread": id, "text": "both"}),
        json!({"channel": "Bad//Path", "text": "x"}),
        json!({"channel": "eng", "text": "x", "extra": 1}),
        json!({"channel": "eng", "text": ""}),
    ];
    for b in bodies {
        let (status, body) = call_json(&h.app, post_req(Some("alice"), None, b.clone())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{b}");
        assert_eq!(body["error"]["code"], "invalid_input", "{b}");
    }
    let req = Request::builder()
        .method(Method::POST)
        .uri("/v1/boards/main/messages")
        .header("x-stigmer-as", "alice")
        .body(Body::from("{not json"))
        .unwrap();
    let (status, body) = call_json(&h.app, req).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "invalid_input");
}

#[tokio::test]
async fn reply_to_unknown_thread_is_404_not_found() {
    let h = harness().await;
    let (status, body) = call_json(
        &h.app,
        post_req(
            Some("alice"),
            None,
            json!({"thread": "msg_0123456789abcdef01234567", "text": "x"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "not_found");
}

#[tokio::test]
async fn any_board_other_than_main_is_404_not_found() {
    let h = harness().await;
    for uri in [
        "/v1/boards/other/channels?prefix=eng",
        "/v1/boards/other/events",
    ] {
        let (status, body) = call_json(&h.app, get_req(uri)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
        assert_eq!(body["error"]["code"], "not_found");
    }
    let req = Request::builder()
        .method(Method::POST)
        .uri("/v1/boards/other/messages")
        .header("x-stigmer-as", "alice")
        .body(Body::from(
            json!({"channel": "eng", "text": "x"}).to_string(),
        ))
        .unwrap();
    let (status, _) = call_json(&h.app, req).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn channels_lists_threads_under_a_prefix() {
    let h = harness().await;
    for (ch, text) in [("eng/ops", "one"), ("eng/dev", "two"), ("sales", "three")] {
        call(
            &h.app,
            post_req(Some("alice"), None, json!({"channel": ch, "text": text})),
        )
        .await;
    }
    let (status, body) = call_json(&h.app, get_req("/v1/boards/main/channels?prefix=eng")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["threads"].as_array().unwrap().len(), 2);
    let (status, body) = call_json(
        &h.app,
        get_req("/v1/boards/main/channels?prefix=eng&limit=1"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["threads"].as_array().unwrap().len(), 1);
    let (status, body) = call_json(&h.app, get_req("/v1/boards/main/channels?prefix=Bad//")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "invalid_input");
    let (status, _) = call_json(
        &h.app,
        get_req("/v1/boards/main/channels?prefix=eng&limit=abc"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn thread_read_of_bad_or_unknown_id() {
    let h = harness().await;
    let (status, body) = call_json(
        &h.app,
        get_req("/v1/boards/main/threads/msg_0123456789abcdef01234567"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "not_found");
    let (status, body) = call_json(&h.app, get_req("/v1/boards/main/threads/garbage")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "invalid_input");
}

#[tokio::test]
async fn unknown_route_is_json_404() {
    let h = harness().await;
    let (status, body) = call_json(&h.app, get_req("/nope")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "not_found");
}

#[tokio::test]
async fn healthz_is_200() {
    let h = harness().await;
    let (status, body) = call(&h.app, get_req("/healthz")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "ok");
}

#[tokio::test]
async fn readyz_is_200_when_the_store_answers() {
    let h = harness().await;
    let (status, _) = call(&h.app, get_req("/readyz")).await;
    assert_eq!(status, StatusCode::OK);
}

#[derive(Clone)]
struct DenyAll;

impl Authorize for DenyAll {
    fn check(&self, _: &Principal, _: Action, _: Option<&ChannelPath>) -> Result<(), Denied> {
        Err(Denied)
    }
}

#[tokio::test]
async fn denied_authorizer_returns_403() {
    let store = Arc::new(SqliteStore::open_memory().await.unwrap());
    let (_tx, rx) = watch::channel(false);
    let app = router(store, DenyAll, rx);
    let (status, body) = call_json(
        &app,
        post_req(Some("alice"), None, json!({"channel": "eng", "text": "x"})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "forbidden");
    for uri in ["/v1/boards/main/channels?prefix=eng"] {
        let (status, body) = call_json(&app, get_req(uri)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{uri}");
        assert_eq!(body["error"]["code"], "forbidden");
    }
}

#[test]
fn require_loopback_accepts_127_0_0_1_and_ipv6_loopback() {
    for addr in ["127.0.0.1:7878", "127.8.9.10:1", "[::1]:7878"] {
        let addr: SocketAddr = addr.parse().unwrap();
        assert!(require_loopback(&addr).is_ok(), "{addr}");
    }
}

#[test]
fn require_loopback_rejects_0_0_0_0_and_192_168_1_5_with_message_naming_the_address() {
    for raw in ["0.0.0.0:7878", "192.168.1.5:7878", "[::]:7878"] {
        let addr: SocketAddr = raw.parse().unwrap();
        let err = require_loopback(&addr).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("refusing to bind {raw}: this board is loopback only")
        );
    }
}
