//! Request limits: failed-authentication limiting, forwarding headers, the wait cap and the
//! host allow-list.

mod common;

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use common::*;
use stigmer_api::{router, AllowAll, ApiConfig, IpNet, Limits, PeerAddr, RoleAuthorize};
use stigmer_core::{BoardId, Role};
use stigmer_store::{IdentityStore, Mode, SecurityEventKind};
use stigmer_store_sqlite::SqliteStore;
use tokio::sync::watch;

#[test]
fn api_config_defaults() {
    let local = ApiConfig::local();
    assert_eq!(local.mode, Mode::Local);
    assert_eq!(ApiConfig::network().mode, Mode::Network);
    assert_eq!(
        local.limits,
        Limits {
            max_waits: 256,
            auth_failures_per_minute: 10,
            join_per_minute: 10,
            max_tracked_sources: 10_000,
        }
    );
    assert!(local.allowed_hosts.is_empty());
    assert!(local.trusted_proxies.is_empty());
}

fn forwarded(mut req: Request<Body>, xff: &str) -> Request<Body> {
    req.headers_mut()
        .insert("x-forwarded-for", xff.parse().unwrap());
    req
}

fn events_with(token: &str) -> Request<Body> {
    request(Method::GET, "/v1/boards/main/events", Some(token), None)
}

async fn log_of(store: &SqliteStore, kind: SecurityEventKind) -> Vec<String> {
    store
        .security_log(1000)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.kind == kind)
        .map(|e| e.detail)
        .collect()
}

fn assert_rate_limited(reply: &Reply) -> u64 {
    assert_eq!(
        reply.status,
        StatusCode::TOO_MANY_REQUESTS,
        "{}",
        reply.body
    );
    assert_eq!(reply.json()["error"]["code"], "rate_limited");
    reply
        .headers
        .get("retry-after")
        .expect("Retry-After header")
        .to_str()
        .unwrap()
        .parse()
        .unwrap()
}

#[tokio::test]
async fn failed_auth_is_rate_limited_per_source_with_429_and_retry_after() {
    let net = network_with(RoleAuthorize, |c| c.limits.auth_failures_per_minute = 3).await;
    let good = member_token(&net.store, &BoardId::main(), "alice", Role::Member).await;
    let attacker = "203.0.113.1";
    for _ in 0..3 {
        let reply = send(&net.app, from_peer(events_with("garbage"), attacker)).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    }
    for _ in 0..3 {
        let reply = send(&net.app, from_peer(events_with("garbage"), attacker)).await;
        // Three failures a minute refill one every 20 s.
        assert_eq!(assert_rate_limited(&reply), 20);
    }
    // Limiting comes before credentials: even a good token is refused from this source.
    let reply = send(&net.app, from_peer(events_with(&good), attacker)).await;
    assert_rate_limited(&reply);
    // Another source is unaffected.
    let reply = send(&net.app, from_peer(events_with(&good), "203.0.113.2")).await;
    assert_eq!(reply.status, StatusCode::OK);
    // One row of each kind per source per minute, naming the source and nothing secret.
    let failed = log_of(&net.store, SecurityEventKind::AuthFailed).await;
    let limited = log_of(&net.store, SecurityEventKind::RateLimited).await;
    assert_eq!(failed.len(), 1, "{failed:?}");
    assert_eq!(limited.len(), 1, "{limited:?}");
    assert!(failed[0].contains(attacker) && limited[0].contains(attacker));
    // Once the bucket refills the source may try again.
    net.now.fetch_add(20_000, Ordering::SeqCst);
    let reply = send(&net.app, from_peer(events_with(&good), attacker)).await;
    assert_eq!(reply.status, StatusCode::OK);
    // A minute on, failures are logged again.
    net.now.fetch_add(60_000, Ordering::SeqCst);
    send(&net.app, from_peer(events_with("garbage"), attacker)).await;
    assert_eq!(
        log_of(&net.store, SecurityEventKind::AuthFailed)
            .await
            .len(),
        2
    );
}

fn without_peer(mut req: Request<Body>) -> Request<Body> {
    req.extensions_mut().remove::<PeerAddr>();
    req
}

#[tokio::test]
async fn network_mode_request_without_peer_addr_is_500() {
    let warnings = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = Arc::clone(&warnings);
    let net = network_with(RoleAuthorize, move |c| {
        c.warn = Arc::new(move |line| sink.lock().unwrap().push(line.to_owned()));
    })
    .await;
    let good = member_token(&net.store, &BoardId::main(), "alice", Role::Member).await;
    // Fail closed on every route, with or without a valid token, without saying why.
    for req in [
        events_with(&good),
        events_with("garbage"),
        request(Method::GET, "/healthz", None, None),
        request(Method::POST, "/v1/join", None, None),
    ] {
        let reply = send(&net.app, without_peer(req)).await;
        assert_eq!(reply.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            reply.body,
            r#"{"error":{"code":"internal","message":"internal error"}}"#
        );
    }
    // One warning for the process, naming the misconfiguration and no request data.
    let lines = warnings.lock().unwrap().clone();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("peer address"), "{lines:?}");
    assert!(!lines[0].contains(&good), "{lines:?}");
    // Nothing was attributed to a shared unknown source.
    assert!(log_of(&net.store, SecurityEventKind::AuthFailed)
        .await
        .is_empty());
    // With the peer address the same request is served.
    let reply = send(&net.app, from_peer(events_with(&good), "192.0.2.1")).await;
    assert_eq!(reply.status, StatusCode::OK);
}

#[tokio::test]
async fn local_mode_needs_no_peer_addr() {
    let store = Arc::new(SqliteStore::open_memory().await.unwrap());
    let (_tx, rx) = watch::channel(false);
    let app = router(store, AllowAll, rx, ApiConfig::local());
    let req = without_peer(request(Method::GET, "/v1/boards/main/events", None, None));
    assert_eq!(send(&app, req).await.status, StatusCode::OK);
}

#[tokio::test]
async fn forged_x_forwarded_for_from_untrusted_peer_is_ignored() {
    let net = network_with(RoleAuthorize, |c| c.limits.auth_failures_per_minute = 2).await;
    let peer = "198.51.100.7";
    for i in 0..2 {
        let req = forwarded(
            from_peer(events_with("garbage"), peer),
            &format!("1.1.1.{i}"),
        );
        assert_eq!(send(&net.app, req).await.status, StatusCode::UNAUTHORIZED);
    }
    let req = forwarded(from_peer(events_with("garbage"), peer), "1.1.1.9");
    assert_rate_limited(&send(&net.app, req).await);
    for detail in log_of(&net.store, SecurityEventKind::AuthFailed).await {
        assert!(
            detail.contains(peer) && !detail.contains("1.1.1."),
            "{detail}"
        );
    }
}

#[tokio::test]
async fn x_forwarded_for_honoured_only_from_trusted_proxy() {
    let net = network_with(RoleAuthorize, |c| {
        c.limits.auth_failures_per_minute = 2;
        c.trusted_proxies = vec!["10.0.0.0/8".parse::<IpNet>().unwrap()];
    })
    .await;
    let proxy = "10.0.0.1";
    let via = |xff: &str| forwarded(from_peer(events_with("garbage"), proxy), xff);
    // The client is the first untrusted hop from the right; trusted hops are skipped.
    for _ in 0..2 {
        let reply = send(&net.app, via("192.0.2.1, 10.0.0.2")).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    }
    assert_rate_limited(&send(&net.app, via("192.0.2.1, 10.0.0.2")).await);
    // A different client behind the same proxy has its own bucket.
    let reply = send(&net.app, via("192.0.2.2, 10.0.0.2")).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    // A client cannot escape by forging hops to the left of the one the proxy appended.
    assert_rate_limited(&send(&net.app, via("192.0.2.77, 192.0.2.1")).await);
    // The proxy itself, without the header, is its own source.
    let reply = send(&net.app, from_peer(events_with("garbage"), proxy)).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    let details = log_of(&net.store, SecurityEventKind::AuthFailed).await;
    assert!(
        details.iter().any(|d| d.contains("192.0.2.1")),
        "{details:?}"
    );
}

#[tokio::test]
async fn waits_beyond_the_cap_get_429() {
    let store = Arc::new(SqliteStore::open_memory().await.unwrap());
    let (_tx, rx) = watch::channel(false);
    let mut config = ApiConfig::local();
    config.limits.max_waits = 1;
    let app = router(store, AllowAll, rx, config);
    let wait = |secs: u32| {
        request(
            Method::GET,
            &format!("/v1/boards/main/events?timeout_s={secs}"),
            None,
            None,
        )
    };
    let first = tokio::spawn({
        let app = app.clone();
        async move { send(&app, wait(10)).await.status }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    let started = Instant::now();
    let reply = send(&app, wait(5)).await;
    assert_rate_limited(&reply);
    assert!(started.elapsed() < Duration::from_secs(1));
    // A read that does not wait needs no slot.
    assert_eq!(send(&app, wait(0)).await.status, StatusCode::OK);
    // Cancelling the waiter frees its slot.
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    let reply = send(&app, wait(1)).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert_eq!(reply.json()["timed_out"], true);
}

#[tokio::test]
async fn allowed_host_extends_the_host_guard_and_rebinding_still_blocked() {
    let store = Arc::new(SqliteStore::open_memory().await.unwrap());
    let (_tx, rx) = watch::channel(false);
    let mut config = ApiConfig::local();
    config.allowed_hosts = vec!["board.example.com".to_owned()];
    let app = router(store, AllowAll, rx, config);
    let with = |host: &str, origin: Option<&str>| {
        let mut req = request(
            Method::GET,
            "/v1/boards/main/channels?prefix=eng",
            None,
            None,
        );
        req.headers_mut().insert("host", host.parse().unwrap());
        if let Some(o) = origin {
            req.headers_mut().insert("origin", o.parse().unwrap());
        }
        req
    };
    for (host, origin) in [
        ("board.example.com", None),
        ("BOARD.Example.COM:8443", None),
        ("board.example.com:443", Some("https://board.example.com")),
        ("localhost:7878", Some("http://localhost:7878")),
    ] {
        let reply = send(&app, with(host, origin)).await;
        assert_eq!(reply.status, StatusCode::OK, "{host} {origin:?}");
    }
    for (host, origin) in [
        ("evil.example", None),
        ("board.example.com.evil.example", None),
        ("evil.board.example.com", None),
        ("board.example.com@evil.example", None),
        ("board.example.com", Some("https://evil.example")),
    ] {
        let reply = send(&app, with(host, origin)).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{host} {origin:?}");
        assert_eq!(reply.json()["error"]["code"], "forbidden");
    }
}

/// A well-formed token whose id is unknown: verification has to ask the store.
fn unknown_token(i: usize) -> String {
    format!("stg1_{i:016x}_{}", "A".repeat(43))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_bad_requests_beyond_the_limit_get_429() {
    let net = network_with(RoleAuthorize, |c| c.limits.auth_failures_per_minute = 2).await;
    let mut tasks = Vec::new();
    for i in 0..20 {
        let app = net.app.clone();
        tasks.push(tokio::spawn(async move {
            send(
                &app,
                from_peer(events_with(&unknown_token(i)), "203.0.113.5"),
            )
            .await
            .status
        }));
    }
    let mut unauthorized = 0;
    for task in tasks {
        match task.await.unwrap() {
            StatusCode::UNAUTHORIZED => unauthorized += 1,
            StatusCode::TOO_MANY_REQUESTS => {}
            other => panic!("unexpected {other}"),
        }
    }
    assert!(
        unauthorized <= 2,
        "{unauthorized} requests reached verification"
    );
}

#[tokio::test]
async fn successful_requests_do_not_consume_the_failure_budget() {
    let net = network_with(RoleAuthorize, |c| c.limits.auth_failures_per_minute = 2).await;
    let good = member_token(&net.store, &BoardId::main(), "alice", Role::Member).await;
    for i in 0..100 {
        let reply = send(&net.app, from_peer(events_with(&good), "203.0.113.6")).await;
        assert_eq!(reply.status, StatusCode::OK, "request {i}");
    }
    // The whole budget is still there for failures.
    for _ in 0..2 {
        let reply = send(&net.app, from_peer(events_with("garbage"), "203.0.113.6")).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn ipv6_sources_in_one_slash_64_share_a_bucket() {
    let net = network_with(RoleAuthorize, |c| c.limits.auth_failures_per_minute = 2).await;
    for peer in ["2001:db8::1", "2001:db8::2"] {
        let reply = send(&net.app, from_peer(events_with("garbage"), peer)).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{peer}");
    }
    let same_64 = send(
        &net.app,
        from_peer(events_with("garbage"), "2001:db8::ffff:1"),
    )
    .await;
    assert_rate_limited(&same_64);
    let next_64 = send(
        &net.app,
        from_peer(events_with("garbage"), "2001:db8:0:1::1"),
    )
    .await;
    assert_eq!(next_64.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn limiter_fails_closed_for_new_keys_at_the_cap() {
    let net = network_with(RoleAuthorize, |c| {
        c.limits.auth_failures_per_minute = 1;
        c.limits.max_tracked_sources = 2;
    })
    .await;
    let good = member_token(&net.store, &BoardId::main(), "alice", Role::Member).await;
    for peer in ["192.0.2.1", "192.0.2.2"] {
        let reply = send(&net.app, from_peer(events_with("garbage"), peer)).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{peer}");
    }
    // Both slots hold drained buckets: a new source is refused, even with a good token.
    let reply = send(&net.app, from_peer(events_with(&good), "192.0.2.3")).await;
    assert_eq!(assert_rate_limited(&reply), 60);
    // Once the tracked buckets have refilled they are pruned and the new source gets in.
    net.now.fetch_add(60_000, Ordering::SeqCst);
    let reply = send(&net.app, from_peer(events_with(&good), "192.0.2.3")).await;
    assert_eq!(reply.status, StatusCode::OK);
}

#[tokio::test]
async fn limiter_memory_does_not_grow_with_forged_forwarded_for_from_untrusted_peers() {
    let net = network_with(RoleAuthorize, |c| {
        c.limits.auth_failures_per_minute = 2;
        c.limits.max_tracked_sources = 2;
    })
    .await;
    for i in 0..50 {
        let req = forwarded(
            from_peer(events_with("garbage"), "198.51.100.7"),
            &format!("192.0.2.{i}"),
        );
        let status = send(&net.app, req).await.status;
        assert!(
            status == StatusCode::UNAUTHORIZED || status == StatusCode::TOO_MANY_REQUESTS,
            "{status}"
        );
    }
    // The forged hops took no slots: a fresh source still has room for a bucket of its own.
    let reply = send(&net.app, from_peer(events_with("garbage"), "198.51.100.8")).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
}
