//! Network-mode authentication and the 401/403/404 policy.

mod common;

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use axum::http::{Method, StatusCode};
use common::*;
use serde_json::json;
use stigmer_api::{
    router, Action, AllowAll, ApiConfig, Authenticated, Authorize, Denied, RoleAuthorize, Scope,
};
use stigmer_core::{BoardId, Principal, PrincipalKind, Role};
use stigmer_store::{CredentialScope, IdentityStore, Store};
use stigmer_store_sqlite::SqliteStore;
use tokio::sync::watch;

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
        .revoke_credential(
            &token_id(&revoked),
            audit(SecurityEventKind::TokenRevoked, NOW),
        )
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
    // Change one secret character; to a different one, or one run in 64 would keep the token valid.
    let flipped = if good[good.len() - 43..].starts_with('A') {
        'B'
    } else {
        'A'
    };
    let wrong_secret = format!(
        "{}{flipped}{}",
        &good[..good.len() - 43],
        &good[good.len() - 42..]
    );
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
    net.store
        .create_board(&other, None, audit(SecurityEventKind::BoardCreated, NOW))
        .await
        .unwrap();
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
    let ops = BoardId::new("ops").unwrap();
    net.store
        .create_board(&ops, None, audit(SecurityEventKind::BoardCreated, NOW))
        .await
        .unwrap();
    let token = member_token(&net.store, &ops, "alice", Role::Admin).await;
    net.store
        .archive_board(&ops, audit(SecurityEventKind::BoardArchived, NOW))
        .await
        .unwrap();
    let reply = send(
        &net.app,
        request(
            Method::POST,
            "/v1/boards/ops/messages",
            Some(&token),
            Some(&json!({"channel": "eng", "text": "late"})),
        ),
    )
    .await;
    assert_eq!(reply.status, StatusCode::CONFLICT, "{}", reply.body);
    assert_eq!(reply.json()["error"]["code"], "board_archived");
    let reply = send(
        &net.app,
        request(Method::GET, "/v1/boards/ops/events", Some(&token), None),
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

#[tokio::test]
async fn removed_member_is_refused_on_the_very_next_request() {
    let net = network().await;
    let main = BoardId::main();
    let token = member_token(&net.store, &main, "alice", Role::Member).await;
    let get = || request(Method::GET, "/v1/boards/main/events", Some(&token), None);
    assert_eq!(send(&net.app, get()).await.status, StatusCode::OK);
    net.store
        .remove_member(
            &main,
            &Principal::new("alice").unwrap(),
            audit(SecurityEventKind::MemberRemoved, NOW),
        )
        .await
        .unwrap();
    let reply = send(&net.app, get()).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.body, UNAUTHORIZED_BODY);
}

/// Starts a long poll on main for `token` and checks that it is parked.
async fn parked_wait(net: &Net, token: &str) -> tokio::task::JoinHandle<Reply> {
    let (app, token) = (net.app.clone(), token.to_owned());
    let uri = "/v1/boards/main/events?from_now=true&timeout_s=30";
    let handle =
        tokio::spawn(
            async move { send(&app, request(Method::GET, uri, Some(&token), None)).await },
        );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!handle.is_finished(), "the wait must be parked");
    handle
}

async fn finished(handle: tokio::task::JoinHandle<Reply>) -> Reply {
    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("the wait must end once a post lands")
        .expect("wait task")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revocation_ends_an_open_wait_with_401() {
    let net = network().await;
    let main = BoardId::main();
    let revoked = member_token(&net.store, &main, "alice", Role::Member).await;
    let kept = member_token(&net.store, &main, "bob", Role::Member).await;
    let (revoked_wait, kept_wait) = (
        parked_wait(&net, &revoked).await,
        parked_wait(&net, &kept).await,
    );
    net.store
        .revoke_credential(
            &token_id(&revoked),
            audit(SecurityEventKind::TokenRevoked, NOW),
        )
        .await
        .unwrap();
    seed_thread(&net.store, &main).await;

    let reply = finished(revoked_wait).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{}", reply.body);
    assert_eq!(reply.body, UNAUTHORIZED_BODY);
    let reply = finished(kept_wait).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert_eq!(reply.json()["events"].as_array().unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn member_removal_ends_an_open_wait_with_401() {
    let net = network().await;
    let main = BoardId::main();
    let token = member_token(&net.store, &main, "alice", Role::Member).await;
    let waiting = parked_wait(&net, &token).await;
    net.store
        .remove_member(
            &main,
            &Principal::new("alice").unwrap(),
            audit(SecurityEventKind::MemberRemoved, NOW),
        )
        .await
        .unwrap();
    seed_thread(&net.store, &main).await;
    let reply = finished(waiting).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{}", reply.body);
    assert_eq!(reply.body, UNAUTHORIZED_BODY);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expiry_during_an_open_wait_ends_it_with_401() {
    let net = network().await;
    let main = BoardId::main();
    let token = member_token(&net.store, &main, "alice", Role::Member).await;
    let waiting = parked_wait(&net, &token).await;
    net.now.store(NOW + 2 * DAY, Ordering::SeqCst);
    seed_thread(&net.store, &main).await;
    let reply = finished(waiting).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{}", reply.body);
}
