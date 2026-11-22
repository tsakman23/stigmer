//! Join and whoami: redeeming invites, the join rate limit, and who a token is.

mod common;

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::http::{Method, Request, StatusCode};
use common::*;
use serde_json::json;
use stigmer_api::{ApiConfig, RoleAuthorize};
use stigmer_core::Role;
use stigmer_store::IdentityStore;

#[tokio::test]
async fn invite_join_roundtrip_returns_token_once_and_whoami_matches() {
    let net = network().await;
    let admin = member_token(&net.store, &board("main"), "ann", Role::Admin).await;
    let invite = mint_invite(&net.app, &admin, "main", "agent", "member").await;
    assert!(invite.starts_with("stgi1_"));

    let joined = join_as(&net.app, &invite, "bot-1").await;
    assert_eq!(joined.status, StatusCode::CREATED, "{}", joined.body);
    let body = joined.json();
    let token = body["token"].as_str().unwrap().to_owned();
    assert!(token.starts_with("stg1_"));
    assert_eq!(body["board"], "main");
    assert_eq!(body["role"], "member");
    assert_eq!(body["kind"], "agent");
    assert_eq!(body["expires_at_ms"], NOW + 90 * DAY);

    let who = get(&net, "/v1/whoami", &token).await;
    assert_eq!(
        who.json(),
        json!({"principal": "bot-1", "kind": "agent", "board": "main", "role": "member", "instance_admin": false})
    );
    // The invite is single use and the token is never shown again.
    let again = join_as(&net.app, &invite, "bot-2").await;
    assert_eq!(again.status, StatusCode::UNAUTHORIZED);
    let tokens = get(&net, "/v1/boards/main/tokens", &admin).await;
    assert!(!tokens.body.contains(&token));
}

#[tokio::test]
async fn join_with_taken_name_is_409_and_invite_still_usable() {
    let net = network().await;
    let admin = member_token(&net.store, &board("main"), "ann", Role::Admin).await;
    let invite = mint_invite(&net.app, &admin, "main", "human", "member").await;
    let taken = join_as(&net.app, &invite, "ann").await;
    assert_eq!(taken.status, StatusCode::CONFLICT);
    assert_eq!(taken.json()["error"]["code"], "conflict");
    let ok = join_as(&net.app, &invite, "bob").await;
    assert_eq!(ok.status, StatusCode::CREATED, "{}", ok.body);
}

#[tokio::test]
async fn join_with_bad_expired_or_used_invite_returns_the_identical_401() {
    let net = network().await;
    let root = instance_token(&net.store).await;
    let admin = member_token(&net.store, &board("main"), "ann", Role::Admin).await;
    let good = mint_invite(&net.app, &admin, "main", "human", "member").await;
    let used = mint_invite(&net.app, &admin, "main", "human", "member").await;
    assert_eq!(
        join_as(&net.app, &used, "u1").await.status,
        StatusCode::CREATED
    );
    let expired = mint_invite(&net.app, &admin, "main", "human", "member").await;
    send(
        &net.app,
        request(
            Method::POST,
            "/v1/boards",
            Some(&root),
            Some(&json!({"name": "ops"})),
        ),
    )
    .await;
    let ops_admin = member_token(&net.store, &board("ops"), "oda", Role::Admin).await;
    let archived = mint_invite(&net.app, &ops_admin, "ops", "human", "member").await;
    let archive = request(Method::POST, "/v1/boards/ops/archive", Some(&root), None);
    assert_eq!(send(&net.app, archive).await.status, StatusCode::OK);

    let (id, secret) = good["stgi1_".len()..].split_at(16);
    let wrong_secret = format!("stgi1_{id}_{}", "x".repeat(secret.len() - 1));
    let unknown = format!("stgi1_0000000000000000_{}", &secret[1..]);
    let token_kind = member_token(&net.store, &board("main"), "tk", Role::Member).await;
    let cases = [
        "garbage".to_owned(),
        String::new(),
        wrong_secret,
        unknown,
        token_kind,
        used,
        archived,
    ];
    // The reference: what the authentication middleware answers to a bad token.
    let reference = get(&net, "/v1/whoami", "stg1_not_a_token").await;
    assert_eq!(reference.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reference.body, UNAUTHORIZED_BODY);
    let same_as_reference = |reply: &Reply, what: &str| {
        assert_eq!(reply.status, reference.status, "{what}");
        assert_eq!(reply.headers, reference.headers, "{what}");
        assert_eq!(reply.body, reference.body, "{what}");
    };
    for invite in &cases {
        same_as_reference(&join_as(&net.app, invite, "newcomer").await, invite);
    }
    net.now.fetch_add(2 * DAY, Ordering::SeqCst);
    same_as_reference(&join_as(&net.app, &expired, "newcomer").await, "expired");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_joins_with_one_invite_succeed_exactly_once() {
    let net = network().await;
    let admin = member_token(&net.store, &board("main"), "ann", Role::Admin).await;
    let invite = mint_invite(&net.app, &admin, "main", "agent", "member").await;
    let tasks: Vec<_> = (0..8)
        .map(|i| {
            let (app, invite) = (net.app.clone(), invite.clone());
            tokio::spawn(async move { join_as(&app, &invite, &format!("bot-{i}")).await.status })
        })
        .collect();
    let mut created = 0;
    for task in tasks {
        match task.await.unwrap() {
            StatusCode::CREATED => created += 1,
            other => assert_eq!(other, StatusCode::UNAUTHORIZED),
        }
    }
    assert_eq!(created, 1);
    let members = net.store.list_members(&board("main")).await.unwrap();
    assert_eq!(members.len(), 2);
    // Exactly one credential for the one new member, besides the admin's own.
    let credentials = net.store.list_credentials(&board("main")).await.unwrap();
    let bots: Vec<_> = credentials
        .iter()
        .filter(|c| c.principal.as_str().starts_with("bot-"))
        .collect();
    assert_eq!(bots.len(), 1);
    assert_eq!(credentials.len(), 2);
}

#[tokio::test]
async fn join_is_rate_limited() {
    let net = network_with(RoleAuthorize, |c: &mut ApiConfig| {
        c.limits.join_per_minute = 2;
        c.limits.auth_failures_per_minute = 10_000;
    })
    .await;
    let admin = member_token(&net.store, &board("main"), "ann", Role::Admin).await;
    let attempt = || async {
        let body = json!({"invite": "garbage", "name": "bot"});
        let req = request(Method::POST, "/v1/join", None, Some(&body));
        send(&net.app, from_peer(req, "192.0.2.9")).await
    };
    assert_eq!(attempt().await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(attempt().await.status, StatusCode::UNAUTHORIZED);
    let limited = attempt().await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(limited.headers.contains_key("retry-after"));
    assert_eq!(limited.json()["error"]["code"], "rate_limited");
    // The join budget is its own: authenticated requests from the same source still pass.
    let who = from_peer(
        request(Method::GET, "/v1/whoami", Some(&admin), None),
        "192.0.2.9",
    );
    assert_eq!(send(&net.app, who).await.status, StatusCode::OK);
}

#[tokio::test]
async fn whoami_matches_the_credential() {
    let net = network().await;
    let root = instance_token(&net.store).await;
    let main = board("main");
    let admin = member_token(&net.store, &main, "ann", Role::Admin).await;
    let bridge = member_token(&net.store, &main, "hook", Role::Bridge).await;
    async fn who(net: &Net, token: String) -> serde_json::Value {
        let reply = send(
            &net.app,
            request(Method::GET, "/v1/whoami", Some(&token), None),
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        reply.json()
    }
    assert_eq!(
        who(&net, admin).await,
        json!({"principal": "ann", "kind": "human", "board": "main", "role": "admin", "instance_admin": false})
    );
    assert_eq!(
        who(&net, bridge).await,
        json!({"principal": "hook", "kind": "bridge", "board": "main", "role": "bridge", "instance_admin": false})
    );
    assert_eq!(
        who(&net, root).await,
        json!({"principal": "root", "kind": "human", "board": null, "role": null, "instance_admin": true})
    );
    let anon = send(&net.app, request(Method::GET, "/v1/whoami", None, None)).await;
    assert_eq!(anon.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn join_limit_survives_a_concurrent_flood() {
    const LIMIT: u32 = 5;
    const FLOOD: usize = 40;
    let net = network_with(RoleAuthorize, |c: &mut ApiConfig| {
        c.limits.join_per_minute = LIMIT;
        c.limits.auth_failures_per_minute = 10_000;
    })
    .await;
    let admin = member_token(&net.store, &board("main"), "ann", Role::Admin).await;
    let mut invites = Vec::new();
    for _ in 0..FLOOD {
        invites.push(mint_invite(&net.app, &admin, "main", "agent", "member").await);
    }
    let tasks: Vec<_> = invites
        .into_iter()
        .enumerate()
        .map(|(i, invite)| {
            let app = net.app.clone();
            tokio::spawn(async move {
                let req = request(
                    Method::POST,
                    "/v1/join",
                    None,
                    Some(&json!({"invite": invite, "name": format!("bot-{i}")})),
                );
                send(&app, from_peer(req, "192.0.2.9")).await.status
            })
        })
        .collect();
    let mut created = 0;
    let mut limited = 0;
    for task in tasks {
        match task.await.unwrap() {
            StatusCode::CREATED => created += 1,
            StatusCode::TOO_MANY_REQUESTS => limited += 1,
            other => panic!("unexpected {other}"),
        }
    }
    // Only the limit's worth of attempts reached the store: every other invite is unused.
    assert_eq!((created, limited), (LIMIT as usize, FLOOD - LIMIT as usize));
    let members = net.store.list_members(&board("main")).await.unwrap();
    assert_eq!(members.len(), 1 + LIMIT as usize);
}

#[tokio::test]
async fn join_limit_ignores_forged_x_forwarded_for_from_an_untrusted_peer() {
    let net = network_with(RoleAuthorize, |c: &mut ApiConfig| {
        c.limits.join_per_minute = 2;
        c.limits.auth_failures_per_minute = 10_000;
    })
    .await;
    let mut statuses = Vec::new();
    for i in 0..4 {
        let body = json!({"invite": "garbage", "name": "bot"});
        let mut req = request(Method::POST, "/v1/join", None, Some(&body));
        req.headers_mut()
            .insert("x-forwarded-for", format!("203.0.113.{i}").parse().unwrap());
        statuses.push(send(&net.app, from_peer(req, "192.0.2.9")).await.status);
    }
    assert_eq!(
        statuses,
        [
            StatusCode::UNAUTHORIZED,
            StatusCode::UNAUTHORIZED,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::TOO_MANY_REQUESTS,
        ]
    );
}

#[tokio::test]
async fn join_budget_is_separate_from_the_auth_failure_budget() {
    let net = network_with(RoleAuthorize, |c: &mut ApiConfig| {
        c.limits.join_per_minute = 2;
        c.limits.auth_failures_per_minute = 2;
    })
    .await;
    let admin = member_token(&net.store, &board("main"), "ann", Role::Admin).await;
    let bad_join = |peer: &'static str| {
        let body = json!({"invite": "garbage", "name": "bot"});
        send(
            &net.app,
            from_peer(request(Method::POST, "/v1/join", None, Some(&body)), peer),
        )
    };
    let whoami = |token: String, peer: &'static str| {
        let req = request(Method::GET, "/v1/whoami", Some(&token), None);
        let app = net.app.clone();
        async move { send(&app, from_peer(req, peer)).await.status }
    };
    // Source A runs out of failed authentications; its joins are untouched.
    for _ in 0..2 {
        assert_eq!(
            whoami("junk".into(), "192.0.2.1").await,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        whoami("junk".into(), "192.0.2.1").await,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(bad_join("192.0.2.1").await.status, StatusCode::UNAUTHORIZED);
    // Source B runs out of joins; its authentication is untouched.
    for _ in 0..2 {
        assert_eq!(bad_join("192.0.2.2").await.status, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(
        bad_join("192.0.2.2").await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(whoami(admin.clone(), "192.0.2.2").await, StatusCode::OK);
    assert_eq!(
        whoami("junk".into(), "192.0.2.2").await,
        StatusCode::UNAUTHORIZED
    );
}

/// A request body whose bytes never arrive.
struct NeverSent;

impl http_body::Body for NeverSent {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, Infallible>>> {
        Poll::Pending
    }
}

#[tokio::test]
async fn join_limit_answers_429_without_waiting_for_the_body() {
    let net = network_with(RoleAuthorize, |c| c.limits.join_per_minute = 1).await;
    let spent = join_as(&net.app, "stgi1_not-an-invite", "bot").await;
    assert_eq!(spent.status, StatusCode::UNAUTHORIZED, "{}", spent.body);

    let stalled = Request::builder()
        .method(Method::POST)
        .uri("/v1/join")
        .header("content-type", "application/json")
        .header("content-length", "64")
        .extension(stigmer_api::PeerAddr(DEFAULT_PEER.parse().unwrap()))
        .body(Body::new(NeverSent))
        .unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(5), send(&net.app, stalled))
        .await
        .expect("the 429 must not wait for a body that never comes");
    assert_eq!(
        reply.status,
        StatusCode::TOO_MANY_REQUESTS,
        "{}",
        reply.body
    );
    assert_eq!(reply.json()["error"]["code"], "rate_limited");
}

#[tokio::test]
async fn invalid_join_body_never_echoes_the_submitted_invite() {
    let net = network().await;
    let admin = member_token(&net.store, &board("main"), "ann", Role::Admin).await;
    let invite = mint_invite(&net.app, &admin, "main", "agent", "member").await;
    let bodies = [
        // Swapped fields: the invite lands where a name belongs.
        json!({"invite": "bot", "name": invite}),
        json!({"invite": invite, "name": "Not A Name"}),
        json!({"invite": invite, "name": "bot", invite.clone(): 1}),
        json!({"invite": invite}),
    ];
    for body in bodies {
        let reply = send(
            &net.app,
            request(Method::POST, "/v1/join", None, Some(&body)),
        )
        .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.body);
        assert_eq!(
            reply.json(),
            json!({"error": {"code": "invalid_input", "message": "invalid join request"}})
        );
        assert!(!reply.body.contains(&invite));
    }
    // The invite was never used.
    let joined = join_as(&net.app, &invite, "bot").await;
    assert_eq!(joined.status, StatusCode::CREATED, "{}", joined.body);
}
