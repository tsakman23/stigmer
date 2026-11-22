//! Invites, join, members and tokens, and the security log they write.

mod common;

use axum::http::{Method, StatusCode};
use common::*;
use serde_json::json;
use stigmer_api::{ApiConfig, RoleAuthorize};
use stigmer_core::{hash_secret, Role};
use stigmer_store::{IdentityStore, SecurityEventKind};

const MINUTE: i64 = 60_000;

async fn get(net: &Net, uri: &str, token: &str) -> Reply {
    send(&net.app, request(Method::GET, uri, Some(token), None)).await
}

async fn delete(net: &Net, uri: &str, token: &str) -> Reply {
    send(&net.app, request(Method::DELETE, uri, Some(token), None)).await
}

async fn invite_with(net: &Net, token: &str, body: serde_json::Value) -> Reply {
    let req = request(
        Method::POST,
        "/v1/boards/main/invites",
        Some(token),
        Some(&body),
    );
    send(&net.app, req).await
}

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
    for invite in &cases {
        let reply = join_as(&net.app, invite, "newcomer").await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{invite:?}");
        assert_eq!(reply.body, UNAUTHORIZED_BODY, "{invite:?}");
        assert!(reply.headers.contains_key("www-authenticate"));
    }
    net.now
        .fetch_add(2 * DAY, std::sync::atomic::Ordering::SeqCst);
    let late = join_as(&net.app, &expired, "newcomer").await;
    assert_eq!(late.body, UNAUTHORIZED_BODY);
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
}

#[tokio::test]
async fn member_lists_are_visible_to_board_admin_and_instance_admin_only() {
    let net = network().await;
    let root = instance_token(&net.store).await;
    let main = board("main");
    let admin = member_token(&net.store, &main, "ann", Role::Admin).await;
    let member = member_token(&net.store, &main, "bob", Role::Member).await;
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
    let other = member_token(&net.store, &board("ops"), "oda", Role::Admin).await;
    let uri = "/v1/boards/main/members";
    for token in [&admin, &root] {
        let reply = get(&net, uri, token).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        let names: Vec<_> = reply.json()["members"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["name"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(names, ["ann", "bob"]);
    }
    assert!(get(&net, uri, &admin).await.json()["members"][0]["last_seen_ms"].is_i64());
    assert_eq!(get(&net, uri, &member).await.status, StatusCode::FORBIDDEN);
    assert_eq!(get(&net, uri, &other).await.status, StatusCode::NOT_FOUND);
    let anon = send(&net.app, request(Method::GET, uri, None, None)).await;
    assert_eq!(anon.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn tokens_list_never_contains_secrets_or_hashes() {
    let net = network().await;
    let main = board("main");
    let admin = member_token(&net.store, &main, "ann", Role::Admin).await;
    let member = member_token(&net.store, &main, "bob", Role::Member).await;
    let reply = get(&net, "/v1/boards/main/tokens", &admin).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let tokens = reply.json()["tokens"].as_array().unwrap().clone();
    assert_eq!(tokens.len(), 2);
    for token in &tokens {
        let mut keys: Vec<_> = token.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "expires_at_ms",
                "id",
                "last_seen_ms",
                "principal",
                "revoked",
                "role"
            ]
        );
    }
    let bob = tokens.iter().find(|t| t["principal"] == "bob").unwrap();
    assert_eq!(bob["role"], "member");
    assert_eq!(bob["id"], token_id(&member).as_str());
    for full in [&admin, &member] {
        let secret = &full["stg1_".len() + 17..];
        let hash: String = hash_secret(secret)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert!(!reply.body.contains(secret));
        assert!(!reply.body.contains(&hash));
        assert!(!reply.body.contains(full.as_str()));
    }
}

#[tokio::test]
async fn revoked_token_is_refused_on_the_next_request() {
    let net = network().await;
    let main = board("main");
    let admin = member_token(&net.store, &main, "ann", Role::Admin).await;
    let member = member_token(&net.store, &main, "bob", Role::Member).await;
    let events = "/v1/boards/main/events";
    assert_eq!(get(&net, events, &member).await.status, StatusCode::OK);

    let uri = format!("/v1/boards/main/tokens/{}", token_id(&member));
    assert_eq!(
        delete(&net, &uri, &admin).await.status,
        StatusCode::NO_CONTENT
    );
    let refused = get(&net, events, &member).await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
    assert_eq!(refused.body, UNAUTHORIZED_BODY);
    // Revoking again is fine and writes no second row.
    assert_eq!(
        delete(&net, &uri, &admin).await.status,
        StatusCode::NO_CONTENT
    );
    let unknown = "/v1/boards/main/tokens/0000000000000000";
    assert_eq!(
        delete(&net, unknown, &admin).await.status,
        StatusCode::NOT_FOUND
    );
    let malformed = "/v1/boards/main/tokens/nope";
    assert_eq!(
        delete(&net, malformed, &admin).await.status,
        StatusCode::NOT_FOUND
    );
    let log = net.store.security_log(10).await.unwrap();
    let revoked = log
        .iter()
        .filter(|e| e.kind == SecurityEventKind::TokenRevoked);
    assert_eq!(revoked.count(), 1);
    let listed = get(&net, "/v1/boards/main/tokens", &admin).await;
    let tokens = listed.json()["tokens"].as_array().unwrap().clone();
    let bob = tokens.iter().find(|t| t["principal"] == "bob").unwrap();
    assert_eq!(bob["revoked"], true);
}

#[tokio::test]
async fn token_of_another_board_cannot_be_revoked_through_this_one() {
    let net = network().await;
    let root = instance_token(&net.store).await;
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
    let admin = member_token(&net.store, &board("main"), "ann", Role::Admin).await;
    let ops = member_token(&net.store, &board("ops"), "oda", Role::Member).await;
    for id in [token_id(&ops), token_id(&root)] {
        let uri = format!("/v1/boards/main/tokens/{id}");
        assert_eq!(
            delete(&net, &uri, &admin).await.status,
            StatusCode::NOT_FOUND
        );
    }
    assert_eq!(get(&net, "/v1/whoami", &ops).await.status, StatusCode::OK);
    assert_eq!(get(&net, "/v1/whoami", &root).await.status, StatusCode::OK);
}

#[tokio::test]
async fn remove_member_revokes_tokens() {
    let net = network().await;
    let main = board("main");
    let admin = member_token(&net.store, &main, "ann", Role::Admin).await;
    let member = member_token(&net.store, &main, "bob", Role::Member).await;
    assert_eq!(
        delete(&net, "/v1/boards/main/members/bob", &member)
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    let removed = delete(&net, "/v1/boards/main/members/bob", &admin).await;
    assert_eq!(removed.status, StatusCode::NO_CONTENT);
    assert_eq!(
        get(&net, "/v1/whoami", &member).await.status,
        StatusCode::UNAUTHORIZED
    );
    let again = delete(&net, "/v1/boards/main/members/bob", &admin).await;
    assert_eq!(again.status, StatusCode::NOT_FOUND);
    let members = get(&net, "/v1/boards/main/members", &admin).await;
    assert_eq!(members.json()["members"].as_array().unwrap().len(), 1);
    // An admin may remove themselves; their own token then stops working.
    let me = delete(&net, "/v1/boards/main/members/ann", &admin).await;
    assert_eq!(me.status, StatusCode::NO_CONTENT);
    assert_eq!(
        get(&net, "/v1/whoami", &admin).await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn invite_expiry_default_60_minutes_max_7_days() {
    let net = network().await;
    let admin = member_token(&net.store, &board("main"), "ann", Role::Admin).await;
    let invite = |minutes: Option<u64>| {
        let mut body = json!({"kind": "agent", "role": "member"});
        if let Some(m) = minutes {
            body["expires_in_minutes"] = json!(m);
        }
        invite_with(&net, &admin, body)
    };
    let default = invite(None).await;
    assert_eq!(default.status, StatusCode::CREATED);
    assert_eq!(default.json()["expires_at_ms"], NOW + 60 * MINUTE);
    for (minutes, expires) in [(1, NOW + MINUTE), (10_080, NOW + 7 * DAY)] {
        let reply = invite(Some(minutes)).await;
        assert_eq!(reply.status, StatusCode::CREATED, "{minutes}");
        assert_eq!(reply.json()["expires_at_ms"], expires);
    }
    for minutes in [0, 10_081] {
        let reply = invite(Some(minutes)).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{minutes}");
        assert_eq!(reply.json()["error"]["code"], "invalid_input");
    }
}

#[tokio::test]
async fn invite_kind_role_combinations_are_validated() {
    let net = network().await;
    let admin = member_token(&net.store, &board("main"), "ann", Role::Admin).await;
    let combos = [
        ("human", "admin", true),
        ("human", "member", true),
        ("agent", "admin", true),
        ("agent", "member", true),
        ("bridge", "bridge", true),
        ("bridge", "member", false),
        ("bridge", "admin", false),
        ("human", "bridge", false),
        ("agent", "bridge", false),
    ];
    for (kind, role, allowed) in combos {
        let reply = invite_with(&net, &admin, json!({"kind": kind, "role": role})).await;
        let want = if allowed {
            StatusCode::CREATED
        } else {
            StatusCode::BAD_REQUEST
        };
        assert_eq!(reply.status, want, "{kind}/{role}: {}", reply.body);
    }
}

#[tokio::test]
async fn no_token_can_be_obtained_for_an_archived_board() {
    let net = network().await;
    let root = instance_token(&net.store).await;
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
    let ops = board("ops");
    let admin = member_token(&net.store, &ops, "oda", Role::Admin).await;
    let member = member_token(&net.store, &ops, "mo", Role::Member).await;
    let invite = mint_invite(&net.app, &admin, "ops", "agent", "member").await;
    let archive = request(Method::POST, "/v1/boards/ops/archive", Some(&admin), None);
    assert_eq!(send(&net.app, archive).await.status, StatusCode::OK);

    assert_eq!(
        get(&net, "/v1/whoami", &member).await.status,
        StatusCode::UNAUTHORIZED
    );
    let joined = join_as(&net.app, &invite, "late").await;
    assert_eq!(joined.body, UNAUTHORIZED_BODY);
    let body = json!({"kind": "agent", "role": "member"});
    let req = request(
        Method::POST,
        "/v1/boards/ops/invites",
        Some(&admin),
        Some(&body),
    );
    let minted = send(&net.app, req).await;
    assert_eq!(minted.status, StatusCode::CONFLICT);
    assert_eq!(minted.json()["error"]["code"], "board_archived");
    assert_eq!(
        get(&net, "/v1/boards/ops/events", &admin).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn every_mutation_writes_a_security_log_row_without_secrets() {
    let net = network().await;
    let root = instance_token(&net.store).await;
    let peer = "192.0.2.7";
    let call = |method, uri: &str, token: &str, body: Option<serde_json::Value>| {
        let req = from_peer(request(method, uri, Some(token), body.as_ref()), peer);
        send(&net.app, req)
    };
    let made = call(
        Method::POST,
        "/v1/boards",
        &root,
        Some(json!({"name": "ops"})),
    )
    .await;
    assert_eq!(made.status, StatusCode::CREATED);
    let admin = member_token(&net.store, &board("ops"), "oda", Role::Admin).await;
    let minted = call(
        Method::POST,
        "/v1/boards/ops/invites",
        &admin,
        Some(json!({"kind": "agent", "role": "member"})),
    )
    .await;
    let invite = minted.json()["invite"].as_str().unwrap().to_owned();
    let body = json!({"invite": invite, "name": "bot"});
    let join = from_peer(request(Method::POST, "/v1/join", None, Some(&body)), peer);
    let joined = send(&net.app, join).await;
    let token = joined.json()["token"].as_str().unwrap().to_owned();
    let revoke = format!("/v1/boards/ops/tokens/{}", token_id(&token));
    assert_eq!(
        call(Method::DELETE, &revoke, &admin, None).await.status,
        StatusCode::NO_CONTENT
    );
    let remove = call(Method::DELETE, "/v1/boards/ops/members/bot", &admin, None).await;
    assert_eq!(remove.status, StatusCode::NO_CONTENT);
    let archived = call(Method::POST, "/v1/boards/ops/archive", &admin, None).await;
    assert_eq!(archived.status, StatusCode::OK);

    let mut log = net.store.security_log(50).await.unwrap();
    log.reverse();
    let kinds: Vec<_> = log.iter().map(|e| e.kind).collect();
    assert_eq!(
        kinds,
        [
            SecurityEventKind::BoardCreated,
            SecurityEventKind::InviteCreated,
            SecurityEventKind::Join,
            SecurityEventKind::TokenRevoked,
            SecurityEventKind::MemberRemoved,
            SecurityEventKind::BoardArchived,
        ]
    );
    let secrets = [&invite[6..], &token[5..], &token, &invite];
    for event in &log {
        assert_eq!(event.board, Some(board("ops")));
        assert!(event.detail.contains("source=192.0.2.7"), "{event:?}");
        for secret in secrets {
            assert!(!event.detail.contains(secret), "{event:?}");
        }
    }
    assert_eq!(log[0].principal.as_deref(), Some("root"));
    assert_eq!(log[2].principal.as_deref(), Some("bot"));
    assert!(log[3].detail.contains(token_id(&token).as_str()));
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
