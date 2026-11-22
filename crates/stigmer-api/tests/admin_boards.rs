//! Board management routes: create, list, get, archive, whoami, and local mode.

mod common;

use std::sync::Arc;

use axum::http::{Method, StatusCode};
use common::*;
use serde_json::{json, Value};
use stigmer_api::{router, AllowAll, ApiConfig};
use stigmer_core::Role;
use stigmer_store::{IdentityStore, SecurityEventKind, Store};
use stigmer_store_sqlite::SqliteStore;
use tokio::sync::watch;

fn ids(reply: &Reply) -> Vec<String> {
    reply.json()["boards"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["id"].as_str().unwrap().to_owned())
        .collect()
}

async fn create(net: &Net, token: &str, name: &str) -> Reply {
    let body = json!({"name": name});
    send(
        &net.app,
        request(Method::POST, "/v1/boards", Some(token), Some(&body)),
    )
    .await
}

#[tokio::test]
async fn instance_admin_creates_and_lists_boards() {
    let net = network().await;
    let root = instance_token(&net.store).await;
    let reply = create(&net, &root, "ops").await;
    assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
    let made = reply.json();
    assert_eq!(made["id"], "ops");
    assert_eq!(made["archived"], false);
    assert!(made["created_at_ms"].is_i64());

    let list = send(
        &net.app,
        request(Method::GET, "/v1/boards", Some(&root), None),
    )
    .await;
    assert_eq!(list.status, StatusCode::OK);
    assert_eq!(ids(&list), ["main", "ops"]);
    let one = send(
        &net.app,
        request(Method::GET, "/v1/boards/ops", Some(&root), None),
    )
    .await;
    assert_eq!(one.status, StatusCode::OK);
    assert_eq!(one.json(), made);
    let info = net.store.get_board(&board("ops")).await.unwrap();
    assert_eq!(info.created_by.unwrap().as_str(), "root");
    let log = net.store.security_log(5).await.unwrap();
    assert_eq!(log[0].kind, SecurityEventKind::BoardCreated);
    assert_eq!(log[0].board, Some(board("ops")));
}

#[tokio::test]
async fn board_admin_gets_403_creating_boards_and_sees_only_own_board_in_list() {
    let net = network().await;
    let root = instance_token(&net.store).await;
    let admin = member_token(&net.store, &board("main"), "ann", Role::Admin).await;
    assert_eq!(create(&net, &root, "ops").await.status, StatusCode::CREATED);

    let denied = create(&net, &admin, "mine").await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);
    assert_eq!(denied.json()["error"]["code"], "forbidden");

    let list = send(
        &net.app,
        request(Method::GET, "/v1/boards", Some(&admin), None),
    )
    .await;
    assert_eq!(ids(&list), ["main"]);
    let other = send(
        &net.app,
        request(Method::GET, "/v1/boards/ops", Some(&admin), None),
    )
    .await;
    assert_eq!(other.status, StatusCode::NOT_FOUND);
    // An archived own board is still listed, so its admin can see why posts fail.
    let archive = send(
        &net.app,
        request(Method::POST, "/v1/boards/main/archive", Some(&admin), None),
    )
    .await;
    assert_eq!(archive.status, StatusCode::OK, "{}", archive.body);
    let list = send(
        &net.app,
        request(Method::GET, "/v1/boards", Some(&admin), None),
    )
    .await;
    assert_eq!(list.json()["boards"][0]["archived"], true);
}

#[tokio::test]
async fn create_duplicate_board_is_409() {
    let net = network().await;
    let root = instance_token(&net.store).await;
    for name in ["main", "ops"] {
        if name == "ops" {
            assert_eq!(create(&net, &root, name).await.status, StatusCode::CREATED);
        }
        let again = create(&net, &root, name).await;
        assert_eq!(again.status, StatusCode::CONFLICT, "{name}");
        assert_eq!(again.json()["error"]["code"], "conflict");
    }
}

#[tokio::test]
async fn invalid_board_name_is_400() {
    let net = network().await;
    let root = instance_token(&net.store).await;
    for name in ["Bad Name", "", "a/b", "UPPER"] {
        let reply = create(&net, &root, name).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{name:?}");
        assert_eq!(reply.json()["error"]["code"], "invalid_input");
    }
    for body in [json!({}), json!({"name": "ok", "extra": 1}), json!([1])] {
        let reply = send(
            &net.app,
            request(Method::POST, "/v1/boards", Some(&root), Some(&body)),
        )
        .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{body}");
    }
}

#[tokio::test]
async fn archive_revokes_non_admin_tokens_keeps_admin_read_only_and_posts_409() {
    let net = network().await;
    let root = instance_token(&net.store).await;
    create(&net, &root, "ops").await;
    let ops = board("ops");
    let admin = member_token(&net.store, &ops, "ann", Role::Admin).await;
    let member = member_token(&net.store, &ops, "bob", Role::Member).await;
    let bridge = member_token(&net.store, &ops, "hook", Role::Bridge).await;
    let thread = seed_thread(&net.store, &ops).await;

    let archived = send(
        &net.app,
        request(Method::POST, "/v1/boards/ops/archive", Some(&admin), None),
    )
    .await;
    assert_eq!(archived.status, StatusCode::OK, "{}", archived.body);
    assert_eq!(archived.json()["archived"], true);

    for token in [&member, &bridge] {
        let reads = format!("/v1/boards/ops/threads/{thread}");
        let reply = send(&net.app, request(Method::GET, &reads, Some(token), None)).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert_eq!(reply.body, UNAUTHORIZED_BODY);
    }
    let read = format!("/v1/boards/ops/threads/{thread}");
    let reply = send(&net.app, request(Method::GET, &read, Some(&admin), None)).await;
    assert_eq!(reply.status, StatusCode::OK);
    let post = json!({"channel": "eng", "text": "late"});
    let reply = send(
        &net.app,
        request(
            Method::POST,
            "/v1/boards/ops/messages",
            Some(&admin),
            Some(&post),
        ),
    )
    .await;
    assert_eq!(reply.status, StatusCode::CONFLICT);
    assert_eq!(reply.json()["error"]["code"], "board_archived");
    // Archiving again changes nothing.
    let again = send(
        &net.app,
        request(Method::POST, "/v1/boards/ops/archive", Some(&admin), None),
    )
    .await;
    assert_eq!(again.status, StatusCode::OK);
    assert_eq!(again.json(), archived.json());
}

#[tokio::test]
async fn archive_allowed_for_instance_admin_and_board_admin_only() {
    let net = network().await;
    let root = instance_token(&net.store).await;
    for name in ["ops", "dev"] {
        create(&net, &root, name).await;
    }
    let member = member_token(&net.store, &board("ops"), "bob", Role::Member).await;
    let dev_admin = member_token(&net.store, &board("dev"), "dee", Role::Admin).await;
    let ops_admin = member_token(&net.store, &board("ops"), "ann", Role::Admin).await;
    let archive = |token: Option<String>, on: &str| {
        let req = request(
            Method::POST,
            &format!("/v1/boards/{on}/archive"),
            token.as_deref(),
            None,
        );
        send(&net.app, req)
    };
    assert_eq!(archive(None, "ops").await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        archive(Some(member), "ops").await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        archive(Some(dev_admin.clone()), "ops").await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(archive(Some(ops_admin), "ops").await.status, StatusCode::OK);
    assert_eq!(archive(Some(root), "dev").await.status, StatusCode::OK);
    // The instance credential reads only the board's summary.
    let summary = send(
        &net.app,
        request(Method::GET, "/v1/boards/dev", Some(&dev_admin), None),
    )
    .await;
    assert_eq!(summary.json()["archived"], true);
    let kinds: Vec<_> = net
        .store
        .security_log(50)
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.kind)
        .collect();
    assert_eq!(
        kinds
            .iter()
            .filter(|k| **k == SecurityEventKind::BoardArchived)
            .count(),
        2
    );
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

#[tokio::test]
async fn instance_credential_cannot_read_content_but_can_list_members() {
    let net = network().await;
    let root = instance_token(&net.store).await;
    member_token(&net.store, &board("main"), "ann", Role::Admin).await;
    let thread = seed_thread(&net.store, &board("main")).await;
    let members = send(
        &net.app,
        request(Method::GET, "/v1/boards/main/members", Some(&root), None),
    )
    .await;
    assert_eq!(members.status, StatusCode::OK, "{}", members.body);
    assert_eq!(members.json()["members"][0]["name"], "ann");
    for (method, uri, body) in board_routes("main", &thread) {
        let reply = send(&net.app, request(method, &uri, Some(&root), body.as_ref())).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{uri}");
    }
}

#[tokio::test]
async fn local_mode_board_routes_work_and_identity_routes_are_409() {
    let store = Arc::new(SqliteStore::open_memory().await.unwrap());
    let (_tx, rx) = watch::channel(false);
    let app = router(store, AllowAll, rx, ApiConfig::local());
    let as_alice = |method, uri: &str, body: Option<&Value>| {
        let mut req = request(method, uri, None, body);
        req.headers_mut()
            .insert("x-stigmer-as", "alice".parse().unwrap());
        req
    };
    let made = send(
        &app,
        as_alice(Method::POST, "/v1/boards", Some(&json!({"name": "ops"}))),
    )
    .await;
    assert_eq!(made.status, StatusCode::CREATED, "{}", made.body);
    let list = send(&app, as_alice(Method::GET, "/v1/boards", None)).await;
    assert_eq!(ids(&list), ["main", "ops"]);
    let one = send(&app, as_alice(Method::GET, "/v1/boards/ops", None)).await;
    assert_eq!(one.status, StatusCode::OK);
    let archived = send(&app, as_alice(Method::POST, "/v1/boards/ops/archive", None)).await;
    assert_eq!(archived.json()["archived"], true);

    let id = "0123456789abcdef";
    let invite = json!({"kind": "agent", "role": "member"});
    let join = json!({"invite": "x", "name": "bot"});
    let identity: Vec<(Method, String, Option<&Value>)> = vec![
        (Method::GET, "/v1/boards/main/members".into(), None),
        (Method::DELETE, "/v1/boards/main/members/bob".into(), None),
        (
            Method::POST,
            "/v1/boards/main/invites".into(),
            Some(&invite),
        ),
        (Method::GET, "/v1/boards/main/tokens".into(), None),
        (Method::DELETE, format!("/v1/boards/main/tokens/{id}"), None),
        (Method::POST, "/v1/join".into(), Some(&join)),
    ];
    for (method, uri, body) in identity {
        let reply = send(&app, as_alice(method, &uri, body)).await;
        assert_eq!(reply.status, StatusCode::CONFLICT, "{uri}");
        assert_eq!(reply.json()["error"]["code"], "conflict");
        assert_eq!(
            reply.json()["error"]["message"],
            "this server is in local mode; run stigmerd admin enable-auth"
        );
    }
    let who = send(&app, as_alice(Method::GET, "/v1/whoami", None)).await;
    assert_eq!(
        who.json(),
        json!({"principal": "alice", "kind": "agent", "board": null, "role": "admin", "instance_admin": false})
    );
    let anon = send(&app, request(Method::GET, "/v1/whoami", None, None)).await;
    assert_eq!(anon.json()["principal"], "anonymous");
}
