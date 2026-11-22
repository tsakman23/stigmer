//! Identity: instance mode, members, credentials, invites, local-author adoption and the
//! security log, plus the builders those scenarios share.
//!
//! Identity methods take time from the caller, so every scenario runs on the fixed clock
//! [`NOW`] and needs no sleeps.

use std::future::Future;

use stigmer_core::{hash_secret, BoardId, PrincipalKind, Role, TokenId};
use stigmer_store::{
    ConflictKind, CredentialScope, Entity, IdentityStore, Member, Mode, NewCredential, NewInvite,
    SecurityEvent, SecurityEventKind, Store, StoreError,
};

use crate::support::{board, ok, principal};
use crate::{identity_adoption, identity_credentials, identity_invites, identity_members};

/// The scenarios' fixed "now", in milliseconds since the Unix epoch.
pub(crate) const NOW: i64 = 1_700_000_000_000;
pub(crate) const HOUR: i64 = 3_600_000;

/// Runs every identity scenario, each against a fresh store from `factory`. Run it on a
/// multi-thread tokio runtime: the concurrent invite scenario spawns tasks.
pub async fn run_identity_all<S, F, Fut>(factory: F)
where
    S: Store + IdentityStore,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    fresh_store_is_local_mode(factory().await).await;
    enable_network_mode_is_one_way(factory().await).await;
    identity_methods_on_unknown_board_are_not_found(factory().await).await;
    identity_members::add_member_then_list_and_name_taken_conflict(factory().await).await;
    identity_members::member_names_are_unique_per_board_not_globally(factory().await).await;
    identity_members::remove_member_revokes_their_credentials(factory().await).await;
    identity_credentials::credential_roundtrip_and_find_unknown_is_none(factory().await).await;
    identity_credentials::revoke_credential_is_idempotent(factory().await).await;
    identity_credentials::archive_style_revoke_keeps_admins_when_asked(factory().await).await;
    identity_invites::invite_consumes_once(factory().await).await;
    identity_invites::invite_expired_is_not_found(factory().await).await;
    identity_invites::invite_wrong_hash_is_not_found_and_not_consumed(factory().await).await;
    identity_invites::invite_with_taken_name_conflicts_and_stays_unconsumed(factory().await).await;
    identity_invites::concurrent_consumes_of_one_invite_create_exactly_one_member(factory().await)
        .await;
    identity_adoption::list_local_authors_returns_distinct_sorted_authors(factory().await).await;
    identity_adoption::adopt_local_authors_creates_members_and_flips_author_kind_atomically(
        factory().await,
    )
    .await;
    identity_adoption::adopt_local_authors_leaves_the_hash_chain_valid(factory().await).await;
    security_log_newest_first_and_limited(factory().await).await;
    no_secret_material_in_security_log_rows(factory().await).await;
}

/// The token id `n` as 16 hex chars.
#[track_caller]
pub(crate) fn token_id(n: u8) -> TokenId {
    ok(TokenId::new(&format!("{n:016x}")), "test token id")
}

/// The hash of the made-up secret `seed`.
pub(crate) fn hash_of(seed: &str) -> [u8; 32] {
    hash_secret(seed)
}

pub(crate) fn hex(hash: &[u8; 32]) -> String {
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

/// A credential with id `n` for `who`, valid for 90 days from [`NOW`].
#[track_caller]
pub(crate) fn credential(n: u8, scope: CredentialScope, who: &str) -> NewCredential {
    NewCredential {
        id: token_id(n),
        secret_hash: hash_of(&format!("token-{n}")),
        scope,
        principal: principal(who),
        expires_at_ms: NOW + 90 * 24 * HOUR,
    }
}

/// An invite with id `n` into `into`, made by `root`, valid for an hour from [`NOW`].
#[track_caller]
pub(crate) fn invite(n: u8, into: &BoardId, role: Role, kind: PrincipalKind) -> NewInvite {
    NewInvite {
        id: token_id(n),
        secret_hash: hash_of(&format!("invite-{n}")),
        board: into.clone(),
        role,
        kind,
        created_by: principal("root"),
        expires_at_ms: NOW + HOUR,
    }
}

#[track_caller]
pub(crate) fn member(
    on: &BoardId,
    name: &str,
    kind: PrincipalKind,
    role: Role,
    at_ms: i64,
) -> Member {
    Member {
        board: on.clone(),
        name: principal(name),
        kind,
        role,
        created_at_ms: at_ms,
    }
}

pub(crate) fn not_found(entity: Entity, id: impl ToString) -> StoreError {
    StoreError::NotFound {
        entity,
        id: id.to_string(),
    }
}

async fn fresh_store_is_local_mode<S: IdentityStore>(store: S) {
    const SCENARIO: &str = "fresh_store_is_local_mode";
    assert_eq!(store.mode().await, Ok(Mode::Local), "{SCENARIO}");
}

async fn enable_network_mode_is_one_way<S: IdentityStore>(store: S) {
    const SCENARIO: &str = "enable_network_mode_is_one_way";
    assert_eq!(store.enable_network_mode().await, Ok(()), "{SCENARIO}");
    assert_eq!(store.mode().await, Ok(Mode::Network), "{SCENARIO}");
    assert_eq!(
        store.enable_network_mode().await,
        Err(StoreError::Conflict(ConflictKind::AlreadyNetwork)),
        "{SCENARIO}: second call"
    );
    assert_eq!(
        store.mode().await,
        Ok(Mode::Network),
        "{SCENARIO}: still network"
    );
}

async fn identity_methods_on_unknown_board_are_not_found<S: Store + IdentityStore>(store: S) {
    const SCENARIO: &str = "identity_methods_on_unknown_board_are_not_found";
    let nowhere = board("nowhere");
    let alice = principal("alice");
    let expect = |result: Result<(), StoreError>, method: &str| {
        assert_eq!(
            result,
            Err(not_found(Entity::Board, "nowhere")),
            "{SCENARIO}: {method}"
        );
    };
    let (human, admin) = (PrincipalKind::Human, Role::Admin);
    let added = store.add_member(&nowhere, &alice, human, admin, NOW).await;
    expect(added.map(drop), "add_member");
    expect(
        store.get_member(&nowhere, &alice).await.map(drop),
        "get_member",
    );
    expect(store.list_members(&nowhere).await.map(drop), "list_members");
    let removed = store.remove_member(&nowhere, &alice, NOW).await;
    expect(removed, "remove_member");
    let authors = store.list_local_authors(&nowhere).await;
    expect(authors.map(drop), "list_local_authors");
    let adopted = store.adopt_local_authors(&nowhere, &[], NOW).await;
    expect(adopted.map(drop), "adopt_local_authors");
    let listed = store.list_credentials(&nowhere).await;
    expect(listed.map(drop), "list_credentials");
    let revoked = store.revoke_board_credentials(&nowhere, false, NOW).await;
    expect(revoked.map(drop), "revoke_board_credentials");
    let scoped = credential(1, CredentialScope::Board(nowhere.clone()), "alice");
    expect(
        store.create_credential(scoped, NOW).await,
        "create_credential",
    );
    let into = invite(2, &nowhere, Role::Member, PrincipalKind::Agent);
    expect(store.create_invite(into, NOW).await, "create_invite");
    assert_eq!(
        store.find_credential(&token_id(1)).await,
        Ok(None),
        "{SCENARIO}: nothing was stored"
    );
}

fn event(
    at_ms: i64,
    kind: SecurityEventKind,
    on: Option<BoardId>,
    who: Option<&str>,
) -> SecurityEvent {
    SecurityEvent {
        at_ms,
        kind,
        board: on,
        principal: who.map(str::to_owned),
        detail: format!("{kind} at {at_ms}"),
    }
}

async fn security_log_newest_first_and_limited<S: IdentityStore>(store: S) {
    const SCENARIO: &str = "security_log_newest_first_and_limited";
    let events = vec![
        event(NOW, SecurityEventKind::ModeEnabled, None, None),
        event(
            NOW + 1,
            SecurityEventKind::BoardCreated,
            Some(board("research")),
            Some("root"),
        ),
        event(
            NOW + 2,
            SecurityEventKind::Join,
            Some(BoardId::main()),
            Some("alice"),
        ),
        event(NOW + 3, SecurityEventKind::AuthFailed, None, None),
        // Logged later but stamped earlier: the log keeps insertion order.
        event(
            NOW - 5,
            SecurityEventKind::RateLimited,
            None,
            Some("unknown"),
        ),
    ];
    for e in &events {
        ok(
            store.log_security(e.clone()).await,
            format_args!("{SCENARIO}: log {}", e.kind),
        );
    }
    let newest_first: Vec<_> = events.iter().rev().cloned().collect();
    assert_eq!(
        store.security_log(3).await,
        Ok(newest_first[..3].to_vec()),
        "{SCENARIO}: limit 3"
    );
    assert_eq!(
        store.security_log(50).await,
        Ok(newest_first),
        "{SCENARIO}: all"
    );
    assert_eq!(
        store.security_log(0).await,
        Ok(vec![]),
        "{SCENARIO}: limit 0"
    );
}

async fn no_secret_material_in_security_log_rows<S: Store + IdentityStore>(store: S) {
    const SCENARIO: &str = "no_secret_material_in_security_log_rows";
    let main = BoardId::main();
    let token = credential(1, CredentialScope::Board(main.clone()), "alice");
    let into = invite(2, &main, Role::Member, PrincipalKind::Agent);
    let (token_hash, invite_hash, wrong_hash) =
        (token.secret_hash, into.secret_hash, hash_of("wrong"));
    ok(store.create_credential(token, NOW).await, SCENARIO);
    ok(store.create_invite(into, NOW).await, SCENARIO);

    let refused = store
        .consume_invite(&token_id(2), &wrong_hash, &principal("dave"), NOW)
        .await;
    let joined = ok(
        store
            .consume_invite(&token_id(2), &invite_hash, &principal("dave"), NOW)
            .await,
        format_args!("{SCENARIO}: join"),
    );
    // What an API would log for these: ids and names, never secrets.
    for e in [
        event(NOW, SecurityEventKind::AuthFailed, Some(main.clone()), None),
        SecurityEvent {
            detail: format!("joined with invite {}", token_id(2)),
            ..event(
                NOW,
                SecurityEventKind::Join,
                Some(main.clone()),
                Some("dave"),
            )
        },
    ] {
        ok(store.log_security(e).await, SCENARIO);
    }
    let found = ok(store.find_credential(&token_id(1)).await, SCENARIO);
    let log = ok(store.security_log(50).await, SCENARIO);

    let mut shown = vec![
        format!("{refused:?}"),
        format!("{joined:?}"),
        format!("{found:?}"),
    ];
    if let Err(e) = &refused {
        shown.push(e.to_string());
    }
    shown.extend(log.iter().map(|e| format!("{e:?}")));
    for text in &shown {
        for hash in [&token_hash, &invite_hash, &wrong_hash] {
            assert!(
                !text.contains(&hex(hash)) && !text.contains(&format!("{hash:?}")),
                "{SCENARIO}: a secret hash leaked into {text}"
            );
        }
    }
    assert_eq!(
        log.len(),
        2,
        "{SCENARIO}: the store logs only what it is given"
    );
}
