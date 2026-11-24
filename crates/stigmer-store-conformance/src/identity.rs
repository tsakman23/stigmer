//! Identity: instance mode, members, credentials, invites, local-author adoption and the
//! security log, plus the builders those scenarios share.
//!
//! Identity methods take time from the caller, so every scenario runs on the fixed clock
//! [`NOW`] and needs no sleeps.

use std::future::Future;

use stigmer_core::{hash_secret, BoardId, PrincipalKind, Role, TokenId};
use stigmer_store::{
    ConflictKind, CredentialScope, Entity, IdentityStore, Member, Mode, NewCredential, NewInvite,
    NewJoinCredential, Store, StoreError,
};

use crate::support::{board, ok, principal};
use crate::support::{invite_created, member_removed, mode_enabled, token_issued};
use crate::{
    identity_adoption, identity_archive, identity_audit, identity_audit_failures,
    identity_credentials, identity_enable, identity_invites, identity_join, identity_log,
    identity_members,
};

pub(crate) use crate::support::NOW;
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
    identity_members::instance_admin_is_a_reserved_member_name(factory().await).await;
    identity_credentials::credential_roundtrip_and_find_unknown_is_none(factory().await).await;
    identity_credentials::revoke_credential_is_idempotent(factory().await).await;
    identity_credentials::archive_style_revoke_keeps_admins_when_asked(factory().await).await;
    identity_credentials::revoke_instance_credentials_except_spares_the_kept_one_and_board_credentials(
        factory().await,
    )
    .await;
    identity_credentials::replace_instance_credential_stores_the_new_one_and_revokes_the_rest_atomically(
        factory().await,
    )
    .await;
    identity_invites::invite_consumes_once(factory().await).await;
    identity_invites::invite_expired_is_not_found(factory().await).await;
    identity_invites::invite_wrong_hash_is_not_found_and_not_consumed(factory().await).await;
    identity_invites::invite_with_taken_name_conflicts_and_stays_unconsumed(factory().await).await;
    identity_invites::concurrent_consumes_of_one_invite_create_exactly_one_member(factory().await)
        .await;
    identity_join::join_creates_member_credential_and_audit_row_atomically(factory().await).await;
    identity_join::join_failure_leaves_no_member_credential_or_audit_row(factory().await).await;
    identity_join::create_credential_on_archived_board_is_board_archived(factory().await).await;
    identity_join::concurrent_joins_with_one_invite_create_exactly_one_member_and_one_credential(
        factory().await,
    )
    .await;
    identity_adoption::list_local_authors_returns_distinct_sorted_authors(factory().await).await;
    identity_adoption::adopt_local_authors_creates_members_and_flips_author_kind_atomically(
        factory().await,
    )
    .await;
    identity_adoption::adopt_local_authors_leaves_the_hash_chain_valid(factory().await).await;
    identity_adoption::adopt_local_authors_writes_one_audit_row_and_a_failure_writes_none(
        factory().await,
    )
    .await;
    identity_adoption::members_posts_are_not_listed_as_local_authors(factory().await).await;
    identity_archive::add_member_on_archived_board_is_board_archived(factory().await).await;
    identity_archive::create_invite_on_archived_board_is_board_archived(factory().await).await;
    identity_archive::adopt_local_authors_on_archived_board_is_board_archived(factory().await)
        .await;
    identity_archive::consume_invite_for_archived_board_is_the_generic_not_found(factory().await)
        .await;
    identity_archive::remove_member_and_revoke_still_work_on_archived_board(factory().await).await;
    identity_log::security_log_newest_first_and_limited(factory().await).await;
    identity_log::no_secret_material_in_security_log_rows(factory().await).await;
    identity_audit::create_board_writes_exactly_one_board_created_row(factory().await).await;
    identity_audit::duplicate_create_board_writes_no_row(factory().await).await;
    identity_audit::archive_board_writes_one_row_and_a_second_archive_writes_none(factory().await)
        .await;
    identity_archive::archive_board_revoking_archives_revokes_non_admin_credentials_and_keeps_admins_in_one_transaction(
        factory().await,
    )
    .await;
    identity_audit::revoke_credential_writes_one_row_and_a_repeat_writes_none(factory().await)
        .await;
    identity_audit::remove_member_revokes_credentials_and_writes_one_row(factory().await).await;
    identity_audit::create_invite_and_create_credential_and_replace_instance_credential_each_write_one_row(
        factory().await,
    )
    .await;
    identity_audit::replace_instance_credential_writes_a_token_revoked_row_with_the_count_when_it_revokes_others(
        factory().await,
    )
    .await;
    identity_audit::replace_instance_credential_writes_no_extra_row_when_nothing_is_revoked(
        factory().await,
    )
    .await;
    identity_audit::enable_network_mode_writes_one_row_and_a_second_call_none(factory().await)
        .await;
    identity_audit_failures::failed_mutations_write_no_rows(factory().await).await;
    identity_enable::enable_network_writes_its_rows_in_order(factory().await).await;
    identity_enable::enable_network_without_invite_writes_two_rows(factory().await).await;
    identity_enable::enable_network_twice_is_already_network_and_writes_nothing(factory().await)
        .await;
    identity_enable::enable_network_is_atomic_all_or_nothing(factory().await).await;
    identity_enable::enable_network_rejects_an_invite_without_its_audit_row_and_the_reverse(
        factory().await,
    )
    .await;
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

/// The credential `consume_invite` creates for a new member: id `n`, valid for 90 days.
pub(crate) fn join_credential(n: u8) -> NewJoinCredential {
    NewJoinCredential {
        id: token_id(n),
        secret_hash: hash_of(&format!("join-{n}")),
        expires_at_ms: NOW + 90 * 24 * HOUR,
    }
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
    assert_eq!(
        store.enable_network_mode(mode_enabled(NOW)).await,
        Ok(()),
        "{SCENARIO}"
    );
    assert_eq!(store.mode().await, Ok(Mode::Network), "{SCENARIO}");
    assert_eq!(
        store.enable_network_mode(mode_enabled(NOW)).await,
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
    let removed = store
        .remove_member(&nowhere, &alice, NOW, member_removed(&nowhere, NOW))
        .await;
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
        store
            .create_credential(scoped, NOW, token_issued(NOW))
            .await,
        "create_credential",
    );
    let into = invite(2, &nowhere, Role::Member, PrincipalKind::Agent);
    expect(
        store.create_invite(into, NOW, invite_created(NOW)).await,
        "create_invite",
    );
    assert_eq!(
        store.find_credential(&token_id(1)).await,
        Ok(None),
        "{SCENARIO}: nothing was stored"
    );
}
