//! The token commands: enable-auth, new-instance-token, revoke-token and issue-member-token.

use stigmer_core::{
    BoardId, NewSecret, Principal, PrincipalKind, Role, SecretKind, TokenId, TOKEN_PREFIX,
};
use stigmer_store::{
    ConflictKind, CredentialScope, EnableAudits, IdentityStore, NewCredential, NewInvite,
    SecurityEvent, SecurityEventKind, StoreError,
};

use super::{
    event, instance_admin, new_secret, store_failure, DAY_MS, INSTANCE_TOKEN_DAYS,
    MAIN_INVITE_HOURS,
};
use crate::Failure;

pub(super) struct Issued {
    pub(super) token: String,
    pub(super) invite: Option<String>,
}

/// Enables network mode in one store transaction: the instance credential, the optional main
/// admin invite, the one-way switch and their security log rows all happen, or none does. The
/// secrets are returned only after it committed, so a failure shows no secret and leaves local
/// mode for a plain retry.
pub(super) async fn enable_auth<S: IdentityStore>(
    store: &S,
    now: i64,
    with_invite: bool,
) -> Result<Issued, Failure> {
    let token = new_secret(SecretKind::Token)?;
    let credential = instance_credential(&token, now, INSTANCE_TOKEN_DAYS)?;
    let invite = if with_invite {
        Some(new_secret(SecretKind::Invite)?)
    } else {
        None
    };
    let new_invite = invite
        .as_ref()
        .map(|secret| main_admin_invite(secret, now))
        .transpose()?;
    let audits = EnableAudits {
        mode: event(
            now,
            SecurityEventKind::ModeEnabled,
            None,
            "network mode enabled",
        ),
        token: token_issued(now, &token.id, INSTANCE_TOKEN_DAYS),
        invite: invite.as_ref().map(|secret| {
            event(
                now,
                SecurityEventKind::InviteCreated,
                Some(BoardId::main()),
                &format!("invite {} role admin kind human", secret.id),
            )
        }),
    };
    match store
        .enable_network(credential, new_invite, now, audits)
        .await
    {
        Ok(()) => Ok(Issued {
            token: token.full,
            invite: invite.map(|i| i.full),
        }),
        Err(StoreError::Conflict(ConflictKind::AlreadyNetwork)) => Err(already_network()),
        Err(e) => Err(store_failure("cannot enable network mode", &e)),
    }
}

fn already_network() -> Failure {
    Failure::Runtime(
        "already in network mode; if you have no instance token, run stigmerd admin new-instance-token"
            .into(),
    )
}

/// A new instance token and what came with it.
pub(super) struct IssuedInstanceToken {
    pub(super) token: String,
    /// How many other instance tokens were revoked, when asked to.
    pub(super) revoked: Option<u64>,
}

/// Stores a new instance credential and its security log row and, with `revoke_others`,
/// revokes every other instance credential in the same store transaction (the store then also
/// records the count in a `TokenRevoked` row), so a failure leaves the old tokens valid rather
/// than no token at all.
pub(super) async fn issue_instance_token<S: IdentityStore>(
    store: &S,
    now: i64,
    days: u32,
    revoke_others: bool,
) -> Result<IssuedInstanceToken, Failure> {
    let secret = new_secret(SecretKind::Token)?;
    let credential = instance_credential(&secret, now, days)?;
    let row = token_issued(now, &secret.id, days);
    let revoked = if revoke_others {
        let revoked = store
            .replace_instance_credential(credential, now, row)
            .await
            .map_err(|e| store_failure("cannot replace the instance token", &e))?;
        Some(revoked)
    } else {
        store
            .create_credential(credential, now, row)
            .await
            .map_err(|e| store_failure("cannot store the instance token", &e))?;
        None
    };
    Ok(IssuedInstanceToken {
        token: secret.full,
        revoked,
    })
}

/// The instance credential for `secret`, valid `days` from `now`.
fn instance_credential(secret: &NewSecret, now: i64, days: u32) -> Result<NewCredential, Failure> {
    Ok(NewCredential {
        id: secret.id.clone(),
        secret_hash: secret.hash,
        scope: CredentialScope::Instance,
        principal: instance_admin()?,
        expires_at_ms: now + i64::from(days) * DAY_MS,
    })
}

/// The `InstanceTokenIssued` row for the instance credential `id`.
fn token_issued(now: i64, id: &TokenId, days: u32) -> SecurityEvent {
    event(
        now,
        SecurityEventKind::InstanceTokenIssued,
        None,
        &format!("credential {id} expires in {days} days"),
    )
}

/// The admin invite into board main for `secret`, valid for `MAIN_INVITE_HOURS`.
fn main_admin_invite(secret: &NewSecret, now: i64) -> Result<NewInvite, Failure> {
    Ok(NewInvite {
        id: secret.id.clone(),
        secret_hash: secret.hash,
        board: BoardId::main(),
        role: Role::Admin,
        kind: PrincipalKind::Human,
        created_by: instance_admin()?,
        expires_at_ms: now + MAIN_INVITE_HOURS * 3_600_000,
    })
}

/// Revokes the credential `raw_id`, whatever its scope, and logs it the first time.
///
/// A malformed id is not echoed: it may be a whole token pasted by mistake.
pub(super) async fn revoke_token<S: IdentityStore>(
    store: &S,
    now: i64,
    raw_id: &str,
) -> Result<String, Failure> {
    let id = TokenId::new(raw_id).map_err(|_| {
        Failure::Config(format!(
            "not a token id: pass the 16 hex characters after {TOKEN_PREFIX} (the value is not shown)"
        ))
    })?;
    let unknown = || Failure::Config(format!("no token with id {id}"));
    let credential = store
        .find_credential(&id)
        .await
        .map_err(|e| store_failure("cannot read the token", &e))?
        .ok_or_else(unknown)?;
    let board = match credential.scope {
        CredentialScope::Instance => None,
        CredentialScope::Board(board) => Some(board),
    };
    let row = event(
        now,
        SecurityEventKind::TokenRevoked,
        board,
        &format!("credential {id}"),
    );
    // A repeat revoke keeps the first time; the store writes no row for it.
    match store.revoke_credential(&id, now, row).await {
        Ok(()) => Ok(format!("revoked {id}\n")),
        Err(StoreError::NotFound { .. }) => Err(unknown()),
        Err(e) => Err(store_failure("cannot revoke the token", &e)),
    }
}

/// Stores a board credential for the existing member `raw_member` of `raw_board` and returns
/// the token, which is never stored or logged (only its hash and id are).
pub(super) async fn issue_member_token<S: IdentityStore>(
    store: &S,
    now: i64,
    raw_board: &str,
    raw_member: &str,
    days: u32,
) -> Result<String, Failure> {
    let not_a_member =
        || Failure::Config(format!("{raw_member} is not a member of board {raw_board}"));
    let board = BoardId::new(raw_board).map_err(|_| not_a_member())?;
    let name = Principal::new(raw_member)
        .map_err(|e| Failure::Config(format!("--member {raw_member:?}: {e}")))?;
    let member = match store.get_member(&board, &name).await {
        Ok(Some(member)) => member,
        Ok(None) | Err(StoreError::NotFound { .. }) => return Err(not_a_member()),
        Err(e) => return Err(store_failure("cannot read the member", &e)),
    };
    let secret = new_secret(SecretKind::Token)?;
    let row = event(
        now,
        SecurityEventKind::MemberTokenIssued,
        Some(board.clone()),
        &format!("credential {} for member {}", secret.id, member.name),
    );
    store
        .create_credential(
            NewCredential {
                id: secret.id.clone(),
                secret_hash: secret.hash,
                scope: CredentialScope::Board(board.clone()),
                principal: member.name.clone(),
                expires_at_ms: now + i64::from(days) * DAY_MS,
            },
            now,
            row,
        )
        .await
        .map_err(|e| match e {
            StoreError::Conflict(ConflictKind::BoardArchived) => {
                Failure::Runtime(format!("board {board} is archived and takes no new tokens"))
            }
            e => store_failure("cannot store the member token", &e),
        })?;
    Ok(secret.full)
}
