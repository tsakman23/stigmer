//! The token commands: enable-auth, new-instance-token, revoke-token and issue-member-token.

use stigmer_core::{
    BoardId, NewSecret, Principal, PrincipalKind, Role, SecretKind, TokenId, TOKEN_PREFIX,
};
use stigmer_store::{
    ConflictKind, CredentialScope, IdentityStore, Mode, NewCredential, NewInvite,
    SecurityEventKind, StoreError,
};

use super::{
    instance_admin, log, new_secret, store_failure, DAY_MS, INSTANCE_TOKEN_DAYS, MAIN_INVITE_HOURS,
};
use crate::Failure;

pub(super) struct Issued {
    pub(super) token: String,
    pub(super) invite: Option<String>,
    /// Set when the secrets are valid but the security log could not be written.
    pub(super) log_failure: Option<Failure>,
}

/// Enables network mode without ever stranding the instance: the credential and invite are
/// stored while the instance is still local, the one-way switch comes next, and the secrets
/// are returned only then. A failure before the switch leaves local mode plus at most an
/// unused credential whose secret was never shown, so a plain retry works.
pub(super) async fn enable_auth<S: IdentityStore>(
    store: &S,
    now: i64,
    with_invite: bool,
) -> Result<Issued, Failure> {
    if store
        .mode()
        .await
        .map_err(|e| store_failure("cannot read instance mode", &e))?
        == Mode::Network
    {
        return Err(already_network());
    }
    let token = store_instance_token(store, now, INSTANCE_TOKEN_DAYS).await?;
    let invite = if with_invite {
        Some(store_main_admin_invite(store, now).await?)
    } else {
        None
    };
    match store.enable_network_mode().await {
        Ok(()) => {}
        Err(StoreError::Conflict(ConflictKind::AlreadyNetwork)) => return Err(already_network()),
        Err(e) => return Err(store_failure("cannot enable network mode", &e)),
    }
    // Past the switch the secrets are valid, so a log failure must not hide them.
    let mut logged = log(
        store,
        now,
        SecurityEventKind::ModeEnabled,
        None,
        "network mode enabled",
    )
    .await;
    if logged.is_ok() {
        logged = log_token_issued(store, now, &token.id, INSTANCE_TOKEN_DAYS).await;
    }
    if let (Ok(()), Some(invite)) = (&logged, &invite) {
        logged = log_invite_created(store, now, &invite.id).await;
    }
    Ok(Issued {
        token: token.full,
        invite: invite.map(|i| i.full),
        log_failure: logged.err(),
    })
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
    /// Set when the token is valid but the security log could not be written.
    pub(super) log_failure: Option<Failure>,
}

/// Stores a new instance credential and, with `revoke_others`, revokes every other instance
/// credential in the same store transaction, so a failure leaves the old tokens valid rather
/// than no token at all. Once stored the token is returned even if the log write fails.
pub(super) async fn issue_instance_token<S: IdentityStore>(
    store: &S,
    now: i64,
    days: u32,
    revoke_others: bool,
) -> Result<IssuedInstanceToken, Failure> {
    let (secret, revoked) = if revoke_others {
        let secret = new_secret(SecretKind::Token)?;
        let revoked = store
            .replace_instance_credential(instance_credential(&secret, now, days)?, now)
            .await
            .map_err(|e| store_failure("cannot replace the instance token", &e))?;
        (secret, Some(revoked))
    } else {
        (store_instance_token(store, now, days).await?, None)
    };
    let mut logged = log_token_issued(store, now, &secret.id, days).await;
    // Nothing revoked is nothing to record.
    if let (Ok(()), Some(revoked @ 1..)) = (&logged, revoked) {
        logged = log(
            store,
            now,
            SecurityEventKind::TokenRevoked,
            None,
            &format!(
                "revoked {revoked} other instance credentials, kept credential {}",
                secret.id
            ),
        )
        .await;
    }
    Ok(IssuedInstanceToken {
        token: secret.full,
        revoked,
        log_failure: logged.err(),
    })
}

async fn store_instance_token<S: IdentityStore>(
    store: &S,
    now: i64,
    days: u32,
) -> Result<NewSecret, Failure> {
    let secret = new_secret(SecretKind::Token)?;
    store
        .create_credential(instance_credential(&secret, now, days)?, now)
        .await
        .map_err(|e| store_failure("cannot store the instance token", &e))?;
    Ok(secret)
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
    match store.revoke_credential(&id, now).await {
        Ok(()) => {}
        Err(StoreError::NotFound { .. }) => return Err(unknown()),
        Err(e) => return Err(store_failure("cannot revoke the token", &e)),
    }
    // A repeat revoke keeps the first time and is not a new event.
    if credential.revoked_at_ms.is_none() {
        let board = match credential.scope {
            CredentialScope::Instance => None,
            CredentialScope::Board(board) => Some(board),
        };
        log(
            store,
            now,
            SecurityEventKind::TokenRevoked,
            board,
            &format!("credential {id}"),
        )
        .await?;
    }
    Ok(format!("revoked {id}\n"))
}

async fn log_token_issued<S: IdentityStore>(
    store: &S,
    now: i64,
    id: &TokenId,
    days: u32,
) -> Result<(), Failure> {
    log(
        store,
        now,
        SecurityEventKind::InstanceTokenIssued,
        None,
        &format!("credential {id} expires in {days} days"),
    )
    .await
}

async fn log_invite_created<S: IdentityStore>(
    store: &S,
    now: i64,
    id: &TokenId,
) -> Result<(), Failure> {
    log(
        store,
        now,
        SecurityEventKind::InviteCreated,
        Some(BoardId::main()),
        &format!("invite {id} role admin kind human"),
    )
    .await
}

async fn store_main_admin_invite<S: IdentityStore>(
    store: &S,
    now: i64,
) -> Result<NewSecret, Failure> {
    let secret = new_secret(SecretKind::Invite)?;
    store
        .create_invite(
            NewInvite {
                id: secret.id.clone(),
                secret_hash: secret.hash,
                board: BoardId::main(),
                role: Role::Admin,
                kind: PrincipalKind::Human,
                created_by: instance_admin()?,
                expires_at_ms: now + MAIN_INVITE_HOURS * 3_600_000,
            },
            now,
        )
        .await
        .map_err(|e| store_failure("cannot store the main admin invite", &e))?;
    Ok(secret)
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
        )
        .await
        .map_err(|e| match e {
            StoreError::Conflict(ConflictKind::BoardArchived) => {
                Failure::Runtime(format!("board {board} is archived and takes no new tokens"))
            }
            e => store_failure("cannot store the member token", &e),
        })?;
    log(
        store,
        now,
        SecurityEventKind::MemberTokenIssued,
        Some(board),
        &format!("credential {} for member {}", secret.id, member.name),
    )
    .await?;
    Ok(secret.full)
}
