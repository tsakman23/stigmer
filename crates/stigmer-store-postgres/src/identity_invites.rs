//! Invites: storing them and redeeming one (the join). Only secret hashes are stored.
//!
//! A join locks the invite's board row and then the invite row (`FOR UPDATE`), the same order
//! as every other write on a board, so concurrent redemptions of one invite queue and exactly
//! one of them finds it unused.

use deadpool_postgres::Pool;
use stigmer_core::{hashes_match, BoardId, Principal, TokenId};
use stigmer_store::{
    Consumed, CredentialScope, Entity, NewCredential, NewInvite, NewJoinCredential, SecurityEvent,
    SecurityEventKind, StoreError,
};
use tokio_postgres::Transaction;

use crate::audit::log_in_tx;
use crate::boards::lock_writable;
use crate::error::{backend, db, not_found};
use crate::identity_credentials::{insert_credential, to_hash};
use crate::identity_members::{insert, parse_kind, parse_role};
use crate::pool;

/// What an unknown invite id is compared against: no stored invite has this hash's secret.
const UNKNOWN_INVITE_HASH: [u8; 32] = [0; 32];

/// Stores an invite into an existing, unarchived board and writes its audit row.
pub(crate) async fn create_invite(
    pool: &Pool,
    invite: &NewInvite,
    audit: &SecurityEvent,
) -> Result<(), StoreError> {
    let mut client = pool::client(pool).await?;
    let tx = client.transaction().await.map_err(db)?;
    insert_invite(&tx, invite, audit.at_ms).await?;
    log_in_tx(&tx, audit).await?;
    tx.commit().await.map_err(db)
}

/// Inserts an invite inside the caller's transaction after locking its board, which must exist
/// and be unarchived.
pub(crate) async fn insert_invite(
    tx: &Transaction<'_>,
    invite: &NewInvite,
    now_ms: i64,
) -> Result<(), StoreError> {
    lock_writable(tx, &invite.board).await?;
    tx.execute(
        "INSERT INTO invites
             (id, secret_hash, board_id, role, kind, created_by, created_at_ms, expires_at_ms)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        &[
            &invite.id.as_str(),
            &&invite.secret_hash[..],
            &invite.board.as_str(),
            &invite.role.as_str(),
            &invite.kind.as_str(),
            &invite.created_by.as_str(),
            &now_ms,
            &invite.expires_at_ms,
        ],
    )
    .await
    .map_err(db)?;
    Ok(())
}

/// Checks and uses an invite in one transaction: lookup, board and invite row locks,
/// constant-time hash comparison, expiry, use and archived-board checks, member insert, the
/// member's credential, the used mark and the `Join` log row. Every refusal of the invite itself
/// is the same `NotFound`, so callers cannot tell why it failed; any failure rolls everything
/// back.
pub(crate) async fn consume_invite(
    pool: &Pool,
    id: &TokenId,
    secret_hash: &[u8; 32],
    name: &Principal,
    now_ms: i64,
    join: NewJoinCredential,
) -> Result<Consumed, StoreError> {
    let refused = || not_found(Entity::Invite, id);
    let mut client = pool::client(pool).await?;
    let tx = client.transaction().await.map_err(db)?;
    let board = tx
        .query_opt(
            "SELECT board_id FROM invites WHERE id = $1",
            &[&id.as_str()],
        )
        .await
        .map_err(db)?;
    let Some(board) = board else {
        // Do the same hash work as for a wrong secret, so the time an unknown id takes does not
        // tell a caller which invite ids exist. `black_box` keeps the comparison from being
        // optimised away.
        std::hint::black_box(hashes_match(&UNKNOWN_INVITE_HASH, secret_hash));
        return Err(refused());
    };
    let board = BoardId::new(board.try_get(0).map_err(db)?).map_err(backend)?;

    // Board row first, then the invite row: the lock order of every write on a board. A board
    // that is archived refuses the invite like any other unusable one.
    let board_usable = match lock_writable(&tx, &board).await {
        Ok(()) => true,
        Err(StoreError::Conflict(_)) => false,
        Err(e) => return Err(e),
    };
    let stored = tx
        .query_opt(
            "SELECT secret_hash, role, kind, expires_at_ms, used_at_ms
             FROM invites WHERE id = $1 FOR UPDATE",
            &[&id.as_str()],
        )
        .await
        .map_err(db)?
        .ok_or_else(refused)?;
    let matches = hashes_match(&to_hash(stored.try_get(0).map_err(db)?)?, secret_hash);
    let expires_at_ms: i64 = stored.try_get(3).map_err(db)?;
    let used_at_ms: Option<i64> = stored.try_get(4).map_err(db)?;
    let usable = now_ms < expires_at_ms && used_at_ms.is_none() && board_usable;
    if !matches || !usable {
        return Err(refused());
    }
    let role = parse_role(stored.try_get(1).map_err(db)?)?;
    let kind = parse_kind(stored.try_get(2).map_err(db)?)?;
    let member = insert(&tx, &board, name, kind, role, now_ms).await?;
    let token_id = join.id.clone();
    let credential = NewCredential {
        id: join.id,
        secret_hash: join.secret_hash,
        scope: CredentialScope::Board(board.clone()),
        principal: name.clone(),
        expires_at_ms: join.expires_at_ms,
    };
    insert_credential(&tx, &credential, Some(&board), now_ms).await?;
    tx.execute(
        "UPDATE invites SET used_at_ms = $2 WHERE id = $1",
        &[&id.as_str(), &now_ms],
    )
    .await
    .map_err(db)?;
    let row = SecurityEvent {
        at_ms: now_ms,
        kind: SecurityEventKind::Join,
        board: Some(board.clone()),
        principal: Some(name.to_string()),
        detail: format!(
            "joined as {}/{} via invite {id} token {token_id}",
            kind.as_str(),
            role.as_str()
        ),
    };
    log_in_tx(&tx, &row).await?;
    tx.commit().await.map_err(db)?;
    Ok(Consumed {
        board,
        role,
        kind,
        member,
    })
}
