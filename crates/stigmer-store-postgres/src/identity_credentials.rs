//! Credentials. Only secret hashes are stored, as 32-byte `bytea` (the column checks the
//! length), never secrets.
//!
//! A write that touches a board's credentials together with other rows of the board locks the
//! board row first (see `boards`). Revoking or touching one credential locks only that row:
//! holding a single row it cannot be part of a lock cycle, and the hot path (`touch`, on every
//! authenticated request) stays off the board's lock.

use deadpool_postgres::Pool;
use stigmer_core::{BoardId, Principal, Role, TokenId};
use stigmer_store::{
    Credential, CredentialScope, Entity, NewCredential, SecurityEvent, SecurityEventKind,
    StoreError,
};
use tokio_postgres::{Row, Transaction};

use crate::audit::log_in_tx;
use crate::boards::{lock_board, lock_writable};
use crate::error::{backend, db, not_found};
use crate::pool;
use crate::reads::{require_board, snapshot};

const CREDENTIAL_COLUMNS: &str = "SELECT id, secret_hash, board_id, principal, expires_at_ms,
    revoked_at_ms, last_seen_ms FROM credentials";

/// Stores a credential and writes its audit row; a board-scoped one needs an existing,
/// unarchived board, whose row it locks first.
pub(crate) async fn create(
    pool: &Pool,
    credential: &NewCredential,
    audit: &SecurityEvent,
) -> Result<(), StoreError> {
    let mut client = pool::client(pool).await?;
    let tx = client.transaction().await.map_err(db)?;
    let board = match &credential.scope {
        CredentialScope::Instance => None,
        CredentialScope::Board(board) => {
            lock_writable(&tx, board).await?;
            Some(board)
        }
    };
    insert_credential(&tx, credential, board, audit.at_ms).await?;
    log_in_tx(&tx, audit).await?;
    tx.commit().await.map_err(db)
}

/// Inserts a credential row inside the caller's transaction.
pub(crate) async fn insert_credential(
    tx: &Transaction<'_>,
    credential: &NewCredential,
    board: Option<&BoardId>,
    now_ms: i64,
) -> Result<(), StoreError> {
    tx.execute(
        "INSERT INTO credentials
             (id, secret_hash, board_id, principal, created_at_ms, expires_at_ms)
         VALUES ($1, $2, $3, $4, $5, $6)",
        &[
            &credential.id.as_str(),
            &&credential.secret_hash[..],
            &board.map(BoardId::as_str),
            &credential.principal.as_str(),
            &now_ms,
            &credential.expires_at_ms,
        ],
    )
    .await
    .map_err(db)?;
    Ok(())
}

/// The credential `id`, or `None`.
pub(crate) async fn find(pool: &Pool, id: &TokenId) -> Result<Option<Credential>, StoreError> {
    let client = pool::client(pool).await?;
    let row = client
        .query_opt(
            &format!("{CREDENTIAL_COLUMNS} WHERE id = $1"),
            &[&id.as_str()],
        )
        .await
        .map_err(db)?;
    row.as_ref().map(credential_from_row).transpose()
}

/// Records the last use of a credential.
pub(crate) async fn touch(pool: &Pool, id: &TokenId, now_ms: i64) -> Result<(), StoreError> {
    let client = pool::client(pool).await?;
    let changed = client
        .execute(
            "UPDATE credentials SET last_seen_ms = $2 WHERE id = $1",
            &[&id.as_str(), &now_ms],
        )
        .await
        .map_err(db)?;
    if changed == 0 {
        return Err(not_found(Entity::Credential, id));
    }
    Ok(())
}

/// Every credential scoped to an existing board, oldest first.
pub(crate) async fn list(pool: &Pool, board: &BoardId) -> Result<Vec<Credential>, StoreError> {
    let mut client = pool::client(pool).await?;
    let tx = snapshot(&mut client).await?;
    require_board(&tx, board).await?;
    let rows = tx
        .query(
            &format!("{CREDENTIAL_COLUMNS} WHERE board_id = $1 ORDER BY created_at_ms, id"),
            &[&board.as_str()],
        )
        .await
        .map_err(db)?;
    let credentials = rows
        .iter()
        .map(credential_from_row)
        .collect::<Result<_, _>>()?;
    tx.commit().await.map_err(db)?;
    Ok(credentials)
}

/// Revokes a live credential and writes its audit row. A revoked one keeps its first revocation
/// time and gets no new row. The credential's row is locked, so two revocations racing write
/// one row between them.
pub(crate) async fn revoke(
    pool: &Pool,
    id: &TokenId,
    audit: &SecurityEvent,
) -> Result<(), StoreError> {
    let mut client = pool::client(pool).await?;
    let tx = client.transaction().await.map_err(db)?;
    let row = tx
        .query_opt(
            "SELECT revoked_at_ms FROM credentials WHERE id = $1 FOR UPDATE",
            &[&id.as_str()],
        )
        .await
        .map_err(db)?
        .ok_or_else(|| not_found(Entity::Credential, id))?;
    let revoked_at: Option<i64> = row.try_get(0).map_err(db)?;
    if revoked_at.is_some() {
        // Already revoked: the first time stands and no row is written.
        return tx.rollback().await.map_err(db);
    }
    tx.execute(
        "UPDATE credentials SET revoked_at_ms = $2 WHERE id = $1",
        &[&id.as_str(), &audit.at_ms],
    )
    .await
    .map_err(db)?;
    log_in_tx(&tx, audit).await?;
    tx.commit().await.map_err(db)
}

/// Revokes the board's live credentials, optionally sparing those of the board's admins, under
/// the board's row lock.
pub(crate) async fn revoke_board(
    pool: &Pool,
    board: &BoardId,
    keep_admins: bool,
    now_ms: i64,
) -> Result<u64, StoreError> {
    let mut client = pool::client(pool).await?;
    let tx = client.transaction().await.map_err(db)?;
    lock_board(&tx, board).await?;
    let revoked = revoke_board_in_tx(&tx, board, keep_admins, now_ms).await?;
    tx.commit().await.map_err(db)?;
    Ok(revoked)
}

/// Revokes, inside the caller's transaction (which holds the board's row lock), the board's live
/// credentials, optionally sparing those of the board's admins. Returns the number revoked.
pub(crate) async fn revoke_board_in_tx(
    tx: &Transaction<'_>,
    board: &BoardId,
    keep_admins: bool,
    now_ms: i64,
) -> Result<u64, StoreError> {
    tx.execute(
        "UPDATE credentials SET revoked_at_ms = $2
         WHERE board_id = $1 AND revoked_at_ms IS NULL
           AND NOT ($3 AND EXISTS (
               SELECT 1 FROM principals p
               WHERE p.board_id = credentials.board_id
                 AND p.name = credentials.principal
                 AND p.role = $4))",
        &[
            &board.as_str(),
            &now_ms,
            &keep_admins,
            &Role::Admin.as_str(),
        ],
    )
    .await
    .map_err(db)
}

/// Revokes every live instance credential but `keep`.
pub(crate) async fn revoke_instance_except(
    pool: &Pool,
    keep: &TokenId,
    now_ms: i64,
) -> Result<u64, StoreError> {
    let mut client = pool::client(pool).await?;
    let tx = client.transaction().await.map_err(db)?;
    let revoked = revoke_other_instance(&tx, keep, now_ms).await?;
    tx.commit().await.map_err(db)?;
    Ok(revoked)
}

/// Stores a new instance credential, revokes every other live one and writes the audit row,
/// plus a `TokenRevoked` row with the count when it revoked any, in one transaction.
pub(crate) async fn replace_instance(
    pool: &Pool,
    credential: &NewCredential,
    audit: &SecurityEvent,
) -> Result<u64, StoreError> {
    require_instance_scope(credential)?;
    let now_ms = audit.at_ms;
    let mut client = pool::client(pool).await?;
    let tx = client.transaction().await.map_err(db)?;
    insert_credential(&tx, credential, None, now_ms).await?;
    let revoked = revoke_other_instance(&tx, &credential.id, now_ms).await?;
    log_in_tx(&tx, audit).await?;
    if revoked > 0 {
        let count_row = SecurityEvent {
            at_ms: now_ms,
            kind: SecurityEventKind::TokenRevoked,
            board: None,
            principal: audit.principal.clone(),
            detail: format!("revoked {revoked} other instance credentials"),
        };
        log_in_tx(&tx, &count_row).await?;
    }
    tx.commit().await.map_err(db)?;
    Ok(revoked)
}

/// Refuses a credential that should be the instance credential but is scoped to a board.
pub(crate) fn require_instance_scope(credential: &NewCredential) -> Result<(), StoreError> {
    if credential.scope != CredentialScope::Instance {
        return Err(StoreError::Backend(
            "an instance credential must have the instance scope".into(),
        ));
    }
    Ok(())
}

/// Revokes, inside the caller's transaction, every live instance credential but `keep`.
async fn revoke_other_instance(
    tx: &Transaction<'_>,
    keep: &TokenId,
    now_ms: i64,
) -> Result<u64, StoreError> {
    tx.execute(
        "UPDATE credentials SET revoked_at_ms = $2
         WHERE board_id IS NULL AND revoked_at_ms IS NULL AND id <> $1",
        &[&keep.as_str(), &now_ms],
    )
    .await
    .map_err(db)
}

/// Rebuilds a credential from a `CREDENTIAL_COLUMNS` row, re-validating what was stored.
fn credential_from_row(row: &Row) -> Result<Credential, StoreError> {
    let id: &str = row.try_get(0).map_err(db)?;
    let board: Option<&str> = row.try_get(2).map_err(db)?;
    let principal: &str = row.try_get(3).map_err(db)?;
    Ok(Credential {
        id: TokenId::new(id).map_err(backend)?,
        secret_hash: to_hash(row.try_get(1).map_err(db)?)?,
        scope: match board {
            None => CredentialScope::Instance,
            Some(raw) => CredentialScope::Board(BoardId::new(raw).map_err(backend)?),
        },
        principal: Principal::new(principal).map_err(backend)?,
        expires_at_ms: row.try_get(4).map_err(db)?,
        revoked_at_ms: row.try_get(5).map_err(db)?,
        last_seen_ms: row.try_get(6).map_err(db)?,
    })
}

/// A stored secret hash as a fixed array. The error never shows the bytes.
pub(crate) fn to_hash(stored: &[u8]) -> Result<[u8; 32], StoreError> {
    <[u8; 32]>::try_from(stored)
        .map_err(|_| StoreError::Backend("stored secret hash is not 32 bytes".into()))
}
