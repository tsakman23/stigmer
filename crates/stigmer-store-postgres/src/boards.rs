//! Board lifecycle: creating, reading, listing and archiving boards.
//!
//! Every write takes the board's row lock, the same lock a post takes, so an archive and a post
//! on one board are ordered and never interleave.

use deadpool_postgres::Pool;
use stigmer_core::{BoardId, BoardInfo, Principal, GENESIS_HASH};
use stigmer_store::{ConflictKind, Entity, SecurityEvent, StoreError};
use tokio_postgres::{Row, Transaction};

use crate::audit::log_in_tx;
use crate::error::{backend, db, not_found};
use crate::{hash, pool};

const BOARD_COLUMNS: &str = "SELECT id, created_at_ms, created_by, archived_at_ms FROM boards";

/// Creates an empty board at the genesis hash and writes its audit row in one transaction. An id
/// that is taken is `BoardExists` (the primary key's uniqueness violation, so two concurrent
/// creates cannot both win) and writes nothing.
pub(crate) async fn create(
    pool: &Pool,
    id: &BoardId,
    created_by: Option<&Principal>,
    audit: &SecurityEvent,
) -> Result<BoardInfo, StoreError> {
    let info = BoardInfo {
        id: id.clone(),
        created_at_ms: audit.at_ms,
        created_by: created_by.cloned(),
        archived_at_ms: None,
    };
    let mut client = pool::client(pool).await?;
    let tx = client.transaction().await.map_err(db)?;
    tx.execute(
        "INSERT INTO boards (id, head_seq, head_hash, created_at_ms, created_by)
         VALUES ($1, 0, $2, $3, $4)",
        &[
            &info.id.as_str(),
            &hash::to_bytes(GENESIS_HASH)?,
            &info.created_at_ms,
            &info.created_by.as_ref().map(Principal::as_str),
        ],
    )
    .await
    .map_err(db)?;
    log_in_tx(&tx, audit).await?;
    tx.commit().await.map_err(db)?;
    Ok(info)
}

/// The board `id`, or `NotFound` with `Entity::Board`.
pub(crate) async fn get(pool: &Pool, id: &BoardId) -> Result<BoardInfo, StoreError> {
    let client = pool::client(pool).await?;
    let row = client
        .query_opt(&format!("{BOARD_COLUMNS} WHERE id = $1"), &[&id.as_str()])
        .await
        .map_err(db)?;
    row.as_ref()
        .map(board_from_row)
        .transpose()?
        .ok_or_else(|| not_found(Entity::Board, id))
}

/// Every board, oldest first, ties broken by id.
pub(crate) async fn list(pool: &Pool) -> Result<Vec<BoardInfo>, StoreError> {
    let client = pool::client(pool).await?;
    let rows = client
        .query(&format!("{BOARD_COLUMNS} ORDER BY created_at_ms, id"), &[])
        .await
        .map_err(db)?;
    rows.iter().map(board_from_row).collect()
}

/// Sets the board's archive time and writes the audit row, under the board's row lock, unless
/// it is already archived; returns the board as stored. `main` is refused with
/// `BoardProtected`.
pub(crate) async fn archive(
    pool: &Pool,
    id: &BoardId,
    audit: &SecurityEvent,
) -> Result<BoardInfo, StoreError> {
    if *id == BoardId::main() {
        return Err(StoreError::Conflict(ConflictKind::BoardProtected));
    }
    let mut client = pool::client(pool).await?;
    let tx = client.transaction().await.map_err(db)?;
    let (info, archived) = set_archived(&tx, id, audit.at_ms).await?;
    if archived {
        log_in_tx(&tx, audit).await?;
    }
    tx.commit().await.map_err(db)?;
    Ok(info)
}

/// Locks board `id` and sets its archive time unless it is archived already. Returns the board
/// as it now is and whether this call archived it.
pub(crate) async fn set_archived(
    tx: &Transaction<'_>,
    id: &BoardId,
    now_ms: i64,
) -> Result<(BoardInfo, bool), StoreError> {
    let row = tx
        .query_opt(
            &format!("{BOARD_COLUMNS} WHERE id = $1 FOR UPDATE"),
            &[&id.as_str()],
        )
        .await
        .map_err(db)?;
    let mut info = row
        .as_ref()
        .map(board_from_row)
        .transpose()?
        .ok_or_else(|| not_found(Entity::Board, id))?;
    if info.archived_at_ms.is_some() {
        return Ok((info, false));
    }
    tx.execute(
        "UPDATE boards SET archived_at_ms = $1 WHERE id = $2",
        &[&now_ms, &id.as_str()],
    )
    .await
    .map_err(db)?;
    info.archived_at_ms = Some(now_ms);
    Ok((info, true))
}

/// Locks board `id` for a write and returns its head `(seq, hash)`: `NotFound` for an unknown
/// board, `Conflict(BoardArchived)` for an archived one. Writers on one board queue here, so
/// each reads the head its predecessor committed.
pub(crate) async fn lock_writable_head(
    tx: &Transaction<'_>,
    id: &BoardId,
) -> Result<(u64, String), StoreError> {
    let row = tx
        .query_opt(
            "SELECT head_seq, head_hash, archived_at_ms FROM boards WHERE id = $1 FOR UPDATE",
            &[&id.as_str()],
        )
        .await
        .map_err(db)?
        .ok_or_else(|| not_found(Entity::Board, id))?;
    let archived: Option<i64> = row.try_get(2).map_err(db)?;
    if archived.is_some() {
        return Err(StoreError::Conflict(ConflictKind::BoardArchived));
    }
    head_from_row(&row)
}

/// The `(seq, hash)` in columns 0 and 1 of `row`.
pub(crate) fn head_from_row(row: &Row) -> Result<(u64, String), StoreError> {
    let seq: i64 = row.try_get(0).map_err(db)?;
    let bytes: Vec<u8> = row.try_get(1).map_err(db)?;
    let hash = hash::to_hex(&bytes)
        .ok_or_else(|| StoreError::Backend("stored board head hash is not 32 bytes".into()))?;
    Ok((u64::try_from(seq).map_err(backend)?, hash))
}

/// Rebuilds a board from a `BOARD_COLUMNS` row, re-validating its ids.
fn board_from_row(row: &Row) -> Result<BoardInfo, StoreError> {
    let id: &str = row.try_get(0).map_err(db)?;
    let created_by: Option<&str> = row.try_get(2).map_err(db)?;
    Ok(BoardInfo {
        id: BoardId::new(id).map_err(backend)?,
        created_at_ms: row.try_get(1).map_err(db)?,
        created_by: created_by
            .map(|raw| Principal::new(raw).map_err(backend))
            .transpose()?,
        archived_at_ms: row.try_get(3).map_err(db)?,
    })
}
