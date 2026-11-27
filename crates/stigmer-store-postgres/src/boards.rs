//! Board lifecycle: creating, reading, listing and archiving boards.
//!
//! Every board write here takes the board's row lock, the same lock a post takes, so an archive
//! and a post on one board are ordered and never interleave. Multi-row writes on a board lock
//! the board row first, then its dependent rows (members, credentials, invites, messages), so
//! they queue on the board row instead of deadlocking on the rows behind it; the exceptions
//! that lock a single row are listed in the crate documentation.

use deadpool_postgres::Pool;
use stigmer_core::{BoardId, BoardInfo, Principal, GENESIS_HASH};
use stigmer_store::{ConflictKind, Entity, SecurityEvent, StoreError};
use tokio_postgres::{Row, Transaction};

use crate::audit::log_in_tx;
use crate::error::{backend, db, not_found};
use crate::identity_credentials::revoke_board_in_tx;
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
/// it is already archived; returns the board as stored and its final head sequence. `main` is refused with
/// `BoardProtected`.
pub(crate) async fn archive(
    pool: &Pool,
    id: &BoardId,
    audit: &SecurityEvent,
) -> Result<(BoardInfo, u64), StoreError> {
    if *id == BoardId::main() {
        return Err(StoreError::Conflict(ConflictKind::BoardProtected));
    }
    let mut client = pool::client(pool).await?;
    let tx = client.transaction().await.map_err(db)?;
    let (info, archived, head) = set_archived(&tx, id, audit.at_ms).await?;
    if archived {
        log_in_tx(&tx, audit).await?;
    }
    tx.commit().await.map_err(db)?;
    Ok((info, head))
}

/// Archives the board and revokes every live non-admin credential on it in one transaction,
/// writing the audit row when anything changed. The board's row lock comes first, as in every
/// multi-row write on a board, so a join or a credential issue on the board either commits before the
/// archive (and is revoked by it) or waits and then finds the board archived: nothing escapes
/// the revocation. Returns the board and its final head sequence.
pub(crate) async fn archive_revoking(
    pool: &Pool,
    id: &BoardId,
    audit: &SecurityEvent,
) -> Result<(BoardInfo, u64), StoreError> {
    if *id == BoardId::main() {
        return Err(StoreError::Conflict(ConflictKind::BoardProtected));
    }
    let mut client = pool::client(pool).await?;
    let tx = client.transaction().await.map_err(db)?;
    let (info, archived, head) = set_archived(&tx, id, audit.at_ms).await?;
    let revoked = revoke_board_in_tx(&tx, id, true, audit.at_ms).await?;
    if archived || revoked > 0 {
        log_in_tx(&tx, audit).await?;
        tx.commit().await.map_err(db)?;
    } else {
        // Archived already and nothing left to revoke: no change, so no row.
        tx.rollback().await.map_err(db)?;
    }
    Ok((info, head))
}

/// Locks board `id`, archived or not, before a write to its dependent rows: `NotFound` for an
/// unknown board.
pub(crate) async fn lock_board(tx: &Transaction<'_>, id: &BoardId) -> Result<(), StoreError> {
    tx.query_opt(
        "SELECT 1 FROM boards WHERE id = $1 FOR UPDATE",
        &[&id.as_str()],
    )
    .await
    .map_err(db)?
    .map(drop)
    .ok_or_else(|| not_found(Entity::Board, id))
}

/// Locks board `id` before a write to its dependent rows, as [`lock_writable_head`]: `NotFound`
/// for an unknown board, `Conflict(BoardArchived)` for an archived one.
pub(crate) async fn lock_writable(tx: &Transaction<'_>, id: &BoardId) -> Result<(), StoreError> {
    lock_writable_head(tx, id).await.map(drop)
}

/// Locks board `id` and sets its archive time unless it is archived already. Returns the board
/// as it now is, whether this call archived it, and its head sequence (final once archived).
pub(crate) async fn set_archived(
    tx: &Transaction<'_>,
    id: &BoardId,
    now_ms: i64,
) -> Result<(BoardInfo, bool, u64), StoreError> {
    let row = tx
        .query_opt(
            "SELECT id, created_at_ms, created_by, archived_at_ms, head_seq
               FROM boards WHERE id = $1 FOR UPDATE",
            &[&id.as_str()],
        )
        .await
        .map_err(db)?
        .ok_or_else(|| not_found(Entity::Board, id))?;
    let mut info = board_from_row(&row)?;
    let head: i64 = row.try_get(4).map_err(db)?;
    let head = u64::try_from(head).map_err(backend)?;
    if info.archived_at_ms.is_some() {
        return Ok((info, false, head));
    }
    tx.execute(
        "UPDATE boards SET archived_at_ms = $1 WHERE id = $2",
        &[&now_ms, &id.as_str()],
    )
    .await
    .map_err(db)?;
    info.archived_at_ms = Some(now_ms);
    Ok((info, true, head))
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
