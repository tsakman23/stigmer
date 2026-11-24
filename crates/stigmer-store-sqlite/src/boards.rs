//! Board lifecycle: creating, reading, listing and archiving boards.

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior};
use stigmer_core::{BoardId, BoardInfo, Principal, GENESIS_HASH};
use stigmer_store::{ConflictKind, Entity, SecurityEvent, StoreError};

use crate::credentials::{log_in_tx, revoke_board_in_tx};
use crate::{backend, not_found};

const BOARD_COLUMNS: &str = "SELECT id, created_at_ms, created_by, archived_at_ms FROM boards";

/// Creates an empty board at the genesis hash and writes its audit row, or `BoardExists` if the
/// id is taken.
pub(crate) fn create(
    conn: &mut Connection,
    id: &BoardId,
    created_by: Option<&Principal>,
    now_ms: i64,
    audit: &SecurityEvent,
) -> Result<BoardInfo, StoreError> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(backend)?;
    if find(&tx, id)?.is_some() {
        return Err(StoreError::Conflict(ConflictKind::BoardExists));
    }
    let info = BoardInfo {
        id: id.clone(),
        created_at_ms: now_ms,
        created_by: created_by.cloned(),
        archived_at_ms: None,
    };
    tx.execute(
        "INSERT INTO boards (id, head_seq, head_hash, created_at_ms, created_by)
         VALUES (?1, 0, ?2, ?3, ?4)",
        (
            info.id.as_str(),
            GENESIS_HASH,
            info.created_at_ms,
            info.created_by.as_ref().map(Principal::as_str),
        ),
    )
    .map_err(backend)?;
    log_in_tx(&tx, audit)?;
    tx.commit().map_err(backend)?;
    Ok(info)
}

/// The board `id`, or `NotFound` with `Entity::Board`.
pub(crate) fn get(conn: &mut Connection, id: &BoardId) -> Result<BoardInfo, StoreError> {
    let tx = conn.transaction().map_err(backend)?;
    require(&tx, id)
}

/// Every board, oldest first, ties broken by id.
pub(crate) fn list(conn: &mut Connection) -> Result<Vec<BoardInfo>, StoreError> {
    let mut stmt = conn
        .prepare(&format!("{BOARD_COLUMNS} ORDER BY created_at_ms, id"))
        .map_err(backend)?;
    let mut rows = stmt.query([]).map_err(backend)?;
    let mut boards = Vec::new();
    while let Some(row) = rows.next().map_err(backend)? {
        boards.push(board_from_row(row)?);
    }
    Ok(boards)
}

/// Sets the board's archive time and writes the audit row unless it is already archived;
/// returns the board as stored. `main` is refused with `BoardProtected`.
pub(crate) fn archive(
    conn: &mut Connection,
    id: &BoardId,
    now_ms: i64,
    audit: &SecurityEvent,
) -> Result<BoardInfo, StoreError> {
    let tx = archivable(conn, id)?;
    let (info, archived) = set_archived(&tx, id, now_ms)?;
    if archived {
        log_in_tx(&tx, audit)?;
        tx.commit().map_err(backend)?;
    }
    Ok(info)
}

/// Archives the board and revokes every live non-admin credential on it in one transaction,
/// writing the audit row when anything changed. Once the board is archived no credential can be
/// added to it, so nothing escapes the revocation.
pub(crate) fn archive_revoking(
    conn: &mut Connection,
    id: &BoardId,
    now_ms: i64,
    audit: &SecurityEvent,
) -> Result<BoardInfo, StoreError> {
    let tx = archivable(conn, id)?;
    let (info, archived) = set_archived(&tx, id, now_ms)?;
    let revoked = revoke_board_in_tx(&tx, id, true, now_ms)?;
    if archived || revoked > 0 {
        log_in_tx(&tx, audit)?;
        tx.commit().map_err(backend)?;
    }
    Ok(info)
}

/// A write transaction for archiving `id`; `main` is refused with `BoardProtected` first.
fn archivable<'c>(conn: &'c mut Connection, id: &BoardId) -> Result<Transaction<'c>, StoreError> {
    if *id == BoardId::main() {
        return Err(StoreError::Conflict(ConflictKind::BoardProtected));
    }
    conn.transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(backend)
}

/// Sets the archive time of an unarchived board inside `tx`. Returns the board as it now is and
/// whether this call archived it.
fn set_archived(
    tx: &Transaction<'_>,
    id: &BoardId,
    now_ms: i64,
) -> Result<(BoardInfo, bool), StoreError> {
    let mut info = require(tx, id)?;
    if info.archived_at_ms.is_some() {
        return Ok((info, false));
    }
    tx.execute(
        "UPDATE boards SET archived_at_ms = ?1 WHERE id = ?2",
        (now_ms, id.as_str()),
    )
    .map_err(backend)?;
    info.archived_at_ms = Some(now_ms);
    Ok((info, true))
}

/// The head `(seq, hash)` of a board that accepts posts: `NotFound` for an unknown board,
/// `Conflict(BoardArchived)` for an archived one.
pub(crate) fn writable_head(
    tx: &Transaction<'_>,
    id: &BoardId,
) -> Result<(u64, String), StoreError> {
    let row: Option<(i64, String, Option<i64>)> = tx
        .query_row(
            "SELECT head_seq, head_hash, archived_at_ms FROM boards WHERE id = ?1",
            [id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(backend)?;
    match row {
        None => Err(not_found(Entity::Board, id)),
        Some((_, _, Some(_archived))) => Err(StoreError::Conflict(ConflictKind::BoardArchived)),
        Some((seq, hash, None)) => Ok((u64::try_from(seq).map_err(backend)?, hash)),
    }
}

/// Checks that board `id` accepts writes: `NotFound` for an unknown board,
/// `Conflict(BoardArchived)` for an archived one.
pub(crate) fn require_writable(tx: &Transaction<'_>, id: &BoardId) -> Result<(), StoreError> {
    writable_head(tx, id).map(drop)
}

/// The board `id`, or `NotFound` with `Entity::Board`.
pub(crate) fn require(tx: &Transaction<'_>, id: &BoardId) -> Result<BoardInfo, StoreError> {
    find(tx, id)?.ok_or_else(|| not_found(Entity::Board, id))
}

fn find(tx: &Transaction<'_>, id: &BoardId) -> Result<Option<BoardInfo>, StoreError> {
    let mut stmt = tx
        .prepare(&format!("{BOARD_COLUMNS} WHERE id = ?1"))
        .map_err(backend)?;
    let mut rows = stmt.query([id.as_str()]).map_err(backend)?;
    rows.next()
        .map_err(backend)?
        .map(board_from_row)
        .transpose()
}

/// Rebuilds a board from a `BOARD_COLUMNS` row, re-validating its ids.
fn board_from_row(row: &rusqlite::Row<'_>) -> Result<BoardInfo, StoreError> {
    let id: String = row.get(0).map_err(backend)?;
    let created_by: Option<String> = row.get(2).map_err(backend)?;
    Ok(BoardInfo {
        id: BoardId::new(&id).map_err(backend)?,
        created_at_ms: row.get(1).map_err(backend)?,
        created_by: created_by
            .map(|raw| Principal::new(&raw).map_err(backend))
            .transpose()?,
        archived_at_ms: row.get(3).map_err(backend)?,
    })
}
