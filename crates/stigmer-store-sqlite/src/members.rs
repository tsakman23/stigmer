//! Instance mode, board members and the adoption of local authors.

use rusqlite::{Connection, Row, Transaction, TransactionBehavior};
use stigmer_core::{BoardId, Principal, PrincipalKind, Role};
use stigmer_store::{Adoption, ConflictKind, Entity, Member, Mode, StoreError};

use crate::boards::{require, require_writable};
use crate::posts::{LOCAL_AUTHOR_KIND, PRINCIPAL_AUTHOR_KIND};
use crate::{backend, not_found};

const MEMBER_COLUMNS: &str = "SELECT name, kind, role, created_at_ms FROM principals";

/// The instance mode, from the single `instance` row.
pub(crate) fn mode(conn: &Connection) -> Result<Mode, StoreError> {
    let raw: String = conn
        .query_row("SELECT mode FROM instance WHERE id = 1", [], |row| {
            row.get(0)
        })
        .map_err(backend)?;
    match raw.as_str() {
        "local" => Ok(Mode::Local),
        "network" => Ok(Mode::Network),
        other => Err(StoreError::Backend(format!(
            "unknown instance mode {other:?}"
        ))),
    }
}

/// Moves a local instance to network mode; `AlreadyNetwork` if it is there already.
pub(crate) fn enable_network_mode(conn: &mut Connection) -> Result<(), StoreError> {
    let tx = immediate(conn)?;
    if mode(&tx)? == Mode::Network {
        return Err(StoreError::Conflict(ConflictKind::AlreadyNetwork));
    }
    tx.execute("UPDATE instance SET mode = 'network' WHERE id = 1", [])
        .map_err(backend)?;
    tx.commit().map_err(backend)
}

/// Adds a member to an existing board.
pub(crate) fn add(
    conn: &mut Connection,
    board: &BoardId,
    name: &Principal,
    kind: PrincipalKind,
    role: Role,
    now_ms: i64,
) -> Result<Member, StoreError> {
    let tx = immediate(conn)?;
    require_writable(&tx, board)?;
    let member = insert(&tx, board, name, kind, role, now_ms)?;
    tx.commit().map_err(backend)?;
    Ok(member)
}

/// Inserts a member inside the caller's transaction; `NameTaken` if the name is on the board.
pub(crate) fn insert(
    tx: &Transaction<'_>,
    board: &BoardId,
    name: &Principal,
    kind: PrincipalKind,
    role: Role,
    now_ms: i64,
) -> Result<Member, StoreError> {
    if find(tx, board, name)?.is_some() {
        return Err(StoreError::Conflict(ConflictKind::NameTaken));
    }
    tx.execute(
        "INSERT INTO principals (board_id, name, kind, role, created_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        (
            board.as_str(),
            name.as_str(),
            kind.as_str(),
            role.as_str(),
            now_ms,
        ),
    )
    .map_err(backend)?;
    Ok(Member {
        board: board.clone(),
        name: name.clone(),
        kind,
        role,
        created_at_ms: now_ms,
    })
}

/// The member `name` of an existing board, or `None`.
pub(crate) fn get(
    conn: &mut Connection,
    board: &BoardId,
    name: &Principal,
) -> Result<Option<Member>, StoreError> {
    let tx = conn.transaction().map_err(backend)?;
    require(&tx, board)?;
    find(&tx, board, name)
}

/// Every member of an existing board, by name.
pub(crate) fn list(conn: &mut Connection, board: &BoardId) -> Result<Vec<Member>, StoreError> {
    let tx = conn.transaction().map_err(backend)?;
    require(&tx, board)?;
    let mut stmt = tx
        .prepare(&format!(
            "{MEMBER_COLUMNS} WHERE board_id = ?1 ORDER BY name"
        ))
        .map_err(backend)?;
    let mut rows = stmt.query([board.as_str()]).map_err(backend)?;
    let mut members = Vec::new();
    while let Some(row) = rows.next().map_err(backend)? {
        members.push(member_from_row(board, row)?);
    }
    Ok(members)
}

/// Removes a member and revokes their live credentials on that board, in one transaction.
pub(crate) fn remove(
    conn: &mut Connection,
    board: &BoardId,
    name: &Principal,
    now_ms: i64,
) -> Result<(), StoreError> {
    let tx = immediate(conn)?;
    require(&tx, board)?;
    let removed = tx
        .execute(
            "DELETE FROM principals WHERE board_id = ?1 AND name = ?2",
            (board.as_str(), name.as_str()),
        )
        .map_err(backend)?;
    if removed == 0 {
        return Err(not_found(Entity::Member, name));
    }
    tx.execute(
        "UPDATE credentials SET revoked_at_ms = ?3
         WHERE board_id = ?1 AND principal = ?2 AND revoked_at_ms IS NULL",
        (board.as_str(), name.as_str(), now_ms),
    )
    .map_err(backend)?;
    tx.commit().map_err(backend)
}

/// The distinct authors, sorted, of the board's messages still marked local.
pub(crate) fn local_authors(
    conn: &mut Connection,
    board: &BoardId,
) -> Result<Vec<Principal>, StoreError> {
    let tx = conn.transaction().map_err(backend)?;
    require(&tx, board)?;
    let mut stmt = tx
        .prepare(
            "SELECT DISTINCT author FROM messages
             WHERE board_id = ?1 AND author_kind = ?2 ORDER BY author",
        )
        .map_err(backend)?;
    let mut rows = stmt
        .query((board.as_str(), LOCAL_AUTHOR_KIND))
        .map_err(backend)?;
    let mut authors = Vec::new();
    while let Some(row) = rows.next().map_err(backend)? {
        let raw: String = row.get(0).map_err(backend)?;
        authors.push(Principal::new(&raw).map_err(backend)?);
    }
    Ok(authors)
}

/// Creates each adopted member and marks their local messages on the board, all or nothing.
/// Only `messages.author_kind` changes, which the event hash does not cover.
pub(crate) fn adopt(
    conn: &mut Connection,
    board: &BoardId,
    adoptions: &[Adoption],
    now_ms: i64,
) -> Result<u64, StoreError> {
    let tx = immediate(conn)?;
    require_writable(&tx, board)?;
    let mut marked = 0u64;
    for adoption in adoptions {
        insert(
            &tx,
            board,
            &adoption.name,
            adoption.kind,
            adoption.role,
            now_ms,
        )?;
        let changed = tx
            .execute(
                "UPDATE messages SET author_kind = ?3
                 WHERE board_id = ?1 AND author = ?2 AND author_kind = ?4",
                (
                    board.as_str(),
                    adoption.name.as_str(),
                    PRINCIPAL_AUTHOR_KIND,
                    LOCAL_AUTHOR_KIND,
                ),
            )
            .map_err(backend)?;
        marked += u64::try_from(changed).map_err(backend)?;
    }
    tx.commit().map_err(backend)?;
    Ok(marked)
}

/// Starts a write transaction that takes the database lock at once.
pub(crate) fn immediate(conn: &mut Connection) -> Result<Transaction<'_>, StoreError> {
    conn.transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(backend)
}

fn find(
    tx: &Transaction<'_>,
    board: &BoardId,
    name: &Principal,
) -> Result<Option<Member>, StoreError> {
    let mut stmt = tx
        .prepare(&format!(
            "{MEMBER_COLUMNS} WHERE board_id = ?1 AND name = ?2"
        ))
        .map_err(backend)?;
    let mut rows = stmt
        .query((board.as_str(), name.as_str()))
        .map_err(backend)?;
    rows.next()
        .map_err(backend)?
        .map(|row| member_from_row(board, row))
        .transpose()
}

/// Rebuilds a member from a `MEMBER_COLUMNS` row, re-validating what was stored.
fn member_from_row(board: &BoardId, row: &Row<'_>) -> Result<Member, StoreError> {
    let name: String = row.get(0).map_err(backend)?;
    let kind: String = row.get(1).map_err(backend)?;
    let role: String = row.get(2).map_err(backend)?;
    Ok(Member {
        board: board.clone(),
        name: Principal::new(&name).map_err(backend)?,
        kind: parse_kind(&kind)?,
        role: parse_role(&role)?,
        created_at_ms: row.get(3).map_err(backend)?,
    })
}

pub(crate) fn parse_kind(raw: &str) -> Result<PrincipalKind, StoreError> {
    [
        PrincipalKind::Human,
        PrincipalKind::Agent,
        PrincipalKind::Bridge,
    ]
    .into_iter()
    .find(|kind| kind.as_str() == raw)
    .ok_or_else(|| StoreError::Backend(format!("unknown principal kind {raw:?}")))
}

pub(crate) fn parse_role(raw: &str) -> Result<Role, StoreError> {
    [Role::Admin, Role::Member, Role::Bridge]
        .into_iter()
        .find(|role| role.as_str() == raw)
        .ok_or_else(|| StoreError::Backend(format!("unknown role {raw:?}")))
}
