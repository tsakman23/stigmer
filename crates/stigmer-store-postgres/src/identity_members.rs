//! Board members and the adoption of local authors. A write to a board's members locks the
//! board row first (see `boards`).

use deadpool_postgres::Pool;
use stigmer_core::{BoardId, Principal, PrincipalKind, Role};
use stigmer_store::{
    Adoption, ConflictKind, Entity, Member, SecurityEvent, SecurityEventKind, StoreError,
};
use tokio_postgres::{Row, Transaction};

use crate::audit::log_in_tx;
use crate::boards::{lock_board, lock_writable};
use crate::error::{backend, db, not_found};
use crate::pool;
use crate::posts::{LOCAL_AUTHOR_KIND, PRINCIPAL_AUTHOR_KIND};
use crate::reads::{require_board, snapshot};

/// The operator's principal: the instance credential's and the adopter of local authors (only
/// through `stigmerd admin map-local-principals`). Reserved: no member may take it.
pub(crate) const INSTANCE_ADMIN: &str = "instance-admin";

const MEMBER_COLUMNS: &str = "SELECT name, kind, role, created_at_ms FROM principals";

/// Adds a member to an existing, unarchived board.
pub(crate) async fn add(
    pool: &Pool,
    board: &BoardId,
    name: &Principal,
    kind: PrincipalKind,
    role: Role,
    now_ms: i64,
) -> Result<Member, StoreError> {
    let mut client = pool::client(pool).await?;
    let tx = client.transaction().await.map_err(db)?;
    lock_writable(&tx, board).await?;
    let member = insert(&tx, board, name, kind, role, now_ms).await?;
    tx.commit().await.map_err(db)?;
    Ok(member)
}

/// Inserts a member inside the caller's transaction, which holds the board's row lock.
/// `NameTaken` if the name is on the board (the primary key's uniqueness violation, so there is
/// no check-then-insert window) or is the reserved `instance-admin`.
pub(crate) async fn insert(
    tx: &Transaction<'_>,
    board: &BoardId,
    name: &Principal,
    kind: PrincipalKind,
    role: Role,
    now_ms: i64,
) -> Result<Member, StoreError> {
    // The operator's name in the security log is never a member's.
    if name.as_str() == INSTANCE_ADMIN {
        return Err(StoreError::Conflict(ConflictKind::NameTaken));
    }
    tx.execute(
        "INSERT INTO principals (board_id, name, kind, role, created_at_ms)
         VALUES ($1, $2, $3, $4, $5)",
        &[
            &board.as_str(),
            &name.as_str(),
            &kind.as_str(),
            &role.as_str(),
            &now_ms,
        ],
    )
    .await
    .map_err(db)?;
    Ok(Member {
        board: board.clone(),
        name: name.clone(),
        kind,
        role,
        created_at_ms: now_ms,
    })
}

/// The member `name` of an existing board, or `None`.
pub(crate) async fn get(
    pool: &Pool,
    board: &BoardId,
    name: &Principal,
) -> Result<Option<Member>, StoreError> {
    let mut client = pool::client(pool).await?;
    let tx = snapshot(&mut client).await?;
    require_board(&tx, board).await?;
    let row = tx
        .query_opt(
            &format!("{MEMBER_COLUMNS} WHERE board_id = $1 AND name = $2"),
            &[&board.as_str(), &name.as_str()],
        )
        .await
        .map_err(db)?;
    let member = row.map(|row| member_from_row(board, &row)).transpose()?;
    tx.commit().await.map_err(db)?;
    Ok(member)
}

/// Every member of an existing board, by name.
pub(crate) async fn list(pool: &Pool, board: &BoardId) -> Result<Vec<Member>, StoreError> {
    let mut client = pool::client(pool).await?;
    let tx = snapshot(&mut client).await?;
    require_board(&tx, board).await?;
    let rows = tx
        .query(
            &format!("{MEMBER_COLUMNS} WHERE board_id = $1 ORDER BY name"),
            &[&board.as_str()],
        )
        .await
        .map_err(db)?;
    let members = rows
        .iter()
        .map(|row| member_from_row(board, row))
        .collect::<Result<_, _>>()?;
    tx.commit().await.map_err(db)?;
    Ok(members)
}

/// Removes a member, revokes their live credentials on that board and writes the audit row, in
/// one transaction under the board's row lock.
pub(crate) async fn remove(
    pool: &Pool,
    board: &BoardId,
    name: &Principal,
    audit: &SecurityEvent,
) -> Result<(), StoreError> {
    let mut client = pool::client(pool).await?;
    let tx = client.transaction().await.map_err(db)?;
    lock_board(&tx, board).await?;
    let removed = tx
        .execute(
            "DELETE FROM principals WHERE board_id = $1 AND name = $2",
            &[&board.as_str(), &name.as_str()],
        )
        .await
        .map_err(db)?;
    if removed == 0 {
        return Err(not_found(Entity::Member, name));
    }
    tx.execute(
        "UPDATE credentials SET revoked_at_ms = $3
         WHERE board_id = $1 AND principal = $2 AND revoked_at_ms IS NULL",
        &[&board.as_str(), &name.as_str(), &audit.at_ms],
    )
    .await
    .map_err(db)?;
    log_in_tx(&tx, audit).await?;
    tx.commit().await.map_err(db)
}

/// The distinct authors, sorted, of the board's messages still marked local.
pub(crate) async fn local_authors(
    pool: &Pool,
    board: &BoardId,
) -> Result<Vec<Principal>, StoreError> {
    let mut client = pool::client(pool).await?;
    let tx = snapshot(&mut client).await?;
    require_board(&tx, board).await?;
    let rows = tx
        .query(
            "SELECT DISTINCT author FROM messages
             WHERE board_id = $1 AND author_kind = $2 ORDER BY author",
            &[&board.as_str(), &LOCAL_AUTHOR_KIND],
        )
        .await
        .map_err(db)?;
    let authors = rows
        .iter()
        .map(|row| {
            let raw: &str = row.try_get(0).map_err(db)?;
            Principal::new(raw).map_err(backend)
        })
        .collect::<Result<_, _>>()?;
    tx.commit().await.map_err(db)?;
    Ok(authors)
}

/// Creates each adopted member, marks their local messages on the board and writes the
/// `PrincipalsAdopted` log row, all or nothing, under the board's row lock. Only
/// `messages.author_kind` changes, which the event hash does not cover.
pub(crate) async fn adopt(
    pool: &Pool,
    board: &BoardId,
    adoptions: &[Adoption],
    now_ms: i64,
) -> Result<u64, StoreError> {
    let mut client = pool::client(pool).await?;
    let tx = client.transaction().await.map_err(db)?;
    lock_writable(&tx, board).await?;
    let mut marked = 0u64;
    for adoption in adoptions {
        let (name, kind, role) = (&adoption.name, adoption.kind, adoption.role);
        insert(&tx, board, name, kind, role, now_ms).await?;
        marked += tx
            .execute(
                "UPDATE messages SET author_kind = $3
                 WHERE board_id = $1 AND author = $2 AND author_kind = $4",
                &[
                    &board.as_str(),
                    &name.as_str(),
                    &PRINCIPAL_AUTHOR_KIND,
                    &LOCAL_AUTHOR_KIND,
                ],
            )
            .await
            .map_err(db)?;
    }
    let row = SecurityEvent {
        at_ms: now_ms,
        kind: SecurityEventKind::PrincipalsAdopted,
        board: Some(board.clone()),
        principal: Some(INSTANCE_ADMIN.to_owned()),
        detail: format!(
            "adopted {} authors ({marked} messages) into board {board}",
            adoptions.len()
        ),
    };
    log_in_tx(&tx, &row).await?;
    tx.commit().await.map_err(db)?;
    Ok(marked)
}

/// Rebuilds a member from a `MEMBER_COLUMNS` row, re-validating what was stored.
fn member_from_row(board: &BoardId, row: &Row) -> Result<Member, StoreError> {
    let name: &str = row.try_get(0).map_err(db)?;
    Ok(Member {
        board: board.clone(),
        name: Principal::new(name).map_err(backend)?,
        kind: parse_kind(row.try_get(1).map_err(db)?)?,
        role: parse_role(row.try_get(2).map_err(db)?)?,
        created_at_ms: row.try_get(3).map_err(db)?,
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
