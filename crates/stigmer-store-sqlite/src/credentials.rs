//! Credentials and the security log (invites live in `invites`). Only secret hashes are stored,
//! never secrets.

use rusqlite::{Connection, OptionalExtension, Row, Transaction};
use stigmer_core::{BoardId, Principal, Role, TokenId};
use stigmer_store::{
    Credential, CredentialScope, Entity, NewCredential, SecurityEvent, SecurityEventKind,
    StoreError,
};

use crate::boards::{require, require_writable};
use crate::members::immediate;
use crate::{backend, not_found};

const CREDENTIAL_COLUMNS: &str = "SELECT id, secret_hash, board_id, principal, expires_at_ms,
    revoked_at_ms, last_seen_ms FROM credentials";

/// Stores a credential and writes its audit row; a board-scoped one needs an existing,
/// unarchived board.
pub(crate) fn create(
    conn: &mut Connection,
    credential: NewCredential,
    audit: &SecurityEvent,
) -> Result<(), StoreError> {
    let now_ms = audit.at_ms;
    let tx = immediate(conn)?;
    let board = match &credential.scope {
        CredentialScope::Instance => None,
        CredentialScope::Board(board) => {
            require_writable(&tx, board)?;
            Some(board)
        }
    };
    insert_credential(&tx, &credential, board, now_ms)?;
    log_in_tx(&tx, audit)?;
    tx.commit().map_err(backend)
}

/// Inserts a credential row inside the caller's transaction.
pub(crate) fn insert_credential(
    tx: &Transaction<'_>,
    credential: &NewCredential,
    board: Option<&BoardId>,
    now_ms: i64,
) -> Result<(), StoreError> {
    tx.execute(
        "INSERT INTO credentials
             (id, secret_hash, board_id, principal, created_at_ms, expires_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        (
            credential.id.as_str(),
            &credential.secret_hash[..],
            board.map(BoardId::as_str),
            credential.principal.as_str(),
            now_ms,
            credential.expires_at_ms,
        ),
    )
    .map_err(backend)?;
    Ok(())
}

/// The credential `id`, or `None`.
pub(crate) fn find(conn: &Connection, id: &TokenId) -> Result<Option<Credential>, StoreError> {
    let mut stmt = conn
        .prepare(&format!("{CREDENTIAL_COLUMNS} WHERE id = ?1"))
        .map_err(backend)?;
    let mut rows = stmt.query([id.as_str()]).map_err(backend)?;
    rows.next()
        .map_err(backend)?
        .map(credential_from_row)
        .transpose()
}

/// Records the last use of a credential.
pub(crate) fn touch(conn: &Connection, id: &TokenId, now_ms: i64) -> Result<(), StoreError> {
    let changed = conn
        .execute(
            "UPDATE credentials SET last_seen_ms = ?2 WHERE id = ?1",
            (id.as_str(), now_ms),
        )
        .map_err(backend)?;
    if changed == 0 {
        return Err(not_found(Entity::Credential, id));
    }
    Ok(())
}

/// Every credential scoped to an existing board, oldest first.
pub(crate) fn list(conn: &mut Connection, board: &BoardId) -> Result<Vec<Credential>, StoreError> {
    let tx = conn.transaction().map_err(backend)?;
    require(&tx, board)?;
    let mut stmt = tx
        .prepare(&format!(
            "{CREDENTIAL_COLUMNS} WHERE board_id = ?1 ORDER BY created_at_ms, id"
        ))
        .map_err(backend)?;
    let mut rows = stmt.query([board.as_str()]).map_err(backend)?;
    let mut credentials = Vec::new();
    while let Some(row) = rows.next().map_err(backend)? {
        credentials.push(credential_from_row(row)?);
    }
    Ok(credentials)
}

/// Revokes a live credential and writes its audit row. A revoked one keeps its first revocation
/// time and gets no new row.
pub(crate) fn revoke(
    conn: &mut Connection,
    id: &TokenId,
    audit: &SecurityEvent,
) -> Result<(), StoreError> {
    let now_ms = audit.at_ms;
    let tx = immediate(conn)?;
    let revoked_at: Option<Option<i64>> = tx
        .query_row(
            "SELECT revoked_at_ms FROM credentials WHERE id = ?1",
            [id.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(backend)?;
    match revoked_at {
        None => Err(not_found(Entity::Credential, id)),
        Some(Some(_)) => Ok(()),
        Some(None) => {
            tx.execute(
                "UPDATE credentials SET revoked_at_ms = ?2 WHERE id = ?1",
                (id.as_str(), now_ms),
            )
            .map_err(backend)?;
            log_in_tx(&tx, audit)?;
            tx.commit().map_err(backend)
        }
    }
}

/// Revokes the board's live credentials, optionally sparing those of the board's admins.
pub(crate) fn revoke_board(
    conn: &mut Connection,
    board: &BoardId,
    keep_admins: bool,
    now_ms: i64,
) -> Result<u64, StoreError> {
    let tx = immediate(conn)?;
    require(&tx, board)?;
    let changed = revoke_board_in_tx(&tx, board, keep_admins, now_ms)?;
    tx.commit().map_err(backend)?;
    Ok(changed)
}

/// Revokes, inside the caller's transaction, the board's live credentials, optionally sparing
/// those of the board's admins. Returns the number revoked.
pub(crate) fn revoke_board_in_tx(
    tx: &Transaction<'_>,
    board: &BoardId,
    keep_admins: bool,
    now_ms: i64,
) -> Result<u64, StoreError> {
    let changed = tx
        .execute(
            "UPDATE credentials SET revoked_at_ms = ?2
             WHERE board_id = ?1 AND revoked_at_ms IS NULL
               AND NOT (?3 AND EXISTS (
                   SELECT 1 FROM principals p
                   WHERE p.board_id = credentials.board_id
                     AND p.name = credentials.principal
                     AND p.role = ?4))",
            (board.as_str(), now_ms, keep_admins, Role::Admin.as_str()),
        )
        .map_err(backend)?;
    u64::try_from(changed).map_err(backend)
}

/// Revokes every live instance credential but `keep`.
pub(crate) fn revoke_instance_except(
    conn: &mut Connection,
    keep: &TokenId,
    now_ms: i64,
) -> Result<u64, StoreError> {
    let tx = immediate(conn)?;
    let revoked = revoke_other_instance(&tx, keep, now_ms)?;
    tx.commit().map_err(backend)?;
    Ok(revoked)
}

/// Stores a new instance credential, revokes every other live one and writes the audit row,
/// plus a `TokenRevoked` row with the count when it revoked any, in one transaction.
pub(crate) fn replace_instance(
    conn: &mut Connection,
    credential: NewCredential,
    audit: &SecurityEvent,
) -> Result<u64, StoreError> {
    let now_ms = audit.at_ms;
    require_instance_scope(&credential)?;
    let tx = immediate(conn)?;
    insert_credential(&tx, &credential, None, now_ms)?;
    let revoked = revoke_other_instance(&tx, &credential.id, now_ms)?;
    log_in_tx(&tx, audit)?;
    if revoked > 0 {
        log_in_tx(
            &tx,
            &SecurityEvent {
                at_ms: audit.at_ms,
                kind: SecurityEventKind::TokenRevoked,
                board: None,
                principal: audit.principal.clone(),
                detail: format!("revoked {revoked} other instance credentials"),
            },
        )?;
    }
    tx.commit().map_err(backend)?;
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
fn revoke_other_instance(
    tx: &Transaction<'_>,
    keep: &TokenId,
    now_ms: i64,
) -> Result<u64, StoreError> {
    let changed = tx
        .execute(
            "UPDATE credentials SET revoked_at_ms = ?2
             WHERE board_id IS NULL AND revoked_at_ms IS NULL AND id <> ?1",
            (keep.as_str(), now_ms),
        )
        .map_err(backend)?;
    u64::try_from(changed).map_err(backend)
}

/// Appends a security log entry on `conn`: inside the caller's transaction for a mutation's
/// audit row, so a failed write rolls the mutation back, or on its own for `log_security`.
pub(crate) fn log_in_tx(conn: &Connection, event: &SecurityEvent) -> Result<(), StoreError> {
    conn.execute(
        "INSERT INTO security_log (at_ms, kind, board_id, principal, detail)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        (
            event.at_ms,
            event.kind.as_str(),
            event.board.as_ref().map(BoardId::as_str),
            &event.principal,
            &event.detail,
        ),
    )
    .map_err(backend)?;
    Ok(())
}

/// Up to `limit` security log entries, newest (last inserted) first.
pub(crate) fn security_log(
    conn: &Connection,
    limit: u32,
) -> Result<Vec<SecurityEvent>, StoreError> {
    let mut stmt = conn
        .prepare(
            "SELECT at_ms, kind, board_id, principal, detail FROM security_log
             ORDER BY id DESC LIMIT ?1",
        )
        .map_err(backend)?;
    let mut rows = stmt.query([limit]).map_err(backend)?;
    let mut events = Vec::new();
    while let Some(row) = rows.next().map_err(backend)? {
        let kind: String = row.get(1).map_err(backend)?;
        let board: Option<String> = row.get(2).map_err(backend)?;
        events.push(SecurityEvent {
            at_ms: row.get(0).map_err(backend)?,
            kind: SecurityEventKind::parse(&kind).ok_or_else(|| {
                StoreError::Backend(format!("unknown security event kind {kind:?}"))
            })?,
            board: board
                .map(|raw| BoardId::new(&raw).map_err(backend))
                .transpose()?,
            principal: row.get(3).map_err(backend)?,
            detail: row.get(4).map_err(backend)?,
        });
    }
    Ok(events)
}

/// Rebuilds a credential from a `CREDENTIAL_COLUMNS` row, re-validating what was stored.
fn credential_from_row(row: &Row<'_>) -> Result<Credential, StoreError> {
    let id: String = row.get(0).map_err(backend)?;
    let board: Option<String> = row.get(2).map_err(backend)?;
    let principal: String = row.get(3).map_err(backend)?;
    Ok(Credential {
        id: TokenId::new(&id).map_err(backend)?,
        secret_hash: to_hash(row.get(1).map_err(backend)?)?,
        scope: match board {
            None => CredentialScope::Instance,
            Some(raw) => CredentialScope::Board(BoardId::new(&raw).map_err(backend)?),
        },
        principal: Principal::new(&principal).map_err(backend)?,
        expires_at_ms: row.get(4).map_err(backend)?,
        revoked_at_ms: row.get(5).map_err(backend)?,
        last_seen_ms: row.get(6).map_err(backend)?,
    })
}

/// A stored secret hash as a fixed array. The error never shows the bytes.
pub(crate) fn to_hash(stored: Vec<u8>) -> Result<[u8; 32], StoreError> {
    <[u8; 32]>::try_from(stored)
        .map_err(|_| StoreError::Backend("stored secret hash is not 32 bytes".into()))
}
