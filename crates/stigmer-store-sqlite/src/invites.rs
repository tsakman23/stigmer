//! Invites: storing them and redeeming one (the join). Only secret hashes are stored.

use rusqlite::{Connection, OptionalExtension, Transaction};
use stigmer_core::{hashes_match, BoardId, Principal, TokenId};
use stigmer_store::{
    Consumed, CredentialScope, Entity, NewCredential, NewInvite, NewJoinCredential, SecurityEvent,
    SecurityEventKind, StoreError,
};

use crate::boards::require_writable;
use crate::credentials::{insert_credential, log_in_tx, to_hash};
use crate::members::{immediate, insert, parse_kind, parse_role};
use crate::{backend, not_found};

/// What an unknown invite id is compared against: no stored invite has this hash's secret.
const UNKNOWN_INVITE_HASH: [u8; 32] = [0; 32];

/// An invite row as stored, before validation.
struct StoredInvite {
    secret_hash: Vec<u8>,
    board: String,
    role: String,
    kind: String,
    expires_at_ms: i64,
    used_at_ms: Option<i64>,
    board_archived: bool,
}

/// Stores an invite into an existing, unarchived board and writes its audit row.
pub(crate) fn create_invite(
    conn: &mut Connection,
    invite: NewInvite,
    audit: &SecurityEvent,
) -> Result<(), StoreError> {
    let now_ms = audit.at_ms;
    let tx = immediate(conn)?;
    insert_invite(&tx, &invite, now_ms)?;
    log_in_tx(&tx, audit)?;
    tx.commit().map_err(backend)
}

/// Inserts an invite inside the caller's transaction; the board must exist and be unarchived.
pub(crate) fn insert_invite(
    tx: &Transaction<'_>,
    invite: &NewInvite,
    now_ms: i64,
) -> Result<(), StoreError> {
    require_writable(tx, &invite.board)?;
    tx.execute(
        "INSERT INTO invites
             (id, secret_hash, board_id, role, kind, created_by, created_at_ms, expires_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        (
            invite.id.as_str(),
            &invite.secret_hash[..],
            invite.board.as_str(),
            invite.role.as_str(),
            invite.kind.as_str(),
            invite.created_by.as_str(),
            now_ms,
            invite.expires_at_ms,
        ),
    )
    .map_err(backend)?;
    Ok(())
}

/// Checks and uses an invite in one `BEGIN IMMEDIATE` transaction: lookup, constant-time hash
/// comparison, expiry, use and archived-board checks, member insert, the member's credential,
/// the used mark and the `Join` log row. Every refusal of the invite itself is the same
/// `NotFound`, so callers cannot tell why it failed; any failure rolls everything back.
pub(crate) fn consume_invite(
    conn: &mut Connection,
    id: &TokenId,
    secret_hash: &[u8; 32],
    name: &Principal,
    now_ms: i64,
    join: NewJoinCredential,
) -> Result<Consumed, StoreError> {
    let tx = immediate(conn)?;
    let stored = tx
        .query_row(
            "SELECT i.secret_hash, i.board_id, i.role, i.kind, i.expires_at_ms, i.used_at_ms,
                    b.archived_at_ms
             FROM invites i JOIN boards b ON b.id = i.board_id WHERE i.id = ?1",
            [id.as_str()],
            |row| {
                Ok(StoredInvite {
                    secret_hash: row.get(0)?,
                    board: row.get(1)?,
                    role: row.get(2)?,
                    kind: row.get(3)?,
                    expires_at_ms: row.get(4)?,
                    used_at_ms: row.get(5)?,
                    board_archived: row.get::<_, Option<i64>>(6)?.is_some(),
                })
            },
        )
        .optional()
        .map_err(backend)?;
    let refused = || not_found(Entity::Invite, id);
    let Some(stored) = stored else {
        // Do the same hash work as for a wrong secret, so the time an unknown id takes does not
        // tell a caller which invite ids exist. `black_box` keeps the comparison from being
        // optimised away.
        std::hint::black_box(hashes_match(&UNKNOWN_INVITE_HASH, secret_hash));
        return Err(refused());
    };
    let matches = hashes_match(&to_hash(stored.secret_hash)?, secret_hash);
    let usable =
        now_ms < stored.expires_at_ms && stored.used_at_ms.is_none() && !stored.board_archived;
    if !matches || !usable {
        return Err(refused());
    }
    let board = BoardId::new(&stored.board).map_err(backend)?;
    let (role, kind) = (parse_role(&stored.role)?, parse_kind(&stored.kind)?);
    let member = insert(&tx, &board, name, kind, role, now_ms)?;
    let token_id = join.id.clone();
    let credential = NewCredential {
        id: join.id,
        secret_hash: join.secret_hash,
        scope: CredentialScope::Board(board.clone()),
        principal: name.clone(),
        expires_at_ms: join.expires_at_ms,
    };
    insert_credential(&tx, &credential, Some(&board), now_ms)?;
    tx.execute(
        "UPDATE invites SET used_at_ms = ?2 WHERE id = ?1",
        (id.as_str(), now_ms),
    )
    .map_err(backend)?;
    log_in_tx(
        &tx,
        &SecurityEvent {
            at_ms: now_ms,
            kind: SecurityEventKind::Join,
            board: Some(board.clone()),
            principal: Some(name.to_string()),
            detail: format!(
                "joined as {}/{} via invite {id} token {token_id}",
                kind.as_str(),
                role.as_str()
            ),
        },
    )?;
    tx.commit().map_err(backend)?;
    Ok(Consumed {
        board,
        role,
        kind,
        member,
    })
}
