//! Invites: storing them and redeeming one (the join). Only secret hashes are stored.
//!
//! A join is checked first without any lock, so a refused attempt never waits on (or reveals
//! anything through) the board's locks. A join that passes then locks the invite's board row and
//! the invite row (`FOR UPDATE`), the same order as every other write on a board, so
//! concurrent redemptions of one invite queue and exactly one of them finds it unused.

use deadpool_postgres::Pool;
use stigmer_core::{hashes_match, BoardId, Principal, PrincipalKind, Role, TokenId};
use stigmer_store::{
    Consumed, CredentialScope, Entity, NewCredential, NewInvite, NewJoinCredential, SecurityEvent,
    SecurityEventKind, StoreError,
};
use tokio_postgres::{Row, Transaction};

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

/// What the unlocked first read of `consume_invite` found: everything needed to refuse an
/// unusable invite without taking a lock.
struct Candidate {
    secret_hash: [u8; 32],
    board: BoardId,
    role: Role,
    kind: PrincipalKind,
    expires_at_ms: i64,
    used: bool,
    board_archived: bool,
}

impl Candidate {
    fn usable(&self, now_ms: i64) -> bool {
        now_ms < self.expires_at_ms && !self.used && !self.board_archived
    }
}

/// Checks and uses an invite. Every refusal of the invite itself is the same `NotFound`, so
/// callers cannot tell why it failed; any failure rolls everything back.
///
/// The check comes first, in ONE unlocked read on the connection (no transaction, no lock): the
/// invite with its board's archived flag, the constant-time hash comparison (against a dummy
/// hash for an unknown id) and the expiry, use and archive checks. So an unknown id and a wrong
/// secret cost the same single round trip and never wait behind a lock, whatever else is
/// happening on the board, and their timing tells a caller nothing. Only a matching invite that
/// looks usable goes on to one transaction: lock the board row, then the invite row (`FOR
/// UPDATE`), the lock order of every write on a board; re-check use, expiry and archive under
/// the locks (another join or an archive may have committed since the read); then the member
/// insert, the member's credential, the used mark and the `Join` log row.
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
    let row = client
        .query_opt(
            "SELECT i.secret_hash, i.board_id, i.role, i.kind, i.expires_at_ms,
                    i.used_at_ms IS NOT NULL, b.archived_at_ms IS NOT NULL
             FROM invites i JOIN boards b ON b.id = i.board_id WHERE i.id = $1",
            &[&id.as_str()],
        )
        .await
        .map_err(db)?;
    let Some(row) = row else {
        // Do the same hash work as for a wrong secret, so the time an unknown id takes does not
        // tell a caller which invite ids exist. `black_box` keeps the comparison from being
        // optimised away.
        std::hint::black_box(hashes_match(&UNKNOWN_INVITE_HASH, secret_hash));
        return Err(refused());
    };
    let candidate = candidate_from_row(&row)?;
    let matches = hashes_match(&candidate.secret_hash, secret_hash);
    if !matches || !candidate.usable(now_ms) {
        return Err(refused());
    }
    let Candidate {
        board, role, kind, ..
    } = candidate;

    let tx = client.transaction().await.map_err(db)?;
    // Board row first, then the invite row. A board archived since the read refuses the invite
    // like any other unusable one.
    match lock_writable(&tx, &board).await {
        Ok(()) => {}
        Err(StoreError::Conflict(_)) => return Err(refused()),
        Err(e) => return Err(e),
    }
    let locked = tx
        .query_opt(
            "SELECT expires_at_ms, used_at_ms IS NOT NULL FROM invites WHERE id = $1 FOR UPDATE",
            &[&id.as_str()],
        )
        .await
        .map_err(db)?
        .ok_or_else(refused)?;
    let expires_at_ms: i64 = locked.try_get(0).map_err(db)?;
    let used: bool = locked.try_get(1).map_err(db)?;
    if now_ms >= expires_at_ms || used {
        return Err(refused());
    }
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

/// Rebuilds the first read of `consume_invite`, re-validating what was stored.
fn candidate_from_row(row: &Row) -> Result<Candidate, StoreError> {
    Ok(Candidate {
        secret_hash: to_hash(row.try_get(0).map_err(db)?)?,
        board: BoardId::new(row.try_get(1).map_err(db)?).map_err(backend)?,
        role: parse_role(row.try_get(2).map_err(db)?)?,
        kind: parse_kind(row.try_get(3).map_err(db)?)?,
        expires_at_ms: row.try_get(4).map_err(db)?,
        used: row.try_get(5).map_err(db)?,
        board_archived: row.try_get(6).map_err(db)?,
    })
}
