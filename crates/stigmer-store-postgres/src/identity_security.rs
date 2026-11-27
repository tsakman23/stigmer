//! The instance mode and the security log.
//!
//! The mode switch locks the single `instance` row, so two replicas switching at once queue
//! there: the second reads the committed network mode and is refused with `AlreadyNetwork`,
//! writing nothing.

use deadpool_postgres::Pool;
use stigmer_core::BoardId;
use stigmer_store::{
    ConflictKind, EnableAudits, Mode, NewCredential, NewInvite, SecurityEvent, SecurityEventKind,
    StoreError,
};
use tokio_postgres::Transaction;

use crate::audit::log_in_tx;
use crate::error::{backend, db};
use crate::identity_credentials::{insert_credential, require_instance_scope};
use crate::identity_invites::insert_invite;
use crate::pool;

/// The instance mode, from the single `instance` row.
pub(crate) async fn mode(pool: &Pool) -> Result<Mode, StoreError> {
    let client = pool::client(pool).await?;
    let row = client
        .query_one("SELECT mode FROM instance WHERE id = 1", &[])
        .await
        .map_err(db)?;
    parse_mode(row.try_get(0).map_err(db)?)
}

/// Moves a local instance to network mode and writes the audit row; `AlreadyNetwork` if it is
/// there already.
pub(crate) async fn enable_network_mode(
    pool: &Pool,
    audit: &SecurityEvent,
) -> Result<(), StoreError> {
    let mut client = pool::client(pool).await?;
    let tx = client.transaction().await.map_err(db)?;
    switch_to_network(&tx).await?;
    log_in_tx(&tx, audit).await?;
    tx.commit().await.map_err(db)
}

/// Stores the instance credential and the optional invite, moves a local instance to network
/// mode and writes the audit rows, all in one transaction. The instance row is locked first and
/// the invite's board row after it; nothing locks them the other way round.
pub(crate) async fn enable_network(
    pool: &Pool,
    credential: &NewCredential,
    invite: Option<&(NewInvite, SecurityEvent)>,
    audits: &EnableAudits,
) -> Result<(), StoreError> {
    require_instance_scope(credential)?;
    let mut client = pool::client(pool).await?;
    let tx = client.transaction().await.map_err(db)?;
    switch_to_network(&tx).await?;
    insert_credential(&tx, credential, None, audits.token.at_ms).await?;
    if let Some((invite, row)) = invite {
        insert_invite(&tx, invite, row.at_ms).await?;
    }
    for row in audits.rows(invite.map(|(_, row)| row)) {
        log_in_tx(&tx, row).await?;
    }
    tx.commit().await.map_err(db)
}

/// Locks the instance row and sets network mode inside `tx`; `AlreadyNetwork` if the instance
/// is not local. A concurrent caller waits on the lock, then reads the committed mode.
async fn switch_to_network(tx: &Transaction<'_>) -> Result<(), StoreError> {
    let row = tx
        .query_one("SELECT mode FROM instance WHERE id = 1 FOR UPDATE", &[])
        .await
        .map_err(db)?;
    if parse_mode(row.try_get(0).map_err(db)?)? == Mode::Network {
        return Err(StoreError::Conflict(ConflictKind::AlreadyNetwork));
    }
    tx.execute("UPDATE instance SET mode = 'network' WHERE id = 1", &[])
        .await
        .map_err(db)?;
    Ok(())
}

/// Appends a security log entry in a transaction of its own, for an event that is not part of
/// a mutation. Mutations write their rows inside their own transactions (`audit::log_in_tx`).
pub(crate) async fn log_security(pool: &Pool, event: &SecurityEvent) -> Result<(), StoreError> {
    let mut client = pool::client(pool).await?;
    let tx = client.transaction().await.map_err(db)?;
    log_in_tx(&tx, event).await?;
    tx.commit().await.map_err(db)
}

/// Up to `limit` security log entries, newest (last inserted) first.
pub(crate) async fn security_log(
    pool: &Pool,
    limit: u32,
) -> Result<Vec<SecurityEvent>, StoreError> {
    let client = pool::client(pool).await?;
    let rows = client
        .query(
            "SELECT at_ms, kind, board_id, principal, detail FROM security_log
             ORDER BY id DESC LIMIT $1",
            &[&i64::from(limit)],
        )
        .await
        .map_err(db)?;
    rows.iter()
        .map(|row| {
            let kind: &str = row.try_get(1).map_err(db)?;
            let board: Option<&str> = row.try_get(2).map_err(db)?;
            Ok(SecurityEvent {
                at_ms: row.try_get(0).map_err(db)?,
                kind: SecurityEventKind::parse(kind).ok_or_else(|| {
                    StoreError::Backend(format!("unknown security event kind {kind:?}"))
                })?,
                board: board
                    .map(|raw| BoardId::new(raw).map_err(backend))
                    .transpose()?,
                principal: row.try_get(3).map_err(db)?,
                detail: row.try_get(4).map_err(db)?,
            })
        })
        .collect()
}

fn parse_mode(raw: &str) -> Result<Mode, StoreError> {
    match raw {
        "local" => Ok(Mode::Local),
        "network" => Ok(Mode::Network),
        other => Err(StoreError::Backend(format!(
            "unknown instance mode {other:?}"
        ))),
    }
}
