//! Security log rows written inside a mutation's transaction (ADR 0014): a row that cannot be
//! written fails the transaction, so the mutation and its row commit together or not at all.

use stigmer_core::BoardId;
use stigmer_store::{SecurityEvent, StoreError};
use tokio_postgres::Transaction;

use crate::error::db;

/// Appends `event` to the security log inside `tx`, stored as given.
pub(crate) async fn log_in_tx(
    tx: &Transaction<'_>,
    event: &SecurityEvent,
) -> Result<(), StoreError> {
    tx.execute(
        "INSERT INTO security_log (at_ms, kind, board_id, principal, detail)
         VALUES ($1, $2, $3, $4, $5)",
        &[
            &event.at_ms,
            &event.kind.as_str(),
            &event.board.as_ref().map(BoardId::as_str),
            &event.principal,
            &event.detail,
        ],
    )
    .await
    .map_err(db)?;
    Ok(())
}
