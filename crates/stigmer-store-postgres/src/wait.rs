//! Waiting for a board's head to move past a cursor.
//!
//! The wait subscribes to the board's entry in the handle's notifier, THEN reads the head from
//! the database, then sleeps on the subscription: a post that commits before the read is seen
//! by it, one that commits after it reaches the subscription through NOTIFY (or, if the
//! listener is down, through its reconnect re-read or the safety poll). See `listener`.
//!
//! The head is read on a connection taken from the pool for that one statement and given back
//! before the wait sleeps: a wait never holds a connection or a transaction while it sleeps, so
//! waiters cannot starve writers of connections.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use deadpool_postgres::Pool;
use stigmer_core::{BoardId, Cursor};
use stigmer_store::StoreError;

use crate::events::{cursor_seq, head_state};
use crate::notify::Notifier;

/// Waits up to `timeout` for the head of `board` to pass `after`; see `Store::wait_past`.
/// `between` runs after the subscription and before the head read (a seam for tests).
pub(crate) async fn wait_past(
    pool: &Pool,
    notifier: &Arc<Notifier>,
    board: &BoardId,
    after: Option<&Cursor>,
    timeout: Duration,
    between: impl Future<Output = ()>,
) -> Result<bool, StoreError> {
    let after_seq = cursor_seq(after)?;
    // First: any commit after this point reaches the subscription. Dropped on every return,
    // which removes the board's entry if this was its last waiter.
    let mut subscription = notifier.subscribe(board);
    between.await;
    let (head, archived) = head_state(pool, board).await?;
    if after_seq > head {
        return Err(StoreError::InvalidCursor);
    }
    if head > after_seq {
        return Ok(true);
    }
    if archived {
        // An archived board's head can no longer move: no entry, sleep out the timeout.
        drop(subscription);
        let _ = tokio::time::timeout(timeout, std::future::pending::<()>()).await;
        return Ok(false);
    }
    // No spawned task: dropping this future drops the subscription and the timer with it.
    Ok(
        tokio::time::timeout(timeout, subscription.moved_past(after_seq))
            .await
            .unwrap_or(false),
    )
}

#[cfg(test)]
mod tests;
