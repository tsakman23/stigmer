//! Waiting for a board's head to move past a cursor.
//!
//! The wait subscribes to the board's entry in the handle's notifier, THEN reads the head from
//! the database, then sleeps on the subscription: a post that commits before the read is seen
//! by it, one that commits after it reaches the subscription through NOTIFY (or, if the
//! listener is down, through its reconnect re-read or the safety poll). See `listener`.
//!
//! The listener starts with the first wait that has to sleep, never for a wait that returns
//! at once, so a store that never waits opens no connection beyond its pool.
//!
//! The head is read on a connection taken from the pool for that one statement and given back
//! before the wait sleeps: a wait never holds a connection or a transaction while it sleeps, so
//! waiters cannot starve writers of connections.

use std::future::Future;
use std::time::Duration;

use deadpool_postgres::Pool;
use stigmer_core::{BoardId, Cursor};
use stigmer_store::StoreError;

use crate::events::{cursor_seq, head_state};
use crate::wakeups::Wakeups;

/// Waits up to `timeout` for the head of `board` to pass `after`; see `Store::wait_past`.
/// `seams` run just before and just after the head read (test seams; no-ops otherwise).
pub(crate) async fn wait_past(
    pool: &Pool,
    wakeups: &Wakeups,
    board: &BoardId,
    after: Option<&Cursor>,
    timeout: Duration,
    seams: Seams<impl Future<Output = ()>, impl Future<Output = ()>>,
) -> Result<bool, StoreError> {
    let after_seq = cursor_seq(after)?;
    // First: any commit after this point reaches the subscription. Dropped on every return,
    // which removes the board's entry if this was its last waiter.
    let mut subscription = wakeups.notifier().subscribe(board);
    seams.before_read.await;
    let (head, archived) = head_state(pool, board).await?;
    seams.after_read.await;
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
    // About to sleep: this is the first point a wait needs the listener. Starting it here,
    // after the subscription, is safe: its first re-read sees any commit the head read missed.
    wakeups.ensure_started().await?;
    // No spawned task: dropping this future drops the subscription and the timer with it.
    Ok(
        tokio::time::timeout(timeout, subscription.moved_past(after_seq))
            .await
            .unwrap_or(false),
    )
}

/// Futures a wait runs just before and just after it reads the head, so a test can commit a
/// post at exactly those points.
pub(crate) struct Seams<B, A> {
    pub(crate) before_read: B,
    pub(crate) after_read: A,
}

/// No seams: what every real wait uses.
pub(crate) fn no_seams() -> Seams<std::future::Ready<()>, std::future::Ready<()>> {
    Seams {
        before_read: std::future::ready(()),
        after_read: std::future::ready(()),
    }
}

#[cfg(test)]
mod tests;
