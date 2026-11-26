//! Waiting for a board's head to move, by polling it.
//!
//! Each round reads the head on a connection taken from the pool for that one statement and
//! given back before the round sleeps: a wait never holds a connection or a transaction while
//! it sleeps, so waiters cannot starve writers of connections. The head is read before every
//! decision, so a post that commits at any point is seen by the next round at the latest
//! (ADR 0005: the caller reads the head before it scans). Task 6 replaces the polling with
//! LISTEN/NOTIFY wake-ups.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use deadpool_postgres::Pool;
use stigmer_core::{BoardId, Cursor};
use stigmer_store::StoreError;
use tokio::time::Instant;

use crate::events::{cursor_seq, head_state};

/// How often a waiting caller reads the head.
pub(crate) const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// The callers currently waiting on each board through one handle.
#[derive(Default)]
pub(crate) struct Waiters(Mutex<HashMap<BoardId, usize>>);

impl Waiters {
    /// Counts a waiter on `board` until the returned guard is dropped.
    fn enter(self: &Arc<Self>, board: &BoardId) -> Waiting {
        *self.lock().entry(board.clone()).or_default() += 1;
        Waiting {
            waiters: Arc::clone(self),
            board: board.clone(),
        }
    }

    /// The number of callers waiting on `board` right now.
    pub(crate) fn count(&self, board: &BoardId) -> usize {
        self.lock().get(board).copied().unwrap_or(0)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<BoardId, usize>> {
        // The map stays consistent even if a holder panicked: every update is one statement.
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// One counted waiter; dropping it (on return or cancellation) uncounts it.
struct Waiting {
    waiters: Arc<Waiters>,
    board: BoardId,
}

impl Drop for Waiting {
    fn drop(&mut self) {
        let mut map = self.waiters.lock();
        if let Some(count) = map.get_mut(&self.board) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                map.remove(&self.board);
            }
        }
    }
}

/// Waits up to `timeout` for the head of `board` to pass `after`; see `Store::wait_past`.
pub(crate) async fn wait_past(
    pool: &Pool,
    waiters: &Arc<Waiters>,
    board: &BoardId,
    after: Option<&Cursor>,
    timeout: Duration,
) -> Result<bool, StoreError> {
    let deadline = Instant::now().checked_add(timeout);
    let after_seq = cursor_seq(after)?;
    let mut waiting = None;
    loop {
        let (head, archived) = head_state(pool, board).await?;
        if after_seq > head {
            return Err(StoreError::InvalidCursor);
        }
        if head > after_seq {
            return Ok(true);
        }
        if archived {
            // An archived board's head can no longer move: sleep out the timeout, no polling.
            sleep_until(deadline).await;
            return Ok(false);
        }
        // Counted only once the wait is known to block, so a test can post after this.
        waiting.get_or_insert_with(|| waiters.enter(board));
        let pause = match deadline {
            None => POLL_INTERVAL,
            Some(deadline) => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Ok(false);
                }
                left.min(POLL_INTERVAL)
            }
        };
        tokio::time::sleep(pause).await;
    }
}

/// Sleeps until `deadline`, or forever when there is none (a timeout too large to represent).
async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waiters_are_counted_per_board_until_their_guard_drops() {
        let waiters = Arc::new(Waiters::default());
        let (main, other) = (BoardId::main(), BoardId::new("other").unwrap());
        let first = waiters.enter(&main);
        let second = waiters.enter(&main);
        assert_eq!((waiters.count(&main), waiters.count(&other)), (2, 0));
        drop(first);
        assert_eq!(waiters.count(&main), 1);
        drop(second);
        assert_eq!(waiters.count(&main), 0);
        assert!(waiters.lock().is_empty(), "no entry is left behind");
    }
}
