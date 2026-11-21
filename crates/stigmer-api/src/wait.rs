//! The events read: a plain feed read, or a long poll that waits for a matching event.

use std::future::pending;
use std::time::Duration;

use stigmer_core::{BoardId, Cursor, EventFilter, EventsResponse};
use stigmer_store::{Store, StoreError};
use tokio::sync::watch;
use tokio::time::Instant;

/// Reads events after `after`. With `timeout > 0` and nothing to return, waits until a
/// matching event lands, the deadline passes, or `shutdown` flips to `true`. The deadline is
/// fixed once; wake-ups for events the filter rejects do not extend it.
///
/// Dropping the returned future cancels the wait, so a client disconnect needs no cleanup.
pub(crate) async fn read_events<S: Store>(
    store: &S,
    mut shutdown: watch::Receiver<bool>,
    board: &BoardId,
    after: Option<Cursor>,
    filter: &EventFilter,
    limit: u32,
    timeout: Duration,
) -> Result<EventsResponse, StoreError> {
    let deadline = Instant::now() + timeout;
    loop {
        // Read the head first: everything up to it is examined by the query below, so if the
        // query comes back empty the wait can start from here. Waiting from `after` instead
        // would return at once for every non-matching event already in the log.
        //
        // Invariant: a cursor returned without events (`after.or(head)` below) never lets a
        // resume skip a matching event. `after` was the request's own start. `head` is read
        // BEFORE the scan that found nothing, so every event at or below it was scanned and none
        // matched. An event committed after this read has a higher sequence number: it is
        // either seen by the next pass of this loop (`wait_past` returns at once because the
        // head has moved) or returned to the request that resumes from `head`. Reading the head
        // after the scan instead would let an event that lands between the two be skipped.
        let head = store.head(board).await?;
        let events = store
            .events_after(board, after.as_ref(), filter, limit)
            .await?;
        if let Some(last) = events.last() {
            let cursor = Some(last.cursor.clone());
            return Ok(EventsResponse {
                events,
                cursor,
                timed_out: false,
            });
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let give_up = !timeout.is_zero() && (remaining.is_zero() || *shutdown.borrow());
        if timeout.is_zero() || give_up {
            return Ok(EventsResponse {
                events,
                cursor: after.or(head),
                timed_out: give_up,
            });
        }
        tokio::select! {
            woke = store.wait_past(board, head.as_ref(), remaining) => { woke?; }
            _ = shutdown_changed(&mut shutdown) => {}
        }
    }
}

/// Resolves when the shutdown value changes; never resolves if the sender is gone.
async fn shutdown_changed(shutdown: &mut watch::Receiver<bool>) {
    if shutdown.changed().await.is_err() {
        pending::<()>().await;
    }
}
