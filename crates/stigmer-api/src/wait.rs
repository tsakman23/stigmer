//! The events read: a plain feed read, or a long poll that waits for a matching event.

use std::future::{pending, Future};
use std::time::Duration;

use stigmer_core::{BoardId, Cursor, EventFilter, EventsResponse};
use stigmer_store::{Store, StoreError};
use tokio::sync::watch;
use tokio::time::Instant;

/// What an events read came to.
#[derive(Debug)]
pub(crate) enum Read {
    Events(EventsResponse),
    /// The caller stopped being allowed while the read waited (`still_allowed` said no).
    NoLongerAllowed,
}

/// What to read: the board, where to start, which events count and how long to wait.
#[derive(Debug)]
pub(crate) struct WaitRequest<'a> {
    pub(crate) board: &'a BoardId,
    pub(crate) after: Option<Cursor>,
    pub(crate) filter: &'a EventFilter,
    pub(crate) limit: u32,
    /// Zero reads once and returns; anything else is a long poll with this deadline.
    pub(crate) timeout: Duration,
}

/// Reads events after `request.after`. With `request.timeout > 0` and nothing to return, waits until a
/// matching event lands, the deadline passes, or `shutdown` flips to `true`. The deadline is
/// fixed once; wake-ups for events the filter rejects do not extend it.
///
/// After every wake `still_allowed` is asked again before anything is read or returned, so a
/// credential revoked, expired or removed while the request waited gets no events.
///
/// Dropping the returned future cancels the wait, so a client disconnect needs no cleanup.
pub(crate) async fn read_events<S, F, Fut>(
    store: &S,
    mut shutdown: watch::Receiver<bool>,
    request: WaitRequest<'_>,
    mut still_allowed: F,
) -> Result<Read, StoreError>
where
    S: Store,
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<bool, StoreError>>,
{
    let WaitRequest {
        board,
        after,
        filter,
        limit,
        timeout,
    } = request;
    let deadline = Instant::now() + timeout;
    // Where the next scan starts: the request's cursor, then the head read by the last pass that
    // found nothing, so a long wait woken by non-matching events does not rescan them every time.
    let mut scan_from = after.clone();
    loop {
        // Read the head first: everything up to it is examined by the query below, so if the
        // query comes back empty the wait can start from here, and so can the next scan.
        // Waiting from `after` instead would return at once for every non-matching event
        // already in the log.
        //
        // Invariant: a cursor returned without events (`after.or(head)` below) never lets a
        // resume skip a matching event. `after` was the request's own start. `head` is read
        // BEFORE the scan that found nothing, so every event at or below it was scanned and none
        // matched. An event committed after this read has a higher sequence number: it is
        // either seen by the next pass of this loop (`wait_past` returns at once because the
        // head has moved) or returned to the request that resumes from `head`. Reading the head
        // after the scan instead would let an event that lands between the two be skipped. The
        // same holds for the next pass, which scans from this `head` (`scan_from`).
        let head = store.head(board).await?;
        let events = store
            .events_after(board, scan_from.as_ref(), filter, limit)
            .await?;
        if let Some(last) = events.last() {
            let cursor = Some(last.cursor.clone());
            return Ok(Read::Events(EventsResponse {
                events,
                cursor,
                timed_out: false,
            }));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let give_up = !timeout.is_zero() && (remaining.is_zero() || *shutdown.borrow());
        if timeout.is_zero() || give_up {
            return Ok(Read::Events(EventsResponse {
                events,
                cursor: after.or(head),
                timed_out: give_up,
            }));
        }
        if head.is_some() {
            scan_from.clone_from(&head);
        }
        tokio::select! {
            woke = store.wait_past(board, head.as_ref(), remaining) => { woke?; }
            _ = shutdown_changed(&mut shutdown) => {}
        }
        if !still_allowed().await? {
            return Ok(Read::NoLongerAllowed);
        }
    }
}

/// Resolves when the shutdown value changes; never resolves if the sender is gone.
async fn shutdown_changed(shutdown: &mut watch::Receiver<bool>) {
    if shutdown.changed().await.is_err() {
        pending::<()>().await;
    }
}

#[cfg(test)]
mod tests;
