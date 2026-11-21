//! The event feed and the board head.

use rusqlite::Connection;
use stigmer_core::{BoardId, Cursor, Event, EventFilter};
use stigmer_store::StoreError;

use crate::backend;
use crate::posts::{board_head, event_from_row};
use crate::reads::channel_matches;

const MAX_EVENTS: u32 = 500;

/// Decodes an optional cursor to a sequence number; `None` is before the first event.
pub(crate) fn cursor_seq(after: Option<&Cursor>) -> Result<u64, StoreError> {
    match after {
        None => Ok(0),
        Some(cursor) => cursor.seq().map_err(|_| StoreError::InvalidCursor),
    }
}

/// The board's head sequence (0 while it has no events).
pub(crate) fn head_seq(conn: &mut Connection, board: &BoardId) -> Result<u64, StoreError> {
    let tx = conn.transaction().map_err(backend)?;
    let (seq, _hash) =
        board_head(&tx, board)?.ok_or_else(|| StoreError::NotFound(format!("board {board}")))?;
    Ok(seq)
}

/// The cursor of the latest event, or `None` on an empty board.
pub(crate) fn head(conn: &mut Connection, board: &BoardId) -> Result<Option<Cursor>, StoreError> {
    let seq = head_seq(conn, board)?;
    Ok((seq > 0).then(|| Cursor::from_seq(seq)))
}

/// Events after `after` matching `filter`, ascending by sequence.
pub(crate) fn events_after(
    conn: &mut Connection,
    board: &BoardId,
    after: Option<&Cursor>,
    filter: &EventFilter,
    limit: u32,
) -> Result<Vec<Event>, StoreError> {
    let after_seq = cursor_seq(after)?;
    let limit = limit.clamp(1, MAX_EVENTS);
    // One read transaction, so the head check and the events come from the same snapshot.
    let tx = conn.transaction().map_err(backend)?;
    let (head, _hash) =
        board_head(&tx, board)?.ok_or_else(|| StoreError::NotFound(format!("board {board}")))?;
    if after_seq > head {
        return Err(StoreError::InvalidCursor);
    }

    let sql = format!(
        "SELECT e.seq, e.kind, e.actor, e.message_id, e.thread_id, e.channel, e.at_ms, e.hash
           FROM events e
          WHERE e.board_id = ?1 AND e.seq > ?2
            AND (?3 IS NULL OR {})
            AND (?4 IS NULL OR e.thread_id = ?4)
            AND (?5 IS NULL OR EXISTS (
                  SELECT 1 FROM labels l
                   WHERE l.message_id = e.message_id AND l.key = ?5 AND l.value = ?6))
          ORDER BY e.seq
          LIMIT ?7",
        channel_matches("e.channel", "?3")
    );
    let mut stmt = tx.prepare(&sql).map_err(backend)?;
    let mut rows = stmt
        .query((
            board.as_str(),
            i64::try_from(after_seq).map_err(backend)?,
            filter.channel_prefix.as_ref().map(|c| c.as_str()),
            filter.thread.as_ref().map(|t| t.as_str()),
            filter.label.as_ref().map(|l| l.key.as_str()),
            filter.label.as_ref().map(|l| l.value.as_str()),
            i64::from(limit),
        ))
        .map_err(backend)?;
    let mut events = Vec::new();
    while let Some(row) = rows.next().map_err(backend)? {
        let event = event_from_row(row)?
            .ok_or_else(|| StoreError::Backend("stored event is invalid".into()))?;
        events.push(event);
    }
    Ok(events)
}
