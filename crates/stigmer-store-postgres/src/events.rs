//! The event feed and the board head.

use deadpool_postgres::Pool;
use stigmer_core::{BoardId, Cursor, Event, EventFilter};
use stigmer_store::{Entity, StoreError};

use crate::chain::{event_from_row, EVENT_COLUMNS};
use crate::error::{backend, db, not_found};
use crate::pool;
use crate::reads::{channel_matches, snapshot};

const MAX_EVENTS: u32 = 500;

/// Decodes an optional cursor to a sequence number; `None` is before the first event.
pub(crate) fn cursor_seq(after: Option<&Cursor>) -> Result<u64, StoreError> {
    match after {
        None => Ok(0),
        Some(cursor) => cursor.seq().map_err(|_| StoreError::InvalidCursor),
    }
}

/// The board's head sequence (0 while it has no events) and whether it is archived. Takes a
/// connection for one statement and gives it back before returning.
pub(crate) async fn head_state(pool: &Pool, board: &BoardId) -> Result<(u64, bool), StoreError> {
    let client = pool::client(pool).await?;
    let row = client
        .query_opt(
            "SELECT head_seq, archived_at_ms IS NOT NULL FROM boards WHERE id = $1",
            &[&board.as_str()],
        )
        .await
        .map_err(db)?
        .ok_or_else(|| not_found(Entity::Board, board))?;
    let seq: i64 = row.try_get(0).map_err(db)?;
    let archived: bool = row.try_get(1).map_err(db)?;
    Ok((u64::try_from(seq).map_err(backend)?, archived))
}

/// The cursor of the latest event, or `None` on an empty board.
pub(crate) async fn head(pool: &Pool, board: &BoardId) -> Result<Option<Cursor>, StoreError> {
    let (seq, _archived) = head_state(pool, board).await?;
    Ok((seq > 0).then(|| Cursor::from_seq(seq)))
}

/// Events after `after` matching `filter`, ascending by sequence.
pub(crate) async fn events_after(
    pool: &Pool,
    board: &BoardId,
    after: Option<&Cursor>,
    filter: &EventFilter,
    limit: u32,
) -> Result<Vec<Event>, StoreError> {
    let after_seq = cursor_seq(after)?;
    let limit = i64::from(limit.clamp(1, MAX_EVENTS));
    let mut client = pool::client(pool).await?;
    // One snapshot, so the head check and the events agree.
    let tx = snapshot(&mut client).await?;
    let head: i64 = tx
        .query_opt(
            "SELECT head_seq FROM boards WHERE id = $1",
            &[&board.as_str()],
        )
        .await
        .map_err(db)?
        .ok_or_else(|| not_found(Entity::Board, board))?
        .try_get(0)
        .map_err(db)?;
    if after_seq > u64::try_from(head).map_err(backend)? {
        return Err(StoreError::InvalidCursor);
    }

    let sql = format!(
        "SELECT {EVENT_COLUMNS} FROM events e
          WHERE e.board_id = $1 AND e.seq > $2
            AND ($3::text IS NULL OR {})
            AND ($4::text IS NULL OR e.thread_id = $4)
            AND ($5::text IS NULL OR EXISTS (
                  SELECT 1 FROM labels l
                   WHERE l.message_id = e.message_id AND l.key = $5 AND l.value = $6))
          ORDER BY e.seq
          LIMIT $7",
        channel_matches("e.channel", "$3")
    );
    let rows = tx
        .query(
            &sql,
            &[
                &board.as_str(),
                &i64::try_from(after_seq).map_err(backend)?,
                &filter.channel_prefix.as_ref().map(|c| c.as_str()),
                &filter.thread.as_ref().map(|t| t.as_str()),
                &filter.label.as_ref().map(|l| l.key.as_str()),
                &filter.label.as_ref().map(|l| l.value.as_str()),
                &limit,
            ],
        )
        .await
        .map_err(db)?;
    tx.commit().await.map_err(db)?;
    rows.iter()
        .map(|row| {
            event_from_row(row)?
                .ok_or_else(|| StoreError::Backend("stored event is invalid".into()))
        })
        .collect()
}
