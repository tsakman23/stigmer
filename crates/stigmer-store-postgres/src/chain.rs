//! Reading events back and re-checking a board's hash chain.

use deadpool_postgres::Pool;
use stigmer_core::{
    event_hash, BoardId, ChannelPath, Cursor, Event, EventKind, HashInput, MessageId, Principal,
    GENESIS_HASH,
};
use stigmer_store::{ChainReport, Entity, StoreError};
use tokio_postgres::Row;

use crate::boards::head_from_row;
use crate::error::{backend, db, not_found};
use crate::{hash, pool};

/// Events read per round trip while checking a chain.
const VERIFY_BATCH: i64 = 1000;

/// The event columns `event_from_row` reads, in order.
pub(crate) const EVENT_COLUMNS: &str =
    "e.seq, e.kind, e.actor, e.message_id, e.thread_id, e.channel, e.at_ms, e.hash";

/// Recomputes the board's chain from genesis, in seq order, and compares it with the board
/// head, all in one snapshot.
pub(crate) async fn verify_chain(pool: &Pool, board: &BoardId) -> Result<ChainReport, StoreError> {
    let mut client = pool::client(pool).await?;
    let tx = client
        .build_transaction()
        .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
        .read_only(true)
        .start()
        .await
        .map_err(db)?;
    let head = tx
        .query_opt(
            "SELECT head_seq, head_hash FROM boards WHERE id = $1",
            &[&board.as_str()],
        )
        .await
        .map_err(db)?
        .ok_or_else(|| not_found(Entity::Board, board))?;
    let (head_seq, head_hash) = head_from_row(&head)?;

    let mut prev = GENESIS_HASH.to_owned();
    let mut last_seq = 0u64;
    loop {
        let rows = tx
            .query(
                &format!(
                    "SELECT {EVENT_COLUMNS} FROM events e
                      WHERE e.board_id = $1 AND e.seq > $2 ORDER BY e.seq LIMIT $3"
                ),
                &[
                    &board.as_str(),
                    &i64::try_from(last_seq).map_err(backend)?,
                    &VERIFY_BATCH,
                ],
            )
            .await
            .map_err(db)?;
        for row in &rows {
            let expected_seq = last_seq + 1;
            let bad = ChainReport {
                valid: false,
                checked: expected_seq,
                first_bad_seq: Some(expected_seq),
            };
            let Some(event) = event_from_row(row)? else {
                return Ok(bad);
            };
            let recomputed = event_hash(&HashInput {
                prev: &prev,
                seq: event.seq,
                kind: event.kind,
                actor: &event.actor,
                message_id: &event.message_id,
                thread_id: &event.thread_id,
                channel: &event.channel,
                at_ms: event.at_ms,
            });
            if event.seq != expected_seq || event.hash != recomputed {
                return Ok(bad);
            }
            prev = recomputed;
            last_seq = event.seq;
        }
        if i64::try_from(rows.len()).map_err(backend)? < VERIFY_BATCH {
            break;
        }
    }
    tx.commit().await.map_err(db)?;

    Ok(ChainReport {
        valid: head_seq == last_seq && head_hash == prev,
        checked: last_seq,
        // Events past the head, or a head past the last event: the first seq they disagree on.
        // When only the head hash is wrong every event checks out, so there is no bad seq.
        first_bad_seq: (head_seq != last_seq).then(|| head_seq.min(last_seq) + 1),
    })
}

/// Rebuilds an event from an `EVENT_COLUMNS` row, re-validating every field. Returns `None` when
/// the row holds a value no valid event could have.
pub(crate) fn event_from_row(row: &Row) -> Result<Option<Event>, StoreError> {
    let seq: i64 = row.try_get(0).map_err(db)?;
    let kind: &str = row.try_get(1).map_err(db)?;
    let actor: &str = row.try_get(2).map_err(db)?;
    let message_id: &str = row.try_get(3).map_err(db)?;
    let thread_id: &str = row.try_get(4).map_err(db)?;
    let channel: &str = row.try_get(5).map_err(db)?;
    let at_ms: i64 = row.try_get(6).map_err(db)?;
    let hash: &[u8] = row.try_get(7).map_err(db)?;

    let Ok(seq) = u64::try_from(seq) else {
        return Ok(None);
    };
    let (Some(kind), Ok(actor), Ok(message_id), Ok(thread_id), Ok(channel), Some(hash)) = (
        EventKind::from_name(kind),
        Principal::new(actor),
        MessageId::new(message_id),
        MessageId::new(thread_id),
        ChannelPath::new(channel),
        hash::to_hex(hash),
    ) else {
        return Ok(None);
    };
    Ok(Some(Event {
        seq,
        cursor: Cursor::from_seq(seq),
        kind,
        actor,
        message_id,
        thread_id,
        channel,
        at_ms,
        hash,
    }))
}
