//! Thread summaries: one row per thread root, kept in step with the post transaction.
//!
//! `read_channel` lists threads from this table instead of scanning messages (ADR 0015). A row
//! is written in the same transaction as the post's message and event: inserted for a new
//! thread, updated for a reply. Migration 8 backfills it for databases that predate it.

use rusqlite::Connection;
use stigmer_core::{BoardId, ChannelPath, MessageId};
use stigmer_store::StoreError;

use crate::backend;

/// Characters (not bytes) of the root text kept as a thread's preview.
pub(crate) const PREVIEW_CHARS: usize = 200;

/// Records thread root `thread`, whose event is `seq`, posted at `at_ms`.
pub(crate) fn insert_thread(
    conn: &Connection,
    board: &BoardId,
    thread: &MessageId,
    channel: &ChannelPath,
    root_text: &str,
    seq: i64,
    at_ms: i64,
) -> Result<(), StoreError> {
    let preview: String = root_text.chars().take(PREVIEW_CHARS).collect();
    conn.execute(
        "INSERT INTO threads
             (board_id, thread_id, channel, preview, reply_count, first_seq, last_seq, last_at_ms)
         VALUES (?1, ?2, ?3, ?4, 0, ?5, ?5, ?6)",
        (
            board.as_str(),
            thread.as_str(),
            channel.as_str(),
            preview,
            seq,
            at_ms,
        ),
    )
    .map_err(backend)?;
    Ok(())
}

/// Records a reply to `thread` whose event is `seq`, posted at `at_ms`. A thread root with no
/// summary row is a damaged database: the post fails and writes nothing.
pub(crate) fn record_reply(
    conn: &Connection,
    board: &BoardId,
    thread: &MessageId,
    seq: i64,
    at_ms: i64,
) -> Result<(), StoreError> {
    let updated = conn
        .execute(
            "UPDATE threads SET reply_count = reply_count + 1, last_seq = ?1, last_at_ms = ?2
              WHERE board_id = ?3 AND thread_id = ?4",
            (seq, at_ms, board.as_str(), thread.as_str()),
        )
        .map_err(backend)?;
    if updated != 1 {
        return Err(StoreError::Backend(format!(
            "thread {thread} on board {board} has no summary row"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
