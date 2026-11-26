//! Thread summaries: one row per thread root, kept in step with the post transaction (ADR 0015).

use stigmer_core::{BoardId, ChannelPath, MessageId};
use stigmer_store::StoreError;
use tokio_postgres::Transaction;

use crate::error::db;

/// Characters (not bytes) of the root text kept as a thread's preview.
pub(crate) const PREVIEW_CHARS: usize = 200;

/// Records thread root `thread`, whose event is `seq`, posted at `at_ms`.
pub(crate) async fn insert_thread(
    tx: &Transaction<'_>,
    board: &BoardId,
    thread: &MessageId,
    channel: &ChannelPath,
    root_text: &str,
    seq: i64,
    at_ms: i64,
) -> Result<(), StoreError> {
    let preview: String = root_text.chars().take(PREVIEW_CHARS).collect();
    tx.execute(
        "INSERT INTO threads
             (board_id, thread_id, channel, preview, reply_count, first_seq, last_seq, last_at_ms)
         VALUES ($1, $2, $3, $4, 0, $5, $5, $6)",
        &[
            &board.as_str(),
            &thread.as_str(),
            &channel.as_str(),
            &preview,
            &seq,
            &at_ms,
        ],
    )
    .await
    .map_err(db)?;
    Ok(())
}

/// Records a reply to `thread` whose event is `seq`, posted at `at_ms`. A thread root with no
/// summary row is a damaged database: the post fails and writes nothing.
pub(crate) async fn record_reply(
    tx: &Transaction<'_>,
    board: &BoardId,
    thread: &MessageId,
    seq: i64,
    at_ms: i64,
) -> Result<(), StoreError> {
    let updated = tx
        .execute(
            "UPDATE threads SET reply_count = reply_count + 1, last_seq = $1, last_at_ms = $2
              WHERE board_id = $3 AND thread_id = $4",
            &[&seq, &at_ms, &board.as_str(), &thread.as_str()],
        )
        .await
        .map_err(db)?;
    if updated != 1 {
        return Err(StoreError::Backend(format!(
            "thread {thread} on board {board} has no summary row"
        )));
    }
    Ok(())
}
