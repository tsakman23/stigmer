//! Thread and channel reads, each in one read-only snapshot.

use deadpool_postgres::{Object, Pool, Transaction};
use stigmer_core::{BoardId, ChannelPath, Message, MessageId, Principal};
use stigmer_store::{Entity, Page, StoreError, Thread, ThreadSummary};
use tokio_postgres::{IsolationLevel, Row};

use crate::error::{backend, db, not_found};
use crate::pool;
use crate::posts::labels_of;

const MAX_PAGE: u32 = 200;

/// SQL condition: channel `$N` is the prefix itself or sits under it, on whole segments.
/// `LIKE` is avoided on purpose: `_` is legal in channel paths and is a LIKE wildcard.
pub(crate) fn channel_matches(column: &str, param: &str) -> String {
    format!("({column} = {param} OR starts_with({column}, {param} || '/'))")
}

/// A read-only transaction that sees one snapshot for all its statements.
pub(crate) async fn snapshot(client: &mut Object) -> Result<Transaction<'_>, StoreError> {
    client
        .build_transaction()
        .isolation_level(IsolationLevel::RepeatableRead)
        .read_only(true)
        .start()
        .await
        .map_err(db)
}

/// `NotFound` with `Entity::Board` unless board `board` exists.
pub(crate) async fn require_board(
    tx: &tokio_postgres::Transaction<'_>,
    board: &BoardId,
) -> Result<(), StoreError> {
    tx.query_opt("SELECT 1 FROM boards WHERE id = $1", &[&board.as_str()])
        .await
        .map_err(db)?
        .map(drop)
        .ok_or_else(|| not_found(Entity::Board, board))
}

/// Lists threads under `prefix` from the summary table, latest event first (then thread id,
/// both descending), one keyset page at a time.
pub(crate) async fn read_channel(
    pool: &Pool,
    board: &BoardId,
    prefix: &ChannelPath,
    page: &Page,
) -> Result<Vec<ThreadSummary>, StoreError> {
    let limit = i64::from(page.limit.clamp(1, MAX_PAGE));
    let mut client = pool::client(pool).await?;
    // One snapshot, so the board check, the cursor thread and the listing agree.
    let tx = snapshot(&mut client).await?;
    require_board(&tx, board).await?;

    let before_seq: Option<i64> = match &page.before {
        None => None,
        Some(before) => Some(
            tx.query_opt(
                "SELECT last_seq FROM threads WHERE board_id = $1 AND thread_id = $2",
                &[&board.as_str(), &before.as_str()],
            )
            .await
            .map_err(db)?
            .ok_or_else(|| not_found(Entity::Thread, before))?
            .try_get(0)
            .map_err(db)?,
        ),
    };
    let before_id = page.before.as_ref().map(MessageId::as_str);

    let sql = format!(
        "SELECT thread_id, channel, preview, reply_count, last_at_ms FROM threads
          WHERE board_id = $1 AND {}
            AND ($3::bigint IS NULL OR last_seq < $3 OR (last_seq = $3 AND thread_id < $4))
          ORDER BY last_seq DESC, thread_id DESC
          LIMIT $5",
        channel_matches("channel", "$2")
    );
    let rows = tx
        .query(
            &sql,
            &[
                &board.as_str(),
                &prefix.as_str(),
                &before_seq,
                &before_id,
                &limit,
            ],
        )
        .await
        .map_err(db)?;
    let threads = rows.iter().map(summary_from_row).collect();
    tx.commit().await.map_err(db)?;
    threads
}

fn summary_from_row(row: &Row) -> Result<ThreadSummary, StoreError> {
    let thread_id: &str = row.try_get(0).map_err(db)?;
    let channel: &str = row.try_get(1).map_err(db)?;
    let replies: i64 = row.try_get(3).map_err(db)?;
    Ok(ThreadSummary {
        thread_id: MessageId::new(thread_id).map_err(backend)?,
        channel: ChannelPath::new(channel).map_err(backend)?,
        root_text_preview: row.try_get(2).map_err(db)?,
        reply_count: u32::try_from(replies).map_err(backend)?,
        last_at_ms: row.try_get(4).map_err(db)?,
    })
}

const MESSAGE_COLUMNS: &str =
    "SELECT m.id, m.board_id, m.channel, m.thread_id, m.author, m.text, m.at_ms";

/// Reads a thread root and its replies in event order. Anything but a thread root on `board`
/// (an unknown id, a reply, an unknown board) is `NotFound` with `Entity::Thread`.
pub(crate) async fn read_thread(
    pool: &Pool,
    board: &BoardId,
    thread: &MessageId,
) -> Result<Thread, StoreError> {
    let mut client = pool::client(pool).await?;
    let tx = snapshot(&mut client).await?;
    let root = tx
        .query_opt(
            &format!(
                "{MESSAGE_COLUMNS} FROM messages m
                  WHERE m.id = $1 AND m.board_id = $2 AND m.thread_id = m.id"
            ),
            &[&thread.as_str(), &board.as_str()],
        )
        .await
        .map_err(db)?
        .ok_or_else(|| not_found(Entity::Thread, thread))?;
    let root = message_from_row(&tx, &root).await?;
    let rows = tx
        .query(
            &format!(
                "{MESSAGE_COLUMNS} FROM messages m
                   JOIN events e ON e.board_id = m.board_id AND e.message_id = m.id
                  WHERE m.board_id = $1 AND m.thread_id = $2 AND m.id <> m.thread_id
                  ORDER BY e.seq"
            ),
            &[&board.as_str(), &thread.as_str()],
        )
        .await
        .map_err(db)?;
    let mut replies = Vec::with_capacity(rows.len());
    for row in &rows {
        replies.push(message_from_row(&tx, row).await?);
    }
    tx.commit().await.map_err(db)?;
    Ok(Thread { root, replies })
}

/// Rebuilds a message from a `MESSAGE_COLUMNS` row plus its labels, re-validating every field.
async fn message_from_row(
    tx: &tokio_postgres::Transaction<'_>,
    row: &Row,
) -> Result<Message, StoreError> {
    let id: &str = row.try_get(0).map_err(db)?;
    let board: &str = row.try_get(1).map_err(db)?;
    let channel: &str = row.try_get(2).map_err(db)?;
    let thread_id: &str = row.try_get(3).map_err(db)?;
    let author: &str = row.try_get(4).map_err(db)?;
    Ok(Message {
        id: MessageId::new(id).map_err(backend)?,
        board: BoardId::new(board).map_err(backend)?,
        channel: ChannelPath::new(channel).map_err(backend)?,
        thread_id: MessageId::new(thread_id).map_err(backend)?,
        author: Principal::new(author).map_err(backend)?,
        text: row.try_get(5).map_err(db)?,
        labels: labels_of(tx, id).await?,
        at_ms: row.try_get(6).map_err(db)?,
    })
}
