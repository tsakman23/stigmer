//! Thread and channel reads.

use rusqlite::{Connection, OptionalExtension, Transaction};
use stigmer_core::{BoardId, ChannelPath, Label, Message, MessageId, Principal};
use stigmer_store::{Entity, Page, StoreError, Thread, ThreadSummary};

use crate::posts::board_head;
use crate::{backend, not_found};

const MAX_PAGE: u32 = 200;
const PREVIEW_CHARS: i64 = 200;

/// SQL condition: channel `?N` is the prefix itself or sits under it, on whole segments.
/// `LIKE` is avoided on purpose: `_` is legal in channel paths and is a LIKE wildcard.
pub(crate) fn channel_matches(column: &str, param: &str) -> String {
    format!("({column} = {param} OR substr({column}, 1, length({param}) + 1) = {param} || '/')")
}

/// Lists threads under `prefix`, newest activity first, one keyset page at a time.
pub(crate) fn read_channel(
    conn: &mut Connection,
    board: &BoardId,
    prefix: &ChannelPath,
    page: &Page,
) -> Result<Vec<ThreadSummary>, StoreError> {
    let limit = page.limit.clamp(1, MAX_PAGE);
    // One read transaction, so the board check, the cursor thread and the listing agree.
    let tx = conn.transaction().map_err(backend)?;
    board_head(&tx, board)?.ok_or_else(|| not_found(Entity::Board, board))?;

    let cursor: Option<(i64, String)> = match &page.before {
        None => None,
        Some(before) => Some(
            thread_activity(&tx, board, before)?
                .ok_or_else(|| not_found(Entity::Thread, before))?,
        ),
    };
    let (before_at, before_id) = match &cursor {
        Some((at, id)) => (Some(*at), Some(id.as_str())),
        None => (None, None),
    };

    let sql = format!(
        "SELECT thread_id, channel, preview, reply_count, last_at FROM (
            SELECT r.id AS thread_id, r.channel AS channel,
                   substr(r.text, 1, {PREVIEW_CHARS}) AS preview,
                   (SELECT COUNT(*) FROM messages x
                     WHERE x.board_id = r.board_id AND x.thread_id = r.id AND x.id <> r.id)
                       AS reply_count,
                   max(r.at_ms, COALESCE((SELECT MAX(x.at_ms) FROM messages x
                     WHERE x.board_id = r.board_id AND x.thread_id = r.id), r.at_ms)) AS last_at
              FROM messages r
             WHERE r.board_id = ?1 AND r.thread_id = r.id AND {}
         )
         WHERE ?3 IS NULL OR last_at < ?3 OR (last_at = ?3 AND thread_id < ?4)
         ORDER BY last_at DESC, thread_id DESC
         LIMIT ?5",
        channel_matches("r.channel", "?2")
    );
    let mut stmt = tx.prepare(&sql).map_err(backend)?;
    let rows = stmt
        .query_map(
            (
                board.as_str(),
                prefix.as_str(),
                before_at,
                before_id,
                i64::from(limit),
            ),
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .map_err(backend)?;
    let mut threads = Vec::new();
    for row in rows {
        let (thread_id, channel, preview, replies, last_at_ms) = row.map_err(backend)?;
        threads.push(ThreadSummary {
            thread_id: MessageId::new(&thread_id).map_err(backend)?,
            channel: ChannelPath::new(&channel).map_err(backend)?,
            root_text_preview: preview,
            reply_count: u32::try_from(replies).map_err(backend)?,
            last_at_ms,
        });
    }
    Ok(threads)
}

/// `(last activity, id)` of thread root `thread`, or `None` if it is not a root on `board`.
fn thread_activity(
    tx: &Transaction<'_>,
    board: &BoardId,
    thread: &MessageId,
) -> Result<Option<(i64, String)>, StoreError> {
    tx.query_row(
        "SELECT max(r.at_ms, COALESCE((SELECT MAX(x.at_ms) FROM messages x
                 WHERE x.board_id = r.board_id AND x.thread_id = r.id), r.at_ms)), r.id
           FROM messages r
          WHERE r.id = ?1 AND r.board_id = ?2 AND r.thread_id = r.id",
        [thread.as_str(), board.as_str()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .optional()
    .map_err(backend)
}

/// Reads a thread root and its replies in event order.
pub(crate) fn read_thread(
    conn: &mut Connection,
    board: &BoardId,
    thread: &MessageId,
) -> Result<Thread, StoreError> {
    let tx = conn.transaction().map_err(backend)?;
    let root = {
        let mut stmt = tx
            .prepare(&format!(
                "{MESSAGE_COLUMNS} FROM messages m
                  WHERE m.id = ?1 AND m.board_id = ?2 AND m.thread_id = m.id"
            ))
            .map_err(backend)?;
        let mut rows = stmt
            .query([thread.as_str(), board.as_str()])
            .map_err(backend)?;
        match rows.next().map_err(backend)? {
            Some(row) => message_from_row(&tx, row)?,
            None => return Err(not_found(Entity::Thread, thread)),
        }
    };
    let mut stmt = tx
        .prepare(&format!(
            "{MESSAGE_COLUMNS} FROM messages m
               JOIN events e ON e.board_id = m.board_id AND e.message_id = m.id
              WHERE m.board_id = ?1 AND m.thread_id = ?2 AND m.id <> m.thread_id
              ORDER BY e.seq"
        ))
        .map_err(backend)?;
    let mut rows = stmt
        .query([board.as_str(), thread.as_str()])
        .map_err(backend)?;
    let mut replies = Vec::new();
    while let Some(row) = rows.next().map_err(backend)? {
        replies.push(message_from_row(&tx, row)?);
    }
    Ok(Thread { root, replies })
}

const MESSAGE_COLUMNS: &str =
    "SELECT m.id, m.board_id, m.channel, m.thread_id, m.author, m.text, m.at_ms";

/// Rebuilds a message from a `MESSAGE_COLUMNS` row plus its labels, re-validating every field.
fn message_from_row(tx: &Transaction<'_>, row: &rusqlite::Row<'_>) -> Result<Message, StoreError> {
    let id: String = row.get(0).map_err(backend)?;
    let board: String = row.get(1).map_err(backend)?;
    let channel: String = row.get(2).map_err(backend)?;
    let thread_id: String = row.get(3).map_err(backend)?;
    let author: String = row.get(4).map_err(backend)?;
    let text: String = row.get(5).map_err(backend)?;
    let at_ms: i64 = row.get(6).map_err(backend)?;

    let mut stmt = tx
        .prepare("SELECT key, value FROM labels WHERE message_id = ?1 ORDER BY rowid")
        .map_err(backend)?;
    let labels = stmt
        .query_map([&id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(backend)?
        .map(|pair| {
            let (key, value) = pair.map_err(backend)?;
            Label::new(&key, &value).map_err(backend)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Message {
        id: MessageId::new(&id).map_err(backend)?,
        board: BoardId::new(&board).map_err(backend)?,
        channel: ChannelPath::new(&channel).map_err(backend)?,
        thread_id: MessageId::new(&thread_id).map_err(backend)?,
        author: Principal::new(&author).map_err(backend)?,
        text,
        labels,
        at_ms,
    })
}
