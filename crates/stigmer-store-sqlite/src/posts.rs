//! The append path: posting messages and checking the board's hash chain.

use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior};
use stigmer_core::{
    event_hash, BoardId, ChannelPath, Cursor, Event, EventKind, Message, MessageId, NewMessage,
    Principal, Target, GENESIS_HASH,
};
use stigmer_store::{ChainReport, Posted, StoreError};

use crate::backend;

/// Stores `msg` and appends its event in one `BEGIN IMMEDIATE` transaction.
///
/// `msg.idempotency_key` is not persisted yet, so `replayed` is always false.
pub(crate) fn post(conn: &mut Connection, msg: NewMessage) -> Result<Posted, StoreError> {
    let id = MessageId::generate().map_err(backend)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(backend)?;

    let (head_seq, head_hash) = board_head(&tx, &msg.board)?
        .ok_or_else(|| StoreError::NotFound(format!("board {}", msg.board)))?;
    let (kind, channel, thread_id) = match msg.target {
        Target::NewThread { channel } => (EventKind::ThreadCreated, channel, id.clone()),
        Target::Reply { thread } => {
            let channel = thread_root_channel(&tx, &msg.board, &thread)?
                .ok_or_else(|| StoreError::NotFound(format!("thread {thread}")))?;
            (EventKind::MessageReplied, channel, thread)
        }
    };
    let seq = head_seq
        .checked_add(1)
        .ok_or_else(|| StoreError::Backend("event sequence overflow".into()))?;
    let at_ms = now_ms()?;
    let hash = event_hash(&head_hash, seq, kind, &msg.author, &id, &channel, at_ms);
    let seq_sql = i64::try_from(seq).map_err(backend)?;

    tx.execute(
        "INSERT INTO messages (id, board_id, channel, thread_id, author, text, at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        (
            id.as_str(),
            msg.board.as_str(),
            channel.as_str(),
            thread_id.as_str(),
            msg.author.as_str(),
            &msg.text,
            at_ms,
        ),
    )
    .map_err(backend)?;
    for label in &msg.labels {
        tx.execute(
            "INSERT INTO labels (message_id, key, value) VALUES (?1, ?2, ?3)",
            (id.as_str(), &label.key, &label.value),
        )
        .map_err(backend)?;
    }
    tx.execute(
        "INSERT INTO events (board_id, seq, kind, actor, message_id, thread_id, channel, at_ms, hash)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        (
            msg.board.as_str(),
            seq_sql,
            kind.as_str(),
            msg.author.as_str(),
            id.as_str(),
            thread_id.as_str(),
            channel.as_str(),
            at_ms,
            &hash,
        ),
    )
    .map_err(backend)?;
    tx.execute(
        "UPDATE boards SET head_seq = ?1, head_hash = ?2 WHERE id = ?3",
        (seq_sql, &hash, msg.board.as_str()),
    )
    .map_err(backend)?;
    tx.commit().map_err(backend)?;

    let event = Event {
        seq,
        cursor: Cursor::from_seq(seq),
        kind,
        actor: msg.author.clone(),
        message_id: id.clone(),
        thread_id: thread_id.clone(),
        channel: channel.clone(),
        at_ms,
        hash,
    };
    let message = Message {
        id,
        board: msg.board,
        channel,
        thread_id,
        author: msg.author,
        text: msg.text,
        labels: msg.labels,
        at_ms,
    };
    Ok(Posted {
        message,
        event,
        replayed: false,
    })
}

/// Recomputes the board's chain from genesis, in seq order, and compares it with the board head.
pub(crate) fn verify_chain(
    conn: &mut Connection,
    board: &BoardId,
) -> Result<ChainReport, StoreError> {
    // One read transaction, so the head and the events come from the same snapshot.
    let tx = conn.transaction().map_err(backend)?;
    let (head_seq, head_hash) =
        board_head(&tx, board)?.ok_or_else(|| StoreError::NotFound(format!("board {board}")))?;

    let mut stmt = tx
        .prepare(
            "SELECT seq, kind, actor, message_id, thread_id, channel, at_ms, hash
             FROM events WHERE board_id = ?1 ORDER BY seq",
        )
        .map_err(backend)?;
    let mut rows = stmt.query([board.as_str()]).map_err(backend)?;

    let mut prev = GENESIS_HASH.to_owned();
    let mut last_seq = 0u64;
    while let Some(row) = rows.next().map_err(backend)? {
        let expected_seq = last_seq + 1;
        let report_bad = || ChainReport {
            valid: false,
            checked: expected_seq,
            first_bad_seq: Some(expected_seq),
        };
        let Some(event) = event_from_row(row)? else {
            return Ok(report_bad());
        };
        let recomputed = event_hash(
            &prev,
            event.seq,
            event.kind,
            &event.actor,
            &event.message_id,
            &event.channel,
            event.at_ms,
        );
        if event.seq != expected_seq || event.hash != recomputed {
            return Ok(report_bad());
        }
        prev = recomputed;
        last_seq = event.seq;
    }

    let head_matches = head_seq == last_seq && head_hash == prev;
    Ok(ChainReport {
        valid: head_matches,
        checked: last_seq,
        // Events past the head, or a head past the last event: the first seq they disagree on.
        // When only the head hash is wrong every event checks out, so there is no bad seq.
        first_bad_seq: (head_seq != last_seq).then(|| head_seq.min(last_seq) + 1),
    })
}

/// Rebuilds an event from a stored row, re-validating every field.
/// Returns `None` when the row holds a value no valid event could have.
fn event_from_row(row: &rusqlite::Row<'_>) -> Result<Option<Event>, StoreError> {
    let seq: i64 = row.get(0).map_err(backend)?;
    let kind: String = row.get(1).map_err(backend)?;
    let actor: String = row.get(2).map_err(backend)?;
    let message_id: String = row.get(3).map_err(backend)?;
    let thread_id: String = row.get(4).map_err(backend)?;
    let channel: String = row.get(5).map_err(backend)?;
    let at_ms: i64 = row.get(6).map_err(backend)?;
    let hash: String = row.get(7).map_err(backend)?;

    let Ok(seq) = u64::try_from(seq) else {
        return Ok(None);
    };
    let (Some(kind), Ok(actor), Ok(message_id), Ok(thread_id), Ok(channel)) = (
        parse_kind(&kind),
        Principal::new(&actor),
        MessageId::new(&message_id),
        MessageId::new(&thread_id),
        ChannelPath::new(&channel),
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

fn parse_kind(raw: &str) -> Option<EventKind> {
    [EventKind::ThreadCreated, EventKind::MessageReplied]
        .into_iter()
        .find(|kind| kind.as_str() == raw)
}

/// The board's head `(seq, hash)`, or `None` if the board does not exist.
fn board_head(tx: &Transaction<'_>, board: &BoardId) -> Result<Option<(u64, String)>, StoreError> {
    let head: Option<(i64, String)> = tx
        .query_row(
            "SELECT head_seq, head_hash FROM boards WHERE id = ?1",
            [board.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(backend)?;
    head.map(|(seq, hash)| Ok((u64::try_from(seq).map_err(backend)?, hash)))
        .transpose()
}

/// The channel of thread root `thread` on `board`, or `None` if `thread` is not a root there.
fn thread_root_channel(
    tx: &Transaction<'_>,
    board: &BoardId,
    thread: &MessageId,
) -> Result<Option<ChannelPath>, StoreError> {
    let channel: Option<String> = tx
        .query_row(
            "SELECT channel FROM messages WHERE id = ?1 AND board_id = ?2 AND thread_id = id",
            [thread.as_str(), board.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(backend)?;
    channel
        .map(|raw| ChannelPath::new(&raw).map_err(backend))
        .transpose()
}

/// Wall-clock time in milliseconds since the Unix epoch.
fn now_ms() -> Result<i64, StoreError> {
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(backend)?;
    i64::try_from(since_epoch.as_millis()).map_err(backend)
}
