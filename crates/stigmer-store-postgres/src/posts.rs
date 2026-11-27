//! The append path: posting messages and checking the board's hash chain.
//!
//! A post locks its board's row (`SELECT ... FOR UPDATE`), assigns `head_seq + 1` and writes the
//! message, its labels, its event, the thread summary and finally the new head in one
//! transaction. Writers on one board queue on that lock, in this process or any other, so the
//! sequence is gapless; a post that fails anywhere rolls back whole and uses no number. Its last
//! statement before the commit is the NOTIFY that wakes waits on every replica (`listener`).

use deadpool_postgres::Pool;
use stigmer_core::{
    event_hash, BoardId, ChannelPath, Cursor, Event, EventKind, HashInput, Label, Message,
    MessageId, NewMessage, Principal, Target,
};
use stigmer_store::{ConflictKind, Entity, Posted, StoreError};
use tokio_postgres::Transaction;

use crate::boards::lock_writable_head;
use crate::chain::{event_from_row, EVENT_COLUMNS};
use crate::error::{backend, db, not_found};
use crate::listener::notify;
use crate::threads::{insert_thread, record_reply};
use crate::{hash, pool};

/// `messages.author_kind` of a post whose author is not a member of the board.
pub(crate) const LOCAL_AUTHOR_KIND: &str = "local";

/// `messages.author_kind` of a post whose author is a member of the board.
pub(crate) const PRINCIPAL_AUTHOR_KIND: &str = "principal";

/// Stores `msg` and appends its event in one transaction under the board's row lock.
///
/// When `msg.idempotency_key` matches an earlier post by the same author on the same board, that
/// post is returned with `replayed: true` and nothing is written. The lookup runs under the same
/// lock as the insert, so two racing retries cannot both insert.
pub(crate) async fn post(pool: &Pool, msg: NewMessage) -> Result<Posted, StoreError> {
    let id = MessageId::generate().map_err(backend)?;
    let mut client = pool::client(pool).await?;
    let tx = client.transaction().await.map_err(db)?;

    // First, so an archived board refuses even a retry and no sequence number is read.
    let (head_seq, head_hash) = lock_writable_head(&tx, &msg.board).await?;

    if let Some(key) = &msg.idempotency_key {
        if let Some(original) = find_keyed(&tx, &msg.board, &msg.author, key).await? {
            let replayed = replay(&tx, original, &msg).await?;
            tx.commit().await.map_err(db)?;
            return Ok(replayed);
        }
    }

    let (kind, channel, thread_id) = match msg.target {
        Target::NewThread { channel } => (EventKind::ThreadCreated, channel, id.clone()),
        Target::Reply { thread } => {
            let channel = thread_root_channel(&tx, &msg.board, &thread)
                .await?
                .ok_or_else(|| not_found(Entity::Thread, &thread))?;
            (EventKind::MessageReplied, channel, thread)
        }
    };
    let seq = head_seq
        .checked_add(1)
        .ok_or_else(|| StoreError::Backend("event sequence overflow".into()))?;
    let at_ms = stigmer_core::now_ms();
    let hash = event_hash(&HashInput {
        prev: &head_hash,
        seq,
        kind,
        actor: &msg.author,
        message_id: &id,
        thread_id: &thread_id,
        channel: &channel,
        at_ms,
    });
    let hash_bytes = hash::to_bytes(&hash)?;
    let seq_sql = i64::try_from(seq).map_err(backend)?;
    let author_kind = author_kind(&tx, &msg.board, &msg.author).await?;
    let (board, author) = (msg.board.as_str(), msg.author.as_str());

    tx.execute(
        "INSERT INTO messages
             (id, board_id, channel, thread_id, author, author_kind, text, at_ms, idempotency_key)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        &[
            &id.as_str(),
            &board,
            &channel.as_str(),
            &thread_id.as_str(),
            &author,
            &author_kind,
            &msg.text,
            &at_ms,
            &msg.idempotency_key,
        ],
    )
    .await
    .map_err(db)?;
    for (position, label) in (0i32..).zip(&msg.labels) {
        tx.execute(
            "INSERT INTO labels (message_id, position, key, value) VALUES ($1, $2, $3, $4)",
            &[&id.as_str(), &position, &label.key, &label.value],
        )
        .await
        .map_err(db)?;
    }
    tx.execute(
        "INSERT INTO events (board_id, seq, kind, actor, message_id, thread_id, channel, at_ms, hash)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        &[
            &board,
            &seq_sql,
            &kind.as_str(),
            &author,
            &id.as_str(),
            &thread_id.as_str(),
            &channel.as_str(),
            &at_ms,
            &hash_bytes,
        ],
    )
    .await
    .map_err(db)?;
    match kind {
        EventKind::ThreadCreated => {
            let text = &msg.text;
            insert_thread(&tx, &msg.board, &thread_id, &channel, text, seq_sql, at_ms).await?
        }
        _ => record_reply(&tx, &msg.board, &thread_id, seq_sql, at_ms).await?,
    }
    // The head moves last: everything the event stands for is written by then.
    tx.execute(
        "UPDATE boards SET head_seq = $1, head_hash = $2 WHERE id = $3",
        &[&seq_sql, &hash_bytes, &board],
    )
    .await
    .map_err(db)?;
    // Inside the transaction: delivered to listeners only if, and once, the post commits.
    notify(&tx, &msg.board, seq).await?;
    tx.commit().await.map_err(db)?;

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

/// The author kind a new post by `author` on `board` is stored with: `principal` when the
/// author is a member of the board, else `local`.
async fn author_kind(
    tx: &Transaction<'_>,
    board: &BoardId,
    author: &Principal,
) -> Result<&'static str, StoreError> {
    let member: bool = tx
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM principals WHERE board_id = $1 AND name = $2)",
            &[&board.as_str(), &author.as_str()],
        )
        .await
        .map_err(db)?
        .try_get(0)
        .map_err(db)?;
    Ok(if member {
        PRINCIPAL_AUTHOR_KIND
    } else {
        LOCAL_AUTHOR_KIND
    })
}

/// The message `author` already posted on `board` under `key`, if any.
async fn find_keyed(
    tx: &Transaction<'_>,
    board: &BoardId,
    author: &Principal,
    key: &str,
) -> Result<Option<Message>, StoreError> {
    let row = tx
        .query_opt(
            "SELECT id, channel, thread_id, text, at_ms FROM messages
              WHERE board_id = $1 AND author = $2 AND idempotency_key = $3",
            &[&board.as_str(), &author.as_str(), &key],
        )
        .await
        .map_err(db)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let id: &str = row.try_get(0).map_err(db)?;
    let channel: &str = row.try_get(1).map_err(db)?;
    let thread_id: &str = row.try_get(2).map_err(db)?;
    Ok(Some(Message {
        id: MessageId::new(id).map_err(backend)?,
        board: board.clone(),
        channel: ChannelPath::new(channel).map_err(backend)?,
        thread_id: MessageId::new(thread_id).map_err(backend)?,
        author: author.clone(),
        text: row.try_get(3).map_err(db)?,
        labels: labels_of(tx, id).await?,
        at_ms: row.try_get(4).map_err(db)?,
    }))
}

/// The labels of message `id`, in the order they were posted.
pub(crate) async fn labels_of(tx: &Transaction<'_>, id: &str) -> Result<Vec<Label>, StoreError> {
    let rows = tx
        .query(
            "SELECT key, value FROM labels WHERE message_id = $1 ORDER BY position",
            &[&id],
        )
        .await
        .map_err(db)?;
    rows.iter()
        .map(|row| {
            let key: &str = row.try_get(0).map_err(db)?;
            let value: &str = row.try_get(1).map_err(db)?;
            Label::new(key, value).map_err(backend)
        })
        .collect()
}

/// Answers a retry: the stored post if `request` asks for the same thing, else a conflict.
async fn replay(
    tx: &Transaction<'_>,
    original: Message,
    request: &NewMessage,
) -> Result<Posted, StoreError> {
    let same_target = match &request.target {
        Target::NewThread { channel } => {
            original.thread_id == original.id && original.channel == *channel
        }
        Target::Reply { thread } => {
            original.thread_id == *thread && original.thread_id != original.id
        }
    };
    if !same_target || original.text != request.text || original.labels != request.labels {
        return Err(StoreError::Conflict(ConflictKind::IdempotencyKeyReused));
    }
    let row = tx
        .query_opt(
            &format!(
                "SELECT {EVENT_COLUMNS} FROM events e WHERE e.board_id = $1 AND e.message_id = $2"
            ),
            &[&original.board.as_str(), &original.id.as_str()],
        )
        .await
        .map_err(db)?;
    let event = row
        .as_ref()
        .map(event_from_row)
        .transpose()?
        .flatten()
        .ok_or_else(|| {
            StoreError::Backend(format!("message {} has no valid event", original.id))
        })?;
    Ok(Posted {
        message: original,
        event,
        replayed: true,
    })
}

/// The channel of thread root `thread` on `board`, or `None` if `thread` is not a root there.
async fn thread_root_channel(
    tx: &Transaction<'_>,
    board: &BoardId,
    thread: &MessageId,
) -> Result<Option<ChannelPath>, StoreError> {
    let row = tx
        .query_opt(
            "SELECT channel FROM messages WHERE id = $1 AND board_id = $2 AND thread_id = id",
            &[&thread.as_str(), &board.as_str()],
        )
        .await
        .map_err(db)?;
    row.map(|row| {
        let channel: &str = row.try_get(0).map_err(db)?;
        ChannelPath::new(channel).map_err(backend)
    })
    .transpose()
}

#[cfg(test)]
mod tests;
