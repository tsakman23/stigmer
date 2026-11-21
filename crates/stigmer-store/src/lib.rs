//! stigmer-store: the storage boundary every backend implements.

use std::fmt;
use std::future::Future;
use std::time::Duration;

use thiserror::Error;

use stigmer_core::{BoardId, ChannelPath, Cursor, Event, MessageId, NewMessage};

pub use stigmer_core::{EventFilter, Message, Page, Posted, Thread, ThreadSummary};

/// The kind of thing a lookup did not find.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entity {
    Board,
    Thread,
    Message,
}

impl fmt::Display for Entity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Entity::Board => "board",
            Entity::Thread => "thread",
            Entity::Message => "message",
        })
    }
}

/// Why a write conflicts with what is already stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictKind {
    /// An idempotency key was sent again with a request that differs from the stored one.
    IdempotencyKeyReused,
}

impl fmt::Display for ConflictKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ConflictKind::IdempotencyKeyReused => "idempotency key reused with a different request",
        })
    }
}

/// Why a store operation failed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StoreError {
    #[error("not found: {entity} {id}")]
    NotFound { entity: Entity, id: String },
    #[error("invalid cursor")]
    InvalidCursor,
    #[error("conflict: {0}")]
    Conflict(ConflictKind),
    #[error("storage backend error: {0}")]
    Backend(String),
}

/// Result of re-checking a board's hash chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainReport {
    /// True when every event and the board head check out.
    pub valid: bool,
    /// Number of events examined.
    pub checked: u64,
    /// The first sequence number whose event does not check out, if any. `None` together with
    /// `valid == false` means only the board head disagreed with the events.
    pub first_bad_seq: Option<u64>,
}

/// Storage for boards, messages and their event log.
///
/// Guarantees every backend must meet: a gapless per-board event sequence starting at 1,
/// read-your-writes, and visibility in commit order. Verified by `stigmer-store-conformance`.
///
/// Every `NotFound` names the entity that is missing, as each method states below; an unknown
/// board is `Entity::Board` except where a method says otherwise.
///
/// Not object-safe on purpose: callers are generic over `S: Store`.
pub trait Store: Send + Sync + 'static {
    /// Stores a new thread or a reply and appends its event to the board's chain, atomically.
    ///
    /// Errors: an unknown board is `NotFound` with `Entity::Board`. A reply whose target thread
    /// does not exist on the board, or is a reply rather than a thread root, is `NotFound` with
    /// `Entity::Thread`. An idempotency key the same author already used on this board with a
    /// different request (other text, labels or target) is
    /// `Conflict(ConflictKind::IdempotencyKeyReused)`; with the same request it is a replay.
    fn post(&self, msg: NewMessage) -> impl Future<Output = Result<Posted, StoreError>> + Send;

    /// Recomputes the board's hash chain from genesis and reports the first bad event.
    /// An unknown board is `NotFound` with `Entity::Board`.
    fn verify_chain(
        &self,
        board: &BoardId,
    ) -> impl Future<Output = Result<ChainReport, StoreError>> + Send;

    /// Lists the threads of every channel under `prefix` (whole path segments), newest activity
    /// first. `page.before` is the thread id of the last item of the previous page.
    ///
    /// An unknown board is not an error: it has no threads, so the list is empty. A
    /// `page.before` that is not a thread root on the board is `NotFound` with `Entity::Thread`.
    fn read_channel(
        &self,
        board: &BoardId,
        prefix: &ChannelPath,
        page: Page,
    ) -> impl Future<Output = Result<Vec<ThreadSummary>, StoreError>> + Send;

    /// Reads a thread root and its replies in event order. `NotFound` with `Entity::Thread`
    /// unless `thread` is a thread root on `board`: an id that does not exist, a reply's id, and
    /// any id on an unknown board all report the thread, not the board.
    fn read_thread(
        &self,
        board: &BoardId,
        thread: &MessageId,
    ) -> impl Future<Output = Result<Thread, StoreError>> + Send;

    /// Events with a sequence number greater than `after`'s (all events when `None`), oldest
    /// first, matching `filter`. `limit` is clamped to 1..=500. A cursor that does not decode or
    /// lies beyond the board head is `InvalidCursor`, never an empty success. An unknown board is
    /// `NotFound` with `Entity::Board` (a cursor that does not decode is `InvalidCursor` first).
    fn events_after(
        &self,
        board: &BoardId,
        after: Option<&Cursor>,
        filter: &EventFilter,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<Event>, StoreError>> + Send;

    /// The cursor of the board's latest event, or `None` while it has no events. An unknown
    /// board is `NotFound` with `Entity::Board`.
    fn head(
        &self,
        board: &BoardId,
    ) -> impl Future<Output = Result<Option<Cursor>, StoreError>> + Send;

    /// Waits up to `timeout` for the board head to move past `after` (`None` means before the
    /// first event). Returns `true` as soon as it has, `false` on timeout. A cursor beyond the
    /// head is `InvalidCursor` at once. An unknown board is `NotFound` with `Entity::Board` (a
    /// cursor that does not decode is `InvalidCursor` first). Dropping the future cancels the
    /// wait.
    fn wait_past(
        &self,
        board: &BoardId,
        after: Option<&Cursor>,
        timeout: Duration,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn not_found(entity: Entity, id: &str) -> StoreError {
        StoreError::NotFound {
            entity,
            id: id.into(),
        }
    }

    #[test]
    fn entity_names_are_lowercase_nouns() {
        assert_eq!(Entity::Board.to_string(), "board");
        assert_eq!(Entity::Thread.to_string(), "thread");
        assert_eq!(Entity::Message.to_string(), "message");
    }

    #[test]
    fn conflict_kind_explains_the_conflict() {
        assert_eq!(
            ConflictKind::IdempotencyKeyReused.to_string(),
            "idempotency key reused with a different request"
        );
    }

    #[test]
    fn store_error_messages_name_the_problem() {
        assert_eq!(
            not_found(Entity::Board, "brd_x").to_string(),
            "not found: board brd_x"
        );
        assert_eq!(
            not_found(Entity::Thread, "msg_x").to_string(),
            "not found: thread msg_x"
        );
        assert_eq!(
            not_found(Entity::Message, "msg_y").to_string(),
            "not found: message msg_y"
        );
        assert_eq!(StoreError::InvalidCursor.to_string(), "invalid cursor");
        assert_eq!(
            StoreError::Conflict(ConflictKind::IdempotencyKeyReused).to_string(),
            "conflict: idempotency key reused with a different request"
        );
        assert_eq!(
            StoreError::Backend("disk full".into()).to_string(),
            "storage backend error: disk full"
        );
    }

    #[test]
    fn chain_report_holds_its_fields() {
        let report = ChainReport {
            valid: false,
            checked: 3,
            first_bad_seq: Some(2),
        };
        assert_eq!(report.clone(), report);
        assert!(!report.valid);
        assert_eq!(report.checked, 3);
        assert_eq!(report.first_bad_seq, Some(2));
    }

    // Compile-time check: generic callers get futures they can hand to a multi-thread runtime.
    #[allow(dead_code)]
    fn store_futures_are_send<S: Store>(store: &S, msg: NewMessage, board: &BoardId) {
        fn assert_send<T: Send>(_: T) {}
        assert_send(store.post(msg));
        assert_send(store.verify_chain(board));
        let (prefix, thread) = (
            ChannelPath::new("eng").unwrap(),
            MessageId::generate().unwrap(),
        );
        let page = Page {
            limit: 1,
            before: None,
        };
        assert_send(store.read_channel(board, &prefix, page));
        assert_send(store.read_thread(board, &thread));
        let filter = EventFilter::default();
        assert_send(store.events_after(board, None, &filter, 1));
        assert_send(store.head(board));
        assert_send(store.wait_past(board, None, Duration::ZERO));
    }
}
