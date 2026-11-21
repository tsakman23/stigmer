//! stigmer-store: the storage boundary every backend implements.

use std::future::Future;

use thiserror::Error;

use stigmer_core::{BoardId, ChannelPath, MessageId, NewMessage};

pub use stigmer_core::{EventFilter, Message, Page, Posted, Thread, ThreadSummary};

/// Why a store operation failed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StoreError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("invalid cursor")]
    InvalidCursor,
    #[error("conflict: {0}")]
    Conflict(String),
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
/// Not object-safe on purpose: callers are generic over `S: Store`.
pub trait Store: Send + Sync + 'static {
    /// Stores a new thread or a reply and appends its event to the board's chain, atomically.
    fn post(&self, msg: NewMessage) -> impl Future<Output = Result<Posted, StoreError>> + Send;

    /// Recomputes the board's hash chain from genesis and reports the first bad event.
    fn verify_chain(
        &self,
        board: &BoardId,
    ) -> impl Future<Output = Result<ChainReport, StoreError>> + Send;

    /// Lists the threads of every channel under `prefix` (whole path segments), newest activity
    /// first. `page.before` is the thread id of the last item of the previous page.
    fn read_channel(
        &self,
        board: &BoardId,
        prefix: &ChannelPath,
        page: Page,
    ) -> impl Future<Output = Result<Vec<ThreadSummary>, StoreError>> + Send;

    /// Reads a thread root and its replies in event order. `NotFound` unless `thread` is a
    /// thread root on `board`.
    fn read_thread(
        &self,
        board: &BoardId,
        thread: &MessageId,
    ) -> impl Future<Output = Result<Thread, StoreError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_error_messages_name_the_problem() {
        assert_eq!(
            StoreError::NotFound("thread msg_x".into()).to_string(),
            "not found: thread msg_x"
        );
        assert_eq!(StoreError::InvalidCursor.to_string(), "invalid cursor");
        assert_eq!(
            StoreError::Conflict("key reused".into()).to_string(),
            "conflict: key reused"
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
    }
}
