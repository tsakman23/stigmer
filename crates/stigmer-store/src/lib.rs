//! stigmer-store: the storage boundary every backend implements.

use std::fmt;
use std::future::Future;
use std::time::Duration;

use thiserror::Error;

use stigmer_core::{BoardId, ChannelPath, Cursor, Event, MessageId, NewMessage, Principal};

mod identity;

pub use identity::{
    Adoption, Consumed, Credential, CredentialScope, IdentityStore, Member, Mode, NewCredential,
    NewInvite, NewJoinCredential, SecurityEvent, SecurityEventKind,
};

pub use stigmer_core::{BoardInfo, EventFilter, Message, Page, Posted, Thread, ThreadSummary};

/// The kind of thing a lookup did not find.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entity {
    Board,
    Thread,
    Message,
    Member,
    Credential,
    Invite,
}

impl fmt::Display for Entity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Entity::Board => "board",
            Entity::Thread => "thread",
            Entity::Message => "message",
            Entity::Member => "member",
            Entity::Credential => "credential",
            Entity::Invite => "invite",
        })
    }
}

/// Why a write conflicts with what is already stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictKind {
    /// An idempotency key was sent again with a request that differs from the stored one.
    IdempotencyKeyReused,
    /// A board with this id already exists.
    BoardExists,
    /// The board is archived and accepts no more posts.
    BoardArchived,
    /// The principal name is already a member of this board.
    NameTaken,
    /// The instance is already in network mode; the switch is one-way.
    AlreadyNetwork,
    /// The board may not be archived: `main` always exists and always takes posts.
    BoardProtected,
}

impl fmt::Display for ConflictKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ConflictKind::IdempotencyKeyReused => "idempotency key reused with a different request",
            ConflictKind::BoardExists => "board already exists",
            ConflictKind::BoardArchived => "board is archived",
            ConflictKind::NameTaken => "principal name already taken on this board",
            ConflictKind::AlreadyNetwork => "already in network mode",
            ConflictKind::BoardProtected => "the main board cannot be archived",
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
/// Every `NotFound` names the entity that is missing, as each method states below. Every method
/// that takes a board reports an unknown board as `NotFound` with `Entity::Board`, except
/// `read_thread`, which reports the thread.
///
/// Not object-safe on purpose: callers are generic over `S: Store`.
pub trait Store: Send + Sync + 'static {
    /// Creates an empty board, stamped with the store's clock (the same clock `post` uses).
    /// An id that already exists, archived or not, is `Conflict(ConflictKind::BoardExists)`.
    fn create_board(
        &self,
        id: &BoardId,
        created_by: Option<&Principal>,
    ) -> impl Future<Output = Result<BoardInfo, StoreError>> + Send;

    /// The board `id`, archived or not. An unknown board is `NotFound` with `Entity::Board`.
    fn get_board(&self, id: &BoardId)
        -> impl Future<Output = Result<BoardInfo, StoreError>> + Send;

    /// Every board, archived ones included, oldest first (ties by id).
    fn list_boards(&self) -> impl Future<Output = Result<Vec<BoardInfo>, StoreError>> + Send;

    /// Archives the board: from then on `post` refuses it with
    /// `Conflict(ConflictKind::BoardArchived)`, while reads, `events_after`, `head`,
    /// `wait_past` and `verify_chain` keep working. Archiving an archived board changes nothing
    /// and returns it as it is, first archive time kept. An unknown board is `NotFound` with
    /// `Entity::Board`. The board `main` is never archived: it is
    /// `Conflict(ConflictKind::BoardProtected)` and changes nothing.
    fn archive_board(
        &self,
        id: &BoardId,
    ) -> impl Future<Output = Result<BoardInfo, StoreError>> + Send;

    /// Stores a new thread or a reply and appends its event to the board's chain, atomically.
    ///
    /// Errors: an unknown board is `NotFound` with `Entity::Board`. An archived board is
    /// `Conflict(ConflictKind::BoardArchived)`, checked before anything else (an idempotent
    /// retry included), so a refused post consumes no sequence number. A reply whose target thread
    /// does not exist on the board, or is a reply rather than a thread root, is `NotFound` with
    /// `Entity::Thread`. An idempotency key the same author already used on this board with a
    /// different request (other text, labels or target) is
    /// `Conflict(ConflictKind::IdempotencyKeyReused)`; with the same request it is a replay.
    fn post(&self, msg: NewMessage) -> impl Future<Output = Result<Posted, StoreError>> + Send;

    /// Recomputes the board's hash chain from genesis and reports the first bad event.
    /// An unknown board is `NotFound` with `Entity::Board`. Works on archived boards.
    fn verify_chain(
        &self,
        board: &BoardId,
    ) -> impl Future<Output = Result<ChainReport, StoreError>> + Send;

    /// Lists the threads of every channel under `prefix` (whole path segments), newest activity
    /// first. `page.before` is the thread id of the last item of the previous page.
    ///
    /// An unknown board is `NotFound` with `Entity::Board`. A `page.before` that is not a thread
    /// root on the board is `NotFound` with `Entity::Thread`. Works on archived boards.
    fn read_channel(
        &self,
        board: &BoardId,
        prefix: &ChannelPath,
        page: Page,
    ) -> impl Future<Output = Result<Vec<ThreadSummary>, StoreError>> + Send;

    /// Reads a thread root and its replies in event order. `NotFound` with `Entity::Thread`
    /// unless `thread` is a thread root on `board`: an id that does not exist, a reply's id, and
    /// any id on an unknown board all report the thread, not the board. Works on archived boards.
    fn read_thread(
        &self,
        board: &BoardId,
        thread: &MessageId,
    ) -> impl Future<Output = Result<Thread, StoreError>> + Send;

    /// Events with a sequence number greater than `after`'s (all events when `None`), oldest
    /// first, matching `filter`. `limit` is clamped to 1..=500. A cursor that does not decode or
    /// lies beyond the board head is `InvalidCursor`, never an empty success. An unknown board is
    /// `NotFound` with `Entity::Board` (a cursor that does not decode is `InvalidCursor` first).
    /// Works on archived boards.
    fn events_after(
        &self,
        board: &BoardId,
        after: Option<&Cursor>,
        filter: &EventFilter,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<Event>, StoreError>> + Send;

    /// The cursor of the board's latest event, or `None` while it has no events. An unknown
    /// board is `NotFound` with `Entity::Board`. Works on archived boards.
    fn head(
        &self,
        board: &BoardId,
    ) -> impl Future<Output = Result<Option<Cursor>, StoreError>> + Send;

    /// Waits up to `timeout` for the board head to move past `after` (`None` means before the
    /// first event). Returns `true` as soon as it has, `false` on timeout. A cursor beyond the
    /// head is `InvalidCursor` at once. An unknown board is `NotFound` with `Entity::Board` (a
    /// cursor that does not decode is `InvalidCursor` first), and waiting on it leaves nothing
    /// behind. On an archived board the head can no longer move, so a wait at the head returns
    /// `false` on timeout. Dropping the future cancels the wait.
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
        assert_eq!(Entity::Member.to_string(), "member");
        assert_eq!(Entity::Credential.to_string(), "credential");
        assert_eq!(Entity::Invite.to_string(), "invite");
    }

    #[test]
    fn conflict_kind_explains_the_conflict() {
        assert_eq!(
            ConflictKind::IdempotencyKeyReused.to_string(),
            "idempotency key reused with a different request"
        );
        assert_eq!(
            ConflictKind::BoardExists.to_string(),
            "board already exists"
        );
        assert_eq!(ConflictKind::BoardArchived.to_string(), "board is archived");
        assert_eq!(
            ConflictKind::NameTaken.to_string(),
            "principal name already taken on this board"
        );
        assert_eq!(
            ConflictKind::AlreadyNetwork.to_string(),
            "already in network mode"
        );
        assert_eq!(
            StoreError::Conflict(ConflictKind::BoardArchived).to_string(),
            "conflict: board is archived"
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
            ConflictKind::BoardProtected.to_string(),
            "the main board cannot be archived"
        );
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
        assert_send(store.create_board(board, None));
        assert_send(store.get_board(board));
        assert_send(store.list_boards());
        assert_send(store.archive_board(board));
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

    // Compile-time check, as above, for the identity store.
    #[allow(dead_code, clippy::too_many_arguments)]
    fn identity_futures_are_send<S: IdentityStore>(
        store: &S,
        board: &BoardId,
        name: &Principal,
        id: &stigmer_core::TokenId,
        credential: NewCredential,
        invite: NewInvite,
        join: NewJoinCredential,
        event: SecurityEvent,
    ) {
        use stigmer_core::{PrincipalKind, Role};
        fn assert_send<T: Send>(_: T) {}
        assert_send(store.mode());
        assert_send(store.enable_network_mode());
        assert_send(store.add_member(board, name, PrincipalKind::Human, Role::Admin, 0));
        assert_send(store.get_member(board, name));
        assert_send(store.list_members(board));
        assert_send(store.remove_member(board, name, 0));
        assert_send(store.list_local_authors(board));
        assert_send(store.adopt_local_authors(board, &[], 0));
        assert_send(store.create_credential(credential.clone(), 0));
        assert_send(store.find_credential(id));
        assert_send(store.touch_credential(id, 0));
        assert_send(store.list_credentials(board));
        assert_send(store.revoke_credential(id, 0));
        assert_send(store.revoke_board_credentials(board, true, 0));
        assert_send(store.revoke_instance_credentials_except(id, 0));
        assert_send(store.replace_instance_credential(credential, 0));
        assert_send(store.create_invite(invite, 0));
        assert_send(store.consume_invite(id, &[0; 32], name, 0, join));
        assert_send(store.log_security(event));
        assert_send(store.security_log(10));
    }
}
