//! Shared builders and assertion helpers for the scenarios.
//!
//! Failures panic through [`ok`] and [`fail`], which are `#[track_caller]`, so a failing
//! scenario reports its own line. The async helpers cannot be `#[track_caller]` themselves, so
//! they record the caller's line when called and name it in the panic message.

use std::fmt::Display;
use std::future::Future;
use std::panic::Location;
use std::time::Duration;

use stigmer_core::{BoardId, ChannelPath, Label, MessageId, NewMessage, Page, Principal, Target};
use stigmer_store::{ChainReport, IdentityStore, Posted, SecurityEvent, SecurityEventKind, Store};

/// The scenarios' fixed "now", in milliseconds since the Unix epoch.
pub(crate) const NOW: i64 = 1_700_000_000_000;

/// The security log row a scenario hands to an audited mutation: `kind` about `on` at
/// `at_ms`, by `root`. The detail names the kind and time, so two rows never look alike.
pub(crate) fn audit(kind: SecurityEventKind, on: Option<&BoardId>, at_ms: i64) -> SecurityEvent {
    SecurityEvent {
        at_ms,
        kind,
        board: on.cloned(),
        principal: Some("root".to_owned()),
        detail: format!("{kind} at {at_ms}"),
    }
}

pub(crate) fn board_created(on: &BoardId, at_ms: i64) -> SecurityEvent {
    audit(SecurityEventKind::BoardCreated, Some(on), at_ms)
}

pub(crate) fn board_archived(on: &BoardId, at_ms: i64) -> SecurityEvent {
    audit(SecurityEventKind::BoardArchived, Some(on), at_ms)
}

pub(crate) fn mode_enabled(at_ms: i64) -> SecurityEvent {
    audit(SecurityEventKind::ModeEnabled, None, at_ms)
}

pub(crate) fn member_removed(on: &BoardId, at_ms: i64) -> SecurityEvent {
    audit(SecurityEventKind::MemberRemoved, Some(on), at_ms)
}

pub(crate) fn token_issued(at_ms: i64) -> SecurityEvent {
    audit(SecurityEventKind::MemberTokenIssued, None, at_ms)
}

pub(crate) fn instance_token_issued(at_ms: i64) -> SecurityEvent {
    audit(SecurityEventKind::InstanceTokenIssued, None, at_ms)
}

pub(crate) fn token_revoked(at_ms: i64) -> SecurityEvent {
    audit(SecurityEventKind::TokenRevoked, None, at_ms)
}

pub(crate) fn invite_created(at_ms: i64) -> SecurityEvent {
    audit(SecurityEventKind::InviteCreated, None, at_ms)
}

/// Panics with `message`, reported at the caller's line.
#[track_caller]
pub(crate) fn fail(message: impl Display) -> ! {
    panic!("{message}")
}

/// The success value of `result`, or a panic with `context` and the error at the caller's line.
#[track_caller]
pub(crate) fn ok<T, E: Display>(result: Result<T, E>, context: impl Display) -> T {
    match result {
        Ok(value) => value,
        Err(e) => fail(format_args!("{context}: {e}")),
    }
}

/// Like [`ok`], for helpers that run after an `.await` and so report `caller` by hand.
pub(crate) fn ok_from<T, E: Display>(
    caller: &Location<'_>,
    result: Result<T, E>,
    context: impl Display,
) -> T {
    match result {
        Ok(value) => value,
        Err(e) => fail(format_args!("{context}: {e} (called at {caller})")),
    }
}

#[track_caller]
pub(crate) fn board(raw: &str) -> BoardId {
    ok(BoardId::new(raw), format_args!("test board {raw:?}"))
}

#[track_caller]
pub(crate) fn channel(raw: &str) -> ChannelPath {
    ok(ChannelPath::new(raw), format_args!("test channel {raw:?}"))
}

#[track_caller]
pub(crate) fn principal(raw: &str) -> Principal {
    ok(Principal::new(raw), format_args!("test principal {raw:?}"))
}

#[track_caller]
pub(crate) fn label(key: &str, value: &str) -> Label {
    ok(Label::new(key, value), "test label")
}

#[track_caller]
pub(crate) fn message(
    board: BoardId,
    target: Target,
    author: &str,
    text: &str,
    labels: Vec<Label>,
) -> NewMessage {
    ok(
        NewMessage::new(
            board,
            target,
            principal(author),
            text.to_owned(),
            labels,
            None,
        ),
        "test message",
    )
}

#[track_caller]
pub(crate) fn new_thread(channel_path: &str, author: &str, text: &str) -> NewMessage {
    message(
        BoardId::main(),
        Target::NewThread {
            channel: channel(channel_path),
        },
        author,
        text,
        vec![],
    )
}

#[track_caller]
pub(crate) fn reply(thread: &MessageId, author: &str, text: &str) -> NewMessage {
    message(
        BoardId::main(),
        Target::Reply {
            thread: thread.clone(),
        },
        author,
        text,
        vec![],
    )
}

/// A first page of up to 50 threads.
pub(crate) fn all_channels() -> Page {
    Page {
        limit: 50,
        before: None,
    }
}

/// A new thread on `board`.
#[track_caller]
pub(crate) fn new_thread_on(
    board: &BoardId,
    channel_path: &str,
    author: &str,
    text: &str,
) -> NewMessage {
    message(
        board.clone(),
        Target::NewThread {
            channel: channel(channel_path),
        },
        author,
        text,
        vec![],
    )
}

/// A reply on `board`.
#[track_caller]
pub(crate) fn reply_on(
    board: &BoardId,
    thread: &MessageId,
    author: &str,
    text: &str,
) -> NewMessage {
    message(
        board.clone(),
        Target::Reply {
            thread: thread.clone(),
        },
        author,
        text,
        vec![],
    )
}

pub(crate) fn keyed(mut msg: NewMessage, key: &str) -> NewMessage {
    msg.idempotency_key = Some(key.to_owned());
    msg
}

/// Posts `msg`, panicking with `scenario` and the caller's line if the post fails.
#[track_caller]
pub(crate) fn post_ok<'a, S: Store>(
    store: &'a S,
    msg: NewMessage,
    scenario: &'a str,
) -> impl Future<Output = Posted> + 'a {
    let caller = Location::caller();
    async move {
        ok_from(
            caller,
            store.post(msg).await,
            format_args!("{scenario}: post failed"),
        )
    }
}

/// Verifies the main board's chain, panicking with `scenario` and the caller's line on error.
#[track_caller]
pub(crate) fn verify_main<'a, S: Store>(
    store: &'a S,
    scenario: &'a str,
) -> impl Future<Output = ChainReport> + 'a {
    let caller = Location::caller();
    async move {
        ok_from(
            caller,
            store.verify_chain(&BoardId::main()).await,
            format_args!("{scenario}: verify_chain failed"),
        )
    }
}

pub(crate) fn valid_chain(checked: u64) -> ChainReport {
    ChainReport {
        valid: true,
        checked,
        first_bad_seq: None,
    }
}

/// Waits long enough that the next post gets a later millisecond timestamp.
pub(crate) async fn tick() {
    tokio::time::sleep(Duration::from_millis(3)).await;
}

/// The whole security log, oldest first.
pub(crate) async fn log_of<S: IdentityStore>(store: &S, scenario: &str) -> Vec<SecurityEvent> {
    let mut rows = ok(
        store.security_log(1_000).await,
        format_args!("{scenario}: log"),
    );
    rows.reverse();
    rows
}
