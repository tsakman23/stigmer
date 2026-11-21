//! Shared builders and assertion helpers for the scenarios.
//!
//! Failures panic through [`ok`] and [`fail`], which are `#[track_caller]`, so a failing
//! scenario reports its own line. The async helpers cannot be `#[track_caller]` themselves, so
//! they record the caller's line when called and name it in the panic message.

use std::fmt::Display;
use std::future::Future;
use std::panic::Location;
use std::time::Duration;

use stigmer_core::{BoardId, ChannelPath, Label, MessageId, NewMessage, Principal, Target};
use stigmer_store::{ChainReport, Posted, Store};

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
