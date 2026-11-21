//! Wakes `wait_past` callers when a post commits.
//!
//! One `tokio::sync::watch` channel per board carries the highest committed head sequence this
//! process has seen. Waiting spawns no task: the waiter holds a receiver and drops it with its
//! future, so cancelling a wait leaks nothing.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use stigmer_core::BoardId;
use tokio::sync::watch;

#[derive(Default)]
pub(crate) struct Notifier {
    boards: Mutex<HashMap<String, watch::Sender<u64>>>,
}

impl Notifier {
    /// A receiver for `board`. Take it BEFORE reading the head from the database: any commit
    /// after this call is then seen through the receiver, any commit before it by the read.
    pub(crate) fn subscribe(&self, board: &BoardId) -> watch::Receiver<u64> {
        self.with_sender(board, |sender| sender.subscribe())
    }

    /// Records that `board` committed an event with sequence `seq`. Call after the commit.
    pub(crate) fn bump(&self, board: &BoardId, seq: u64) {
        self.with_sender(board, |sender| {
            sender.send_if_modified(|current| {
                let newer = seq > *current;
                if newer {
                    *current = seq;
                }
                newer
            });
        });
    }

    fn with_sender<T>(&self, board: &BoardId, f: impl FnOnce(&watch::Sender<u64>) -> T) -> T {
        // The map stays consistent even if a holder panicked, so a poisoned lock is still usable.
        let mut boards = self.boards.lock().unwrap_or_else(PoisonError::into_inner);
        let sender = boards
            .entry(board.as_str().to_owned())
            .or_insert_with(|| watch::channel(0).0);
        f(sender)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bump_is_monotonic_and_visible_to_earlier_receivers() {
        let notifier = Notifier::default();
        let board = BoardId::main();
        let rx = notifier.subscribe(&board);
        assert_eq!(*rx.borrow(), 0);
        notifier.bump(&board, 5);
        notifier.bump(&board, 3);
        assert_eq!(*rx.borrow(), 5, "a lower seq never moves the head back");
        assert!(rx.has_changed().unwrap());
        assert_eq!(*notifier.subscribe(&board).borrow(), 5);
    }

    #[test]
    fn boards_are_independent() {
        let notifier = Notifier::default();
        let other = BoardId::new("other").unwrap();
        let rx = notifier.subscribe(&other);
        notifier.bump(&BoardId::main(), 9);
        assert_eq!(*rx.borrow(), 0);
        assert!(!rx.has_changed().unwrap());
    }
}
