//! Wakes `wait_past` callers when a post commits.
//!
//! One `tokio::sync::watch` channel per board carries the highest committed head sequence this
//! process has seen. Waiting spawns no task: the waiter holds a receiver and drops it with its
//! future, so cancelling a wait leaks nothing.
//!
//! Entries exist only for live boards: callers check that a board exists (and, to subscribe, that
//! it is not archived) before touching the notifier, and archiving a board drops its entry.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

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

    /// Drops `board`'s entry; its open receivers see the channel close. Call when the board is
    /// archived: its head can no longer move.
    pub(crate) fn forget(&self, board: &BoardId) {
        self.lock().remove(board.as_str());
    }

    /// Number of receivers subscribed to `board`, 0 when it has no entry. Creates no entry.
    pub(crate) fn receiver_count(&self, board: &BoardId) -> usize {
        self.lock()
            .get(board.as_str())
            .map_or(0, watch::Sender::receiver_count)
    }

    /// Number of boards with an entry.
    #[cfg(test)]
    pub(crate) fn entry_count(&self) -> usize {
        self.lock().len()
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, watch::Sender<u64>>> {
        // The map stays consistent even if a holder panicked, so a poisoned lock is still usable.
        self.boards.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn with_sender<T>(&self, board: &BoardId, f: impl FnOnce(&watch::Sender<u64>) -> T) -> T {
        let mut boards = self.lock();
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
    fn forget_drops_the_entry_and_closes_its_receivers() {
        let notifier = Notifier::default();
        let other = BoardId::new("other").unwrap();
        let rx = notifier.subscribe(&BoardId::main());
        let _other_rx = notifier.subscribe(&other);
        assert_eq!(notifier.entry_count(), 2);
        notifier.forget(&BoardId::main());
        assert_eq!(notifier.entry_count(), 1);
        assert!(rx.has_changed().is_err(), "the sender is gone");
        notifier.forget(&BoardId::main());
        assert_eq!(notifier.entry_count(), 1, "forgetting twice is harmless");
    }

    #[test]
    fn receiver_count_counts_live_receivers_and_creates_no_entry() {
        let notifier = Notifier::default();
        let main = BoardId::main();
        assert_eq!(notifier.receiver_count(&main), 0);
        assert_eq!(notifier.entry_count(), 0, "counting creates no entry");
        let first = notifier.subscribe(&main);
        let second = notifier.subscribe(&main);
        assert_eq!(notifier.receiver_count(&main), 2);
        drop(first);
        assert_eq!(notifier.receiver_count(&main), 1);
        drop(second);
        assert_eq!(notifier.receiver_count(&main), 0);
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
