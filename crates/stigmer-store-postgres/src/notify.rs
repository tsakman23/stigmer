//! Wakes `wait_past` callers when a post commits, through this handle or any other.
//!
//! One `tokio::sync::watch` channel per board carries the highest committed head sequence this
//! process has seen. The listener (NOTIFY) and the safety poll feed it; a wait subscribes
//! before it reads the head, so a commit after its read reaches it through the channel and a
//! commit before it is seen by the read. Waiting spawns no task: the wait holds a
//! [`Subscription`] and drops it with its future, so cancelling a wait leaks nothing.
//!
//! An entry exists only while a wait holds a receiver on it: the last subscription to go
//! removes it, and a notification or a poll never creates one. So the entries are exactly the
//! boards with waiters (the boards the safety poll and a reconnect re-read), and a notification
//! for an unknown or archived board, or for a board nobody waits on, leaves nothing behind.
//! Archiving a board drops its entry: its head can no longer move.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use stigmer_core::BoardId;
use tokio::sync::watch;

#[derive(Default)]
pub(crate) struct Notifier {
    boards: Mutex<HashMap<BoardId, watch::Sender<u64>>>,
    /// Notifications for this store's schema the listener has handled, applied or not.
    handled: AtomicU64,
    /// Waits per board that have read the head and are now sleeping on their subscription.
    sleeping: Mutex<HashMap<BoardId, usize>>,
}

impl Notifier {
    /// Subscribes to `board`, creating its entry if it has none. Take it BEFORE reading the head
    /// from the database.
    pub(crate) fn subscribe(self: &Arc<Self>, board: &BoardId) -> Subscription {
        let rx = self
            .lock()
            .entry(board.clone())
            .or_insert_with(|| watch::channel(0).0)
            .subscribe();
        Subscription {
            notifier: Arc::clone(self),
            board: board.clone(),
            rx: Some(rx),
            asleep: false,
        }
    }

    /// Records that `board`'s head has reached `seq` (committed). Only a board with waiters
    /// has an entry to update: anything else is ignored and creates no entry.
    pub(crate) fn bump(&self, board: &BoardId, seq: u64) {
        if let Some(sender) = self.lock().get(board) {
            sender.send_if_modified(|current| {
                let newer = seq > *current;
                if newer {
                    *current = seq;
                }
                newer
            });
        }
    }

    /// Drops `board`'s entry; its subscriptions see the channel close. Call when the board is
    /// archived: its head can no longer move.
    pub(crate) fn forget(&self, board: &BoardId) {
        self.lock().remove(board);
    }

    /// The boards that have waiters right now.
    pub(crate) fn boards(&self) -> Vec<BoardId> {
        self.lock().keys().cloned().collect()
    }

    /// Number of waits subscribed to `board`, 0 when it has no entry. Creates no entry.
    pub(crate) fn receiver_count(&self, board: &BoardId) -> usize {
        self.lock()
            .get(board)
            .map_or(0, watch::Sender::receiver_count)
    }

    /// Number of boards with an entry.
    pub(crate) fn entry_count(&self) -> usize {
        self.lock().len()
    }

    /// Counts one handled notification. Call after applying it.
    pub(crate) fn count_handled(&self) {
        self.handled.fetch_add(1, Ordering::SeqCst);
    }

    /// Notifications for this store's schema handled so far.
    pub(crate) fn handled(&self) -> u64 {
        self.handled.load(Ordering::SeqCst)
    }

    /// Number of waits on `board` that have read the head and are sleeping on their
    /// subscription: they can now be woken only through the notifier.
    pub(crate) fn sleeping(&self, board: &BoardId) -> usize {
        self.lock_sleeping().get(board).copied().unwrap_or(0)
    }

    fn lock_sleeping(&self) -> MutexGuard<'_, HashMap<BoardId, usize>> {
        // Every update is one statement, so a poisoned lock is still consistent.
        self.sleeping.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<BoardId, watch::Sender<u64>>> {
        // The map stays consistent even if a holder panicked, so a poisoned lock is still usable.
        self.boards.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// One wait's receiver on a board's entry. Dropping it removes the entry if it was the last.
pub(crate) struct Subscription {
    notifier: Arc<Notifier>,
    board: BoardId,
    rx: Option<watch::Receiver<u64>>,
    /// Counted in the notifier's `sleeping` (from the first poll of [`Self::moved_past`]).
    asleep: bool,
}

impl Subscription {
    /// Resolves to `true` once the board's head is past `after`. Never resolves once the entry
    /// is dropped (the board was archived): the caller's timeout ends the wait. From its first
    /// poll on, the wait counts as sleeping until the subscription is dropped.
    pub(crate) async fn moved_past(&mut self, after: u64) -> bool {
        if !self.asleep {
            self.asleep = true;
            *self
                .notifier
                .lock_sleeping()
                .entry(self.board.clone())
                .or_default() += 1;
        }
        let Some(rx) = self.rx.as_mut() else {
            return std::future::pending().await;
        };
        loop {
            if *rx.borrow_and_update() > after {
                return true;
            }
            if rx.changed().await.is_err() {
                return std::future::pending().await;
            }
        }
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        if self.asleep {
            let mut sleeping = self.notifier.lock_sleeping();
            if let Some(count) = sleeping.get_mut(&self.board) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    sleeping.remove(&self.board);
                }
            }
        }
        // Under the map's lock, so no subscribe can slip in between the count and the removal.
        let mut boards = self.notifier.lock();
        drop(self.rx.take());
        if boards
            .get(&self.board)
            .is_some_and(|sender| sender.receiver_count() == 0)
        {
            boards.remove(&self.board);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn notifier() -> Arc<Notifier> {
        Arc::new(Notifier::default())
    }

    #[test]
    fn bump_is_monotonic_and_reaches_earlier_subscriptions() {
        let notifier = notifier();
        let main = BoardId::main();
        let sub = notifier.subscribe(&main);
        notifier.bump(&main, 5);
        notifier.bump(&main, 3);
        let rx = sub.rx.as_ref().unwrap();
        assert_eq!(*rx.borrow(), 5, "a lower seq never moves the head back");
        let later = notifier.subscribe(&main);
        assert_eq!(*later.rx.as_ref().unwrap().borrow(), 5);
    }

    #[tokio::test]
    async fn a_wait_counts_as_sleeping_from_its_first_poll_until_it_ends() {
        let notifier = notifier();
        let main = BoardId::main();
        let mut sub = notifier.subscribe(&main);
        assert_eq!(
            notifier.sleeping(&main),
            0,
            "subscribed is not yet sleeping"
        );
        let slept = tokio::time::timeout(std::time::Duration::from_millis(10), sub.moved_past(0));
        assert!(slept.await.is_err());
        assert_eq!(notifier.sleeping(&main), 1);
        assert_eq!(notifier.sleeping(&BoardId::new("other").unwrap()), 0);
        drop(sub);
        assert_eq!(notifier.sleeping(&main), 0);
    }

    #[test]
    fn bump_without_a_waiter_creates_no_entry() {
        let notifier = notifier();
        notifier.bump(&BoardId::main(), 9);
        assert_eq!(notifier.entry_count(), 0);
        assert_eq!(
            notifier.receiver_count(&BoardId::main()),
            0,
            "counting creates none"
        );
    }

    #[test]
    fn the_last_subscription_to_go_removes_the_entry() {
        let notifier = notifier();
        let main = BoardId::main();
        let (first, second) = (notifier.subscribe(&main), notifier.subscribe(&main));
        assert_eq!(
            (notifier.receiver_count(&main), notifier.entry_count()),
            (2, 1)
        );
        assert_eq!(notifier.boards(), vec![main.clone()]);
        drop(first);
        assert_eq!(notifier.receiver_count(&main), 1);
        drop(second);
        assert_eq!(notifier.entry_count(), 0);
        assert!(notifier.boards().is_empty());
    }

    #[test]
    fn forget_drops_the_entry_and_closes_its_subscriptions() {
        let notifier = notifier();
        let (main, other) = (BoardId::main(), BoardId::new("other").unwrap());
        let sub = notifier.subscribe(&main);
        let _other = notifier.subscribe(&other);
        notifier.forget(&main);
        assert_eq!(notifier.entry_count(), 1);
        assert!(
            sub.rx.as_ref().unwrap().has_changed().is_err(),
            "the sender is gone"
        );
        // A new entry for the board is not removed by the old subscription going.
        let fresh = notifier.subscribe(&main);
        drop(sub);
        assert_eq!(notifier.receiver_count(&main), 1);
        drop(fresh);
        assert_eq!(notifier.entry_count(), 1, "only `other` is left");
    }

    #[tokio::test]
    async fn moved_past_wakes_on_a_newer_head_only() {
        let notifier = notifier();
        let main = BoardId::main();
        let mut sub = notifier.subscribe(&main);
        notifier.bump(&main, 2);
        assert!(sub.moved_past(1).await, "2 is past 1");
        let waiting = tokio::time::timeout(std::time::Duration::from_millis(50), sub.moved_past(2));
        assert!(waiting.await.is_err(), "2 is not past 2");
        notifier.forget(&main);
        let closed = tokio::time::timeout(std::time::Duration::from_millis(50), sub.moved_past(2));
        assert!(closed.await.is_err(), "a forgotten board never wakes");
    }
}
