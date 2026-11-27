//! `Store` for `PgStore`: each method clones what it needs and runs as one future, so the
//! futures are `Send` and `'static`-free of the caller's borrows.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use stigmer_core::{BoardId, ChannelPath, Cursor, Event, MessageId, NewMessage, Principal};
use stigmer_store::{
    BoardInfo, ChainReport, EventFilter, Page, Posted, SecurityEvent, Store, StoreError, Thread,
    ThreadSummary,
};

use crate::{boards, chain, events, posts, reads, wait, PgStore};

impl Store for PgStore {
    fn create_board(
        &self,
        id: &BoardId,
        created_by: Option<&Principal>,
        audit: SecurityEvent,
    ) -> impl Future<Output = Result<BoardInfo, StoreError>> + Send {
        let (pool, id, created_by) = (self.pool.clone(), id.clone(), created_by.cloned());
        async move { boards::create(&pool, &id, created_by.as_ref(), &audit).await }
    }

    fn get_board(
        &self,
        id: &BoardId,
    ) -> impl Future<Output = Result<BoardInfo, StoreError>> + Send {
        let (pool, id) = (self.pool.clone(), id.clone());
        async move { boards::get(&pool, &id).await }
    }

    fn list_boards(&self) -> impl Future<Output = Result<Vec<BoardInfo>, StoreError>> + Send {
        let pool = self.pool.clone();
        async move { boards::list(&pool).await }
    }

    fn archive_board(
        &self,
        id: &BoardId,
        audit: SecurityEvent,
    ) -> impl Future<Output = Result<BoardInfo, StoreError>> + Send {
        let (pool, id, notifier) = (self.pool.clone(), id.clone(), Arc::clone(&self.notifier));
        async move {
            let archived = boards::archive(&pool, &id, &audit).await?;
            // Committed: the head can no longer move. Deliver it first, so a wait for a post
            // whose notification is still on its way wakes, then drop the board's entry.
            notifier.bump(&id, archived.head);
            notifier.forget(&id);
            Ok(archived.board)
        }
    }

    fn post(&self, msg: NewMessage) -> impl Future<Output = Result<Posted, StoreError>> + Send {
        let pool = self.pool.clone();
        async move { posts::post(&pool, msg).await }
    }

    fn verify_chain(
        &self,
        board: &BoardId,
    ) -> impl Future<Output = Result<ChainReport, StoreError>> + Send {
        let (pool, board) = (self.pool.clone(), board.clone());
        async move { chain::verify_chain(&pool, &board).await }
    }

    fn read_channel(
        &self,
        board: &BoardId,
        prefix: &ChannelPath,
        page: Page,
    ) -> impl Future<Output = Result<Vec<ThreadSummary>, StoreError>> + Send {
        let (pool, board, prefix) = (self.pool.clone(), board.clone(), prefix.clone());
        async move { reads::read_channel(&pool, &board, &prefix, &page).await }
    }

    fn read_thread(
        &self,
        board: &BoardId,
        thread: &MessageId,
    ) -> impl Future<Output = Result<Thread, StoreError>> + Send {
        let (pool, board, thread) = (self.pool.clone(), board.clone(), thread.clone());
        async move { reads::read_thread(&pool, &board, &thread).await }
    }

    fn events_after(
        &self,
        board: &BoardId,
        after: Option<&Cursor>,
        filter: &EventFilter,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<Event>, StoreError>> + Send {
        let pool = self.pool.clone();
        let (board, after, filter) = (board.clone(), after.cloned(), filter.clone());
        async move { events::events_after(&pool, &board, after.as_ref(), &filter, limit).await }
    }

    fn head(
        &self,
        board: &BoardId,
    ) -> impl Future<Output = Result<Option<Cursor>, StoreError>> + Send {
        let (pool, board) = (self.pool.clone(), board.clone());
        async move { events::head(&pool, &board).await }
    }

    fn wait_past(
        &self,
        board: &BoardId,
        after: Option<&Cursor>,
        timeout: Duration,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send {
        self.wait_past_with_seams(board, after, timeout, wait::no_seams())
    }
}

impl PgStore {
    /// `Store::wait_past`, running `seams` just before and just after the head read: a seam
    /// for tests that commit a post exactly there.
    pub(crate) fn wait_past_with_seams(
        &self,
        board: &BoardId,
        after: Option<&Cursor>,
        timeout: Duration,
        seams: wait::Seams<impl Future<Output = ()> + Send, impl Future<Output = ()> + Send>,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send {
        let (pool, notifier) = (self.pool.clone(), Arc::clone(&self.notifier));
        let (board, after) = (board.clone(), after.cloned());
        // No spawned task: dropping this future ends the wait and drops its subscription.
        async move { wait::wait_past(&pool, &notifier, &board, after.as_ref(), timeout, seams).await }
    }
}
