//! The wait loop's scan position: a pass that found nothing makes the next pass scan from the
//! head it read, and the cursor it returns without events still loses nothing.

use std::collections::VecDeque;
use std::future::Future;
use std::sync::Mutex;
use std::time::Duration;

use stigmer_core::{
    BoardId, BoardInfo, ChannelPath, Cursor, Event, EventFilter, MessageId, NewMessage, Page,
    Posted, Principal, Target, Thread, ThreadSummary,
};
use stigmer_store::{ChainReport, SecurityEvent, Store, StoreError};
use stigmer_store_sqlite::SqliteStore;
use tokio::sync::watch;

use super::{read_events, Read, WaitRequest};

/// What the store does after an events scan, before returning its result.
enum Then {
    Post(NewMessage),
    /// Sleeps (past the wait's deadline), then posts: a post landing after the last scan.
    SleepThenPost(Duration, NewMessage),
}

/// A store that records the `after` cursor of every events scan and runs the next queued
/// `Then` after each one.
struct CountingStore {
    inner: SqliteStore,
    afters: Mutex<Vec<Option<Cursor>>>,
    then: Mutex<VecDeque<Then>>,
}

impl CountingStore {
    async fn new(seed: &[NewMessage], then: Vec<Then>) -> Self {
        let inner = SqliteStore::open_memory().await.unwrap();
        for msg in seed {
            inner.post(msg.clone()).await.unwrap();
        }
        Self {
            inner,
            afters: Mutex::new(Vec::new()),
            then: Mutex::new(then.into()),
        }
    }

    fn afters(&self) -> Vec<Option<Cursor>> {
        self.afters.lock().unwrap().clone()
    }
}

impl Store for CountingStore {
    fn create_board(
        &self,
        id: &BoardId,
        created_by: Option<&Principal>,
        audit: SecurityEvent,
    ) -> impl Future<Output = Result<BoardInfo, StoreError>> + Send {
        self.inner.create_board(id, created_by, audit)
    }

    fn get_board(
        &self,
        id: &BoardId,
    ) -> impl Future<Output = Result<BoardInfo, StoreError>> + Send {
        self.inner.get_board(id)
    }

    fn list_boards(&self) -> impl Future<Output = Result<Vec<BoardInfo>, StoreError>> + Send {
        self.inner.list_boards()
    }

    fn archive_board(
        &self,
        id: &BoardId,
        audit: SecurityEvent,
    ) -> impl Future<Output = Result<BoardInfo, StoreError>> + Send {
        self.inner.archive_board(id, audit)
    }

    fn post(&self, msg: NewMessage) -> impl Future<Output = Result<Posted, StoreError>> + Send {
        self.inner.post(msg)
    }

    fn verify_chain(
        &self,
        board: &BoardId,
    ) -> impl Future<Output = Result<ChainReport, StoreError>> + Send {
        self.inner.verify_chain(board)
    }

    fn read_channel(
        &self,
        board: &BoardId,
        prefix: &ChannelPath,
        page: Page,
    ) -> impl Future<Output = Result<Vec<ThreadSummary>, StoreError>> + Send {
        self.inner.read_channel(board, prefix, page)
    }

    fn read_thread(
        &self,
        board: &BoardId,
        thread: &MessageId,
    ) -> impl Future<Output = Result<Thread, StoreError>> + Send {
        self.inner.read_thread(board, thread)
    }

    fn events_after(
        &self,
        board: &BoardId,
        after: Option<&Cursor>,
        filter: &EventFilter,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<Event>, StoreError>> + Send {
        self.afters.lock().unwrap().push(after.cloned());
        let scan = self.inner.events_after(board, after, filter, limit);
        async move {
            let found = scan.await?;
            let then = self.then.lock().unwrap().pop_front();
            match then {
                Some(Then::Post(msg)) => {
                    self.inner.post(msg).await?;
                }
                Some(Then::SleepThenPost(pause, msg)) => {
                    tokio::time::sleep(pause).await;
                    self.inner.post(msg).await?;
                }
                None => {}
            }
            Ok(found)
        }
    }

    fn head(
        &self,
        board: &BoardId,
    ) -> impl Future<Output = Result<Option<Cursor>, StoreError>> + Send {
        self.inner.head(board)
    }

    fn wait_past(
        &self,
        board: &BoardId,
        after: Option<&Cursor>,
        timeout: Duration,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send {
        self.inner.wait_past(board, after, timeout)
    }
}

fn new_thread(channel: &str, text: &str) -> NewMessage {
    NewMessage::new(
        BoardId::main(),
        Target::NewThread {
            channel: ChannelPath::new(channel).unwrap(),
        },
        Principal::new("alice").unwrap(),
        text.to_owned(),
        vec![],
        None,
    )
    .unwrap()
}

fn noise() -> NewMessage {
    new_thread("sales", "noise")
}

fn signal() -> NewMessage {
    new_thread("eng", "signal")
}

fn eng() -> EventFilter {
    EventFilter {
        channel_prefix: Some(ChannelPath::new("eng").unwrap()),
        ..EventFilter::default()
    }
}

fn at(seq: u64) -> Option<Cursor> {
    Some(Cursor::from_seq(seq))
}

/// Runs one events read on the main board for `eng` events after `after`.
async fn read(
    store: &CountingStore,
    after: Option<Cursor>,
    timeout: Duration,
) -> (Vec<u64>, Option<Cursor>, bool) {
    let (_shutdown, rx) = watch::channel(false);
    let filter = eng();
    let request = WaitRequest {
        board: &BoardId::main(),
        after,
        filter: &filter,
        limit: 50,
        timeout,
    };
    let read = read_events(store, rx, request, || async { Ok(true) })
        .await
        .unwrap();
    let Read::Events(response) = read else {
        panic!("the caller stays allowed");
    };
    let seqs = response.events.iter().map(|e| e.seq).collect();
    (seqs, response.cursor, response.timed_out)
}

#[tokio::test]
async fn a_wait_does_not_rescan_from_its_original_cursor() {
    let store =
        CountingStore::new(&[noise()], vec![Then::Post(noise()), Then::Post(signal())]).await;

    let (seqs, cursor, timed_out) = read(&store, None, Duration::from_secs(5)).await;

    assert_eq!((seqs, cursor, timed_out), (vec![3], at(3), false));
    assert_eq!(
        store.afters(),
        vec![None, at(1), at(2)],
        "each pass after a non-matching wake scans from the head the previous pass read"
    );
}

#[tokio::test]
async fn matching_event_after_non_matching_wakes_is_returned() {
    let store = CountingStore::new(
        &[noise()],
        vec![
            Then::Post(noise()),
            Then::Post(noise()),
            Then::Post(noise()),
            Then::Post(signal()),
        ],
    )
    .await;

    let (seqs, cursor, timed_out) = read(&store, at(1), Duration::from_secs(5)).await;

    assert_eq!((seqs, cursor, timed_out), (vec![5], at(5), false));
    assert_eq!(store.afters(), vec![at(1), at(1), at(2), at(3), at(4)]);
}

#[tokio::test]
async fn resume_cursor_after_timeout_still_loses_nothing() {
    for after in [None, at(1)] {
        // The matching post lands after the last scan, once the deadline has passed.
        let store = CountingStore::new(
            &[noise()],
            vec![
                Then::Post(noise()),
                Then::SleepThenPost(Duration::from_millis(400), signal()),
            ],
        )
        .await;

        let (seqs, cursor, timed_out) =
            read(&store, after.clone(), Duration::from_millis(200)).await;
        assert!(seqs.is_empty() && timed_out, "{after:?}");
        assert_eq!(
            cursor,
            after.clone().or(at(2)),
            "the request's own cursor, else the head read before the last scan"
        );

        let (seqs, _, _) = read(&store, cursor, Duration::ZERO).await;
        assert_eq!(seqs, vec![3], "resuming from {after:?} finds the late post");
    }
}
