//! The listener starts lazily: a store opens its listener connection (and starts its safety
//! poll) only when a wait first has to sleep, and starts it once however many waits arrive
//! together. One-shot users (admin commands, callers that never wait) open no extra connection.

use std::sync::Arc;
use std::time::Duration;

use stigmer_core::{BoardId, ChannelPath, Cursor};
use stigmer_store::{Page, SecurityEvent, SecurityEventKind, Store, StoreError};
use stigmer_store_postgres::testing::{
    database_url, new_thread, spawn_wait, store_with_poll, until, TestSchema, HOURLY_POLL,
    WAIT_TIMEOUT,
};

fn audit(kind: SecurityEventKind) -> SecurityEvent {
    SecurityEvent {
        at_ms: 1_700_000_000_000,
        kind,
        board: None,
        principal: Some("root".to_owned()),
        detail: format!("{kind}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_listener_connection_is_opened_by_a_store_that_never_waits() {
    let Some(url) =
        database_url("no_listener_connection_is_opened_by_a_store_that_never_waits").unwrap()
    else {
        return;
    };
    let schema = TestSchema::create(&url).await.unwrap();
    let a = store_with_poll(&schema, HOURLY_POLL).await.unwrap();
    let main = BoardId::main();

    // Everything but a wait that has to sleep.
    let posted = a.post(new_thread("one").unwrap()).await.unwrap();
    a.head(&main).await.unwrap();
    a.list_boards().await.unwrap();
    let eng = ChannelPath::new("eng").unwrap();
    a.read_channel(
        &main,
        &eng,
        Page {
            limit: 50,
            before: None,
        },
    )
    .await
    .unwrap();
    // Waits that end without sleeping: the head is past the cursor, the cursor is past the
    // head, the board is unknown, and a wait on an archived board (it sleeps out its timeout
    // without a listener: its head can no longer move).
    assert_eq!(a.wait_past(&main, None, WAIT_TIMEOUT).await, Ok(true));
    let future = Cursor::from_seq(posted.event.seq + 5);
    assert_eq!(
        a.wait_past(&main, Some(&future), WAIT_TIMEOUT).await,
        Err(StoreError::InvalidCursor)
    );
    let nowhere = BoardId::new("nowhere").unwrap();
    assert!(a.wait_past(&nowhere, None, WAIT_TIMEOUT).await.is_err());
    let old = BoardId::new("old").unwrap();
    a.create_board(&old, None, audit(SecurityEventKind::BoardCreated))
        .await
        .unwrap();
    a.archive_board(&old, audit(SecurityEventKind::BoardArchived))
        .await
        .unwrap();
    assert_eq!(
        a.wait_past(&old, None, Duration::from_millis(50)).await,
        Ok(false)
    );

    assert_eq!(a.listener_pid_for_tests(), None, "no listener connection");
    assert_eq!(
        a.listener_starts_for_tests(),
        0,
        "and none was ever started"
    );

    // The first wait that has to sleep starts it.
    let a = Arc::new(a);
    let head = posted.event.cursor;
    let waiter = spawn_wait(&a, &main, Some(&head), WAIT_TIMEOUT);
    assert!(
        until(|| a.listener_pid_for_tests().is_some()).await,
        "never reached: the sleeping wait started the listener"
    );
    a.post(new_thread("two").unwrap()).await.unwrap();
    assert_eq!(waiter.await.unwrap(), Ok(true));
    assert_eq!(a.listener_starts_for_tests(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_first_waits_start_exactly_one_listener() {
    const WAITS: usize = 20;
    let Some(url) = database_url("concurrent_first_waits_start_exactly_one_listener").unwrap()
    else {
        return;
    };
    let schema = TestSchema::create(&url).await.unwrap();
    let a = Arc::new(store_with_poll(&schema, HOURLY_POLL).await.unwrap());
    let b = a.second_handle_for_tests().await.unwrap();
    let main = BoardId::main();
    let head = b
        .post(new_thread("start").unwrap())
        .await
        .unwrap()
        .event
        .cursor;
    assert_eq!(a.listener_starts_for_tests(), 0);

    // Twenty first waits at once, all of which must sleep.
    let waiters: Vec<_> = (0..WAITS)
        .map(|_| spawn_wait(&a, &main, Some(&head), WAIT_TIMEOUT))
        .collect();
    assert!(
        until(
            || a.sleeping_waiters_for_tests(&main) == WAITS && a.listener_pid_for_tests().is_some()
        )
        .await,
        "never reached: every wait sleeps and the listener is up"
    );
    b.post(new_thread("wake").unwrap()).await.unwrap();
    for waiter in waiters {
        assert_eq!(waiter.await.unwrap(), Ok(true), "woken through NOTIFY");
    }
    assert_eq!(
        a.listener_starts_for_tests(),
        1,
        "one listener for all of them"
    );
}
