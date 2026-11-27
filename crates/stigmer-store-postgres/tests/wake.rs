//! Cross-replica wake-ups through LISTEN/NOTIFY: two handles on one schema stand for two server
//! processes, each with its own listener and notifier. The safety poll is set to an hour where a
//! wake must come through NOTIFY.

use std::sync::Arc;
use std::time::{Duration, Instant};

use stigmer_core::BoardId;
use stigmer_store::{Store, StoreError};
use stigmer_store_postgres::{
    PgOptions, PgStore, PgTls, DEFAULT_POLL_INTERVAL, MAX_POLL_INTERVAL, MIN_POLL_INTERVAL,
};

use stigmer_store_postgres::testing::{
    database_url, flush_notifications, listening_store, new_thread, spawn_wait, store_with_poll,
    until, yield_times, TestSchema, HOURLY_POLL, WAIT_TIMEOUT, YIELDS,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wake_across_handles() {
    let Some(url) = database_url("wake_across_handles").unwrap() else {
        return;
    };
    let schema = TestSchema::create(&url).await.unwrap();
    // Lazy listeners, as in production: each wait may be the one that starts a's.
    let a = Arc::new(store_with_poll(&schema, HOURLY_POLL).await.unwrap());
    let b = a.second_handle_for_tests().await.unwrap();
    let main = BoardId::main();
    let mut cursor = b
        .post(new_thread("start").unwrap())
        .await
        .unwrap()
        .event
        .cursor;
    // Before, during and after the waiter subscribes: every yield count up to YIELDS.
    for yields in 0..=YIELDS {
        let waiter = spawn_wait(&a, &main, Some(&cursor), WAIT_TIMEOUT);
        yield_times(yields).await;
        let posted_at = Instant::now();
        let posted = b
            .post(new_thread(&format!("after {yields}")).unwrap())
            .await
            .unwrap();
        let woke = waiter.await.unwrap();
        let took = posted_at.elapsed();
        assert_eq!(woke, Ok(true), "a post through b wakes a ({yields} yields)");
        // The hourly safety poll is the proof it was NOTIFY; the bound only catches a hang.
        assert!(
            took < Duration::from_secs(5),
            "woken through NOTIFY, not by the hourly poll: {took:?} ({yields} yields)"
        );
        cursor = posted.event.cursor;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wait_holds_no_connection_while_sleeping() {
    const WAITS: usize = 20;
    let Some(url) = database_url("wait_holds_no_connection_while_sleeping").unwrap() else {
        return;
    };
    let schema = TestSchema::create(&url).await.unwrap();
    let options = PgOptions {
        max_connections: 2,
        ..schema.options()
    };
    let a = PgStore::connect_with_poll_for_tests(schema.url(), options, HOURLY_POLL)
        .await
        .unwrap();
    a.migrate().await.unwrap();
    let a = Arc::new(a);
    let main = BoardId::main();
    let head = a
        .post(new_thread("start").unwrap())
        .await
        .unwrap()
        .event
        .cursor;

    let waiters: Vec<_> = (0..WAITS)
        .map(|_| spawn_wait(&a, &main, Some(&head), WAIT_TIMEOUT))
        .collect();
    assert!(
        until(|| a.waiters_for_tests(&main) == WAITS && a.pool_in_use_for_tests() == 0).await,
        "never reached: every wait is subscribed and no connection is in use"
    );
    assert!(
        waiters.iter().all(|w| !w.is_finished()),
        "all still waiting"
    );

    // A pool of two serves other callers while twenty waits are pending.
    let reads = tokio::time::timeout(Duration::from_secs(5), async {
        for _ in 0..10 {
            a.head(&main).await.unwrap();
            a.list_boards().await.unwrap();
        }
    })
    .await;
    assert!(reads.is_ok(), "queries run while the waits sleep");
    assert!(
        waiters.iter().all(|w| !w.is_finished()),
        "reads wake nobody"
    );

    a.post(new_thread("wake").unwrap()).await.unwrap();
    for waiter in waiters {
        assert_eq!(waiter.await.unwrap(), Ok(true));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stores_in_different_schemas_do_not_wake_each_other() {
    let Some(url) = database_url("stores_in_different_schemas_do_not_wake_each_other").unwrap()
    else {
        return;
    };
    let (here, there) = (
        TestSchema::create(&url).await.unwrap(),
        TestSchema::create(&url).await.unwrap(),
    );
    let a = Arc::new(listening_store(&here, HOURLY_POLL).await.unwrap());
    let other = listening_store(&there, HOURLY_POLL).await.unwrap();
    let main = BoardId::main();
    let client = here.client().await.unwrap();
    let head = a
        .post(new_thread("start").unwrap())
        .await
        .unwrap()
        .event
        .cursor;

    let waiter = spawn_wait(&a, &main, Some(&head), WAIT_TIMEOUT);
    assert!(
        until(|| a.waiters_for_tests(&main) == 1).await,
        "never reached: the waiter subscribed"
    );
    // Board `main` exists in both schemas; a post to the other one must not wake this waiter.
    other.post(new_thread("elsewhere").unwrap()).await.unwrap();
    other
        .post(new_thread("elsewhere again").unwrap())
        .await
        .unwrap();
    // Handled: a's own first post and the marker; the other schema's posts are not counted.
    assert!(
        flush_notifications(&a, &client, 2).await.unwrap(),
        "the marker notification is handled"
    );
    assert!(
        !waiter.is_finished(),
        "another schema's post wakes nobody here"
    );
    assert_eq!(a.notifications_handled_for_tests(), 2);

    a.post(new_thread("here").unwrap()).await.unwrap();
    assert_eq!(
        waiter.await.unwrap(),
        Ok(true),
        "this schema's post wakes it"
    );
}

#[tokio::test]
async fn poll_interval_bounds_are_validated() {
    assert_eq!(DEFAULT_POLL_INTERVAL, Duration::from_millis(2000));
    assert_eq!(MIN_POLL_INTERVAL, Duration::from_millis(100));
    assert_eq!(MAX_POLL_INTERVAL, Duration::from_millis(60_000));
    // Port 1: nothing listens, so an accepted interval fails later, on connecting.
    let closed = "postgres://stigmer@127.0.0.1:1/stigmer_test";
    let options = |ms: u64| PgOptions {
        max_connections: 1,
        tls: PgTls::Disable,
        poll_interval: Duration::from_millis(ms),
    };
    for ms in [0, 99, 60_001, 3_600_000] {
        let Err(StoreError::Backend(text)) = PgStore::connect(closed, options(ms)).await else {
            panic!("{ms} ms is refused");
        };
        assert!(text.contains("poll interval"), "{ms} ms: {text}");
        assert!(
            text.contains("100") && text.contains("60000"),
            "{ms} ms: {text}"
        );
    }
    for ms in [100, 2000, 60_000] {
        let Err(StoreError::Backend(text)) = PgStore::connect(closed, options(ms)).await else {
            panic!("nothing listens on port 1");
        };
        assert!(
            !text.contains("poll interval"),
            "{ms} ms is accepted: {text}"
        );
        assert!(text.contains("cannot connect"), "{ms} ms: {text}");
    }
}
