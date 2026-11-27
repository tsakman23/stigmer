//! The listener's edges: an uncommitted post never wakes anyone, a dropped listener connection
//! loses no wake, and the notifier keeps entries only for live boards that have waiters.

use std::sync::Arc;
use std::time::{Duration, Instant};

use stigmer_core::BoardId;
use stigmer_store::{Entity, IdentityStore, SecurityEvent, SecurityEventKind, Store, StoreError};
use stigmer_store_postgres::PgStore;

use stigmer_store_postgres::testing::{
    database_url, flush_notifications, listening_store, new_thread, new_thread_on, spawn_wait,
    store_with_poll, until, TestSchema, HOURLY_POLL, WAIT_TIMEOUT,
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

async fn create_board(store: &PgStore, raw: &str) -> BoardId {
    let id = BoardId::new(raw).unwrap();
    store
        .create_board(&id, None, audit(SecurityEventKind::BoardCreated))
        .await
        .unwrap();
    id
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn notification_for_an_uncommitted_post_is_never_delivered() {
    let Some(url) =
        database_url("notification_for_an_uncommitted_post_is_never_delivered").unwrap()
    else {
        return;
    };
    let schema = TestSchema::create(&url).await.unwrap();
    let a = Arc::new(listening_store(&schema, HOURLY_POLL).await.unwrap());
    let b = a.second_handle_for_tests().await.unwrap();
    let client = schema.client().await.unwrap();
    let main = BoardId::main();
    let head = b
        .post(new_thread("start").unwrap())
        .await
        .unwrap()
        .event
        .cursor;

    // Fails every post at COMMIT, after everything in it, the notification included, has run.
    client
        .batch_execute(
            "CREATE FUNCTION refuse_commit() RETURNS trigger LANGUAGE plpgsql AS $$
             BEGIN RAISE EXCEPTION 'injected failure at commit'; END $$;
             CREATE CONSTRAINT TRIGGER refuse_commit AFTER INSERT ON events
             DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION refuse_commit();",
        )
        .await
        .unwrap();
    let waiter = spawn_wait(&a, &main, Some(&head), WAIT_TIMEOUT);
    assert!(
        until(|| a.waiters_for_tests(&main) == 1).await,
        "never reached: the waiter subscribed"
    );
    let failed = b.post(new_thread("never committed").unwrap()).await;
    let Err(StoreError::Backend(text)) = failed else {
        panic!("the injected failure fails the post: {failed:?}");
    };
    assert!(text.contains("injected failure at commit"), "{text}");

    // Handled: the first post and the marker; a notification from the rolled-back post would
    // have been delivered before the marker.
    assert!(
        flush_notifications(&a, &client, 2).await.unwrap(),
        "the marker notification is handled"
    );
    // A bounded negative check on top of the flush; the positive path below needs no timer.
    let quiet = tokio::time::timeout(Duration::from_millis(300), async {
        while !waiter.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(quiet.is_err(), "the rolled-back post woke nobody");
    assert_eq!(
        a.notifications_handled_for_tests(),
        2,
        "nothing but the marker"
    );

    client
        .batch_execute("DROP TRIGGER refuse_commit ON events")
        .await
        .unwrap();
    let posted = b.post(new_thread("committed").unwrap()).await.unwrap();
    assert_eq!(posted.event.seq, 2, "the failed post used no number");
    assert_eq!(
        waiter.await.unwrap(),
        Ok(true),
        "the committed post wakes it"
    );
}

/// Terminates `store`'s listener backend and returns its old process id.
async fn kill_listener(store: &PgStore, client: &tokio_postgres::Client) -> i32 {
    let pid = store
        .listener_pid_for_tests()
        .expect("the listener is connected");
    // With a timeout, pg_terminate_backend returns only once the backend has exited, so the
    // old session can no longer receive a notification (and deliver a wake) after this.
    let killed: bool = client
        .query_one("SELECT pg_terminate_backend($1, 10000)", &[&pid])
        .await
        .unwrap()
        .get(0);
    assert!(killed, "listener backend {pid} terminated");
    pid
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn listener_reconnect_does_not_lose_a_wake() {
    const POLL: Duration = Duration::from_millis(250);
    let Some(url) = database_url("listener_reconnect_does_not_lose_a_wake").unwrap() else {
        return;
    };
    let schema = TestSchema::create(&url).await.unwrap();
    let a = Arc::new(listening_store(&schema, POLL).await.unwrap());
    let b = a.second_handle_for_tests().await.unwrap();
    let client = schema.client().await.unwrap();
    let main = BoardId::main();
    let head = b
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
    let old = kill_listener(&a, &client).await;
    let posted_at = Instant::now();
    b.post(new_thread("while the listener is down").unwrap())
        .await
        .unwrap();
    assert_eq!(waiter.await.unwrap(), Ok(true), "the wake is not lost");
    let took = posted_at.elapsed();
    // Within the poll interval, which does not depend on the listener; room for a slow machine.
    assert!(took < POLL + Duration::from_secs(2), "woken after {took:?}");
    assert!(
        until(|| { a.listener_pid_for_tests().is_some_and(|pid| pid != old) }).await,
        "never reached: the listener reconnected on a new backend"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn listener_reconnect_rereads_the_heads_of_boards_with_waiters() {
    let Some(url) =
        database_url("listener_reconnect_rereads_the_heads_of_boards_with_waiters").unwrap()
    else {
        return;
    };
    let schema = TestSchema::create(&url).await.unwrap();
    // No safety poll within the test: only the reconnect (its re-read, or NOTIFY once it
    // listens again) can wake the waiter.
    let a = Arc::new(listening_store(&schema, HOURLY_POLL).await.unwrap());
    let b = a.second_handle_for_tests().await.unwrap();
    let client = schema.client().await.unwrap();
    let main = BoardId::main();
    let head = b
        .post(new_thread("start").unwrap())
        .await
        .unwrap()
        .event
        .cursor;

    let waiter = spawn_wait(&a, &main, Some(&head), Duration::from_secs(10));
    assert!(
        until(|| a.waiters_for_tests(&main) == 1).await,
        "never reached: the waiter subscribed"
    );
    let old = kill_listener(&a, &client).await;
    b.post(new_thread("while the listener is down").unwrap())
        .await
        .unwrap();
    assert_eq!(
        waiter.await.unwrap(),
        Ok(true),
        "the reconnect finds the post"
    );
    // The new session published its pid before its re-read delivered the wake.
    let now = a.listener_pid_for_tests();
    assert!(
        now.is_some_and(|pid| pid != old),
        "woken by the new session, whose pid is published: {now:?} (old {old})"
    );

    // And NOTIFY works again on the new connection.
    let head = a.head(&main).await.unwrap().unwrap();
    let waiter = spawn_wait(&a, &main, Some(&head), WAIT_TIMEOUT);
    assert!(
        until(|| a.waiters_for_tests(&main) == 1).await,
        "never reached: the waiter subscribed"
    );
    b.post(new_thread("after the reconnect").unwrap())
        .await
        .unwrap();
    assert_eq!(waiter.await.unwrap(), Ok(true));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_entry_for_unknown_board() {
    let Some(url) = database_url("no_entry_for_unknown_board").unwrap() else {
        return;
    };
    let schema = TestSchema::create(&url).await.unwrap();
    let a = listening_store(&schema, HOURLY_POLL).await.unwrap();
    let client = schema.client().await.unwrap();

    let nowhere = BoardId::new("nowhere").unwrap();
    let result = a.wait_past(&nowhere, None, WAIT_TIMEOUT).await;
    assert!(
        matches!(
            result,
            Err(StoreError::NotFound {
                entity: Entity::Board,
                ..
            })
        ),
        "{result:?}"
    );
    assert_eq!(
        a.notifier_entries_for_tests(),
        0,
        "a failed wait leaves no entry"
    );

    // Notifications for an unknown and for an archived board create no entry either.
    let old = create_board(&a, "old").await;
    a.archive_board(&old, audit(SecurityEventKind::BoardArchived))
        .await
        .unwrap();
    client
        .batch_execute(
            "SELECT pg_notify('stigmer_events', current_schema() || ':nowhere:5');
             SELECT pg_notify('stigmer_events', current_schema() || ':old:7');",
        )
        .await
        .unwrap();
    assert!(
        flush_notifications(&a, &client, 3).await.unwrap(),
        "the marker notification is handled"
    );
    assert_eq!(
        a.notifier_entries_for_tests(),
        0,
        "notifications create no entry"
    );

    // A wait on an archived board times out and leaves no entry.
    let result = a.wait_past(&old, None, Duration::from_millis(100)).await;
    assert_eq!(result, Ok(false));
    assert_eq!(
        a.notifier_entries_for_tests(),
        0,
        "an archived board keeps no entry"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn archive_drops_the_board_entry() {
    let Some(url) = database_url("archive_drops_the_board_entry").unwrap() else {
        return;
    };
    let schema = TestSchema::create(&url).await.unwrap();
    let a = Arc::new(listening_store(&schema, HOURLY_POLL).await.unwrap());
    let short = Duration::from_millis(300);

    // Through `Store::archive_board` and through `IdentityStore::archive_board_revoking`.
    for (raw, revoking) in [("old", false), ("gone", true)] {
        let board = create_board(&a, raw).await;
        let waiter = spawn_wait(&a, &board, None, short);
        assert!(
            until(|| a.waiters_for_tests(&board) == 1).await,
            "never reached: the waiter subscribed"
        );
        assert_eq!(a.notifier_entries_for_tests(), 1);
        let archived = audit(SecurityEventKind::BoardArchived);
        if revoking {
            a.archive_board_revoking(&board, archived).await.unwrap();
        } else {
            a.archive_board(&board, archived).await.unwrap();
        }
        assert_eq!(
            a.notifier_entries_for_tests(),
            0,
            "{raw}: archiving drops the entry"
        );
        assert_eq!(
            waiter.await.unwrap(),
            Ok(false),
            "{raw}: the wait times out"
        );
        assert_eq!(
            a.notifier_entries_for_tests(),
            0,
            "{raw}: and none comes back"
        );
    }

    // Archived through another process: this one's safety poll drops the entry.
    let c = Arc::new(
        store_with_poll(&schema, Duration::from_millis(100))
            .await
            .unwrap(),
    );
    let board = create_board(&c, "elsewhere").await;
    let waiter = spawn_wait(&c, &board, None, WAIT_TIMEOUT);
    assert!(
        until(|| c.waiters_for_tests(&board) == 1).await,
        "never reached: the waiter subscribed"
    );
    a.archive_board(&board, audit(SecurityEventKind::BoardArchived))
        .await
        .unwrap();
    assert!(
        until(|| { c.notifier_entries_for_tests() == 0 }).await,
        "never reached: the safety poll dropped the entry"
    );
    assert!(
        !waiter.is_finished(),
        "an archived board's wait runs out its timeout"
    );
    waiter.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn archive_does_not_drop_a_wake_still_on_its_way() {
    let Some(url) = database_url("archive_does_not_drop_a_wake_still_on_its_way").unwrap() else {
        return;
    };
    let schema = TestSchema::create(&url).await.unwrap();
    // No safety poll within the test, and the listener is down while the post and the archive
    // commit: only the archive (on this handle) or the reconnect re-read (archived on the
    // other) can deliver the post, and both must deliver it before dropping the entry.
    let a = Arc::new(listening_store(&schema, HOURLY_POLL).await.unwrap());
    let b = a.second_handle_for_tests().await.unwrap();
    let client = schema.client().await.unwrap();

    for (raw, how) in [
        ("one", "here"),
        ("two", "here, revoking"),
        ("three", "elsewhere"),
    ] {
        let board = create_board(&a, raw).await;
        let head = b
            .post(new_thread_on(&board, "start").unwrap())
            .await
            .unwrap()
            .event
            .cursor;
        let waiter = spawn_wait(&a, &board, Some(&head), Duration::from_secs(10));
        assert!(
            until(|| a.waiters_for_tests(&board) == 1).await,
            "never reached: the waiter subscribed"
        );
        assert!(
            until(|| { a.listener_pid_for_tests().is_some() }).await,
            "never reached: the listener is up"
        );
        kill_listener(&a, &client).await;
        assert!(
            until(|| { a.listener_pid_for_tests().is_none() }).await,
            "never reached: the listener is down"
        );

        let started = Instant::now();
        b.post(new_thread_on(&board, "last").unwrap())
            .await
            .unwrap();
        let archived = audit(SecurityEventKind::BoardArchived);
        match how {
            "here" => drop(a.archive_board(&board, archived).await.unwrap()),
            "here, revoking" => drop(a.archive_board_revoking(&board, archived).await.unwrap()),
            _ => drop(b.archive_board(&board, archived).await.unwrap()),
        }
        assert_eq!(
            waiter.await.unwrap(),
            Ok(true),
            "{how}: the last post wakes the wait"
        );
        let took = started.elapsed();
        assert!(took < Duration::from_secs(5), "{how}: woken after {took:?}");
        assert_eq!(
            a.notifier_entries_for_tests(),
            0,
            "{how}: and the entry is gone"
        );
    }
}
