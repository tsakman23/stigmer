use stigmer_core::BoardId;
use stigmer_store::Store;

use crate::testing::{
    database_url, new_thread, store_with_poll, until, yield_times, TestSchema, HOURLY_POLL,
    WAIT_TIMEOUT, YIELDS,
};
use crate::wait::Seams;
use crate::PgStore;

/// A store on a fresh schema whose safety poll runs once an hour, so within a test only the
/// head read or a notification can end a wait, with its listener started, and a second handle
/// (another process) on it.
async fn pair(url: &str) -> (TestSchema, PgStore, PgStore) {
    let schema = TestSchema::create(url).await.unwrap();
    let a = store_with_poll(&schema, HOURLY_POLL).await.unwrap();
    a.start_listener_for_tests().await.unwrap();
    let b = a.second_handle_for_tests().await.unwrap();
    (schema, a, b)
}

/// Returns once `a` has handled more than `handled` notifications.
async fn handled_past(a: &PgStore, handled: u64) {
    let seen = until(|| a.notifications_handled_for_tests() > handled).await;
    assert!(seen, "the listener handled the post's notification");
}

/// Each round commits a post through another handle just before the wait reads the head; the
/// wait must already be subscribed by then. The rounds vary when the post's notification is
/// handled relative to the read: after 0 to `YIELDS` yields, and in the last round only once
/// the listener has handled it. Here the read itself sees the post; the next test covers a
/// commit after the read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wake_is_not_lost_when_the_post_commits_between_subscribe_and_head_read() {
    const TEST: &str = "wake_is_not_lost_when_the_post_commits_between_subscribe_and_head_read";
    let Some(url) = database_url(TEST).unwrap() else {
        return;
    };
    let (_schema, a, b) = pair(&url).await;
    let main = BoardId::main();
    let mut head = b
        .post(new_thread("start").unwrap())
        .await
        .unwrap()
        .event
        .cursor;

    for round in 0..=YIELDS + 1 {
        let mut posted = None;
        let before_read = async {
            assert_eq!(
                a.waiters_for_tests(&main),
                1,
                "the wait subscribed before it reads the head (round {round})"
            );
            let handled = a.notifications_handled_for_tests();
            let post = b
                .post(new_thread(&format!("round {round}")).unwrap())
                .await
                .unwrap();
            posted = Some(post.event.cursor);
            if round > YIELDS {
                handled_past(&a, handled).await;
            } else {
                yield_times(round).await;
            }
        };
        let seams = Seams {
            before_read,
            after_read: std::future::ready(()),
        };
        let woke = a
            .wait_past_with_seams(&main, Some(&head), WAIT_TIMEOUT, seams)
            .await;
        assert_eq!(woke, Ok(true), "the post is seen (round {round})");
        head = posted.expect("the post ran before the head read");
    }
}

/// Each round commits a post through another handle just AFTER the wait has read the head, and
/// lets the wait sleep only once the listener has handled that post's notification. The read
/// missed the post, so only the subscription can deliver it: a wait that subscribes after its
/// read (or not at all) misses it every time and times out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wake_is_not_lost_when_the_post_commits_between_head_read_and_sleep() {
    const TEST: &str = "wake_is_not_lost_when_the_post_commits_between_head_read_and_sleep";
    let Some(url) = database_url(TEST).unwrap() else {
        return;
    };
    let (_schema, a, b) = pair(&url).await;
    let main = BoardId::main();
    let mut head = b
        .post(new_thread("start").unwrap())
        .await
        .unwrap()
        .event
        .cursor;

    for round in 0..5 {
        let mut posted = None;
        let after_read = async {
            let handled = a.notifications_handled_for_tests();
            let post = b
                .post(new_thread(&format!("round {round}")).unwrap())
                .await
                .unwrap();
            posted = Some(post.event.cursor);
            handled_past(&a, handled).await;
        };
        let seams = Seams {
            before_read: std::future::ready(()),
            after_read,
        };
        let woke = a
            .wait_past_with_seams(&main, Some(&head), WAIT_TIMEOUT, seams)
            .await;
        assert_eq!(
            woke,
            Ok(true),
            "woken through the subscription (round {round})"
        );
        head = posted.expect("the post ran after the head read");
    }
}
