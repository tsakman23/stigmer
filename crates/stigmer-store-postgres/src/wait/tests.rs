use std::time::Duration;

use stigmer_core::{BoardId, ChannelPath, NewMessage, Principal, Target};
use stigmer_store::Store;

use crate::testing::{database_url, TestSchema};
use crate::PgStore;

/// Most yields tried after the commit, before the head read: every count in `0..=YIELDS`.
const YIELDS: usize = 20;
const HOUR: Duration = Duration::from_secs(3600);
const LONG: Duration = Duration::from_secs(10);

fn new_thread(text: &str) -> NewMessage {
    let target = Target::NewThread {
        channel: ChannelPath::new("eng").unwrap(),
    };
    let author = Principal::new("alice").unwrap();
    NewMessage::new(
        BoardId::main(),
        target,
        author,
        text.to_owned(),
        vec![],
        None,
    )
    .unwrap()
}

/// Each round commits a post through another handle after the wait has subscribed and before
/// it reads the head. The rounds vary when the post's notification is handled relative to the
/// read: after 0 to `YIELDS` yields, and in the last round only once the listener has handled
/// it, so a wait that subscribed late (after its read) would miss it in that round for sure.
/// The safety poll is an hour: only the read or the notification can end the wait.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wake_is_not_lost_when_the_post_commits_between_subscribe_and_head_read() {
    const TEST: &str = "wake_is_not_lost_when_the_post_commits_between_subscribe_and_head_read";
    let Some(url) = database_url(TEST).unwrap() else {
        return;
    };
    let schema = TestSchema::create(&url).await.unwrap();
    let a = PgStore::connect_with_poll_for_tests(schema.url(), schema.options(), HOUR)
        .await
        .unwrap();
    a.migrate().await.unwrap();
    let b = a.second_handle_for_tests().await.unwrap();
    let main = BoardId::main();
    let mut head = b.post(new_thread("start")).await.unwrap().event.cursor;

    for round in 0..=YIELDS + 1 {
        let mut posted = None;
        let between = async {
            let handled = a.notifications_handled_for_tests();
            let post = b.post(new_thread(&format!("round {round}"))).await.unwrap();
            posted = Some(post.event.cursor);
            if round > YIELDS {
                let seen = tokio::time::timeout(LONG, async {
                    while a.notifications_handled_for_tests() == handled {
                        tokio::task::yield_now().await;
                    }
                })
                .await;
                assert!(seen.is_ok(), "the listener handled the post's notification");
            } else {
                for _ in 0..round {
                    tokio::task::yield_now().await;
                }
            }
        };
        let woke = a.wait_past_between(&main, Some(&head), LONG, between).await;
        assert_eq!(woke, Ok(true), "the post is seen (round {round})");
        head = posted.expect("the post ran between subscribe and read");
    }
}
