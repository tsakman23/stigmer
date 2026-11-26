//! stigmer-store-conformance: the behaviour every `Store` backend must show.
//!
//! A backend's test calls [`run_all`] with a [`Fixture`] that makes fresh, empty stores and
//! second handles on a store's database. Each scenario panics with its name when the backend
//! gets something wrong. Run it on a multi-thread tokio runtime: the concurrency scenarios spawn
//! tasks.
//!
//! This is test-support code: panics are its assertion mechanism, so it uses `panic!` and the
//! `assert!` family where library code would return errors.

mod archive;
mod boards;
mod cross_instance;
mod cross_instance_identity;
mod events;
mod fixture;
mod idempotency;
mod identity;
mod identity_adoption;
mod identity_archive;
mod identity_audit;
mod identity_audit_failures;
mod identity_credentials;
mod identity_enable;
mod identity_invites;
mod identity_join;
mod identity_log;
mod identity_members;
mod posts;
mod reads;
mod reads_threads;
mod support;
mod wait;

use std::future::Future;

use stigmer_store::{IdentityStore, Store};

pub use fixture::Fixture;

/// Runs the store, identity and cross-instance suites, each scenario against fresh stores from
/// `fixture`, then prints one summary line naming [`Fixture::CROSS_PROCESS_WAKE`].
pub async fn run_all<X>(fixture: &X)
where
    X: Fixture,
    X::Store: IdentityStore,
{
    let factory = || fixture.fresh();
    run_store_suite(factory).await;
    identity::run_identity_suite(factory).await;
    cross_instance::run_cross_instance_suite(fixture).await;
    cross_instance::run_cross_instance_identity_suite(fixture).await;
    summarise(fixture::Suites::All, X::CROSS_PROCESS_WAKE);
}

/// Runs only the `Store` half: the store suite and the cross-instance scenarios that need no
/// `IdentityStore`, then prints a summary line that names the half it ran. For a backend that
/// does not implement `IdentityStore` yet; [`run_all`] is the definition of a complete backend.
pub async fn run_store_suites<X: Fixture>(fixture: &X) {
    run_store_suite(|| fixture.fresh()).await;
    cross_instance::run_cross_instance_suite(fixture).await;
    summarise(fixture::Suites::StoreOnly, X::CROSS_PROCESS_WAKE);
}

fn summarise(suites: fixture::Suites, cross_process_wake: bool) {
    support::ok(
        fixture::write_summary(&mut std::io::stderr().lock(), suites, cross_process_wake),
        "conformance: summary line",
    );
}

/// Runs every `Store` scenario, each against a fresh store from `factory`.
async fn run_store_suite<S, F, Fut>(factory: F)
where
    S: Store,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    posts::first_post_creates_thread_with_event_seq_1(factory().await).await;
    posts::reply_appends_event_seq_2_and_keeps_thread_id(factory().await).await;
    posts::sequence_is_gapless_under_50_concurrent_posts(factory().await).await;
    posts::reply_to_unknown_thread_is_not_found(factory().await).await;
    posts::reply_to_a_reply_is_not_found(factory().await).await;
    posts::post_to_unknown_board_is_not_found(factory().await).await;
    posts::concurrent_posts_keep_summaries_equal_to_messages(factory().await).await;
    idempotency::same_key_same_author_returns_original_and_replayed_true(factory().await).await;
    idempotency::same_key_writes_exactly_one_event(factory().await).await;
    idempotency::same_key_different_author_is_a_new_message(factory().await).await;
    idempotency::same_key_different_text_is_conflict(factory().await).await;
    reads::read_channel_lists_threads_newest_first_and_filters_by_prefix(factory().await).await;
    reads::read_channel_matches_whole_path_segments_only(factory().await).await;
    reads::read_channel_paginates_with_before_and_clamps_limit(factory().await).await;
    reads::read_channel_preview_is_200_chars_not_bytes(factory().await).await;
    reads::read_thread_returns_root_and_replies_in_order(factory().await).await;
    reads::read_thread_of_unknown_id_reply_or_other_board_is_not_found(factory().await).await;
    reads::ordering_never_depends_on_wall_clock_time_at_the_store_level(factory().await).await;
    reads_threads::read_channel_orders_by_last_event_sequence_not_wall_clock(factory().await).await;
    reads_threads::reply_moves_its_thread_to_the_top_and_updates_count_and_preview_stays_the_root(
        factory().await,
    )
    .await;
    reads_threads::pagination_returns_every_thread_exactly_once_across_pages_with_tied_times(
        factory().await,
    )
    .await;
    reads_threads::summaries_are_consistent_after_random_operations(factory().await).await;
    events::head_is_none_on_an_empty_board_then_the_latest_cursor(factory().await).await;
    events::events_after_none_returns_from_start(factory().await).await;
    events::events_after_resumes_after_a_cursor_and_clamps_limit(factory().await).await;
    events::events_after_filters_by_channel_thread_and_label(factory().await).await;
    events::events_after_future_cursor_is_invalid_cursor(factory().await).await;
    events::events_after_malformed_cursor_is_invalid_cursor(factory().await).await;
    events::events_after_unknown_board_is_not_found(factory().await).await;
    wait::wait_past_returns_true_when_a_post_lands_during_the_wait(factory().await).await;
    wait::wait_past_returns_false_on_timeout(factory().await).await;
    wait::wait_past_does_not_wake_for_events_before_the_cursor(factory().await).await;
    wait::wait_past_returns_true_at_once_when_head_is_already_past(factory().await).await;
    wait::wait_past_future_cursor_is_invalid_cursor_without_waiting(factory().await).await;
    wait::wait_past_is_not_woken_by_an_idempotent_replay(factory().await).await;
    boards::create_board_then_get_and_list(factory().await).await;
    boards::create_duplicate_board_is_board_exists(factory().await).await;
    boards::concurrent_create_board_has_one_winner(factory().await).await;
    boards::main_exists_on_a_fresh_store(factory().await).await;
    boards::boards_are_isolated_sequences_start_at_1_per_board(factory().await).await;
    boards::unknown_board_is_not_found_from_every_method(factory().await).await;
    archive::post_to_archived_board_is_board_archived_and_uses_no_sequence_number(factory().await)
        .await;
    archive::archived_board_is_still_readable(factory().await).await;
    archive::archive_is_idempotent_and_keeps_first_timestamp(factory().await).await;
    archive::archive_main_is_refused_and_main_stays_writable(factory().await).await;
}
