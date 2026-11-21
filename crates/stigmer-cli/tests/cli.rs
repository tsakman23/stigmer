//! End-to-end tests: the real board server runs in-process on an ephemeral port and the
//! `stigmer` binary is run against it with `--url`.

use std::net::{SocketAddr, TcpListener};
use std::process::Command;
use std::sync::mpsc;
use std::sync::Arc;

use serde_json::Value;
use stigmer_api::{router, AllowAll};
use stigmer_store_sqlite::SqliteStore;
use tokio::sync::watch;

/// Starts a board server on 127.0.0.1:0 in a background thread and returns its base URL.
/// The thread lives until the test process exits.
fn server() -> String {
    let (tx, rx) = mpsc::channel::<SocketAddr>();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let store = Arc::new(SqliteStore::open_memory().await.unwrap());
            let (_shutdown_tx, shutdown_rx) = watch::channel(false);
            let app = router(store, AllowAll, shutdown_rx);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            tx.send(listener.local_addr().unwrap()).unwrap();
            axum::serve(listener, app).await.unwrap();
        });
    });
    format!("http://{}", rx.recv().unwrap())
}

/// A URL on which nothing listens: binds an ephemeral port, then frees it.
fn dead_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    format!("http://{addr}")
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

/// Runs `stigmer --url <url> <args>` with STIGMER_* cleared from the environment.
fn stigmer(url: &str, args: &[&str]) -> Run {
    let out = Command::new(env!("CARGO_BIN_EXE_stigmer"))
        .env_remove("STIGMER_AS")
        .env_remove("STIGMER_URL")
        .arg("--url")
        .arg(url)
        .args(args)
        .output()
        .unwrap();
    Run {
        code: out.status.code().unwrap(),
        stdout: String::from_utf8(out.stdout).unwrap(),
        stderr: String::from_utf8(out.stderr).unwrap(),
    }
}

/// The value after `prefix` on the first line of `text` that starts with it.
fn line_value<'a>(text: &'a str, prefix: &str) -> &'a str {
    text.lines()
        .find_map(|line| line.strip_prefix(prefix))
        .unwrap_or_else(|| panic!("no line starting with {prefix:?} in:\n{text}"))
}

fn assert_failure_lines(run: &Run) {
    let lines: Vec<&str> = run.stderr.lines().collect();
    assert!(
        lines.iter().any(|l| l.starts_with("error: ")),
        "no error line: {}",
        run.stderr
    );
    assert!(
        lines.iter().any(|l| l.starts_with("next: ")),
        "no next line: {}",
        run.stderr
    );
}

#[test]
fn post_prints_message_id_and_cursor() {
    let url = server();
    let run = stigmer(&url, &["--as", "alice", "post", "eng/ops", "hello"]);
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);
    let first = run.stdout.lines().next().unwrap();
    assert!(first.starts_with("posted msg_"), "{first}");
    assert!(first.ends_with(" in eng/ops as alice"), "{first}");
    assert!(line_value(&run.stdout, "cursor: ").starts_with("ev_"));
}

#[test]
fn post_with_a_reused_key_is_marked_replayed() {
    let url = server();
    let args = ["--as", "alice", "post", "eng", "hello", "--key", "k-1"];
    let first = stigmer(&url, &args);
    let second = stigmer(&url, &args);
    assert_eq!(second.code, 0, "stderr: {}", second.stderr);
    let first_line = first.stdout.lines().next().unwrap();
    assert_eq!(
        second.stdout.lines().next().unwrap(),
        format!("{first_line} (replayed)")
    );
}

#[test]
fn missing_as_exits_2_with_next_hint() {
    let url = server();
    let run = stigmer(&url, &["post", "eng", "hello"]);
    assert_eq!(run.code, 2);
    assert_failure_lines(&run);
    assert!(
        run.stderr
            .contains("next: export STIGMER_AS=<name> or pass --as <name>"),
        "{}",
        run.stderr
    );
    assert!(run.stdout.is_empty());
}

#[test]
fn text_over_10000_chars_exits_5() {
    // Nothing listens on this URL, so exit 5 (not 1) shows the check happened client-side.
    let url = dead_url();
    let text = "a".repeat(10_001);
    let run = stigmer(&url, &["--as", "alice", "post", "eng", &text]);
    assert_eq!(run.code, 5, "stderr: {}", run.stderr);
    assert_failure_lines(&run);
}

#[test]
fn trailing_slash_in_channel_is_accepted() {
    let url = server();
    let run = stigmer(&url, &["--as", "alice", "post", "research/", "hello"]);
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);
    assert!(run
        .stdout
        .lines()
        .next()
        .unwrap()
        .ends_with(" in research as alice"));
    let bad = stigmer(
        &dead_url(),
        &["--as", "alice", "post", "research//", "hello"],
    );
    assert_eq!(
        bad.code, 5,
        "only one trailing slash is stripped: {}",
        bad.stderr
    );
}

#[test]
fn json_flag_prints_single_json_object() {
    let url = server();
    let run = stigmer(&url, &["--as", "alice", "--json", "post", "eng", "hello"]);
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);
    let mut values = serde_json::Deserializer::from_str(&run.stdout).into_iter::<Value>();
    let only = values.next().unwrap().unwrap();
    assert!(
        values.next().is_none(),
        "more than one JSON value: {}",
        run.stdout
    );
    assert_eq!(only["message"]["author"], "alice");
    assert_eq!(only["message"]["channel"], "eng");
    assert!(only["event"]["cursor"].as_str().unwrap().starts_with("ev_"));
}

#[test]
fn json_error_goes_to_stderr_with_next_hint() {
    let url = server();
    let run = stigmer(
        &url,
        &["--as", "alice", "--json", "post", "Not A Channel", "hi"],
    );
    assert_eq!(run.code, 5);
    assert!(run.stdout.is_empty(), "stdout: {}", run.stdout);
    let body: Value = serde_json::from_str(&run.stderr).unwrap();
    assert_eq!(body["error"]["code"], "invalid_input");
    assert!(!body["error"]["message"].as_str().unwrap().is_empty());
    assert!(!body["next"].as_str().unwrap().is_empty());

    let usage = stigmer(&url, &["--json", "post", "eng", "hi"]);
    assert_eq!(usage.code, 2);
    let body: Value = serde_json::from_str(&usage.stderr).unwrap();
    assert_eq!(body["error"]["code"], "usage");
    assert_eq!(body["next"], "export STIGMER_AS=<name> or pass --as <name>");
}

#[test]
fn connection_refused_hints_to_start_the_server() {
    let run = stigmer(&dead_url(), &["--as", "alice", "post", "eng", "hi"]);
    assert_eq!(run.code, 1);
    assert_failure_lines(&run);
    assert!(
        run.stderr
            .contains("next: start the server with: stigmerd serve"),
        "{}",
        run.stderr
    );
}

#[test]
fn unknown_flag_is_a_usage_error_with_next_hint() {
    let run = stigmer(&dead_url(), &["post", "--bogus"]);
    assert_eq!(run.code, 2);
    assert_failure_lines(&run);
}
