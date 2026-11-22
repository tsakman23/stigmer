//! tail against failing servers: transient failures are retried, permanent ones end it.

mod common;

use std::time::Duration;

use common::fixtures::{dead_url, tail_until_exit};
use common::{CliUser, Collected, Guard, Stigmerd};

#[test]
fn tail_retries_after_a_server_restart() {
    let mut server = Stigmerd::local();
    let user = CliUser::new();
    let url = server.url.clone();
    let post = |text: &str| user.run(&["--url", &url, "--as", "a", "post", "eng", text]);
    assert_eq!(post("before").code, 0);
    let mut tail = Guard::spawn(&mut user.cmd(&["--url", &url, "tail", "--channel", "eng"]));
    let (stdout, stderr) = (Collected::default(), Collected::default());
    stdout.drain(tail.0.stdout.take().unwrap());
    stderr.drain(tail.0.stderr.take().unwrap());
    stdout.wait_for("before", Duration::from_secs(10));

    server.restart_after(Duration::from_millis(1_500));
    let notes = stderr.wait_for("retrying in", Duration::from_secs(10));
    assert!(notes.lines().all(|l| l.starts_with("stigmer: ")), "{notes}");
    let posted = post("after");
    assert_eq!(posted.code, 0, "{posted:?}");
    stdout.wait_for("after", Duration::from_secs(40));
    assert!(tail.0.try_wait().unwrap().is_none(), "tail never gives up");
}

#[test]
fn tail_exits_on_a_certificate_error_instead_of_retrying() {
    let (server, _files, _pems) = Stigmerd::tls();
    let user = CliUser::new();
    let (run, took) = tail_until_exit(&user, &["--url", &server.url], Duration::from_secs(20));
    assert_eq!(run.code, 1, "{run:?}");
    assert!(took < Duration::from_secs(5), "took {took:?}");
    assert!(!run.stderr.contains("retrying"), "{run:?}");
    assert!(
        run.stderr.contains("next: for a private CA pass --ca-cert"),
        "{run:?}"
    );
}

#[test]
fn tail_exits_on_a_malformed_url() {
    let user = CliUser::new();
    let (run, took) = tail_until_exit(
        &user,
        &["--url", "http://exa mple.invalid"],
        Duration::from_secs(20),
    );
    assert_eq!(run.code, 1, "{run:?}");
    assert!(took < Duration::from_secs(5), "took {took:?}");
    assert!(!run.stderr.contains("retrying"), "{run:?}");
}

#[test]
fn tail_still_retries_after_connection_refused() {
    let user = CliUser::new();
    let url = dead_url();
    let run = common::finish(
        Guard::spawn(&mut user.cmd(&["--url", &url, "tail", "--timeout", "3s"])),
        Duration::from_secs(20),
    );
    assert_eq!(run.code, 0, "tail gives up only at its deadline: {run:?}");
    assert!(run.stderr.contains("retrying in 1s"), "{run:?}");
    assert!(run.stderr.contains("retrying in 2s"), "{run:?}");
}
