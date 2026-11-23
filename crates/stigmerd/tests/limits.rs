//! The serve flags that set request limits: --max-waits, --auth-failures-per-minute and
//! --join-per-minute, applied through the real server.

mod common;

use std::process::Command;
use std::time::Duration;

use common::{http, run_bounded, start_with};

const BAD_JOIN: &str = r#"{"invite":"stgi1_0000000000000000_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","name":"ann"}"#;

fn network_data_dir(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let data = dir.path().join("data");
    assert_eq!(run_bounded(&["admin", "enable-auth"], &data).code, Some(0));
    data
}

#[test]
fn auth_failures_per_minute_sets_the_failed_auth_budget() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = network_data_dir(&dir);
    let server = start_with(&data, &["--auth-failures-per-minute", "2"]);
    let auth = [("Authorization", "Bearer garbage")];
    let path = "/v1/boards/main/events?timeout_s=0";
    for _ in 0..2 {
        assert_eq!(http(&server.addr, "GET", path, &auth, "").0, 401);
    }
    assert_eq!(http(&server.addr, "GET", path, &auth, "").0, 429);
}

#[test]
fn join_per_minute_sets_the_join_budget() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = network_data_dir(&dir);
    let server = start_with(&data, &["--join-per-minute", "2"]);
    let json = [("Content-Type", "application/json")];
    for _ in 0..2 {
        assert_eq!(
            http(&server.addr, "POST", "/v1/join", &json, BAD_JOIN).0,
            401
        );
    }
    assert_eq!(
        http(&server.addr, "POST", "/v1/join", &json, BAD_JOIN).0,
        429
    );
}

#[test]
fn max_waits_bounds_concurrent_waits() {
    let dir = tempfile::tempdir().expect("tempdir");
    let server = start_with(&dir.path().join("data"), &["--max-waits", "1"]);
    let addr = server.addr.clone();
    let first = std::thread::spawn(move || {
        http(&addr, "GET", "/v1/boards/main/events?timeout_s=3", &[], "")
    });
    // Give the first wait time to reach the server and take the only slot.
    std::thread::sleep(Duration::from_millis(500));
    let (status, body) = http(
        &server.addr,
        "GET",
        "/v1/boards/main/events?timeout_s=1",
        &[],
        "",
    );
    assert_eq!(status, 429, "{body}");
    // A read that does not wait needs no slot.
    let (status, _) = http(
        &server.addr,
        "GET",
        "/v1/boards/main/events?timeout_s=0",
        &[],
        "",
    );
    assert_eq!(status, 200);
    assert_eq!(first.join().expect("first wait").0, 200);
}

#[test]
fn limit_flags_reject_out_of_range_values() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    for (flag, value) in [
        ("--max-waits", "0"),
        ("--max-waits", "100001"),
        ("--auth-failures-per-minute", "0"),
        ("--auth-failures-per-minute", "10001"),
        ("--join-per-minute", "0"),
        ("--join-per-minute", "10001"),
    ] {
        let out = run_bounded(&["serve", "--bind", "127.0.0.1:0", flag, value], &data);
        assert_eq!(out.code, Some(2), "{flag} {value}: {}", out.stderr);
        assert!(
            out.stderr.contains(&format!("'{value}'")),
            "{flag} {value}: {}",
            out.stderr
        );
        assert!(
            !out.stderr.contains("unexpected argument"),
            "{flag}: {}",
            out.stderr
        );
        assert!(out.stdout.is_empty());
        assert!(
            !data.exists(),
            "a refused start must not create the data dir"
        );
    }
}

#[test]
fn help_documents_the_limit_flags_and_their_defaults() {
    let out = Command::new(env!("CARGO_BIN_EXE_stigmerd"))
        .args(["serve", "--help"])
        .output()
        .expect("run help");
    let help = String::from_utf8_lossy(&out.stdout);
    for (flag, default) in [
        ("--max-waits", "[default: 256]"),
        ("--auth-failures-per-minute", "[default: 10]"),
        ("--join-per-minute", "[default: 10]"),
    ] {
        let line = help
            .lines()
            .position(|l| l.trim_start().starts_with(flag))
            .unwrap_or_else(|| panic!("{flag} missing from help: {help}"));
        // clap puts the default at the end of the flag's description paragraph.
        let paragraph: String = help
            .lines()
            .skip(line)
            .take_while(|l| !l.trim().is_empty())
            .collect();
        assert!(paragraph.contains(default), "{flag}: {paragraph}");
    }
}
