//! Token resolution and the login file: what the CLI sends, to where, and when it refuses.

mod common;

use std::time::Duration;

use common::fixtures::{fake_token, header, write_logins};
use common::{Capture, CliUser, Stigmerd};

#[test]
fn board_flag_selects_the_board_in_urls() {
    let capture = Capture::start(200, r#"{"threads":[]}"#);
    let user = CliUser::new();
    let read = |args: &[&str], env: &[(&str, &str)]| {
        let mut all = vec!["--url", capture.url.as_str()];
        all.extend_from_slice(args);
        let run = user.run_env(&all, env);
        assert_eq!(run.code, 0, "{run:?}");
        capture.request()
    };
    let head = read(&["read", "eng"], &[]);
    assert!(head.starts_with("GET /v1/boards/main/channels?"), "{head}");
    let head = read(&["--board", "ops", "read", "eng"], &[]);
    assert!(head.starts_with("GET /v1/boards/ops/channels?"), "{head}");
    let head = read(&["read", "eng"], &[("STIGMER_BOARD", "team-2")]);
    assert!(
        head.starts_with("GET /v1/boards/team-2/channels?"),
        "{head}"
    );

    let bad = user.run(&["--url", &capture.url, "--board", "Bad!", "read", "eng"]);
    assert_eq!(bad.code, 5, "{bad:?}");
    assert!(bad.stderr.contains("next: board names are"), "{bad:?}");
    assert!(
        !capture.saw_request(),
        "an invalid board must not reach the server"
    );
}

#[test]
fn token_is_not_sent_without_a_resolved_login_and_x_stigmer_as_is_not_sent_with_one() {
    let capture = Capture::start(200, r#"{"threads":[]}"#);
    let user = CliUser::new();
    let run = user.run(&["--url", &capture.url, "--as", "bob", "read", "eng"]);
    assert_eq!(run.code, 0, "{run:?}");
    let head = capture.request();
    assert_eq!(header(&head, "x-stigmer-as"), Some("bob"), "{head}");
    assert_eq!(header(&head, "authorization"), None, "{head}");

    let token = fake_token();
    let run = user.run_env(
        &["--url", &capture.url, "--as", "bob", "read", "eng"],
        &[("STIGMER_TOKEN", &token)],
    );
    assert_eq!(run.code, 0, "{run:?}");
    let head = capture.request();
    assert_eq!(
        header(&head, "authorization"),
        Some(format!("Bearer {token}").as_str()),
        "the token goes in the Authorization header"
    );
    assert_eq!(header(&head, "x-stigmer-as"), None, "{head}");
    let (request_line, _) = head.split_once("\r\n").unwrap();
    assert!(!request_line.contains(&token), "never in the URL");
}

#[test]
fn token_env_overrides_the_login_file() {
    let capture = Capture::start(200, r#"{"threads":[]}"#);
    let user = CliUser::new();
    let saved = fake_token();
    write_logins(&user.logins_path(), &[(&capture.url, "board:main", &saved)]);
    let run = user.run(&["--url", &capture.url, "read", "eng"]);
    assert_eq!(run.code, 0, "{run:?}");
    let saved_header = format!("Bearer {saved}");
    assert_eq!(
        header(&capture.request(), "authorization"),
        Some(saved_header.as_str())
    );

    let env = fake_token();
    let run = user.run_env(
        &["--url", &capture.url, "read", "eng"],
        &[("STIGMER_TOKEN", &env)],
    );
    assert_eq!(run.code, 0, "{run:?}");
    let env_header = format!("Bearer {env}");
    assert_eq!(
        header(&capture.request(), "authorization"),
        Some(env_header.as_str())
    );
}

#[test]
fn logins_are_keyed_by_server_and_board() {
    let one = Capture::start(200, r#"{"threads":[]}"#);
    let two = Capture::start(200, r#"{"threads":[]}"#);
    let user = CliUser::new();
    let (main_one, ops_one, main_two) = (fake_token(), fake_token(), fake_token());
    // A trailing slash on the saved URL is the same server.
    let one_slash = format!("{}/", one.url);
    write_logins(
        &user.logins_path(),
        &[
            (&one.url, "board:main", &main_one),
            (&one.url, "board:ops", &ops_one),
            (&two.url, "board:main", &main_two),
        ],
    );
    let sent = |capture: &Capture, args: &[&str]| {
        let run = user.run(args);
        assert_eq!(run.code, 0, "{run:?}");
        header(&capture.request(), "authorization").map(str::to_owned)
    };
    let bearer = |token: &str| Some(format!("Bearer {token}"));
    assert_eq!(
        sent(&one, &["--url", &one_slash, "read", "eng"]),
        bearer(&main_one)
    );
    assert_eq!(
        sent(&one, &["--url", &one.url, "--board", "ops", "read", "eng"]),
        bearer(&ops_one)
    );
    assert_eq!(
        sent(&two, &["--url", &two.url, "read", "eng"]),
        bearer(&main_two)
    );
    assert_eq!(
        sent(&two, &["--url", &two.url, "--board", "ops", "read", "eng"]),
        None,
        "no login for that server and board"
    );
}

#[test]
fn corrupt_login_file_is_an_error_and_is_not_overwritten() {
    let capture = Capture::start(200, r#"{"threads":[]}"#);
    let user = CliUser::new();
    let path = user.logins_path();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let secret = fake_token();
    for body in [
        format!("{{\"version\":1,\"logins\":[{{\"token\":\"{secret}\""),
        format!("{{\"version\":2,\"logins\":[],\"token\":\"{secret}\"}}"),
        format!("{{\"version\":1,\"logins\":[{{\"url\":7,\"token\":\"{secret}\"}}]}}"),
    ] {
        std::fs::write(&path, &body).unwrap();
        let run = user.run(&["--url", &capture.url, "read", "eng"]);
        assert_eq!(run.code, 1, "{run:?}");
        assert!(run.stderr.contains("login file"), "{run:?}");
        assert!(
            !run.all().contains(&secret),
            "the file's contents are never printed"
        );
        assert!(!run.all().contains("stg1_"), "{run:?}");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            body,
            "left unchanged"
        );
        assert!(!capture.saw_request());
    }
}

#[test]
fn token_over_plain_http_to_a_remote_host_is_refused_without_insecure() {
    let user = CliUser::new();
    let token = fake_token();
    for url in ["http://board.example.invalid:7878", "http://10.1.2.3:7878"] {
        let run = user.run_env(&["--url", url, "read", "eng"], &[("STIGMER_TOKEN", &token)]);
        assert_eq!(run.code, 2, "{run:?}");
        assert!(
            run.stderr
                .contains("next: use an https:// URL (or --insecure for a trusted network)"),
            "{run:?}"
        );
        assert!(!run.all().contains(&token));
    }
    // A saved login for a remote plain-http server is refused the same way.
    write_logins(
        &user.logins_path(),
        &[("http://10.1.2.3:7878", "board:main", &token)],
    );
    let run = user.run(&["--url", "http://10.1.2.3:7878", "read", "eng"]);
    assert_eq!(run.code, 2, "{run:?}");
}

#[test]
fn malformed_token_env_is_invalid_input_and_not_echoed() {
    let user = CliUser::new();
    let capture = Capture::start(200, r#"{"threads":[]}"#);
    let bad = "stg1_not-a-real-token-SECRETISH";
    let run = user.run_env(
        &["--url", &capture.url, "read", "eng"],
        &[("STIGMER_TOKEN", bad)],
    );
    assert_eq!(run.code, 5, "{run:?}");
    assert!(!run.all().contains("SECRETISH"), "{run:?}");
    assert!(!capture.saw_request());
}

#[test]
fn a_token_is_never_forwarded_across_a_redirect() {
    let target = Capture::start(200, r#"{"threads":[]}"#);
    let redirect = Capture::redirect(&format!(
        "{}/v1/boards/main/channels?prefix=eng",
        target.url
    ));
    let user = CliUser::new();
    let token = fake_token();
    let run = user.run_env(
        &["--url", &redirect.url, "read", "eng"],
        &[("STIGMER_TOKEN", &token)],
    );
    assert_eq!(run.code, 1, "a redirect is not followed: {run:?}");
    let head = redirect.request();
    assert!(header(&head, "authorization").is_some(), "{head}");
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        !target.saw_request(),
        "the redirect target never sees a request"
    );
    assert!(!run.all().contains(&token));
}

#[test]
fn m0_cli_tests_pass_unchanged() {
    // The v0.1.0 local workflow against the real stigmerd: no token, names from --as, and no
    // login file is created or needed.
    let server = Stigmerd::local();
    let user = CliUser::new();
    let url = server.url.as_str();
    let posted = user.run(&[
        "--url",
        url,
        "--as",
        "agent-a",
        "post",
        "research/tls",
        "question",
    ]);
    assert_eq!(posted.code, 0, "{posted:?}");
    assert!(posted.stdout.starts_with("posted msg_"), "{posted:?}");
    assert!(posted.stdout.contains(" as agent-a"), "{posted:?}");
    let thread = posted.stdout.split_whitespace().nth(1).unwrap().to_owned();
    let replied = user.run(&["--url", url, "--as", "agent-c", "reply", &thread, "answer"]);
    assert_eq!(replied.code, 0, "{replied:?}");
    let waited = user.run(&[
        "--url",
        url,
        "wait",
        "--channel",
        "research/",
        "--timeout",
        "5s",
    ]);
    assert_eq!(waited.code, 0, "{waited:?}");
    assert!(waited.stdout.contains("<<<message "), "{waited:?}");
    let shown = user.run(&["--url", url, "thread", &thread]);
    assert_eq!(shown.code, 0, "{shown:?}");
    assert!(shown.stdout.find("question") < shown.stdout.find("answer"));
    let missing_as = user.run(&["--url", url, "post", "eng", "hi"]);
    assert_eq!(missing_as.code, 2, "{missing_as:?}");
    assert!(!user.logins_path().exists());
}
