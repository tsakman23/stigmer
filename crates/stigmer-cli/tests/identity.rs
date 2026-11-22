//! Identity, boards and management: the CLI against the real stigmerd (local, network and TLS
//! modes) or a capture server that records what the CLI sends.

mod common;

use common::{Capture, CliUser};

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
