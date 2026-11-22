//! Identity, boards and management: the CLI against the real stigmerd (local, network and TLS
//! modes) or a capture server that records what the CLI sends.

mod common;

use std::path::Path;

use std::time::Duration;

use common::{Capture, CliUser, Collected, Guard, Stigmerd};
use stigmer_core::{generate_secret, SecretKind};

/// A well-formed token no server knows.
fn fake_token() -> String {
    generate_secret(SecretKind::Token).unwrap().full
}

/// Writes a login file by hand, as `join` or `login` would have.
fn write_logins(path: &Path, entries: &[(&str, &str, &str)]) {
    let logins: Vec<serde_json::Value> = entries
        .iter()
        .map(|(url, scope, token)| {
            serde_json::json!({
                "url": url, "scope": scope, "principal": "ann", "token": token, "saved_at_ms": 1
            })
        })
        .collect();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let body = serde_json::json!({"version": 1, "logins": logins});
    std::fs::write(path, body.to_string()).unwrap();
}

/// The value of header `name` in a request head, if present.
fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

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

/// Joins `server` with `invite` as `name`, asserting success.
fn join(user: &CliUser, server: &Stigmerd, invite: &str, name: &str) -> common::Run {
    let run = user.run(&["--url", &server.url, "join", invite, "--as", name]);
    assert_eq!(run.code, 0, "{run:?}");
    run
}

fn main_invite(server: &Stigmerd) -> String {
    server
        .main_invite
        .clone()
        .expect("enable-auth printed a main invite")
}

#[test]
fn join_stores_a_0600_login_and_never_prints_the_token() {
    let server = Stigmerd::network();
    let user = CliUser::new();
    let invite = main_invite(&server);
    let run = join(&user, &server, &invite, "ann");
    let path = user.logins_path();
    let first = run.stdout.lines().next().unwrap_or_default();
    assert!(first.starts_with("joined board main as ann ("), "{run:?}");
    assert!(run.stdout.contains(&path.display().to_string()), "{run:?}");
    assert!(
        !run.all().contains("stg1_"),
        "the token is never printed: {run:?}"
    );

    let saved: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(saved["version"], 1);
    let login = &saved["logins"][0];
    assert_eq!(login["url"], server.url.as_str());
    assert_eq!(login["scope"], "board:main");
    assert_eq!(login["principal"], "ann");
    assert!(login["token"].as_str().unwrap().starts_with("stg1_"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
    }
    // The saved login is used from now on, and the JSON form never holds the token either.
    let whoami = user.run(&["--url", &server.url, "--json", "whoami"]);
    assert_eq!(whoami.code, 0, "{whoami:?}");
    assert!(!whoami.all().contains("stg1_"));
}

#[test]
fn join_without_xdg_config_home_uses_home_dot_config() {
    let server = Stigmerd::network();
    let user = CliUser::new();
    let mut cmd = user.cmd(&[
        "--url",
        &server.url,
        "join",
        &main_invite(&server),
        "--as",
        "ann",
    ]);
    cmd.env_remove("XDG_CONFIG_HOME");
    let out = cmd.output().unwrap();
    assert!(out.status.success(), "{out:?}");
    assert!(user.home().join(".config/stigmer/logins.json").is_file());
}

#[test]
fn whoami_prints_principal_board_and_role() {
    let server = Stigmerd::network();
    let user = CliUser::new();
    join(&user, &server, &main_invite(&server), "ann");
    let run = user.run(&["--url", &server.url, "whoami"]);
    assert_eq!(run.code, 0, "{run:?}");
    assert!(run.stdout.starts_with("ann ("), "{run:?}");
    assert!(run.stdout.contains("on board main as admin"), "{run:?}");
    let json = user.run(&["--url", &server.url, "--json", "whoami"]);
    let value: serde_json::Value = serde_json::from_str(&json.stdout).unwrap();
    assert_eq!(value["principal"], "ann");
    assert_eq!(value["board"], "main");
    assert_eq!(value["role"], "admin");
    assert_eq!(value["instance_admin"], false);
}

#[test]
fn unauthorized_maps_to_exit_6_with_next_hint_login() {
    let server = Stigmerd::network();
    let user = CliUser::new();
    let run = user.run_env(
        &["--url", &server.url, "whoami"],
        &[("STIGMER_TOKEN", &fake_token())],
    );
    assert_eq!(run.code, 6, "{run:?}");
    assert!(
        run.stderr
            .contains("next: run stigmer join <invite> --as <name> or stigmer login"),
        "{run:?}"
    );
    // Without any token a network-mode board refuses too, with the same hint.
    let run = user.run(&["--url", &server.url, "read", "eng"]);
    assert_eq!(run.code, 6, "{run:?}");

    let help = user.run(&["--help"]);
    for line in [
        "0  ok",
        "1  failure",
        "2  usage",
        "3  wait timed out",
        "4  not found",
        "5  invalid input",
        "6  unauthorized",
        "7  forbidden",
        "8  rate limited",
    ] {
        assert!(
            help.stdout.contains(line),
            "--help lacks {line:?}: {}",
            help.stdout
        );
    }
}

#[test]
fn rate_limited_prints_retry_after_hint() {
    let server = Stigmerd::network();
    let user = CliUser::new();
    let token = fake_token();
    let limited = (0..20)
        .map(|_| {
            user.run_env(
                &["--url", &server.url, "whoami"],
                &[("STIGMER_TOKEN", &token)],
            )
        })
        .find(|run| run.code != 6)
        .expect("failed authentications are rate limited");
    assert_eq!(limited.code, 8, "{limited:?}");
    let next = limited
        .stderr
        .lines()
        .find_map(|line| line.strip_prefix("next: wait "))
        .unwrap_or_else(|| panic!("no wait hint: {limited:?}"));
    let (secs, rest) = next.split_once(' ').unwrap();
    assert!(secs.parse::<u64>().is_ok_and(|s| s > 0), "{next}");
    assert_eq!(rest, "seconds and retry");
}

#[test]
fn login_reads_token_from_stdin_verifies_it_and_never_prints_it() {
    let server = Stigmerd::network();
    let user = CliUser::new();
    let token = server.instance_token.clone().unwrap();
    let run = user.run_stdin(&["--url", &server.url, "login"], &format!("  {token}  \n"));
    assert_eq!(run.code, 0, "{run:?}");
    assert!(!run.all().contains(&token), "{run:?}");
    assert!(!run.all().contains("stg1_"), "{run:?}");
    assert!(run.stdout.contains("instance admin"), "{run:?}");
    let saved = std::fs::read_to_string(user.logins_path()).unwrap();
    assert!(saved.contains("\"scope\": \"instance\""), "{saved}");
    assert!(saved.contains(&token));

    // An unknown token is verified with the server and not saved.
    let other = CliUser::new();
    let run = other.run_stdin(
        &["--url", &server.url, "login"],
        &format!("{}\n", fake_token()),
    );
    assert_eq!(run.code, 6, "{run:?}");
    assert!(!other.logins_path().exists());
    // Nothing on stdin is a usage error; a token is never taken as an argument.
    let run = other.run_stdin(&["--url", &server.url, "login"], "");
    assert_eq!(run.code, 2, "{run:?}");
    let run = other.run(&["--url", &server.url, "login", &token]);
    assert_eq!(run.code, 2, "{run:?}");
    assert!(!run.all().contains(&token), "{run:?}");
}

#[test]
fn join_and_login_refuse_to_touch_a_corrupt_login_file() {
    let server = Stigmerd::network();
    let user = CliUser::new();
    let path = user.logins_path();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "{not json").unwrap();
    let invite = main_invite(&server);
    let run = user.run(&["--url", &server.url, "join", &invite, "--as", "ann"]);
    assert_eq!(run.code, 1, "{run:?}");
    let token = server.instance_token.clone().unwrap();
    let run = user.run_stdin(&["--url", &server.url, "login"], &token);
    assert_eq!(run.code, 1, "{run:?}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "{not json");
    // The invite was not spent by the refused join.
    std::fs::remove_file(&path).unwrap();
    join(&user, &server, &invite, "ann");
}

/// `invite create` by `admin`, returning the invite string from its output.
fn invite(admin: &CliUser, server: &Stigmerd, args: &[&str]) -> String {
    let mut all = vec!["--url", server.url.as_str(), "invite", "create"];
    all.extend_from_slice(args);
    let run = admin.run(&all);
    assert_eq!(run.code, 0, "{run:?}");
    run.stdout
        .lines()
        .find_map(|line| line.strip_prefix("invite: "))
        .unwrap_or_else(|| panic!("no invite line: {run:?}"))
        .to_owned()
}

/// A user logged in with the instance-admin token.
fn instance_admin(server: &Stigmerd) -> CliUser {
    let user = CliUser::new();
    let token = server.instance_token.clone().unwrap();
    let run = user.run_stdin(&["--url", &server.url, "login", "--instance"], &token);
    assert_eq!(run.code, 0, "{run:?}");
    user
}

/// The token saved in `user`'s login file for `scope`.
fn saved_token(user: &CliUser, scope: &str) -> String {
    let saved: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(user.logins_path()).unwrap()).unwrap();
    saved["logins"]
        .as_array()
        .unwrap()
        .iter()
        .find(|login| login["scope"] == scope)
        .and_then(|login| login["token"].as_str())
        .unwrap()
        .to_owned()
}

#[test]
fn boards_create_list_archive_roundtrip_as_instance_admin() {
    let server = Stigmerd::network();
    let root = instance_admin(&server);
    let url = server.url.as_str();
    let run = root.run(&["--url", url, "boards", "create", "ops"]);
    assert_eq!(run.code, 0, "{run:?}");
    assert_eq!(run.stdout, "created board ops\n");
    let list = root.run(&["--url", url, "boards", "list"]);
    assert_eq!(list.code, 0, "{list:?}");
    let line = |out: &str, board: &str| {
        out.lines()
            .find(|l| l.starts_with(&format!("{board}  ")))
            .unwrap_or_else(|| panic!("no {board} line in {out}"))
            .to_owned()
    };
    assert!(
        line(&list.stdout, "main").contains("  active  "),
        "{list:?}"
    );
    assert!(line(&list.stdout, "ops").contains("  active  "), "{list:?}");
    let run = root.run(&["--url", url, "boards", "archive", "ops"]);
    assert_eq!(
        (run.code, run.stdout.as_str()),
        (0, "archived board ops\n"),
        "{run:?}"
    );
    let list = root.run(&["--url", url, "--json", "boards", "list"]);
    let value: serde_json::Value = serde_json::from_str(&list.stdout).unwrap();
    let ops = value["boards"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["id"] == "ops")
        .unwrap()
        .clone();
    assert_eq!(ops["archived"], true);
    let bad = root.run(&["--url", url, "boards", "create", "Not Valid"]);
    assert_eq!(bad.code, 5, "{bad:?}");
}

#[test]
fn instance_login_enables_boards_create_without_a_board_login() {
    let server = Stigmerd::network();
    let root = instance_admin(&server);
    let url = server.url.as_str();
    let run = root.run(&["--url", url, "boards", "create", "team"]);
    assert_eq!(run.code, 0, "{run:?}");
    // With no login for board team, management routes fall back to the instance login.
    let code = invite(&root, &server, &["--kind", "human", "--role", "admin"]);
    assert!(code.starts_with("stgi1_"));
    let team_invite = {
        let run = root.run(&[
            "--url", url, "--board", "team", "invite", "create", "--kind", "agent", "--role",
            "member",
        ]);
        assert_eq!(run.code, 0, "{run:?}");
        run.stdout
            .lines()
            .next()
            .unwrap()
            .strip_prefix("invite: ")
            .unwrap()
            .to_owned()
    };
    let bot = CliUser::new();
    let run = bot.run(&["--url", url, "join", &team_invite, "--as", "bot"]);
    assert_eq!(run.code, 0, "{run:?}");
    assert!(
        run.stdout.starts_with("joined board team as bot (member)"),
        "{run:?}"
    );
    let run = bot.run(&["--url", url, "--board", "team", "post", "eng", "hello"]);
    assert_eq!(run.code, 0, "{run:?}");
    assert!(run.stdout.contains(" as bot"), "{run:?}");
}

#[test]
fn invite_create_prints_once_and_join_consumes_it() {
    let server = Stigmerd::network();
    let ann = CliUser::new();
    join(&ann, &server, &main_invite(&server), "ann");
    let url = server.url.as_str();
    let run = ann.run(&[
        "--url",
        url,
        "invite",
        "create",
        "--kind",
        "agent",
        "--role",
        "member",
        "--expires",
        "2h",
    ]);
    assert_eq!(run.code, 0, "{run:?}");
    let lines: Vec<&str> = run.stdout.lines().collect();
    assert_eq!(lines.len(), 2, "{run:?}");
    let code = lines[0].strip_prefix("invite: ").unwrap();
    assert!(code.starts_with("stgi1_"), "{run:?}");
    assert!(lines[1].starts_with("expires: "), "{run:?}");
    assert_eq!(run.all().matches(code).count(), 1, "printed exactly once");

    let json = ann.run(&[
        "--url", url, "--json", "invite", "create", "--kind", "human", "--role", "admin",
    ]);
    let value: serde_json::Value = serde_json::from_str(&json.stdout).unwrap();
    assert!(value["invite"].as_str().unwrap().starts_with("stgi1_"));
    assert!(value["expires_at_ms"].as_i64().is_some());

    let bob = CliUser::new();
    join(&bob, &server, code, "bob");
    let again = CliUser::new();
    let run = again.run(&["--url", url, "join", code, "--as", "bob2"]);
    assert_eq!(run.code, 6, "a used invite is refused: {run:?}");
    for bad in [
        &["--expires", "0m"][..],
        &["--expires", "5x"],
        &["--kind", "robot"],
    ] {
        let mut args = vec![
            "--url", url, "invite", "create", "--kind", "agent", "--role", "member",
        ];
        args.extend_from_slice(bad);
        let run = ann.run(&args);
        assert_eq!(run.code, 2, "{bad:?}: {run:?}");
    }
}

#[test]
fn join_taken_name_prints_the_409_hint_and_keeps_the_invite_usable() {
    let server = Stigmerd::network();
    let ann = CliUser::new();
    join(&ann, &server, &main_invite(&server), "ann");
    let code = invite(&ann, &server, &["--kind", "agent", "--role", "member"]);
    let bob = CliUser::new();
    let run = bob.run(&["--url", &server.url, "join", &code, "--as", "ann"]);
    assert_eq!(run.code, 1, "{run:?}");
    assert!(
        run.stderr
            .contains("next: choose another --as name; the invite is still valid"),
        "{run:?}"
    );
    assert!(!bob.logins_path().exists());
    join(&bob, &server, &code, "bob");
}

#[test]
fn member_remove_and_token_revoke_take_effect() {
    let server = Stigmerd::network();
    let url = server.url.as_str();
    let ann = CliUser::new();
    join(&ann, &server, &main_invite(&server), "ann");
    let bob = CliUser::new();
    join(
        &bob,
        &server,
        &invite(&ann, &server, &["--kind", "agent", "--role", "member"]),
        "bob",
    );
    let carol = CliUser::new();
    join(
        &carol,
        &server,
        &invite(&ann, &server, &["--kind", "agent", "--role", "member"]),
        "carol",
    );
    assert_eq!(bob.run(&["--url", url, "whoami"]).code, 0);

    let tokens = ann.run(&["--url", url, "token", "list"]);
    assert_eq!(tokens.code, 0, "{tokens:?}");
    let bob_line = tokens
        .stdout
        .lines()
        .find(|line| line.split_whitespace().nth(1) == Some("bob"))
        .unwrap_or_else(|| panic!("no token of bob: {tokens:?}"));
    assert!(bob_line.contains("active"), "{bob_line}");
    let bob_id = bob_line.split_whitespace().next().unwrap();
    let run = ann.run(&["--url", url, "token", "revoke", bob_id]);
    assert_eq!(run.code, 0, "{run:?}");
    assert_eq!(run.stdout, format!("revoked token {bob_id}\n"));
    assert_eq!(bob.run(&["--url", url, "whoami"]).code, 6);
    let tokens = ann.run(&["--url", url, "--json", "token", "list"]);
    let value: serde_json::Value = serde_json::from_str(&tokens.stdout).unwrap();
    let revoked = value["tokens"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["id"] == bob_id)
        .unwrap()
        .clone();
    assert_eq!(revoked["revoked"], true);
    assert!(
        !tokens.all().contains("stg1_"),
        "listings never hold secrets"
    );

    let members = ann.run(&["--url", url, "members", "list"]);
    assert!(
        members
            .stdout
            .lines()
            .any(|l| l.starts_with("carol  agent  member")),
        "{members:?}"
    );
    let run = ann.run(&["--url", url, "members", "remove", "carol"]);
    assert_eq!(
        (run.code, run.stdout.as_str()),
        (0, "removed carol from board main\n"),
        "{run:?}"
    );
    assert_eq!(carol.run(&["--url", url, "whoami"]).code, 6);
    let members = ann.run(&["--url", url, "members", "list"]);
    assert!(!members.stdout.contains("carol"), "{members:?}");
    let bad = ann.run(&["--url", url, "token", "revoke", "not-an-id"]);
    assert_eq!(bad.code, 5, "{bad:?}");
}

#[test]
fn forbidden_and_not_found_have_distinct_exit_codes_and_hints() {
    let server = Stigmerd::network();
    let url = server.url.as_str();
    let ann = CliUser::new();
    join(&ann, &server, &main_invite(&server), "ann");
    let bob = CliUser::new();
    join(
        &bob,
        &server,
        &invite(&ann, &server, &["--kind", "agent", "--role", "member"]),
        "bob",
    );
    let forbidden = bob.run(&[
        "--url", url, "invite", "create", "--kind", "agent", "--role", "admin",
    ]);
    assert_eq!(forbidden.code, 7, "{forbidden:?}");
    assert!(
        forbidden
            .stderr
            .contains("next: your role cannot do this; ask a board admin"),
        "{forbidden:?}"
    );
    // A main token used against another board: not found, with a different hint.
    let token = saved_token(&bob, "board:main");
    let missing = bob.run_env(
        &["--url", url, "--board", "elsewhere", "read", "eng"],
        &[("STIGMER_TOKEN", &token)],
    );
    assert_eq!(missing.code, 4, "{missing:?}");
    assert!(
        missing.stderr.contains("next: check the id and --board"),
        "{missing:?}"
    );
}

#[test]
fn ca_cert_flag_trusts_a_private_ca() {
    let (server, files, _pems) = Stigmerd::tls();
    assert!(server.url.starts_with("https://"), "{}", server.url);
    let url = server.url.as_str();
    let ca = files.ca.display().to_string();
    let user = CliUser::new();
    let token = server.instance_token.clone().unwrap();

    // The private CA is not trusted by default: the handshake fails and nothing is saved.
    let refused = user.run_stdin(&["--url", url, "login", "--instance"], &token);
    assert_eq!(refused.code, 1, "{refused:?}");
    assert!(!refused.all().contains(&token));
    assert!(!user.logins_path().exists());

    let run = user.run_stdin(
        &["--url", url, "--ca-cert", &ca, "login", "--instance"],
        &token,
    );
    assert_eq!(run.code, 0, "{run:?}");
    let run = user.run_env(&["--url", url, "whoami"], &[("STIGMER_CA_CERT", &ca)]);
    assert_eq!(run.code, 0, "{run:?}");
    assert!(run.stdout.contains("instance admin"), "{run:?}");

    // Joining over https with the CA works end to end.
    let ann = CliUser::new();
    let invite = main_invite(&server);
    let run = ann.run(&[
        "--url",
        url,
        "--ca-cert",
        &ca,
        "join",
        &invite,
        "--as",
        "ann",
    ]);
    assert_eq!(run.code, 0, "{run:?}");
    let run = ann.run(&["--url", url, "--ca-cert", &ca, "post", "eng", "over tls"]);
    assert_eq!(run.code, 0, "{run:?}");
}

#[test]
fn unreadable_or_empty_ca_cert_is_a_usage_error() {
    let user = CliUser::new();
    let missing = user.home().join("missing.pem");
    let empty = user.home().join("empty.pem");
    std::fs::write(&empty, "").unwrap();
    let not_pem = user.home().join("junk.pem");
    std::fs::write(&not_pem, "hello").unwrap();
    for path in [&missing, &empty, &not_pem] {
        let path = path.display().to_string();
        let run = user.run(&["--url", "https://127.0.0.1:9", "--ca-cert", &path, "whoami"]);
        assert_eq!(run.code, 2, "{path}: {run:?}");
        assert!(run.stderr.contains("CA certificate"), "{run:?}");
        assert!(run.stderr.contains("next: "), "{run:?}");
    }
}

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
