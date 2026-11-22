//! Board, member, invite and token management against the real stigmerd in network mode.

mod common;

use common::fixtures::{instance_admin, invite, join, main_invite, saved_token};
use common::{CliUser, Stigmerd};

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
fn creating_an_existing_board_says_to_choose_another_name() {
    let server = Stigmerd::network();
    let root = instance_admin(&server);
    let run = root.run(&["--url", &server.url, "boards", "create", "main"]);
    assert_eq!(run.code, 1, "{run:?}");
    assert!(
        run.stderr
            .contains("next: a board with that name already exists; choose another name"),
        "{run:?}"
    );
    assert!(!run.stderr.contains("--key"), "{run:?}");
}
