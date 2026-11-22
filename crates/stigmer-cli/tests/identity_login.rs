//! join, login and whoami against the real stigmerd in network mode, and the auth exit codes.

mod common;

use std::path::Path;

use common::fixtures::{fake_token, invite, join, main_invite};
use common::{CliUser, Stigmerd};

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
