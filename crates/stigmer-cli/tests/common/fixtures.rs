//! Fixtures shared by the identity test files: fake tokens, hand-written login files, and the
//! join, invite and login steps most tests start with.

use std::path::Path;
use std::time::Duration;

use stigmer_core::{generate_secret, SecretKind};

use super::{finish, CliUser, Guard, Run, Stigmerd};

/// A well-formed token no server knows.
pub fn fake_token() -> String {
    generate_secret(SecretKind::Token).unwrap().full
}

/// Writes a login file by hand, as `join` or `login` would have.
pub fn write_logins(path: &Path, entries: &[(&str, &str, &str)]) {
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
pub fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

/// Joins `server` with `invite` as `name`, asserting success.
pub fn join(user: &CliUser, server: &Stigmerd, invite: &str, name: &str) -> Run {
    let run = user.run(&["--url", &server.url, "join", invite, "--as", name]);
    assert_eq!(run.code, 0, "{run:?}");
    run
}

pub fn main_invite(server: &Stigmerd) -> String {
    server
        .main_invite
        .clone()
        .expect("enable-auth printed a main invite")
}

/// `invite create` by `admin`, returning the invite string from its output.
pub fn invite(admin: &CliUser, server: &Stigmerd, args: &[&str]) -> String {
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
pub fn instance_admin(server: &Stigmerd) -> CliUser {
    let user = CliUser::new();
    let token = server.instance_token.clone().unwrap();
    let run = user.run_stdin(&["--url", &server.url, "login", "--instance"], &token);
    assert_eq!(run.code, 0, "{run:?}");
    user
}

/// The token saved in `user`'s login file for `scope`.
pub fn saved_token(user: &CliUser, scope: &str) -> String {
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

/// A loopback URL on which nothing listens.
pub fn dead_url() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    format!("http://{addr}")
}

/// Runs `tail` with a long timeout and returns how it ended, failing after `within`.
pub fn tail_until_exit(user: &CliUser, args: &[&str], within: Duration) -> (Run, Duration) {
    let started = std::time::Instant::now();
    let mut all = args.to_vec();
    all.extend_from_slice(&["tail", "--timeout", "60s"]);
    let run = finish(Guard::spawn(&mut user.cmd(&all)), within);
    (run, started.elapsed())
}
