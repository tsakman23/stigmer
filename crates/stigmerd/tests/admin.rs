//! End-to-end tests of the `stigmerd admin` subcommands, run against the real binary.

mod common;

use std::future::Future;
use std::path::Path;
use std::process::{Command, Output};

use stigmer_core::{parse_secret, secrets_match, SecretKind};
use stigmer_store::{CredentialScope, IdentityStore, Mode, SecurityEventKind};
use stigmer_store_sqlite::SqliteStore;

const DAY_MS: i64 = 86_400_000;

fn admin(data: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_stigmerd"))
        .arg("admin")
        .args(args)
        .arg("--data-dir")
        .arg(data)
        .output()
        .expect("run stigmerd admin")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Runs `f` on a store opened directly on the data dir (no server may be running).
fn with_store<F, Fut, T>(data: &Path, f: F) -> T
where
    F: FnOnce(SqliteStore) -> Fut,
    Fut: Future<Output = T>,
{
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(async {
        let store = SqliteStore::open(&data.join("stigmer.db"))
            .await
            .expect("open store");
        f(store).await
    })
}

fn now_ms() -> i64 {
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch");
    i64::try_from(since.as_millis()).expect("fits i64")
}

/// The secret after the label on the line that starts with `label`.
fn labelled<'a>(text: &'a str, label: &str) -> &'a str {
    text.lines()
        .find_map(|l| l.strip_prefix(label))
        .unwrap_or_else(|| panic!("no line starting {label:?} in {text:?}"))
}

#[test]
fn enable_auth_prints_instance_token_once_and_a_main_admin_invite() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    let out = admin(&data, &["enable-auth"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));

    let text = stdout(&out);
    assert_eq!(text.lines().count(), 2, "stdout: {text:?}");
    let token = labelled(&text, "instance token: ").to_owned();
    let invite = labelled(&text, "main admin invite: ").to_owned();
    assert!(token.starts_with("stg1_") && invite.starts_with("stgi1_"));
    assert!(
        stderr(&out).contains("shown once"),
        "stderr: {}",
        stderr(&out)
    );
    for secret in [&token, &invite] {
        assert!(!stderr(&out).contains(secret.as_str()));
    }

    let (id, secret) = parse_secret(SecretKind::Token, &token).expect("token shape");
    let before = now_ms();
    with_store(&data, |store| async move {
        assert_eq!(store.mode().await, Ok(Mode::Network));
        let cred = store
            .find_credential(&id)
            .await
            .expect("find")
            .expect("instance credential stored");
        assert_eq!(cred.scope, CredentialScope::Instance);
        assert_eq!(cred.principal.as_str(), "instance-admin");
        assert!(secrets_match(&secret, &cred.secret_hash));
        let ttl = cred.expires_at_ms - before;
        assert!(
            (89 * DAY_MS..=91 * DAY_MS).contains(&ttl),
            "expires in {ttl} ms"
        );
    });
}

#[test]
fn enable_auth_twice_refuses_and_prints_no_token() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    assert_eq!(admin(&data, &["enable-auth"]).status.code(), Some(0));
    let out = admin(&data, &["enable-auth"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("already in network mode"));
    assert!(out.stdout.is_empty(), "stdout: {}", stdout(&out));
    assert!(!stderr(&out).contains("stg1_") && !stderr(&out).contains("stgi1_"));
}

#[test]
fn enable_auth_no_main_invite_omits_the_invite() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = admin(
        &dir.path().join("data"),
        &["enable-auth", "--no-main-invite"],
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert_eq!(text.lines().count(), 1, "stdout: {text:?}");
    assert!(text.starts_with("instance token: stg1_"));
    assert!(!text.contains("invite"));
}

#[test]
fn secrets_never_reach_stderr_or_the_security_log() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    let out = admin(&data, &["enable-auth"]);
    let text = stdout(&out);
    let token = labelled(&text, "instance token: ").to_owned();
    let invite = labelled(&text, "main admin invite: ").to_owned();
    let replacement = admin(&data, &["new-instance-token"]);
    let replacement_token = labelled(&stdout(&replacement), "instance token: ").to_owned();

    let secrets = [token, invite, replacement_token];
    let secret_parts: Vec<String> = secrets
        .iter()
        .map(|s| s.rsplit('_').next().expect("secret part").to_owned())
        .collect();
    let log = with_store(&data, |store| async move {
        format!("{:?}", store.security_log(100).await.expect("log"))
    });
    for part in &secret_parts {
        assert!(!log.contains(part.as_str()), "security log leaks a secret");
        assert!(!stderr(&out).contains(part.as_str()));
        assert!(!stderr(&replacement).contains(part.as_str()));
    }
}

#[test]
fn new_instance_token_requires_network_mode_and_prints_once() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    let refused = admin(&data, &["new-instance-token"]);
    assert_eq!(refused.status.code(), Some(1));
    assert!(stderr(&refused).contains("requires network mode"));
    assert!(refused.stdout.is_empty());

    let first = stdout(&admin(&data, &["enable-auth", "--no-main-invite"]));
    let first_token = labelled(&first, "instance token: ");

    let out = admin(&data, &["new-instance-token", "--expires-days", "30"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert_eq!(text.lines().count(), 1, "stdout: {text:?}");
    let token = labelled(&text, "instance token: ");
    assert!(token.starts_with("stg1_") && token != first_token);
    assert!(stderr(&out).contains("shown once"));
    assert!(!stderr(&out).contains(token));

    let (id, secret) = parse_secret(SecretKind::Token, token).expect("token shape");
    let before = now_ms();
    with_store(&data, |store| async move {
        let cred = store
            .find_credential(&id)
            .await
            .expect("find")
            .expect("stored");
        assert_eq!(cred.scope, CredentialScope::Instance);
        assert_eq!(cred.principal.as_str(), "instance-admin");
        assert!(secrets_match(&secret, &cred.secret_hash));
        let ttl = cred.expires_at_ms - before;
        assert!((29 * DAY_MS..=31 * DAY_MS).contains(&ttl), "ttl {ttl}");
        let log = store.security_log(10).await.expect("log");
        assert_eq!(log[0].kind, SecurityEventKind::InstanceTokenIssued);
        assert_eq!(log[0].principal.as_deref(), Some("instance-admin"));
    });
}

#[test]
fn new_instance_token_rejects_out_of_range_expiry() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    for days in ["0", "366"] {
        let out = admin(&data, &["new-instance-token", "--expires-days", days]);
        assert_eq!(out.status.code(), Some(2), "days {days}");
    }
}
