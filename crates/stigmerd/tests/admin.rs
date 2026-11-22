//! End-to-end tests of the `stigmerd admin` subcommands, run against the real binary.

mod common;

use std::future::Future;
use std::path::Path;
use std::process::{Command, Output};

use stigmer_core::{
    hash_secret, parse_secret, secrets_match, BoardId, MessageId, Principal, PrincipalKind, Role,
    SecretKind,
};
use stigmer_store::{CredentialScope, IdentityStore, Mode, SecurityEventKind, Store};
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
    let err = stderr(&out);
    assert!(err.contains("already in network mode"), "stderr: {err}");
    assert!(
        err.contains("if you have no instance token, run stigmerd admin new-instance-token"),
        "stderr: {err}"
    );
    assert!(out.stdout.is_empty(), "stdout: {}", stdout(&out));
    assert!(!stderr(&out).contains("stg1_") && !stderr(&out).contains("stgi1_"));
}

/// The failure is injected by archiving board main before enable-auth, so minting the main
/// admin invite is refused by the store (step b), before the mode switch (step c).
#[test]
fn enable_auth_failure_before_the_mode_switch_leaves_local_mode_and_a_retry_succeeds() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    with_store(&data_dir_ready(&data), |store| async move {
        store
            .archive_board(&BoardId::main())
            .await
            .expect("archive main");
    });

    let failed = admin(&data, &["enable-auth"]);
    assert_eq!(failed.status.code(), Some(1), "stderr: {}", stderr(&failed));
    assert!(
        failed.stdout.is_empty(),
        "no secret may be shown: {}",
        stdout(&failed)
    );
    with_store(&data, |store| async move {
        assert_eq!(
            store.mode().await,
            Ok(Mode::Local),
            "must stay in local mode"
        );
        assert_eq!(
            store.security_log(10).await,
            Ok(vec![]),
            "nothing may be logged"
        );
    });

    let retry = admin(&data, &["enable-auth", "--no-main-invite"]);
    assert_eq!(retry.status.code(), Some(0), "stderr: {}", stderr(&retry));
    assert!(stdout(&retry).starts_with("instance token: stg1_"));
    with_store(&data, |store| async move {
        assert_eq!(store.mode().await, Ok(Mode::Network));
    });
}

#[cfg(unix)]
#[test]
fn existing_database_files_are_tightened_to_0600() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    std::fs::create_dir_all(&data).expect("data dir");
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).expect("chmod dir");
    let names = ["stigmer.db", "stigmer.db-wal", "stigmer.db-shm"];
    for name in names {
        let path = data.join(name);
        std::fs::write(&path, b"").expect("pre-create");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
    }

    let out = admin(&data, &["security-log"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    for name in names {
        let path = data.join(name);
        assert!(
            stderr(&out).contains(&format!("tightened permissions on {}", path.display())),
            "no notice for {name}: {}",
            stderr(&out)
        );
        // SQLite may delete -wal and -shm on a clean close; any that remain must be private.
        if let Ok(meta) = std::fs::metadata(&path) {
            assert_eq!(meta.permissions().mode() & 0o777, 0o600, "{name}");
        }
    }
    let db_mode = std::fs::metadata(data.join("stigmer.db"))
        .expect("db")
        .permissions()
        .mode();
    assert_eq!(db_mode & 0o777, 0o600);
}

/// Creates the data dir with a database, as a first admin or serve run would.
fn data_dir_ready(data: &Path) -> std::path::PathBuf {
    std::fs::create_dir_all(data).expect("create data dir");
    data.to_owned()
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

    // Raw database bytes: no plaintext secret, and the scan really sees stored data.
    let mut raw = std::fs::read(data.join("stigmer.db")).expect("read db");
    if let Ok(wal) = std::fs::read(data.join("stigmer.db-wal")) {
        raw.extend(wal);
    }
    for (secret, part) in secrets.iter().zip(&secret_parts) {
        assert!(
            !contains_bytes(&raw, part.as_bytes()),
            "database holds a plaintext secret"
        );
        assert!(
            !contains_bytes(&raw, secret.as_bytes()),
            "database holds a full token"
        );
    }
    let (id, secret) = parse_secret(SecretKind::Token, &secrets[0]).expect("token shape");
    let hash = hash_secret(&secret);
    assert_ne!(
        hash.as_slice(),
        secret.as_bytes(),
        "the stored hash is not the plaintext"
    );
    assert!(
        contains_bytes(&raw, &hash),
        "scan control: the hash of token {id} must be in the database bytes"
    );
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
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

// ---- security-log ----

#[test]
fn security_log_prints_newest_first() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    assert_eq!(admin(&data, &["enable-auth"]).status.code(), Some(0));
    assert_eq!(admin(&data, &["new-instance-token"]).status.code(), Some(0));

    let out = admin(&data, &["security-log"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    let kinds: Vec<&str> = text
        .lines()
        .map(|l| l.split('\t').nth(1).expect("kind column"))
        .collect();
    assert_eq!(
        kinds,
        [
            "instance_token_issued",
            "invite_created",
            "instance_token_issued",
            "mode_enabled"
        ],
        "stdout: {text}"
    );
    // time, kind, board, principal, detail
    let invite_line = text.lines().nth(1).expect("invite line");
    let cols: Vec<&str> = invite_line.split('\t').collect();
    assert_eq!(cols.len(), 5, "{invite_line}");
    assert_eq!((cols[2], cols[3]), ("main", "instance-admin"));
    assert!(
        cols[0].ends_with('Z') && cols[0].starts_with("20"),
        "time {}",
        cols[0]
    );

    let limited = admin(&data, &["security-log", "--limit", "2"]);
    assert_eq!(stdout(&limited).lines().count(), 2);
}

#[test]
fn security_log_lists_mode_enabled_event() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    assert_eq!(
        admin(&data, &["enable-auth", "--no-main-invite"])
            .status
            .code(),
        Some(0)
    );
    let text = stdout(&admin(&data, &["security-log"]));
    assert_eq!(text.lines().count(), 2, "{text}");
    assert!(text.lines().last().expect("line").contains("mode_enabled"));
}

#[test]
fn security_log_rejects_out_of_range_limit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    for limit in ["0", "1001"] {
        let out = admin(&data, &["security-log", "--limit", limit]);
        assert_eq!(out.status.code(), Some(2), "limit {limit}");
    }
}

// ---- map-local-principals ----

/// Runs an M0 (local mode) server, posts one thread per (author, text) and stops it.
/// Returns the thread ids in post order.
#[cfg(unix)]
fn seed_local_board(data: &Path, posts: &[(&str, &str)]) -> Vec<String> {
    let mut server = common::start(data);
    let ids = posts
        .iter()
        .map(|(author, text)| {
            let (status, body) = common::http(
                &server.addr,
                "POST",
                "/v1/boards/main/messages",
                &[
                    ("X-Stigmer-As", author),
                    ("Content-Type", "application/json"),
                ],
                &format!(r#"{{"channel":"eng","text":"{text}"}}"#),
            );
            assert_eq!(status, 201, "body: {body}");
            body.split("\"id\":\"")
                .nth(1)
                .and_then(|s| s.split('"').next())
                .expect("message id")
                .to_owned()
        })
        .collect();
    common::sigterm(&server);
    assert_eq!(
        common::wait_for_exit(&mut server, std::time::Duration::from_secs(5)),
        Some(0)
    );
    ids
}

const POSTS: [(&str, &str); 4] = [
    ("alice", "one"),
    ("alice", "two"),
    ("bob", "three"),
    ("carol", "four"),
];

#[cfg(unix)]
#[test]
fn map_local_principals_refused_in_local_mode() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    seed_local_board(&data, &POSTS);
    let out = admin(&data, &["map-local-principals", "--admin", "alice"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("requires network mode; run stigmerd admin enable-auth first"));
    assert!(out.stdout.is_empty());
}

#[cfg(unix)]
#[test]
fn map_local_principals_dry_run_changes_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    seed_local_board(&data, &POSTS);
    assert_eq!(
        admin(&data, &["enable-auth", "--no-main-invite"])
            .status
            .code(),
        Some(0)
    );

    let out = admin(
        &data,
        &[
            "map-local-principals",
            "--human",
            "alice",
            "--admin",
            "alice",
        ],
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    let rows: Vec<Vec<String>> = stdout(&out)
        .lines()
        .map(|l| l.split_whitespace().map(str::to_owned).collect())
        .collect();
    assert_eq!(rows[0], ["NAME", "KIND", "ROLE"]);
    assert_eq!(rows[1], ["alice", "human", "admin"]);
    assert_eq!(rows[2], ["bob", "agent", "member"]);
    assert_eq!(rows[3], ["carol", "agent", "member"]);
    assert!(
        stdout(&out).contains("--apply"),
        "dry run must say how to apply"
    );

    with_store(&data, |store| async move {
        let main = BoardId::main();
        assert_eq!(store.list_members(&main).await.expect("members"), []);
        assert_eq!(
            store
                .list_local_authors(&main)
                .await
                .expect("authors")
                .len(),
            3
        );
    });
}

#[cfg(unix)]
#[test]
fn map_local_principals_requires_an_admin() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    seed_local_board(&data, &POSTS);
    assert_eq!(
        admin(&data, &["enable-auth", "--no-main-invite"])
            .status
            .code(),
        Some(0)
    );
    let out = admin(&data, &["map-local-principals", "--human", "bob"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("--admin"), "stderr: {}", stderr(&out));
}

#[cfg(unix)]
#[test]
fn map_local_principals_unknown_name_is_exit_2() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    seed_local_board(&data, &POSTS);
    assert_eq!(
        admin(&data, &["enable-auth", "--no-main-invite"])
            .status
            .code(),
        Some(0)
    );
    for args in [
        ["map-local-principals", "--admin", "zed"],
        ["map-local-principals", "--human", "zed"],
    ] {
        let out = admin(&data, &args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(stderr(&out).contains("zed"), "stderr: {}", stderr(&out));
    }
}

#[test]
fn map_local_principals_nothing_to_map_exits_0() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    assert_eq!(
        admin(&data, &["enable-auth", "--no-main-invite"])
            .status
            .code(),
        Some(0)
    );
    let out = admin(&data, &["map-local-principals"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out).trim(), "nothing to map");
}

#[cfg(unix)]
#[test]
fn map_local_principals_apply_keeps_verify_chain_valid_and_content_readable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    let ids = seed_local_board(&data, &POSTS);
    assert_eq!(
        admin(&data, &["enable-auth", "--no-main-invite"])
            .status
            .code(),
        Some(0)
    );

    let out = admin(
        &data,
        &[
            "map-local-principals",
            "--human",
            "alice",
            "--admin",
            "alice",
            "--admin",
            "carol",
            "--apply",
        ],
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    assert!(
        stdout(&out).contains("adopted 3 authors and 4 messages"),
        "stdout: {}",
        stdout(&out)
    );

    with_store(&data, |store| async move {
        let main = BoardId::main();
        let member = |name: &str| {
            let name = Principal::new(name).expect("name");
            let store = &store;
            let main = main.clone();
            async move {
                store
                    .get_member(&main, &name)
                    .await
                    .expect("get")
                    .expect("member")
            }
        };
        let (alice, bob, carol) = (
            member("alice").await,
            member("bob").await,
            member("carol").await,
        );
        assert_eq!(
            (alice.kind, alice.role),
            (PrincipalKind::Human, Role::Admin)
        );
        assert_eq!((bob.kind, bob.role), (PrincipalKind::Agent, Role::Member));
        assert_eq!(
            (carol.kind, carol.role),
            (PrincipalKind::Agent, Role::Admin)
        );
        assert_eq!(store.list_local_authors(&main).await, Ok(vec![]));

        let report = store.verify_chain(&main).await.expect("verify");
        assert!(report.valid && report.checked == 4, "{report:?}");
        let thread = store
            .read_thread(&main, &MessageId::new(&ids[2]).expect("id"))
            .await
            .expect("thread");
        assert_eq!(
            (thread.root.author.as_str(), thread.root.text.as_str()),
            ("bob", "three")
        );
    });
}

// ---- lock ----

#[cfg(unix)]
#[test]
fn admin_commands_fail_while_serve_holds_the_lock() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    let _server = common::start(&data);
    for args in [
        &["enable-auth"][..],
        &["new-instance-token"],
        &["map-local-principals", "--admin", "alice"],
        &["security-log"],
    ] {
        let out = admin(&data, args);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        assert!(
            stderr(&out)
                .contains("data directory is in use by another stigmerd process; stop it first"),
            "{args:?}: {}",
            stderr(&out)
        );
        assert!(out.stdout.is_empty());
    }
}
