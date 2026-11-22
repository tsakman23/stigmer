//! End-to-end tests of the `stigmerd admin` subcommands, run against the real binary.

mod common;

use std::future::Future;
use std::path::Path;
use std::process::{Command, Output};

use stigmer_core::{
    generate_secret, hash_secret, parse_secret, secrets_match, BoardId, MessageId, Principal,
    PrincipalKind, Role, SecretKind,
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

/// The failure is injected with a trigger that refuses every invite insert, so minting the main
/// admin invite fails in the store (step b), before the mode switch (step c).
#[test]
fn enable_auth_failure_before_the_mode_switch_leaves_local_mode_and_a_retry_succeeds() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    with_store(&data_dir_ready(&data), |_store| async move {});
    let db = rusqlite::Connection::open(data.join("stigmer.db")).expect("open db");
    db.execute_batch(
        "CREATE TRIGGER refuse_invites BEFORE INSERT ON invites
         BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
    )
    .expect("create trigger");
    drop(db);

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

    let secret_parts = [
        secret_half(SecretKind::Token, &token),
        secret_half(SecretKind::Invite, &invite),
        secret_half(SecretKind::Token, &replacement_token),
    ];
    let secrets = [token, invite, replacement_token];
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

/// The 43-character secret half of a printed token or invite. Splitting on `_` would be wrong:
/// base64url secrets can contain `_`, which could leave a 1 or 2 character needle that matches
/// database bytes by chance.
fn secret_half(kind: SecretKind, full: &str) -> String {
    let (_, secret) = parse_secret(kind, full).expect("a printed secret parses");
    assert_eq!(secret.len(), 43, "secret half of the right length");
    secret
}

#[test]
fn secret_half_keeps_underscores_in_the_secret() {
    for kind in [SecretKind::Token, SecretKind::Invite] {
        let generated = (0..1_000)
            .map(|_| generate_secret(kind).expect("secret"))
            .find(|s| {
                s.full
                    .rsplit_once('_')
                    .is_some_and(|(_, tail)| tail.len() < 43)
            })
            .expect("a secret containing '_' within 1000 tries");
        let secret = secret_half(kind, &generated.full);
        assert_eq!(secret.len(), 43);
        assert!(secret.contains('_'), "{kind:?}");
        assert!(generated.full.ends_with(&format!("_{secret}")));
        assert_eq!(hash_secret(&secret), generated.hash);
    }
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

// ---- revoke-token and --revoke-others ----

/// The public id (`stg1_<id>_...`) of a full token.
fn token_id_of(token: &str) -> String {
    let (id, _) = parse_secret(SecretKind::Token, token).expect("token shape");
    id.as_str().to_owned()
}

fn whoami_status(server: &common::Server, token: &str) -> u16 {
    let bearer = format!("Bearer {token}");
    common::http(
        &server.addr,
        "GET",
        "/v1/whoami",
        &[("Authorization", &bearer)],
        "",
    )
    .0
}

#[test]
fn revoke_token_revokes_an_instance_token_and_the_next_request_is_401() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    let first = stdout(&admin(&data, &["enable-auth", "--no-main-invite"]));
    let old = labelled(&first, "instance token: ").to_owned();
    let second = stdout(&admin(&data, &["new-instance-token"]));
    let kept = labelled(&second, "instance token: ").to_owned();
    let id = token_id_of(&old);

    let out = admin(&data, &["revoke-token", &id]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), format!("revoked {id}\n"));
    with_store(&data, |store| async move {
        let log = store.security_log(1).await.expect("log");
        assert_eq!(log[0].kind, SecurityEventKind::TokenRevoked);
        assert_eq!(log[0].principal.as_deref(), Some("instance-admin"));
        assert!(log[0].detail.contains(&id), "{:?}", log[0]);
    });

    let server = common::start(&data);
    assert_eq!(whoami_status(&server, &old), 401);
    assert_eq!(whoami_status(&server, &kept), 200);
}

#[test]
fn revoke_token_revokes_a_board_token_too() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    network_with_members(&data, false);
    let issued = stdout(&issue(&data, &["--board", "main", "--member", "alice"]));
    let token = labelled(&issued, "member token: ").to_owned();
    let out = admin(&data, &["revoke-token", &token_id_of(&token)]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    let server = common::start(&data);
    assert_eq!(whoami_status(&server, &token), 401);
}

#[test]
fn revoke_token_unknown_id_is_exit_2() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    admin(&data, &["enable-auth", "--no-main-invite"]);
    let out = admin(&data, &["revoke-token", "0123456789abcdef"]);
    assert_eq!(out.status.code(), Some(2), "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("no token with id 0123456789abcdef"),
        "stderr: {}",
        stderr(&out)
    );
    assert!(out.stdout.is_empty());
    // A malformed id, such as a whole token pasted by mistake, is refused without being echoed.
    let pasted = generate_secret(SecretKind::Token).expect("secret").full;
    for raw in ["not-an-id", pasted.as_str()] {
        let out = admin(&data, &["revoke-token", raw]);
        assert_eq!(out.status.code(), Some(2), "stderr: {}", stderr(&out));
        assert!(stderr(&out).contains("not a token id"), "{}", stderr(&out));
        assert!(!stderr(&out).contains(raw), "{}", stderr(&out));
        assert!(out.stdout.is_empty());
    }
}

#[test]
fn revoke_token_is_idempotent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    let first = stdout(&admin(&data, &["enable-auth", "--no-main-invite"]));
    let id = token_id_of(labelled(&first, "instance token: "));
    for _ in 0..2 {
        let out = admin(&data, &["revoke-token", &id]);
        assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
        assert_eq!(stdout(&out), format!("revoked {id}\n"));
    }
    with_store(&data, |store| async move {
        let log = store.security_log(10).await.expect("log");
        let revoked = log
            .iter()
            .filter(|e| e.kind == SecurityEventKind::TokenRevoked)
            .count();
        assert_eq!(revoked, 1, "a repeat revoke is not a new event: {log:?}");
    });
}

#[test]
fn revoke_token_requires_network_mode() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    let out = admin(&data, &["revoke-token", "0123456789abcdef"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("requires network mode"),
        "stderr: {}",
        stderr(&out)
    );
    assert!(out.stdout.is_empty());
}

#[test]
fn new_instance_token_revoke_others_leaves_only_the_new_token_valid() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    network_with_members(&data, false);
    let first = stdout(&admin(&data, &["new-instance-token"]));
    let older = labelled(&first, "instance token: ").to_owned();
    let issued = stdout(&issue(&data, &["--board", "main", "--member", "alice"]));
    let member = labelled(&issued, "member token: ").to_owned();

    let out = admin(&data, &["new-instance-token", "--revoke-others"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert_eq!(text.lines().count(), 1, "stdout: {text:?}");
    let newest = labelled(&text, "instance token: ").to_owned();
    assert!(
        stderr(&out).contains("revoked 2 other instance tokens"),
        "stderr: {}",
        stderr(&out)
    );
    with_store(&data, |store| async move {
        let log = store.security_log(2).await.expect("log");
        let kinds: Vec<_> = log.iter().map(|e| e.kind).collect();
        assert_eq!(
            kinds,
            [
                SecurityEventKind::TokenRevoked,
                SecurityEventKind::InstanceTokenIssued
            ]
        );
    });

    let server = common::start(&data);
    assert_eq!(whoami_status(&server, &older), 401);
    assert_eq!(whoami_status(&server, &newest), 200);
    assert_eq!(
        whoami_status(&server, &member),
        200,
        "board tokens are untouched"
    );
}

// ---- issue-member-token ----

/// A network-mode data dir whose board `main` has member `alice`, plus board `ops` with member
/// `bob`, archived when `archive_ops`.
fn network_with_members(data: &Path, archive_ops: bool) {
    let out = admin(data, &["enable-auth", "--no-main-invite"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    with_store(data, |store| async move {
        let ops = BoardId::new("ops").expect("board");
        store.create_board(&ops, None).await.expect("create ops");
        for (board, name) in [(BoardId::main(), "alice"), (ops.clone(), "bob")] {
            store
                .add_member(
                    &board,
                    &Principal::new(name).expect("name"),
                    PrincipalKind::Agent,
                    Role::Member,
                    now_ms(),
                )
                .await
                .expect("add member");
        }
        if archive_ops {
            store.archive_board(&ops).await.expect("archive ops");
        }
    });
}

fn issue(data: &Path, extra: &[&str]) -> Output {
    let mut args = vec!["issue-member-token"];
    args.extend_from_slice(extra);
    admin(data, &args)
}

#[test]
fn issue_member_token_prints_once_and_the_token_authenticates() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    network_with_members(&data, false);
    let out = issue(&data, &["--board", "main", "--member", "alice"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert_eq!(text.lines().count(), 1, "stdout: {text:?}");
    let token = labelled(&text, "member token: ").to_owned();
    assert!(token.starts_with("stg1_"), "{text:?}");
    assert!(
        stderr(&out).contains("shown once"),
        "stderr: {}",
        stderr(&out)
    );
    assert!(!stderr(&out).contains(&token));

    let (id, secret) = parse_secret(SecretKind::Token, &token).expect("token shape");
    let before = now_ms();
    let log_secret = secret.clone();
    with_store(&data, |store| async move {
        let cred = store
            .find_credential(&id)
            .await
            .expect("find")
            .expect("stored");
        assert_eq!(cred.scope, CredentialScope::Board(BoardId::main()));
        assert_eq!(cred.principal.as_str(), "alice");
        assert!(secrets_match(&log_secret, &cred.secret_hash));
        let ttl = cred.expires_at_ms - before;
        assert!((89 * DAY_MS..=91 * DAY_MS).contains(&ttl), "ttl {ttl}");
        let log = store.security_log(10).await.expect("log");
        assert_eq!(log[0].kind, SecurityEventKind::MemberTokenIssued);
        assert_eq!(log[0].board, Some(BoardId::main()));
        assert!(log[0].detail.contains(id.as_str()), "{:?}", log[0]);
        assert!(log[0].detail.contains("alice"), "{:?}", log[0]);
        assert!(!log[0].detail.contains(log_secret.as_str()));
    });

    let server = common::start(&data);
    let bearer = format!("Bearer {token}");
    let (status, body) = common::http(
        &server.addr,
        "GET",
        "/v1/whoami",
        &[("Authorization", &bearer)],
        "",
    );
    assert_eq!(status, 200, "body: {body}");
    assert!(body.contains("\"principal\":\"alice\""), "body: {body}");
    assert!(body.contains("\"board\":\"main\""), "body: {body}");
}

#[test]
fn issue_member_token_unknown_member_is_exit_2() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    network_with_members(&data, false);
    for (board, member) in [("main", "zed"), ("main", "bob"), ("nowhere", "alice")] {
        let out = issue(&data, &["--board", board, "--member", member]);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{board}/{member}: {}",
            stderr(&out)
        );
        assert!(stderr(&out).contains(member), "stderr: {}", stderr(&out));
        assert!(out.stdout.is_empty());
    }
}

#[test]
fn issue_member_token_requires_network_mode() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = data_dir_ready(&dir.path().join("data"));
    let out = issue(&data, &["--board", "main", "--member", "alice"]);
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("requires network mode"),
        "{}",
        stderr(&out)
    );
    assert!(out.stdout.is_empty());
}

#[test]
fn issue_member_token_refuses_archived_board() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    network_with_members(&data, true);
    let out = issue(&data, &["--board", "ops", "--member", "bob"]);
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("archived"),
        "stderr: {}",
        stderr(&out)
    );
    assert!(out.stdout.is_empty());
    with_store(&data, |store| async move {
        let ops = BoardId::new("ops").expect("board");
        assert_eq!(store.list_credentials(&ops).await.map(|c| c.len()), Ok(0));
    });
}

#[test]
fn issue_member_token_expiry_bounds() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    network_with_members(&data, false);
    for days in ["0", "366"] {
        let out = issue(
            &data,
            &[
                "--board",
                "main",
                "--member",
                "alice",
                "--expires-days",
                days,
            ],
        );
        assert_eq!(out.status.code(), Some(2), "days {days}");
        assert!(out.stdout.is_empty());
    }
    let out = issue(
        &data,
        &[
            "--board",
            "main",
            "--member",
            "alice",
            "--expires-days",
            "365",
        ],
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    let token = labelled(&stdout(&out), "member token: ").to_owned();
    let (id, _) = parse_secret(SecretKind::Token, &token).expect("token shape");
    let before = now_ms();
    with_store(&data, |store| async move {
        let cred = store
            .find_credential(&id)
            .await
            .expect("find")
            .expect("stored");
        let ttl = cred.expires_at_ms - before;
        assert!((364 * DAY_MS..=366 * DAY_MS).contains(&ttl), "ttl {ttl}");
    });
}

#[test]
fn issue_member_token_secret_not_in_stderr_or_db_plaintext() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    network_with_members(&data, false);
    let out = issue(&data, &["--board", "main", "--member", "alice"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    let token = labelled(&stdout(&out), "member token: ").to_owned();
    let secret = secret_half(SecretKind::Token, &token);
    assert!(!stderr(&out).contains(&secret));
    let log = with_store(&data, |store| async move {
        format!("{:?}", store.security_log(100).await.expect("log"))
    });
    assert!(!log.contains(&secret), "security log leaks the secret");
    let mut raw = std::fs::read(data.join("stigmer.db")).expect("read db");
    if let Ok(wal) = std::fs::read(data.join("stigmer.db-wal")) {
        raw.extend(wal);
    }
    assert!(
        !contains_bytes(&raw, secret.as_bytes()),
        "plaintext secret stored"
    );
    assert!(!contains_bytes(&raw, token.as_bytes()), "full token stored");
    assert!(
        contains_bytes(&raw, &hash_secret(&secret)),
        "scan control: the hash is stored"
    );
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

/// A network-mode data dir whose main has local posts by `posts`' authors.
#[cfg(unix)]
fn network_with_local_posts(data: &Path, posts: &[(&str, &str)]) {
    seed_local_board(data, posts);
    let out = admin(data, &["enable-auth", "--no-main-invite"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
}

const RESERVED_HINT: &str = "local author \"instance-admin\" uses a reserved name; \
     rerun with --skip instance-admin (its messages stay local)";

#[cfg(unix)]
#[test]
fn map_local_principals_reserved_author_is_exit_2_with_the_skip_hint() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    network_with_local_posts(&data, &[("alice", "one"), ("instance-admin", "two")]);
    for extra in [&[][..], &["--apply"][..]] {
        let mut args = vec!["map-local-principals", "--admin", "alice"];
        args.extend_from_slice(extra);
        let out = admin(&data, &args);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {}", stderr(&out));
        assert!(stderr(&out).contains(RESERVED_HINT), "{}", stderr(&out));
        assert!(
            !stdout(&out).contains("instance-admin"),
            "a reserved author is never listed as adoptable: {}",
            stdout(&out)
        );
    }
    with_store(&data, |store| async move {
        assert_eq!(
            store.list_members(&BoardId::main()).await.expect("members"),
            []
        );
    });
}

#[cfg(unix)]
#[test]
fn map_local_principals_skip_leaves_the_author_local_and_adopts_the_rest() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    network_with_local_posts(
        &data,
        &[
            ("alice", "one"),
            ("instance-admin", "two"),
            ("bob", "three"),
        ],
    );
    let dry = admin(
        &data,
        &[
            "map-local-principals",
            "--admin",
            "alice",
            "--skip",
            "instance-admin",
        ],
    );
    assert_eq!(dry.status.code(), Some(0), "stderr: {}", stderr(&dry));
    let names: Vec<String> = stdout(&dry)
        .lines()
        .skip(1)
        .filter_map(|l| l.split_whitespace().next().map(str::to_owned))
        .filter(|n| n != "dry")
        .collect();
    assert_eq!(names, ["alice", "bob"], "{}", stdout(&dry));

    let out = admin(
        &data,
        &[
            "map-local-principals",
            "--admin",
            "alice",
            "--skip",
            "instance-admin",
            "--apply",
        ],
    );
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    assert!(
        stdout(&out).contains("adopted 2 authors and 2 messages"),
        "{}",
        stdout(&out)
    );
    with_store(&data, |store| async move {
        let main = BoardId::main();
        let members: Vec<String> = store
            .list_members(&main)
            .await
            .expect("members")
            .into_iter()
            .map(|m| m.name.to_string())
            .collect();
        assert_eq!(members, ["alice", "bob"]);
        assert_eq!(
            store.list_local_authors(&main).await.expect("authors"),
            [Principal::new("instance-admin").expect("name")],
            "the skipped author stays local"
        );
    });
}

#[cfg(unix)]
#[test]
fn map_local_principals_skip_unknown_name_is_exit_2() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    network_with_local_posts(&data, &POSTS);
    let out = admin(
        &data,
        &["map-local-principals", "--admin", "alice", "--skip", "zed"],
    );
    assert_eq!(out.status.code(), Some(2), "stderr: {}", stderr(&out));
    assert!(stderr(&out).contains("--skip zed"), "{}", stderr(&out));
    assert!(out.stdout.is_empty());
}

#[cfg(unix)]
#[test]
fn map_local_principals_name_taken_message_names_the_author() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    network_with_local_posts(&data, &POSTS);
    // bob became a member some other way; his M0 posts are still local.
    with_store(&data, |store| async move {
        let bob = Principal::new("bob").expect("name");
        store
            .add_member(
                &BoardId::main(),
                &bob,
                PrincipalKind::Agent,
                Role::Member,
                now_ms(),
            )
            .await
            .expect("add bob");
    });
    let out = admin(
        &data,
        &["map-local-principals", "--admin", "alice", "--apply"],
    );
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains(
            "local author \"bob\" is already a member of board main; rerun with --skip bob"
        ),
        "{}",
        stderr(&out)
    );
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
    let log = admin(&data, &["security-log", "--limit", "1"]);
    let line = stdout(&log);
    let fields: Vec<&str> = line.trim_end().split('\t').collect();
    assert_eq!(
        fields[1..],
        [
            "principals_adopted",
            "main",
            "instance-admin",
            "adopted 3 authors (4 messages) into board main"
        ],
        "security log: {line:?}"
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
        &["revoke-token", "0123456789abcdef"],
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
