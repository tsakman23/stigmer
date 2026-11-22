//! The M1 exit tests: separate CLI processes exchange messages over TLS with board tokens, a
//! revoked token is refused, a token sees nothing of another board, M0 data survives the move to
//! network mode, no secret leaks into server output, files or the database, and the SDK example
//! performs the same exchange. The M0 exit test (e2e_m0.rs) still runs unchanged in local mode.

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use common::fixtures::saved_token;
use common::{finish, CliUser, Guard, Run, Stigmerd};
use stigmer_core::{generate_secret, parse_secret, BoardId, PrincipalKind, Role, SecretKind};
use stigmer_store::{IdentityStore, Store};
use stigmer_store_sqlite::SqliteStore;

const BOARD: &str = "research";
const QUESTION: &str = "Which TLS versions must we support?";
const ANSWER: &str = "TLS 1.3 only.";
const UNAUTHORIZED_HINT: &str = "next: run stigmer join <invite> --as <name> or stigmer login";
/// How long a blocked wait, or the SDK example, may take before the test fails.
const WAKE_TIMEOUT: Duration = Duration::from_secs(60);

/// One CLI user of the TLS server: its own HOME and XDG_CONFIG_HOME, and every run goes to the
/// server's URL trusting the test CA.
struct Agent {
    user: CliUser,
    url: String,
    ca: PathBuf,
}

impl Agent {
    fn new(server: &Stigmerd, ca: &Path) -> Self {
        Self {
            user: CliUser::new(),
            url: server.url.clone(),
            ca: ca.to_owned(),
        }
    }

    fn args<'a>(&'a self, board: &'a str, args: &[&'a str]) -> Vec<&'a str> {
        let ca = self.ca.to_str().expect("utf-8 temp path");
        let mut all = vec![
            "--url",
            self.url.as_str(),
            "--ca-cert",
            ca,
            "--board",
            board,
        ];
        all.extend_from_slice(args);
        all
    }

    fn run(&self, board: &str, args: &[&str]) -> Run {
        self.user.run(&self.args(board, args))
    }

    fn run_env(&self, board: &str, args: &[&str], env: &[(&str, &str)]) -> Run {
        self.user.run_env(&self.args(board, args), env)
    }

    fn spawn(&self, board: &str, args: &[&str]) -> Guard {
        Guard::spawn(&mut self.user.cmd(&self.args(board, args)))
    }

    /// The token join or login saved for `board`.
    fn token(&self, board: &str) -> String {
        saved_token(&self.user, &format!("board:{board}"))
    }
}

/// A TLS network-mode server with board `research`, created by the instance admin, and two
/// agents that joined it with single-use invites.
struct Exchange {
    server: Stigmerd,
    admin: Agent,
    a: Agent,
    c: Agent,
    /// The invites the instance admin minted (both redeemed by now).
    invites: Vec<String>,
    _tls: common::tls::TlsFiles,
    _pems: tempfile::TempDir,
}

impl Exchange {
    fn start() -> Self {
        let (server, tls, pems) = Stigmerd::tls();
        let admin = Agent::new(&server, &tls.ca);
        let instance_token = server.instance_token.clone().expect("instance token");
        let login = admin.user.run_stdin(
            &admin.args("main", &["login", "--instance"]),
            &format!("{instance_token}\n"),
        );
        assert_eq!(login.code, 0, "{login:?}");
        let created = admin.run("main", &["boards", "create", BOARD]);
        assert_eq!(created.code, 0, "{created:?}");
        assert_eq!(created.stdout, format!("created board {BOARD}\n"));

        let mut invites = Vec::new();
        let mut join = |name: &str| {
            let minted = admin.run(
                BOARD,
                &["invite", "create", "--kind", "agent", "--role", "member"],
            );
            assert_eq!(minted.code, 0, "{minted:?}");
            let invite = value(&minted.stdout, "invite: ");
            let agent = Agent::new(&server, &tls.ca);
            let joined = agent.run(BOARD, &["join", &invite, "--as", name]);
            assert_eq!(joined.code, 0, "{joined:?}");
            assert!(
                joined
                    .stdout
                    .starts_with(&format!("joined board {BOARD} as {name} (member)\n")),
                "{joined:?}"
            );
            assert!(!joined.all().contains(&agent.token(BOARD)), "never printed");
            invites.push(invite);
            agent
        };
        let a = join("agent-a");
        let c = join("agent-c");
        Self {
            server,
            admin,
            a,
            c,
            invites,
            _tls: tls,
            _pems: pems,
        }
    }

    /// A posts the question in research/tls and returns the new thread id.
    fn post_question(&self) -> String {
        let posted = self.a.run(BOARD, &["post", "research/tls", QUESTION]);
        assert_eq!(posted.code, 0, "{posted:?}");
        thread_id(&posted)
    }

    /// The instance admin revokes C's token, found by its id in token list.
    fn revoke_c(&self) {
        let (id, _) = parse_secret(SecretKind::Token, &self.c.token(BOARD)).expect("token shape");
        let id = id.to_string();
        let listed = self.admin.run(BOARD, &["token", "list"]);
        assert_eq!(listed.code, 0, "{listed:?}");
        let line = listed
            .stdout
            .lines()
            .find(|line| line.starts_with(&id))
            .unwrap_or_else(|| panic!("C's token {id} not listed: {listed:?}"));
        assert!(line.contains("agent-c"), "{line}");
        let revoked = self.admin.run(BOARD, &["token", "revoke", &id]);
        assert_eq!(revoked.code, 0, "{revoked:?}");
    }
}

/// The value after `prefix` on the first line that starts with it.
fn value(text: &str, prefix: &str) -> String {
    text.lines()
        .find_map(|line| line.strip_prefix(prefix))
        .unwrap_or_else(|| panic!("no {prefix:?} line in {text:?}"))
        .to_owned()
}

/// The thread id from post's first line, `posted <id> in <channel> as <name>`.
fn thread_id(posted: &Run) -> String {
    let id = posted.stdout.split_whitespace().nth(1).unwrap_or_default();
    assert!(id.starts_with("msg_"), "{posted:?}");
    id.to_owned()
}

#[test]
fn two_processes_exchange_over_tls_and_a_revoked_token_is_refused() {
    let ex = Exchange::start();
    let earlier = ex.a.run(
        BOARD,
        &["post", "research/tls", "Earlier note, already handled."],
    );
    assert_eq!(earlier.code, 0, "{earlier:?}");

    // Head first: a zero-timeout --from-now wait resolves the board head and prints it as the
    // cursor; waiting after it skips the earlier note and cannot miss the post that follows,
    // however the processes are scheduled. No sleep is needed.
    let head = ex.c.run(
        BOARD,
        &[
            "wait",
            "--channel",
            "research/",
            "--from-now",
            "--timeout",
            "0s",
        ],
    );
    assert_eq!(head.code, 3, "{head:?}");
    let cursor = value(&head.stdout, "cursor: ");
    let waiter = ex.c.spawn(
        BOARD,
        &[
            "wait",
            "--channel",
            "research/",
            "--after",
            &cursor,
            "--timeout",
            "45s",
        ],
    );

    let thread = ex.post_question();
    let woke = finish(waiter, WAKE_TIMEOUT);
    assert_eq!(woke.code, 0, "{woke:?}");
    assert_eq!(woke.stdout.matches("<<<message ").count(), 1, "{woke:?}");
    assert!(
        woke.stdout
            .contains(&format!("<<<message {thread} from agent-a ")),
        "{woke:?}"
    );
    assert!(woke.stdout.contains(QUESTION), "{woke:?}");
    assert!(
        !woke.stdout.contains("Earlier note"),
        "history skipped: {woke:?}"
    );

    let replied = ex.c.run(BOARD, &["reply", &thread, ANSWER]);
    assert_eq!(replied.code, 0, "{replied:?}");
    assert!(replied.stdout.contains(" as agent-c\n"), "{replied:?}");

    let shown = ex.a.run(BOARD, &["thread", &thread]);
    assert_eq!(shown.code, 0, "{shown:?}");
    let question = shown.stdout.find(QUESTION).expect("question shown");
    let answer = shown.stdout.find(ANSWER).expect("answer shown");
    assert!(question < answer, "{shown:?}");
    assert!(shown.stdout.contains(" from agent-c at "), "{shown:?}");

    ex.revoke_c();
    let refused = ex.c.run(BOARD, &["read", "research/"]);
    assert_eq!(refused.code, 6, "{refused:?}");
    assert!(refused.stderr.contains(UNAUTHORIZED_HINT), "{refused:?}");
    assert!(refused.stdout.is_empty(), "{refused:?}");
    let still = ex.a.run(BOARD, &["read", "research/"]);
    assert_eq!(still.code, 0, "A's token is unaffected: {still:?}");
}

#[test]
fn a_token_for_one_board_gets_404_for_every_other_boards_routes() {
    let ex = Exchange::start();
    let other = "team-two";
    let missing = "team-nope";
    let created = ex.admin.run("main", &["boards", "create", other]);
    assert_eq!(created.code, 0, "{created:?}");
    let thread = ex.post_question();
    let token = ex.a.token(BOARD);
    let env = [("STIGMER_TOKEN", token.as_str())];

    let routes: [&[&str]; 8] = [
        &["post", "research/tls", "hello"],
        &["read", "research/"],
        &["thread", &thread],
        &["wait", "--timeout", "1s"],
        &["tail", "--timeout", "5s"],
        &["members", "list"],
        &["invite", "create", "--kind", "agent", "--role", "member"],
        &["token", "list"],
    ];
    for args in routes {
        let existing = ex.a.run_env(other, args, &env);
        let unknown = ex.a.run_env(missing, args, &env);
        assert_eq!(existing.code, 4, "{args:?} on {other}: {existing:?}");
        assert_eq!(unknown.code, 4, "{args:?} on {missing}: {unknown:?}");
        assert!(existing.stdout.is_empty(), "{args:?}: {existing:?}");
        assert!(unknown.stdout.is_empty(), "{args:?}: {unknown:?}");
        assert_eq!(
            existing.stderr.replace(other, "<board>"),
            unknown.stderr.replace(missing, "<board>"),
            "{args:?}: the other board's existence must not show"
        );
        assert!(!existing.all().contains(&token), "{args:?}");
    }

    // The same token still works on its own board.
    let own = ex.a.run_env(BOARD, &["read", "research/"], &env);
    assert_eq!(own.code, 0, "{own:?}");
}

#[test]
fn enable_auth_and_map_local_principals_on_m0_data_keeps_the_chain_valid() {
    let mut server = Stigmerd::local();
    let user = CliUser::new();
    let url = server.url.clone();
    let as_ = |name: &str, args: &[&str]| {
        let mut all = vec!["--url", url.as_str(), "--as", name];
        all.extend_from_slice(args);
        let run = user.run(&all);
        assert_eq!(run.code, 0, "{run:?}");
        run
    };
    let thread = thread_id(&as_("alice", &["post", "research/tls", QUESTION]));
    as_("bob", &["reply", &thread, ANSWER]);
    as_(
        "alice",
        &["post", "research/ops", "Rotate the staging certificate."],
    );
    server.stop();

    let db = server.data_path().join("stigmer.db");
    let main = BoardId::main();
    let before = block_on(async {
        let store = SqliteStore::open(&db).await.expect("open the M0 database");
        let chain = store.verify_chain(&main).await.expect("verify chain");
        let authors = store
            .list_local_authors(&main)
            .await
            .expect("local authors");
        (chain, authors)
    });
    assert!(before.0.valid, "{:?}", before.0);
    assert_eq!(before.0.checked, 3);
    let names: Vec<&str> = before.1.iter().map(|p| p.as_str()).collect();
    assert_eq!(names, ["alice", "bob"]);

    server.enable_auth();
    let plan = server.admin(&[
        "map-local-principals",
        "--admin",
        "alice",
        "--human",
        "alice",
    ]);
    assert_eq!(plan.code, 0, "{plan:?}");
    assert!(plan.stdout.contains("dry run: nothing changed"), "{plan:?}");
    let applied = server.admin(&[
        "map-local-principals",
        "--admin",
        "alice",
        "--human",
        "alice",
        "--apply",
    ]);
    assert_eq!(applied.code, 0, "{applied:?}");
    assert_eq!(
        applied.stdout,
        "adopted 2 authors and 3 messages into board main\n"
    );

    let (chain, locals, members) = block_on(async {
        let store = SqliteStore::open(&db)
            .await
            .expect("open the mapped database");
        (
            store.verify_chain(&main).await.expect("verify chain"),
            store
                .list_local_authors(&main)
                .await
                .expect("local authors"),
            store.list_members(&main).await.expect("members"),
        )
    });
    assert!(chain.valid, "{chain:?}");
    assert_eq!(chain.checked, before.0.checked, "no event added or changed");
    assert!(
        locals.is_empty(),
        "every message now has a real author: {locals:?}"
    );
    let members: Vec<(&str, PrincipalKind, Role)> = members
        .iter()
        .map(|m| (m.name.as_str(), m.kind, m.role))
        .collect();
    assert_eq!(
        members,
        [
            ("alice", PrincipalKind::Human, Role::Admin),
            ("bob", PrincipalKind::Agent, Role::Member),
        ]
    );

    // Restarted in network mode: a new admin joins main and reads the M0 threads.
    server.start_again();
    let invite = server.main_invite.clone().expect("main admin invite");
    let carol = CliUser::new();
    let joined = carol.run(&["--url", &url, "join", &invite, "--as", "carol"]);
    assert_eq!(joined.code, 0, "{joined:?}");
    let listed = carol.run(&["--url", &url, "read", "research/"]);
    assert_eq!(listed.code, 0, "{listed:?}");
    assert!(listed.stdout.contains(&thread), "{listed:?}");
    assert!(
        listed.stdout.contains("Rotate the staging certificate."),
        "{listed:?}"
    );
    let shown = carol.run(&["--url", &url, "thread", &thread]);
    assert_eq!(shown.code, 0, "{shown:?}");
    assert!(shown.stdout.contains(" from alice at "), "{shown:?}");
    assert!(shown.stdout.contains(" from bob at "), "{shown:?}");
    assert!(shown.stdout.contains(ANSWER), "{shown:?}");
    // The local workflow is gone: a name without a token is refused.
    let anonymous = user.run(&["--url", &url, "--as", "alice", "read", "research/"]);
    assert_eq!(anonymous.code, 6, "{anonymous:?}");
}

#[test]
fn no_secret_appears_in_server_output_and_login_files_are_private() {
    let mut ex = Exchange::start();
    let thread = ex.post_question();
    let replied = ex.c.run(BOARD, &["reply", &thread, ANSWER]);
    assert_eq!(replied.code, 0, "{replied:?}");

    // Failures the server may want to log: a wrong secret for a real token id, a revoked token,
    // and a spent invite.
    let a_token = ex.a.token(BOARD);
    let c_token = ex.c.token(BOARD);
    let (a_id, _) = parse_secret(SecretKind::Token, &a_token).expect("token shape");
    let (_, other_secret) = parse_secret(
        SecretKind::Token,
        &generate_secret(SecretKind::Token).unwrap().full,
    )
    .expect("token shape");
    let forged = format!("stg1_{a_id}_{other_secret}");
    let refused =
        ex.a.run_env(BOARD, &["read", "research/"], &[("STIGMER_TOKEN", &forged)]);
    assert_eq!(refused.code, 6, "{refused:?}");
    ex.revoke_c();
    assert_eq!(ex.c.run(BOARD, &["read", "research/"]).code, 6);
    let spent = CliUser::new().run(&[
        "--url",
        &ex.server.url,
        "--ca-cert",
        ex.a.ca.to_str().unwrap(),
        "join",
        &ex.invites[0],
        "--as",
        "agent-x",
    ]);
    assert_eq!(spent.code, 6, "{spent:?}");

    let mut secrets = vec![
        ex.server.instance_token.clone().unwrap(),
        ex.server.main_invite.clone().unwrap(),
        a_token,
        c_token,
        forged,
    ];
    secrets.extend(ex.invites.iter().cloned());
    let halves: Vec<String> = secrets
        .iter()
        .map(|full| {
            let kind = if full.starts_with("stgi1_") {
                SecretKind::Invite
            } else {
                SecretKind::Token
            };
            parse_secret(kind, full).expect("secret shape").1
        })
        .collect();

    ex.server.stop();
    let output = format!("{}{}", ex.server.stdout.text(), ex.server.stderr.text());
    for (full, half) in secrets.iter().zip(&halves) {
        assert!(
            !output.contains(full.as_str()),
            "a secret in server output: {output}"
        );
        assert!(
            !output.contains(half.as_str()),
            "a secret half in server output: {output}"
        );
    }

    for entry in std::fs::read_dir(ex.server.data_path()).expect("data dir") {
        let path = entry.expect("dir entry").path();
        let bytes = std::fs::read(&path).expect("read data file");
        for half in &halves {
            assert!(
                !bytes.windows(half.len()).any(|w| w == half.as_bytes()),
                "a secret half is stored in {}",
                path.display()
            );
        }
    }

    for agent in [&ex.admin, &ex.a, &ex.c] {
        let file = agent.user.logins_path();
        assert_eq!(mode(&file), 0o600, "{}", file.display());
        assert_eq!(mode(file.parent().unwrap()), 0o700, "{}", file.display());
    }
}

#[test]
fn sdk_example_reproduces_the_exit_exchange() {
    let node_found = Command::new("node")
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success());
    if !node_found {
        assert!(
            std::env::var_os("CI").is_none(),
            "node is required in CI to run the SDK example"
        );
        eprintln!("skipping sdk_example_reproduces_the_exit_exchange: node is not on PATH");
        return;
    }
    let sdk = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sdk/typescript");
    if !sdk.join("dist/src/index.js").exists() {
        for args in [&["ci"][..], &["run", "build"][..]] {
            let status = Command::new("npm")
                .args(args)
                .current_dir(&sdk)
                .stdout(Stdio::null())
                .status()
                .expect("run npm");
            assert!(status.success(), "npm {args:?} failed in {}", sdk.display());
        }
    }

    let ex = Exchange::start();
    let (a_token, c_token) = (ex.a.token(BOARD), ex.c.token(BOARD));
    let mut cmd = Command::new("node");
    cmd.arg("examples/two-agents.mjs")
        .current_dir(&sdk)
        .env_remove("STIGMER_AS_A")
        .env_remove("STIGMER_AS_C")
        .env("STIGMER_URL", &ex.server.url)
        .env("STIGMER_BOARD", BOARD)
        .env("A_TOKEN", &a_token)
        .env("C_TOKEN", &c_token)
        .env("NODE_EXTRA_CA_CERTS", &ex.a.ca)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let run = finish(Guard::spawn(&mut cmd), WAKE_TIMEOUT);
    assert_eq!(run.code, 0, "{run:?}");
    assert!(run.stdout.ends_with("PASS\n"), "{run:?}");
    assert_eq!(run.stdout.matches("<<<message ").count(), 2, "{run:?}");
    assert!(!run.all().contains(&a_token) && !run.all().contains(&c_token));

    // The exchange really landed on the board, as the CLI sees it.
    let listed = ex.a.run(BOARD, &["read", "research/"]);
    assert_eq!(listed.code, 0, "{listed:?}");
    assert!(listed.stdout.contains(QUESTION), "{listed:?}");
    assert!(listed.stdout.contains("  1 reply\n"), "{listed:?}");
}

fn block_on<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("tokio runtime")
        .block_on(future)
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777
}
