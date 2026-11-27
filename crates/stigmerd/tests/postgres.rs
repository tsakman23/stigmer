//! stigmerd on Postgres: choosing the backend, the database URL and its password, TLS settings,
//! schema checks, `admin migrate`, and admin commands next to running servers.
//!
//! Tests in `with_postgres` need the test database (`STIGMER_TEST_DATABASE_URL`); CI's `check`
//! job skips them by that module name and its `postgres` job runs them. The others need none.

mod common;

use std::path::Path;

use common::pg::{stigmerd, URL_VAR};
use common::{run_guarded, Bounded};

/// A URL nothing answers on (port 1), for refusals that must come before any connection.
const CLOSED: &str = "postgres://stigmer@127.0.0.1:1/stigmer_test";

fn run(args: &[&str]) -> Bounded {
    run_guarded(stigmerd(args))
}

fn run_with_url(args: &[&str], url: &str) -> Bounded {
    let mut cmd = stigmerd(args);
    cmd.env(URL_VAR, url);
    run_guarded(cmd)
}

fn assert_usage_error(out: &Bounded, needle: &str) {
    assert_eq!(
        out.code,
        Some(2),
        "stdout: {} stderr: {}",
        out.stdout,
        out.stderr
    );
    assert!(out.stderr.contains(needle), "{needle:?} in: {}", out.stderr);
}

#[test]
fn password_in_the_url_argument_is_refused_with_exit_2() {
    let secret = "hunter2-on-argv";
    for url in [
        format!("postgres://stigmer:{secret}@db.example/stigmer"),
        format!("postgresql://stigmer:{secret}@127.0.0.1:1/stigmer?sslmode=require"),
        format!("postgres://stigmer@127.0.0.1:1/stigmer?password={secret}"),
        format!("host=127.0.0.1 port=1 user=stigmer password={secret} dbname=stigmer"),
    ] {
        for command in [
            &["serve"][..],
            &["admin", "security-log"],
            &["admin", "migrate"],
        ] {
            let mut args = command.to_vec();
            args.extend(["--database-url", &url]);
            let out = run(&args);
            assert_usage_error(&out, URL_VAR);
            assert!(out.stderr.contains("--database-url-file"), "{}", out.stderr);
            assert!(!out.stderr.contains(secret), "{}", out.stderr);
            assert!(!out.stdout.contains(secret), "{}", out.stdout);
        }
    }
    // The same URL from the environment is accepted (and fails later, on connecting).
    let url = format!("postgres://stigmer:{secret}@127.0.0.1:1/stigmer");
    let out = run_with_url(&["admin", "security-log"], &url);
    assert_eq!(out.code, Some(1), "{}", out.stderr);
    assert!(out.stderr.contains("cannot connect"), "{}", out.stderr);
    assert!(!out.stderr.contains(secret), "{}", out.stderr);
}

#[test]
fn an_unencoded_at_sign_in_the_user_info_is_refused_without_showing_the_url() {
    for url in [
        "postgres://u:p@ssw0rdX@127.0.0.1:1/db",
        "postgresql://u:a/b@ssw0rdX@127.0.0.1:1/db?sslmode=require",
    ] {
        for out in [
            run_with_url(&["admin", "migrate"], url),
            run_with_url(&["serve"], url),
            run(&["admin", "migrate", "--database-url", url]),
        ] {
            assert_usage_error(&out, "percent-encode");
            for text in [&out.stdout, &out.stderr] {
                assert!(!text.contains("ssw0rdX"), "{text}");
            }
        }
    }
}

#[test]
fn an_empty_database_url_from_any_source_exits_2() {
    for value in ["", "   "] {
        let out = run_with_url(&["admin", "security-log"], value);
        assert_usage_error(&out, "set but empty");
        let out = run(&["admin", "security-log", "--database-url", value]);
        assert_usage_error(&out, "--database-url is empty");
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("database-url");
        std::fs::write(&file, value).unwrap();
        let out = run(&[
            "admin",
            "security-log",
            "--database-url-file",
            file.to_str().unwrap(),
        ]);
        assert_usage_error(&out, "is empty");
    }
}

#[test]
fn out_of_range_database_flags_exit_2() {
    for (flag, value) in [
        ("--db-max-connections", "0"),
        ("--db-max-connections", "501"),
        ("--db-poll-interval-ms", "99"),
        ("--db-poll-interval-ms", "60001"),
        ("--db-tls", "prefer"),
    ] {
        for command in [&["serve"][..], &["admin", "migrate"]] {
            let mut args = command.to_vec();
            args.extend([flag, value]);
            let out = run_with_url(&args, CLOSED);
            assert_eq!(out.code, Some(2), "{flag} {value}: {}", out.stderr);
        }
    }
    // The bounds themselves are accepted (and fail later, on connecting).
    for (flag, value) in [
        ("--db-max-connections", "1"),
        ("--db-max-connections", "500"),
        ("--db-poll-interval-ms", "100"),
        ("--db-poll-interval-ms", "60000"),
    ] {
        let out = run_with_url(&["admin", "migrate", flag, value], CLOSED);
        assert_eq!(out.code, Some(1), "{flag} {value}: {}", out.stderr);
    }
}

#[test]
fn tls_settings_that_disagree_or_are_unsupported_exit_2() {
    let cases = [
        (
            format!("{CLOSED}?sslmode=require"),
            vec!["--db-tls", "disable"],
            "disagree",
        ),
        (
            format!("{CLOSED}?sslmode=disable"),
            vec!["--db-tls", "verify-full"],
            "disagree",
        ),
        (format!("{CLOSED}?sslmode=prefer"), vec![], "sslmode=prefer"),
        (
            format!("{CLOSED}?sslmode=verify-ca"),
            vec![],
            "sslmode=verify-ca",
        ),
        (
            CLOSED.to_owned(),
            vec!["--db-tls", "require", "--db-tls-ca", "ca.pem"],
            "verify-full",
        ),
        (
            format!("{CLOSED}?sslrootcert=a.pem"),
            vec!["--db-tls-ca", "b.pem"],
            "disagree",
        ),
        (
            CLOSED.to_owned(),
            vec!["--db-tls-ca", "/no/such/ca.pem"],
            "/no/such/ca.pem",
        ),
    ];
    for (url, flags, needle) in cases {
        let mut args = vec!["admin", "migrate"];
        args.extend(flags.iter().copied());
        let out = run_with_url(&args, &url);
        assert_usage_error(&out, needle);
    }
}

#[test]
fn a_ca_bundle_without_certificates_is_named_once() {
    let dir = tempfile::tempdir().unwrap();
    let ca = dir.path().join("ca.pem");
    std::fs::write(&ca, "not a certificate\n").unwrap();
    let out = run_with_url(
        &["admin", "migrate", "--db-tls-ca", ca.to_str().unwrap()],
        CLOSED,
    );
    assert_usage_error(&out, "the CA bundle holds no certificate");
    assert_eq!(out.stderr.matches("CA bundle").count(), 1, "{}", out.stderr);
    assert!(
        !out.stderr.contains("storage backend error"),
        "{}",
        out.stderr
    );
}

#[test]
fn database_flags_without_a_database_url_exit_2() {
    let data = tempfile::tempdir().unwrap();
    let dir = data.path().join("d");
    let dir = dir.to_str().unwrap();
    for flags in [
        &["--db-tls", "require"][..],
        &["--db-max-connections", "4"],
        &["--db-tls-ca", "ca.pem"],
    ] {
        let mut args = vec!["admin", "security-log", "--data-dir", dir];
        args.extend(flags);
        let out = run(&args);
        assert_usage_error(&out, "Postgres");
    }
    assert!(
        !Path::new(dir).exists(),
        "a refused command creates nothing"
    );
}

#[test]
fn a_database_url_file_that_cannot_be_used_exits_2() {
    let dir = tempfile::tempdir().unwrap();
    let empty = dir.path().join("empty");
    std::fs::write(&empty, "\n").unwrap();
    let missing = dir.path().join("missing");
    let directory = dir.path().join("a-directory");
    std::fs::create_dir(&directory).unwrap();
    for (path, needle) in [
        (&empty, "empty"),
        (&missing, "cannot read"),
        (&directory, "is a directory"),
    ] {
        let out = run(&[
            "admin",
            "migrate",
            "--database-url-file",
            path.to_str().unwrap(),
        ]);
        assert_usage_error(&out, needle);
        if path == &directory {
            assert!(!out.stderr.contains("warning"), "{needle}: {}", out.stderr);
        }
    }
    let out = run(&[
        "admin",
        "migrate",
        "--database-url",
        CLOSED,
        "--database-url-file",
        empty.to_str().unwrap(),
    ]);
    assert_eq!(out.code, Some(2), "{}", out.stderr);
}

#[test]
fn sqlite_default_is_unchanged() {
    let data = tempfile::tempdir().unwrap();
    let dir = data.path().join("d");
    let out = run(&["admin", "security-log", "--data-dir", dir.to_str().unwrap()]);
    assert_eq!(out.code, Some(0), "{}", out.stderr);
    assert!(dir.join("stigmer.db").is_file());
    assert!(dir.join("stigmer.lock").is_file());
    assert!(!out.stderr.contains("warning"), "{}", out.stderr);

    // migrate is a no-op on SQLite: it says so and touches nothing.
    let other = data.path().join("untouched");
    let out = run(&["admin", "migrate", "--data-dir", other.to_str().unwrap()]);
    assert_eq!(out.code, Some(0), "{}", out.stderr);
    assert!(out.stdout.contains("automatic"), "{}", out.stdout);
    assert!(!other.exists());
}

mod with_postgres {
    use std::io::Write;
    use std::process::Command;
    use std::thread;

    use super::common::pg::{stigmerd, PgDb, URL_VAR};
    use super::common::{http, run_guarded, spawn_capturing, Bounded, Server, STARTUP_TIMEOUT};
    use super::run_with_url;

    fn serve(url: &str) -> Command {
        let mut cmd = stigmerd(&["serve", "--bind", "127.0.0.1:0"]);
        cmd.env(URL_VAR, url);
        cmd
    }

    fn migrated(db: &PgDb) {
        let out = run_with_url(&["admin", "migrate"], &db.url());
        assert_eq!(out.code, Some(0), "{}", out.stderr);
    }

    fn assert_no_password(db: &PgDb, what: &str, text: &str) {
        assert!(!text.contains(&db.password), "{what}: {text}");
    }

    /// The command line of a running process, as `ps` shows it to anyone on the machine.
    fn process_listing(server: &Server) -> String {
        let out = Command::new("ps")
            .args(["-o", "args=", "-p", &server.child.id().to_string()])
            .output()
            .expect("run ps");
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    #[test]
    fn admin_migrate_applies_and_is_idempotent() {
        let Some(db) = PgDb::create("admin_migrate_applies_and_is_idempotent") else {
            return;
        };
        let first = run_with_url(&["admin", "migrate"], &db.url());
        assert_eq!(first.code, Some(0), "{}", first.stderr);
        assert!(
            first.stdout.contains("from version 0 to 8"),
            "{}",
            first.stdout
        );
        let again = run_with_url(&["admin", "migrate"], &db.url());
        assert_eq!(again.code, Some(0), "{}", again.stderr);
        assert!(again.stdout.contains("up to date"), "{}", again.stdout);
        // Admin commands work on the migrated schema.
        let log = run_with_url(&["admin", "security-log"], &db.url());
        assert_eq!(log.code, Some(0), "{}", log.stderr);
    }

    #[test]
    fn two_concurrent_migrations_both_succeed_and_apply_once() {
        let Some(db) = PgDb::create("two_concurrent_migrations_both_succeed_and_apply_once") else {
            return;
        };
        let url = db.url();
        let runs: Vec<thread::JoinHandle<Bounded>> = (0..2)
            .map(|_| {
                let url = url.clone();
                thread::spawn(move || run_with_url(&["admin", "migrate"], &url))
            })
            .collect();
        let outs: Vec<Bounded> = runs.into_iter().map(|r| r.join().unwrap()).collect();
        for out in &outs {
            assert_eq!(out.code, Some(0), "{}", out.stderr);
        }
        // The advisory lock serialises them: one applies everything, the other finds it done.
        let applied = outs
            .iter()
            .filter(|o| o.stdout.contains("from version 0 to 8"))
            .count();
        assert_eq!(
            applied,
            1,
            "{:?}",
            outs.iter().map(|o| &o.stdout).collect::<Vec<_>>()
        );
        assert_eq!(
            db.query_i64("SELECT count(*) FROM schema_version"),
            8,
            "each migration recorded once"
        );
        assert_eq!(
            db.query_i64("SELECT max(version)::bigint FROM schema_version"),
            8
        );
        assert_eq!(
            db.query_i64("SELECT count(*) FROM boards WHERE id = 'main'"),
            1,
            "one board main"
        );
        let out = run_with_url(&["admin", "security-log"], &url);
        assert_eq!(out.code, Some(0), "{}", out.stderr);
    }

    #[test]
    fn serve_refuses_a_behind_schema_and_names_migrate() {
        let Some(db) = PgDb::create("serve_refuses_a_behind_schema_and_names_migrate") else {
            return;
        };
        let mut cmd = serve(&db.url());
        cmd.args(["--db-max-connections", "2"]);
        let out = run_guarded(cmd);
        assert_eq!(out.code, Some(1), "{}", out.stderr);
        assert!(out.stderr.contains("version 0"), "{}", out.stderr);
        assert!(
            out.stderr.contains("run stigmerd admin migrate"),
            "{}",
            out.stderr
        );
        assert!(out.stdout.is_empty(), "never listened: {}", out.stdout);
        // Admin commands refuse it the same way; migrate is the way out.
        let out = run_with_url(&["admin", "security-log"], &db.url());
        assert_eq!(out.code, Some(1), "{}", out.stderr);
        assert!(
            out.stderr.contains("stigmerd admin migrate"),
            "{}",
            out.stderr
        );
    }

    #[test]
    fn serve_refuses_an_ahead_schema() {
        let Some(db) = PgDb::create("serve_refuses_an_ahead_schema") else {
            return;
        };
        migrated(&db);
        db.execute("INSERT INTO schema_version (version) VALUES (99)");
        let out = run_guarded(serve(&db.url()));
        assert_eq!(out.code, Some(1), "{}", out.stderr);
        assert!(out.stderr.contains("version 99"), "{}", out.stderr);
        assert!(
            out.stderr.contains("older than the database"),
            "{}",
            out.stderr
        );
        // migrate refuses to touch it too.
        let out = run_with_url(&["admin", "migrate"], &db.url());
        assert_eq!(out.code, Some(1), "{}", out.stderr);
    }

    #[test]
    fn url_from_env_and_from_file_work_and_never_print_the_password() {
        let Some(db) = PgDb::create("url_from_env_and_from_file_work_and_never_print_the_password")
        else {
            return;
        };
        // From the environment.
        let out = run_with_url(&["admin", "migrate"], &db.url());
        assert_eq!(out.code, Some(0), "{}", out.stderr);
        assert_no_password(&db, "migrate stdout", &out.stdout);
        assert_no_password(&db, "migrate stderr", &out.stderr);

        // From a file (with a trailing newline, as editors write it).
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("database-url");
        let mut f = std::fs::File::create(&file).unwrap();
        writeln!(f, "{}", db.url()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let path = file.to_str().unwrap();
        let out = run_guarded(stigmerd(&[
            "admin",
            "security-log",
            "--database-url-file",
            path,
        ]));
        assert_eq!(out.code, Some(0), "{}", out.stderr);
        assert_no_password(&db, "security-log stdout", &out.stdout);
        assert_no_password(&db, "security-log stderr", &out.stderr);

        // A server from the file: its argv, stdout and stderr never show the password.
        let mut cmd = stigmerd(&[
            "serve",
            "--bind",
            "127.0.0.1:0",
            "--database-url-file",
            path,
        ]);
        cmd.env_remove(URL_VAR);
        let (server, stderr) = spawn_capturing(cmd);
        let listing = process_listing(&server);
        assert!(listing.contains("--database-url-file"), "{listing}");
        assert_no_password(&db, "process listing", &listing);
        let (status, _) = http(&server.addr, "GET", "/healthz", &[], "");
        assert_eq!(status, 200);
        drop(server);
        assert_no_password(&db, "serve stderr", &stderr.text());

        // A server from the environment: the same.
        let (server, stderr) = spawn_capturing(serve(&db.url()));
        assert_no_password(&db, "process listing", &process_listing(&server));
        let (status, _) = http(&server.addr, "GET", "/healthz", &[], "");
        assert_eq!(status, 200);
        drop(server);
        assert_no_password(&db, "serve stderr", &stderr.text());

        // A failure names the target, never the password.
        let out = run_with_url(&["admin", "security-log"], &db.url_on_port(1));
        assert_eq!(out.code, Some(1), "{}", out.stderr);
        assert!(out.stderr.contains("cannot connect"), "{}", out.stderr);
        assert_no_password(&db, "connect error", &out.stderr);
    }

    #[test]
    fn data_dir_with_database_url_warns_once() {
        let Some(db) = PgDb::create("data_dir_with_database_url_warns_once") else {
            return;
        };
        migrated(&db);
        let data = tempfile::tempdir().unwrap();
        let dir = data.path().join("ignored");
        let dir = dir.to_str().unwrap();
        let out = run_with_url(&["admin", "security-log", "--data-dir", dir], &db.url());
        assert_eq!(out.code, Some(0), "{}", out.stderr);
        assert_eq!(
            out.stderr.matches("--data-dir is ignored").count(),
            1,
            "{}",
            out.stderr
        );
        assert!(
            !std::path::Path::new(dir).exists(),
            "no data dir in Postgres mode"
        );

        let mut cmd = serve(&db.url());
        cmd.args(["--data-dir", dir]);
        let (server, stderr) = spawn_capturing(cmd);
        let (status, _) = http(&server.addr, "GET", "/healthz", &[], "");
        assert_eq!(status, 200);
        drop(server);
        let text = stderr.text();
        assert_eq!(text.matches("--data-dir is ignored").count(), 1, "{text}");
        assert!(
            !std::path::Path::new(dir).exists(),
            "no data dir in Postgres mode"
        );
    }

    #[test]
    fn admin_enable_auth_on_postgres_is_safe_with_two_concurrent_runs() {
        let Some(db) =
            PgDb::create("admin_enable_auth_on_postgres_is_safe_with_two_concurrent_runs")
        else {
            return;
        };
        migrated(&db);
        let url = db.url();
        let runs: Vec<thread::JoinHandle<Bounded>> = (0..2)
            .map(|_| {
                let url = url.clone();
                thread::spawn(move || run_with_url(&["admin", "enable-auth"], &url))
            })
            .collect();
        let outs: Vec<Bounded> = runs.into_iter().map(|r| r.join().unwrap()).collect();
        let won: Vec<&Bounded> = outs.iter().filter(|o| o.code == Some(0)).collect();
        let lost: Vec<&Bounded> = outs.iter().filter(|o| o.code == Some(1)).collect();
        assert_eq!(won.len(), 1, "exactly one run switches the mode");
        assert_eq!(lost.len(), 1, "the other is refused");
        assert!(
            won[0].stdout.contains("instance token: stg1_"),
            "{}",
            won[0].stdout
        );
        assert!(
            lost[0].stderr.contains("already in network mode"),
            "{}",
            lost[0].stderr
        );
        assert!(lost[0].stdout.is_empty(), "the loser prints no token");

        let log = run_with_url(&["admin", "security-log"], &url);
        assert_eq!(log.code, Some(0), "{}", log.stderr);
        assert_eq!(
            log.stdout.matches("mode_enabled").count(),
            1,
            "{}",
            log.stdout
        );
        assert_eq!(
            log.stdout.matches("instance_token_issued").count(),
            1,
            "{}",
            log.stdout
        );
    }

    #[test]
    fn admin_commands_run_while_a_server_is_running_on_postgres() {
        let Some(db) = PgDb::create("admin_commands_run_while_a_server_is_running_on_postgres")
        else {
            return;
        };
        migrated(&db);
        let (server, _stderr) = spawn_capturing(serve(&db.url()));
        let (status, _) = http(&server.addr, "GET", "/healthz", &[], "");
        assert_eq!(status, 200);

        let out = run_with_url(&["admin", "enable-auth"], &db.url());
        assert_eq!(out.code, Some(0), "{}", out.stderr);
        assert!(out.stderr.contains("restart"), "{}", out.stderr);
        let token_line = out
            .stdout
            .lines()
            .find(|l| l.starts_with("instance token: "))
            .expect("token line");
        let token = token_line.trim_start_matches("instance token: ");
        let id = token.split('_').nth(1).expect("token id");
        for args in [
            &["admin", "security-log"][..],
            &["admin", "new-instance-token"],
            &["admin", "revoke-token", id],
        ] {
            let out = run_with_url(args, &db.url());
            assert_eq!(out.code, Some(0), "{args:?}: {}", out.stderr);
        }
        // The running server kept serving throughout.
        let (status, _) = http(&server.addr, "GET", "/healthz", &[], "");
        assert_eq!(status, 200);

        // A second server on the same database starts too: no lock file in Postgres mode.
        let second = super::common::spawn_guarded(serve(&db.url()), STARTUP_TIMEOUT);
        let (status, _) = http(&second.addr, "GET", "/healthz", &[], "");
        assert_eq!(status, 200);
    }
}
