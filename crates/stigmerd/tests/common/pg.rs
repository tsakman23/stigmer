//! Postgres for the stigmerd tests: a schema and a login role with a password on the test
//! database, and a throwaway Postgres server with TLS for the handshake tests.
//!
//! Tests that need the test database skip loudly without `STIGMER_TEST_DATABASE_URL` and fail
//! when `CI` is set, as the store's own Postgres tests do. Tests that need a throwaway server skip
//! loudly when no `initdb` and `pg_ctl` are found, and fail when `CI` is set.

use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use stigmer_store_postgres::testing::{database_url, TestSchema};
use tokio_postgres::config::Host;

use super::tls::TestCa;

/// The variable stigmerd reads the database URL from.
pub const URL_VAR: &str = "STIGMER_DATABASE_URL";

/// Where to look for `initdb` and `pg_ctl` first.
pub const PG_BIN_VAR: &str = "STIGMER_TEST_PG_BIN";

/// `stigmerd` with `args`, and without any `STIGMER_DATABASE_URL` of the caller's.
pub fn stigmerd(args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_stigmerd"));
    cmd.args(args).env_remove(URL_VAR);
    cmd
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
}

/// A schema of its own on the test database and a login role with a password that owns what it
/// creates there; both are dropped at the end.
pub struct PgDb {
    role: String,
    /// The role's password: a test greps for it in everything stigmerd shows.
    pub password: String,
    host: String,
    port: u16,
    dbname: String,
    // Dropped after the role (fields drop after `Drop::drop`).
    pub schema: TestSchema,
}

impl PgDb {
    /// The database for `test`, or `None` (after a loud skip line) without a test database.
    pub fn create(test: &str) -> Option<PgDb> {
        require_with_postgres_module(test);
        let base = database_url(test).unwrap_or_else(|message| panic!("{message}"))?;
        let config: tokio_postgres::Config = base.parse().expect("test database URL");
        let host = match config.get_hosts().first() {
            Some(Host::Tcp(name)) => name.clone(),
            other => panic!("the test database must be reached over TCP, not {other:?}"),
        };
        let port = config.get_ports().first().copied().unwrap_or(5432);
        let dbname = config.get_dbname().expect("test database name").to_owned();
        runtime().block_on(async {
            let schema = TestSchema::create(&base).await.expect("test schema");
            let suffix = unique();
            let role = format!("stigmer_role_{suffix}");
            let password = format!("Pw-{suffix}-x9");
            let client = schema.client().await.expect("client");
            client
                .batch_execute(&format!(
                    "CREATE ROLE {role} LOGIN PASSWORD '{password}';
                     GRANT ALL ON SCHEMA \"{}\" TO {role};",
                    schema.name()
                ))
                .await
                .expect("create role");
            Some(PgDb {
                role,
                password,
                host,
                port,
                dbname,
                schema,
            })
        })
    }

    /// The login role stigmerd connects as.
    pub fn role(&self) -> &str {
        &self.role
    }

    /// The URL of this schema, logging in as the role with its password.
    pub fn url(&self) -> String {
        self.url_on_port(self.port)
    }

    /// `url` with another port, such as one nothing listens on.
    pub fn url_on_port(&self, port: u16) -> String {
        format!(
            "postgres://{}:{}@{}:{port}/{}?options=-c%20search_path%3D{}",
            self.role,
            self.password,
            self.host,
            self.dbname,
            self.schema.name()
        )
    }

    /// The single `bigint` that `sql` returns, read on this schema.
    pub fn query_i64(&self, sql: &str) -> i64 {
        runtime().block_on(async {
            let client = self.schema.client().await.expect("client");
            client.query_one(sql, &[]).await.expect("query").get(0)
        })
    }

    /// Runs `sql` on this schema as the test database's own user.
    pub fn execute(&self, sql: &str) {
        runtime().block_on(async {
            let client = self.schema.client().await.expect("client");
            client.batch_execute(sql).await.expect("sql");
        });
    }
}

impl Drop for PgDb {
    fn drop(&mut self) {
        let role = self.role.clone();
        let schema_url = self.schema.url().to_owned();
        // On a thread of its own: drop may run inside a runtime or while a test panics.
        let dropped = std::thread::spawn(move || {
            runtime().block_on(async {
                let (client, connection) =
                    tokio_postgres::connect(&schema_url, tokio_postgres::NoTls).await?;
                tokio::spawn(connection);
                client
                    .batch_execute(&format!("DROP OWNED BY {role} CASCADE; DROP ROLE {role};"))
                    .await
            })
        })
        .join();
        if !matches!(dropped, Ok(Ok(()))) {
            let _ = writeln!(
                std::io::stderr().lock(),
                "warning: could not drop test role {}",
                self.role
            );
        }
    }
}

/// Fails the calling test unless it runs inside a module named `with_postgres`. CI's check job,
/// which has no database, skips tests by that name and its postgres job runs only them, so a
/// Postgres test anywhere else would fail the one and never run in the other. libtest runs each
/// test on a thread named after its path, so this holds with or without a database.
fn require_with_postgres_module(test: &str) {
    let name = std::thread::current().name().unwrap_or_default().to_owned();
    assert!(
        name.contains("with_postgres::"),
        "{test}: a test that needs Postgres must live in a module named with_postgres \
         (this one runs as {name:?}); see CONTRIBUTING.md"
    );
}

/// `<pid>_<nanos>`: unique across test processes and calls.
fn unique() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    format!("{}_{nanos}", std::process::id())
}

/// The directory holding `initdb` and `pg_ctl`: `STIGMER_TEST_PG_BIN`, then `PATH`, then
/// Homebrew's Postgres 17. `None` after a loud skip line; with `CI` set, a missing pair fails
/// the test instead.
pub fn pg_bin(test: &str) -> Option<PathBuf> {
    require_with_postgres_module(test);
    let has_both = |dir: &Path| dir.join("initdb").is_file() && dir.join("pg_ctl").is_file();
    if let Some(dir) = std::env::var_os(PG_BIN_VAR).filter(|v| !v.is_empty()) {
        let dir = PathBuf::from(dir);
        assert!(
            has_both(&dir),
            "{test}: {PG_BIN_VAR}={} has no initdb and pg_ctl",
            dir.display()
        );
        return Some(dir);
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    let found = std::env::split_paths(&path)
        .chain([PathBuf::from("/opt/homebrew/opt/postgresql@17/bin")])
        .find(|dir| has_both(dir));
    if found.is_none() {
        let ci = std::env::var("CI").is_ok_and(|v| !v.trim().is_empty());
        assert!(
            !ci,
            "{test}: CI is set but no initdb and pg_ctl were found; set {PG_BIN_VAR}"
        );
        let _ = writeln!(
            std::io::stderr().lock(),
            "{test}: SKIPPED: no initdb and pg_ctl found (set {PG_BIN_VAR}), so this test did NOT run"
        );
    }
    found
}

/// A Postgres server of its own in a temporary directory, accepting only TLS connections over
/// TCP on 127.0.0.1 with a certificate from `ca`, user `stigmer` without a password. Stopped
/// (immediately) and deleted on drop. It never touches another server.
pub struct ThrowawayPg {
    bin: PathBuf,
    data: PathBuf,
    pub port: u16,
    _dir: tempfile::TempDir,
}

impl ThrowawayPg {
    pub fn start(bin: &Path, ca: &TestCa) -> ThrowawayPg {
        let dir = tempfile::tempdir().expect("tempdir");
        let data = dir.path().join("data");
        run(Command::new(bin.join("initdb")).arg("-D").arg(&data).args([
            "-U",
            "stigmer",
            "-A",
            "trust",
            "-E",
            "UTF8",
            "--no-locale",
        ]));
        let leaf = ca.leaf();
        std::fs::write(data.join("server.crt"), &leaf.cert_pem).expect("server.crt");
        std::fs::write(data.join("server.key"), &leaf.key_pem).expect("server.key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                data.join("server.key"),
                std::fs::Permissions::from_mode(0o600),
            )
            .expect("chmod server.key");
        }
        let mut conf = std::fs::OpenOptions::new()
            .append(true)
            .open(data.join("postgresql.conf"))
            .expect("postgresql.conf");
        writeln!(
            conf,
            "ssl = on\nssl_cert_file = 'server.crt'\nssl_key_file = 'server.key'\n\
             listen_addresses = '127.0.0.1'\nunix_socket_directories = '{}'\nfsync = off",
            dir.path().display()
        )
        .expect("write postgresql.conf");
        // TLS only over TCP: a plain connection finds no matching rule and is refused.
        std::fs::write(
            data.join("pg_hba.conf"),
            "hostssl all all 127.0.0.1/32 trust\nlocal all all trust\n",
        )
        .expect("pg_hba.conf");
        // A free port can be taken between choosing it and the server binding it, so a failed
        // start is tried again on another port (a handful of times at most).
        for _ in 0..5 {
            let port = free_port();
            let started = Command::new(bin.join("pg_ctl"))
                .arg("-D")
                .arg(&data)
                .arg("-l")
                .arg(dir.path().join("server.log"))
                .args(["-w", "-t", "60", "-o", &format!("-p {port}"), "start"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("run pg_ctl");
            if started.success() {
                return ThrowawayPg {
                    bin: bin.to_owned(),
                    data,
                    port,
                    _dir: dir,
                };
            }
        }
        let log = std::fs::read_to_string(dir.path().join("server.log")).unwrap_or_default();
        panic!("the throwaway Postgres did not start: {log}");
    }
}

impl Drop for ThrowawayPg {
    fn drop(&mut self) {
        let _ = Command::new(self.bin.join("pg_ctl"))
            .arg("-D")
            .arg(&self.data)
            .args(["-m", "immediate", "-w", "stop"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.local_addr().expect("local addr").port()
}

fn run(cmd: &mut Command) {
    let out = cmd.output().expect("run");
    assert!(
        out.status.success(),
        "{cmd:?} failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
