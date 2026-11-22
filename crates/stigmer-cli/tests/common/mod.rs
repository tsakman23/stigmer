//! Helpers shared by the stigmer-cli end-to-end tests: build and locate the binaries, start the
//! real stigmerd under a kill-on-drop guard, run the CLI with an isolated environment, and a tiny
//! capture server that records what the CLI sends.
#![allow(dead_code)] // each test crate uses a different subset

pub mod fixtures;
pub mod tls;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

pub const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);

/// Environment variables the CLI reads; every run starts with them cleared.
pub const CLI_ENV: [&str; 5] = [
    "STIGMER_AS",
    "STIGMER_URL",
    "STIGMER_BOARD",
    "STIGMER_TOKEN",
    "STIGMER_CA_CERT",
];

/// Clears every variable the CLI reads and points HOME and XDG_CONFIG_HOME at a directory under
/// the test target dir, so no developer login or setting can leak into a run. For tests that
/// never save a login (local mode); `CliUser` gives each user its own directory instead.
pub fn isolate(cmd: &mut Command) -> &mut Command {
    let home = Path::new(env!("CARGO_TARGET_TMPDIR")).join("isolated-home");
    for name in CLI_ENV {
        cmd.env_remove(name);
    }
    cmd.env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join("config"))
}

fn bin_dir() -> PathBuf {
    let target = std::env::var_os("CARGO_TARGET_DIR").map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target"),
        PathBuf::from,
    );
    target.join("debug")
}

/// Builds both binaries once per test process and returns their directory.
fn built_bin_dir() -> &'static PathBuf {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let status = Command::new(cargo)
            .args([
                "build",
                "-q",
                "--locked",
                "-p",
                "stigmerd",
                "-p",
                "stigmer-cli",
            ])
            .status()
            .expect("run cargo build");
        assert!(status.success(), "cargo build failed");
        bin_dir()
    })
}

/// The path of a freshly built workspace binary.
pub fn bin(name: &str) -> PathBuf {
    let file = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_owned()
    };
    built_bin_dir().join(file)
}

/// Kills the child on drop so a failing test cannot leak a process. The child is put under the
/// guard straight from spawn.
pub struct Guard(pub Child);

impl Guard {
    pub fn spawn(cmd: &mut Command) -> Self {
        Self(cmd.spawn().expect("spawn child"))
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// What one CLI run printed and how it ended.
#[derive(Debug)]
pub struct Run {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Run {
    /// Everything printed, for "never printed" checks.
    pub fn all(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }
}

/// One CLI user: its own HOME and XDG_CONFIG_HOME, so logins never leak between tests or into
/// the developer's real config.
pub struct CliUser {
    home: tempfile::TempDir,
}

impl CliUser {
    pub fn new() -> Self {
        Self {
            home: tempfile::tempdir().expect("temp home"),
        }
    }

    pub fn home(&self) -> &Path {
        self.home.path()
    }

    pub fn config_home(&self) -> PathBuf {
        self.home.path().join("config")
    }

    /// Where this user's login file lives.
    pub fn logins_path(&self) -> PathBuf {
        self.config_home().join("stigmer").join("logins.json")
    }

    /// `stigmer <args>` with STIGMER_* cleared and this user's HOME and XDG_CONFIG_HOME.
    pub fn cmd(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_stigmer"));
        for name in CLI_ENV {
            cmd.env_remove(name);
        }
        cmd.env("HOME", self.home.path())
            .env("XDG_CONFIG_HOME", self.config_home())
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        cmd
    }

    pub fn run(&self, args: &[&str]) -> Run {
        self.run_env(args, &[])
    }

    /// Runs to completion within `RUN_TIMEOUT`; a run that takes longer fails the test and
    /// its process is killed.
    pub fn run_env(&self, args: &[&str], env: &[(&str, &str)]) -> Run {
        let mut cmd = self.cmd(args);
        cmd.envs(env.iter().copied());
        finish(Guard::spawn(&mut cmd), RUN_TIMEOUT)
    }

    /// Runs with `input` on stdin.
    pub fn run_stdin(&self, args: &[&str], input: &str) -> Run {
        let mut cmd = self.cmd(args);
        cmd.stdin(Stdio::piped());
        let mut child = Guard::spawn(&mut cmd);
        let mut stdin = child.0.stdin.take().expect("piped stdin");
        stdin.write_all(input.as_bytes()).expect("write stdin");
        drop(stdin);
        finish(child, RUN_TIMEOUT)
    }
}

/// How long a CLI run that is not waiting on events may take.
pub const RUN_TIMEOUT: Duration = Duration::from_secs(20);

/// Waits (bounded) for a guarded child with piped output to exit and returns what it printed.
/// Its pipes are drained while it runs, so a large output cannot stall it. A child still running
/// after `within` fails the test, and the guard kills it.
pub fn finish(mut child: Guard, within: Duration) -> Run {
    let (stdout, stderr) = (Collected::default(), Collected::default());
    let readers = [
        child.0.stdout.take().map(|pipe| stdout.drain(pipe)),
        child.0.stderr.take().map(|pipe| stderr.drain(pipe)),
    ];
    let deadline = Instant::now() + within;
    let status = loop {
        if let Some(status) = child.0.try_wait().expect("try_wait") {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "child did not exit in {within:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    for reader in readers.into_iter().flatten() {
        let _ = reader.join();
    }
    Run {
        code: status.code().unwrap_or(-1),
        stdout: stdout.text(),
        stderr: stderr.text(),
    }
}

impl Default for CliUser {
    fn default() -> Self {
        Self::new()
    }
}

/// A one-response-per-connection HTTP server that records every request head it receives.
pub struct Capture {
    pub url: String,
    requests: mpsc::Receiver<String>,
}

impl Capture {
    /// Answers every request with `status` and the JSON `body`.
    pub fn start(status: u16, body: &str) -> Self {
        Self::start_with(status, "", body)
    }

    /// Answers every request with a 302 to `location`.
    pub fn redirect(location: &str) -> Self {
        Self::start_with(302, &format!("Location: {location}\r\n"), "{}")
    }

    /// Answers every request with `status`, the extra header lines `headers` (each ending in
    /// CRLF) and the JSON `body`.
    pub fn start_with(status: u16, headers: &str, body: &str) -> Self {
        let headers = headers.to_owned();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind capture server");
        let url = format!("http://{}", listener.local_addr().expect("capture addr"));
        let (tx, requests) = mpsc::channel();
        let body = body.to_owned();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
                let mut head = String::new();
                let mut length = 0usize;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = value.trim().parse().unwrap_or(0);
                    }
                    head.push_str(&line);
                }
                let mut sink = vec![0u8; length];
                let _ = reader.read_exact(&mut sink);
                let response = format!(
                    "HTTP/1.1 {status} X\r\n{headers}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                if tx.send(head).is_err() {
                    break;
                }
            }
        });
        Self { url, requests }
    }

    /// The next request head, failing the test if none arrives soon.
    pub fn request(&self) -> String {
        self.requests
            .recv_timeout(STARTUP_TIMEOUT)
            .expect("the CLI sent no request")
    }

    /// True if a request arrived (without waiting).
    pub fn saw_request(&self) -> bool {
        self.requests.try_recv().is_ok()
    }
}

/// Everything a child wrote to a pipe so far, collected by a background thread.
#[derive(Clone, Default)]
pub struct Collected(Arc<Mutex<String>>);

impl Collected {
    pub fn text(&self) -> String {
        self.0.lock().expect("collected lock").clone()
    }

    /// Polls until the text contains `needle`, failing the test after `within`.
    pub fn wait_for(&self, needle: &str, within: Duration) -> String {
        let deadline = Instant::now() + within;
        loop {
            let text = self.text();
            if text.contains(needle) {
                return text;
            }
            assert!(Instant::now() < deadline, "never saw {needle:?} in: {text}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Appends everything `pipe` yields, line by line, from a background thread, which ends
    /// when the pipe closes.
    pub fn drain(&self, pipe: impl Read + Send + 'static) -> std::thread::JoinHandle<()> {
        let sink = self.clone();
        std::thread::spawn(move || {
            let mut lines = BufReader::new(pipe);
            let mut line = String::new();
            while lines.read_line(&mut line).is_ok_and(|n| n > 0) {
                sink.0.lock().expect("collected lock").push_str(&line);
                line.clear();
            }
        })
    }
}

/// A running stigmerd and its throwaway data directory.
pub struct Stigmerd {
    guard: Option<Guard>,
    pub addr: String,
    /// `http://addr` or `https://addr`.
    pub url: String,
    pub stderr: Collected,
    dir: tempfile::TempDir,
    extra: Vec<String>,
    /// Printed by `stigmerd admin enable-auth` (network mode only).
    pub instance_token: Option<String>,
    /// The single-use admin invite into `main` (network mode only).
    pub main_invite: Option<String>,
}

impl Stigmerd {
    /// A local-mode server (no auth, as in v0.1.0) on an ephemeral loopback port.
    pub fn local() -> Self {
        Self::start(false, Vec::new())
    }

    /// A network-mode server: `admin enable-auth` first, keeping the instance token and the
    /// main admin invite it prints.
    pub fn network() -> Self {
        Self::start(true, Vec::new())
    }

    /// A network-mode server serving TLS with a leaf from a fresh test CA; returns the
    /// server and the CA's PEM file. The PEM files live in their own temp dir.
    pub fn tls() -> (Self, tls::TlsFiles, tempfile::TempDir) {
        let pem_dir = tempfile::tempdir().expect("pem dir");
        let files = tls::TlsFiles::generate(pem_dir.path());
        let extra = vec![
            "--tls-cert".to_owned(),
            files.cert.display().to_string(),
            "--tls-key".to_owned(),
            files.key.display().to_string(),
        ];
        (Self::start(true, extra), files, pem_dir)
    }

    fn data_dir(dir: &Path) -> PathBuf {
        // A fresh subdirectory, so stigmerd creates it 0700 and has nothing to warn about.
        dir.join("data")
    }

    fn start(network: bool, extra: Vec<String>) -> Self {
        let dir = tempfile::tempdir().expect("temp data dir");
        let mut server = Self {
            guard: None,
            addr: String::new(),
            url: String::new(),
            stderr: Collected::default(),
            dir,
            extra,
            instance_token: None,
            main_invite: None,
        };
        if network {
            server.enable_auth();
        }
        server.serve("127.0.0.1:0");
        server
    }

    /// Runs `stigmerd admin enable-auth` and keeps the secrets it prints once.
    fn enable_auth(&mut self) {
        let out = Command::new(bin("stigmerd"))
            .args(["admin", "enable-auth", "--data-dir"])
            .arg(Self::data_dir(self.dir.path()))
            .output()
            .expect("run stigmerd admin enable-auth");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "enable-auth failed: {stdout}");
        let value = |prefix: &str| {
            stdout
                .lines()
                .find_map(|line| line.strip_prefix(prefix))
                .map(str::to_owned)
        };
        self.instance_token = value("instance token: ");
        self.main_invite = value("main admin invite: ");
        assert!(
            self.instance_token.is_some(),
            "no instance token in {stdout}"
        );
    }

    fn serve(&mut self, bind: &str) {
        let mut cmd = Command::new(bin("stigmerd"));
        cmd.args(["serve", "--bind", bind, "--data-dir"])
            .arg(Self::data_dir(self.dir.path()))
            .args(&self.extra)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut guard = Guard::spawn(&mut cmd);
        let stdout = guard.0.stdout.take().expect("piped stdout");
        self.stderr
            .drain(guard.0.stderr.take().expect("piped stderr"));
        self.guard = Some(guard);
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let _ = BufReader::new(stdout).read_line(&mut line);
            let _ = tx.send(line);
        });
        let line = rx.recv_timeout(STARTUP_TIMEOUT).unwrap_or_else(|_| {
            panic!(
                "no listening line within {STARTUP_TIMEOUT:?}; stderr: {}",
                self.stderr.text()
            )
        });
        let (scheme, rest) = line
            .strip_prefix("listening on http://")
            .map(|rest| ("http", rest))
            .or_else(|| {
                line.strip_prefix("listening on https://")
                    .map(|rest| ("https", rest))
            })
            .unwrap_or_else(|| panic!("unexpected first line: {line:?}"));
        self.addr = rest
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_owned();
        self.url = format!("{scheme}://{}", self.addr);
    }

    /// Kills the server and starts it again on the same address and data directory.
    pub fn restart_after(&mut self, down_for: Duration) {
        drop(self.guard.take());
        std::thread::sleep(down_for);
        let addr = self.addr.clone();
        self.serve(&addr);
    }
}
