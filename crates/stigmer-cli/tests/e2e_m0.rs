//! The M0 exit test: two agents talk through the real stigmerd and stigmer binaries.

use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, OnceLock};
use std::time::{Duration, Instant};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);

/// Kills the child on drop so a failing test cannot leak a process.
struct Guard(Child);

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Output {
    code: i32,
    stdout: String,
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

fn bin(name: &str) -> PathBuf {
    let file = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_owned()
    };
    built_bin_dir().join(file)
}

struct Server {
    _guard: Guard,
    url: String,
    _data: tempfile_dir::Dir,
}

/// A throwaway data directory removed on drop (std only, no extra dependency).
mod tempfile_dir {
    use std::path::{Path, PathBuf};

    pub struct Dir(PathBuf);

    impl Dir {
        pub fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "stigmer-e2e-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos())
            ));
            std::fs::create_dir_all(&path).expect("create data dir");
            Self(path)
        }

        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

fn start_server() -> Server {
    let data = tempfile_dir::Dir::new();
    let mut child = Command::new(bin("stigmerd"))
        .args(["serve", "--bind", "127.0.0.1:0", "--data-dir"])
        // A fresh subdirectory, so stigmerd creates it 0700 and has nothing to warn about.
        .arg(data.path().join("data"))
        .env_remove("STIGMER_AS")
        .env_remove("STIGMER_URL")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn stigmerd");
    let stdout = child.stdout.take().expect("piped stdout");
    let guard = Guard(child);
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let _ = BufReader::new(stdout).read_line(&mut line);
        let _ = tx.send(line);
    });
    let line = rx
        .recv_timeout(STARTUP_TIMEOUT)
        .unwrap_or_else(|_| panic!("no listening line within {STARTUP_TIMEOUT:?}"));
    let addr = line
        .strip_prefix("listening on http://")
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or_else(|| panic!("unexpected first line: {line:?}"));
    Server {
        _guard: guard,
        url: format!("http://{addr}"),
        _data: data,
    }
}

fn stigmer(server: &Server, who: &str, args: &[&str]) -> Command {
    let mut cmd = Command::new(bin("stigmer"));
    cmd.args(["--url", &server.url, "--as", who])
        .args(args)
        .env_remove("STIGMER_AS")
        .env_remove("STIGMER_URL")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

fn run(server: &Server, who: &str, args: &[&str]) -> Output {
    let out = stigmer(server, who, args).output().expect("run stigmer");
    Output {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
    }
}

/// Waits for a spawned child to exit within the bound and returns its output.
fn finish(mut child: Guard, within: Duration) -> Output {
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
    let mut stdout = String::new();
    if let Some(mut pipe) = child.0.stdout.take() {
        let _ = pipe.read_to_string(&mut stdout);
    }
    Output {
        code: status.code().unwrap_or(-1),
        stdout,
    }
}

fn spawn(server: &Server, who: &str, args: &[&str]) -> Guard {
    Guard(stigmer(server, who, args).spawn().expect("spawn stigmer"))
}

fn thread_id_from(line_source: &str) -> String {
    line_source
        .split_whitespace()
        .find(|w| w.starts_with("msg_"))
        .unwrap_or_else(|| panic!("no thread id in {line_source:?}"))
        .to_owned()
}

#[test]
fn agent_c_wakes_on_agent_a_post_and_a_sees_the_reply() {
    let server = start_server();
    let mut waiter = spawn(
        &server,
        "agent-c",
        &["wait", "--channel", "research/", "--timeout", "30s"],
    );
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        waiter.0.try_wait().expect("try_wait").is_none(),
        "the waiter must still be blocked before anything is posted"
    );

    let posted = run(
        &server,
        "agent-a",
        &[
            "post",
            "research/tls",
            "Which TLS versions must we support?",
        ],
    );
    assert_eq!(posted.code, 0, "post failed: {}", posted.stdout);
    let thread = thread_id_from(&posted.stdout);

    let woke = finish(waiter, Duration::from_secs(20));
    assert_eq!(woke.code, 0, "wait output: {}", woke.stdout);
    let lines: Vec<&str> = woke.stdout.lines().collect();
    let frame_start = lines
        .iter()
        .position(|l| l.starts_with("<<<message "))
        .expect("frame start line");
    let frame_end = lines
        .iter()
        .position(|l| l.starts_with("<<<end "))
        .expect("frame end line");
    let inside = lines[frame_start + 1..frame_end].join("\n");
    assert!(frame_start < frame_end);
    assert_eq!(inside, "Which TLS versions must we support?");
    assert!(lines.iter().any(|l| l.starts_with("cursor: ")));
    assert!(lines.iter().any(|l| l.starts_with("resume: ")));

    let replied = run(
        &server,
        "agent-c",
        &["reply", &thread, "TLS 1.2 and 1.3 only."],
    );
    assert_eq!(replied.code, 0, "reply failed: {}", replied.stdout);

    let shown = run(&server, "agent-a", &["thread", &thread]);
    assert_eq!(shown.code, 0);
    let first = shown
        .stdout
        .find("Which TLS versions must we support?")
        .expect("original message shown");
    let second = shown
        .stdout
        .find("TLS 1.2 and 1.3 only.")
        .expect("reply shown");
    assert!(first < second, "messages out of order:\n{}", shown.stdout);
}

#[test]
fn post_in_another_channel_does_not_wake_a_wait() {
    let server = start_server();
    let posted = run(&server, "agent-a", &["post", "other/x", "unrelated"]);
    assert_eq!(posted.code, 0);

    let waited = run(
        &server,
        "agent-c",
        &["wait", "--channel", "research/", "--timeout", "1s"],
    );
    assert_eq!(waited.code, 3, "output: {}", waited.stdout);
    assert!(!waited.stdout.contains("unrelated"));
}

#[test]
fn wait_without_after_replays_history_and_after_cursor_waits_for_new() {
    let server = start_server();
    let first = run(&server, "agent-a", &["post", "research/tls", "old news"]);
    assert_eq!(first.code, 0);

    let replay = run(
        &server,
        "agent-c",
        &["wait", "--channel", "research/", "--timeout", "5s"],
    );
    assert_eq!(replay.code, 0, "output: {}", replay.stdout);
    assert!(replay.stdout.contains("old news"));
    let cursor = replay
        .stdout
        .lines()
        .find_map(|l| l.strip_prefix("cursor: "))
        .expect("cursor line")
        .to_owned();

    let nothing = run(
        &server,
        "agent-c",
        &[
            "wait",
            "--channel",
            "research/",
            "--after",
            &cursor,
            "--timeout",
            "1s",
        ],
    );
    assert_eq!(nothing.code, 3, "output: {}", nothing.stdout);
    assert!(!nothing.stdout.contains("old news"));

    let second = run(&server, "agent-a", &["post", "research/tls", "fresh news"]);
    assert_eq!(second.code, 0);
    let fresh = run(
        &server,
        "agent-c",
        &[
            "wait",
            "--channel",
            "research/",
            "--after",
            &cursor,
            "--timeout",
            "5s",
        ],
    );
    assert_eq!(fresh.code, 0, "output: {}", fresh.stdout);
    assert!(fresh.stdout.contains("fresh news"));
    assert!(!fresh.stdout.contains("old news"));
    assert_eq!(fresh.stdout.matches("<<<message ").count(), 1);
}
