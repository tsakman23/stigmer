//! Helpers shared by the stigmerd end-to-end tests.
#![allow(dead_code)] // each test crate uses a different subset

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);

/// Kills the child on drop so a failing test cannot leak a server process.
pub struct Server {
    pub child: Child,
    pub addr: String,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn start(data_dir: &Path) -> Server {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_stigmerd"));
    cmd.args(["serve", "--bind", "127.0.0.1:0", "--data-dir"])
        .arg(data_dir);
    spawn_guarded(cmd, STARTUP_TIMEOUT)
}

/// Spawns the command under the Drop guard at once, then waits (bounded) for the
/// listening line. A wrong or missing line fails the test without leaking the child.
pub fn spawn_guarded(mut cmd: Command, wait: Duration) -> Server {
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn child");
    let stdout = child.stdout.take().expect("piped stdout");
    let mut server = Server {
        child,
        addr: String::new(),
    };
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let _ = BufReader::new(stdout).read_line(&mut line);
        let _ = tx.send(line);
    });
    let line = rx
        .recv_timeout(wait)
        .unwrap_or_else(|_| panic!("no listening line within {wait:?}"));
    server.addr = line
        .strip_prefix("listening on http://")
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or_else(|| panic!("unexpected first line: {line:?}"))
        .to_owned();
    server
}

/// Sends one HTTP/1.1 request and returns (status, body).
pub fn http(
    addr: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).expect("connect");
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
    stream.write_all(req.as_bytes()).expect("write");
    let mut raw = String::new();
    stream.read_to_string(&mut raw).expect("read");
    let (head, body) = raw.split_once("\r\n\r\n").expect("http response");
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("status code");
    (status, chunked_decoded(head, body))
}

pub fn chunked_decoded(head: &str, body: &str) -> String {
    if !head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        return body.to_owned();
    }
    let mut out = String::new();
    let mut rest = body;
    while let Some((size, tail)) = rest.split_once("\r\n") {
        let n = usize::from_str_radix(size.trim(), 16).unwrap_or(0);
        if n == 0 || tail.len() < n {
            break;
        }
        out.push_str(&tail[..n]);
        rest = tail[n..].trim_start_matches("\r\n");
    }
    out
}

#[cfg(unix)]
pub fn sigterm(server: &Server) {
    let status = Command::new("kill")
        .args(["-TERM", &server.child.id().to_string()])
        .status()
        .expect("run kill");
    assert!(status.success());
}

#[cfg(unix)]
pub fn wait_for_exit(server: &mut Server, within: Duration) -> Option<i32> {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if let Some(status) = server.child.try_wait().expect("try_wait") {
            return status.code();
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

/// What a bounded run of the binary printed and how it ended.
pub struct Bounded {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

/// Runs `stigmerd <args> --data-dir <data>` to completion. The child sits under the Drop
/// guard, so if it has not exited within `RUN_TIMEOUT` the test fails and the child is killed.
pub fn run_bounded(args: &[&str], data: &Path) -> Bounded {
    let child = Command::new(env!("CARGO_BIN_EXE_stigmerd"))
        .args(args)
        .arg("--data-dir")
        .arg(data)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn stigmerd");
    let mut guarded = Server {
        child,
        addr: String::new(),
    };
    let deadline = Instant::now() + RUN_TIMEOUT;
    let code = loop {
        if let Some(status) = guarded.child.try_wait().expect("try_wait") {
            break status.code();
        }
        assert!(
            Instant::now() < deadline,
            "stigmerd {args:?} did not exit within {RUN_TIMEOUT:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    let read = |pipe: Option<&mut dyn Read>| {
        let mut text = String::new();
        if let Some(pipe) = pipe {
            pipe.read_to_string(&mut text).expect("read pipe");
        }
        text
    };
    Bounded {
        code,
        stdout: read(guarded.child.stdout.as_mut().map(|p| p as &mut dyn Read)),
        stderr: read(guarded.child.stderr.as_mut().map(|p| p as &mut dyn Read)),
    }
}

const RUN_TIMEOUT: Duration = Duration::from_secs(10);
