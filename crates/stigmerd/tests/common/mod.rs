//! Helpers shared by the stigmerd end-to-end tests.
#![allow(dead_code)] // each test crate uses a different subset

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
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
    start_with(data_dir, &[])
}

/// `stigmerd serve` on an ephemeral loopback port with `extra` flags.
pub fn serve_cmd(data_dir: &Path, extra: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_stigmerd"));
    cmd.args(["serve", "--bind", "127.0.0.1:0", "--data-dir"])
        .arg(data_dir)
        .args(extra);
    cmd
}

pub fn start_with(data_dir: &Path, extra: &[&str]) -> Server {
    spawn_guarded(serve_cmd(data_dir, extra), STARTUP_TIMEOUT)
}

/// Everything the server wrote to stderr so far, collected by a background thread.
#[derive(Clone, Default)]
pub struct Stderr(Arc<Mutex<String>>);

impl Stderr {
    pub fn text(&self) -> String {
        self.0.lock().expect("stderr lock").clone()
    }

    /// Polls until stderr contains `needle`, failing the test after `within`.
    pub fn wait_for(&self, needle: &str, within: Duration) -> String {
        let deadline = Instant::now() + within;
        loop {
            let text = self.text();
            if text.contains(needle) {
                return text;
            }
            assert!(
                Instant::now() < deadline,
                "stderr never contained {needle:?}: {text}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// Like `start_with`, but stderr is captured instead of inherited.
pub fn start_capturing(data_dir: &Path, extra: &[&str]) -> (Server, Stderr) {
    let mut cmd = serve_cmd(data_dir, extra);
    cmd.stderr(Stdio::piped());
    let mut server = spawn_guarded(cmd, STARTUP_TIMEOUT);
    let stderr = Stderr::default();
    let pipe = server.child.stderr.take().expect("piped stderr");
    let sink = stderr.clone();
    std::thread::spawn(move || {
        let mut lines = BufReader::new(pipe);
        let mut line = String::new();
        while lines.read_line(&mut line).is_ok_and(|n| n > 0) {
            sink.0.lock().expect("stderr lock").push_str(&line);
            line.clear();
        }
    });
    (server, stderr)
}

/// Writes `request` as is on a fresh connection and returns everything read until the server
/// closes it (or `RAW_READ_TIMEOUT` passes, which fails the test).
pub fn raw(addr: &str, request: &[u8]) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream.write_all(request).expect("write");
    read_to_close(&mut stream)
}

pub const RAW_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Reads until EOF or a reset; a stream still open after `RAW_READ_TIMEOUT` fails the test.
pub fn read_to_close(stream: &mut TcpStream) -> String {
    stream
        .set_read_timeout(Some(RAW_READ_TIMEOUT))
        .expect("set read timeout");
    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => break,
            Err(e) => panic!("connection still open after {RAW_READ_TIMEOUT:?}: {e}"),
        }
    }
    String::from_utf8_lossy(&raw).into_owned()
}

/// Spawns the command under the Drop guard at once, then waits (bounded) for the
/// listening line. A wrong or missing line fails the test without leaking the child.
pub fn spawn_guarded(mut cmd: Command, wait: Duration) -> Server {
    let mut child = cmd.stdout(Stdio::piped()).spawn().expect("spawn child");
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
        .or_else(|| line.strip_prefix("listening on https://"))
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
