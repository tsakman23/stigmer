//! End-to-end tests that run the real stigmerd binary.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Kills the child on drop so a failing test cannot leak a server process.
struct Server {
    child: Child,
    addr: String,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start(data_dir: &Path) -> Server {
    let mut child = Command::new(env!("CARGO_BIN_EXE_stigmerd"))
        .args(["serve", "--bind", "127.0.0.1:0", "--data-dir"])
        .arg(data_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn stigmerd");
    let stdout = child.stdout.take().expect("piped stdout");
    let mut line = String::new();
    BufReader::new(stdout)
        .read_line(&mut line)
        .expect("read listening line");
    let addr = line
        .strip_prefix("listening on http://")
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or_else(|| panic!("unexpected first line: {line:?}"))
        .to_owned();
    Server { child, addr }
}

/// Sends one HTTP/1.1 request and returns (status, body).
fn http(
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

fn chunked_decoded(head: &str, body: &str) -> String {
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
fn sigterm(server: &Server) {
    let status = Command::new("kill")
        .args(["-TERM", &server.child.id().to_string()])
        .status()
        .expect("run kill");
    assert!(status.success());
}

#[cfg(unix)]
fn wait_for_exit(server: &mut Server, within: Duration) -> Option<i32> {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if let Some(status) = server.child.try_wait().expect("try_wait") {
            return status.code();
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

#[test]
fn serve_starts_and_healthz_answers() {
    let dir = tempfile::tempdir().expect("tempdir");
    let server = start(&dir.path().join("data"));
    let (status, _) = http(&server.addr, "GET", "/healthz", &[], "");
    assert_eq!(status, 200);
    assert!(dir.path().join("data").join("stigmer.db").exists());
}

#[test]
fn serve_refuses_0_0_0_0_with_nonzero_exit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = Command::new(env!("CARGO_BIN_EXE_stigmerd"))
        .args(["serve", "--bind", "0.0.0.0:0", "--data-dir"])
        .arg(dir.path())
        .output()
        .expect("run stigmerd");
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("0.0.0.0"));
    assert!(out.stdout.is_empty());
}

#[cfg(unix)]
#[test]
fn sigterm_ends_a_pending_wait_cleanly() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut server = start(dir.path());
    let addr = server.addr.clone();
    let waiter = std::thread::spawn(move || {
        http(&addr, "GET", "/v1/boards/main/events?timeout_s=60", &[], "")
    });
    // Give the request time to reach the server and park.
    std::thread::sleep(Duration::from_millis(500));
    sigterm(&server);
    let code = wait_for_exit(&mut server, Duration::from_secs(5));
    assert_eq!(code, Some(0), "server must exit 0 within 5s of SIGTERM");
    let (status, body) = waiter.join().expect("waiter thread");
    assert_eq!(status, 200);
    assert!(body.contains("\"timed_out\":true"), "body: {body}");
}

#[cfg(unix)]
#[test]
fn restart_keeps_data() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut first = start(dir.path());
    let (status, body) = http(
        &first.addr,
        "POST",
        "/v1/boards/main/messages",
        &[
            ("X-Stigmer-As", "alice"),
            ("Content-Type", "application/json"),
        ],
        r#"{"channel":"eng","text":"survives restarts"}"#,
    );
    assert_eq!(status, 201, "body: {body}");
    let id = body
        .split("\"id\":\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("message id in response")
        .to_owned();
    sigterm(&first);
    assert_eq!(wait_for_exit(&mut first, Duration::from_secs(5)), Some(0));

    let second = start(dir.path());
    let (status, body) = http(
        &second.addr,
        "GET",
        &format!("/v1/boards/main/threads/{id}"),
        &[],
        "",
    );
    assert_eq!(status, 200, "body: {body}");
    assert!(body.contains("survives restarts"), "body: {body}");
}
