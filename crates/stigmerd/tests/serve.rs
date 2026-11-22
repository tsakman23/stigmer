//! End-to-end tests that run the real stigmerd binary.

mod common;

use std::process::Command;
use std::time::Duration;

use common::{
    http, raw, read_to_close, run_bounded, sigterm, spawn_guarded, start, start_with, wait_for_exit,
};

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
    let out = run_bounded(&["serve", "--bind", "0.0.0.0:0"], dir.path());
    assert_eq!(out.code, Some(2));
    assert!(out.stderr.contains("0.0.0.0"));
    assert!(out.stdout.is_empty());
}

#[cfg(unix)]
#[test]
fn sigterm_ends_a_pending_wait_cleanly() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut server = start(&dir.path().join("data"));
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
    let mut first = start(&dir.path().join("data"));
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

    let second = start(&dir.path().join("data"));
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

#[test]
#[should_panic(expected = "no listening line within")]
fn startup_that_prints_nothing_fails_instead_of_hanging() {
    let mut cmd = Command::new("sleep");
    cmd.arg("30");
    let _ = spawn_guarded(cmd, Duration::from_millis(300));
}

#[test]
#[should_panic(expected = "unexpected first line")]
fn startup_with_a_wrong_first_line_fails() {
    let mut cmd = Command::new("echo");
    cmd.arg("hello");
    let _ = spawn_guarded(cmd, Duration::from_secs(5));
}

#[cfg(unix)]
#[test]
fn sigterm_sent_immediately_after_the_listening_line_exits_0() {
    for i in 0..20 {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut server = start(&dir.path().join("data"));
        sigterm(&server);
        let code = wait_for_exit(&mut server, Duration::from_secs(5));
        assert_eq!(
            code,
            Some(0),
            "iteration {i}: must exit 0, not die from the signal"
        );
    }
}

#[cfg(unix)]
#[test]
fn fresh_data_dir_is_created_with_mode_0700() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    let _server = start(&data);
    let mode = std::fs::metadata(&data)
        .expect("data dir")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o700, "mode {mode:o}");
}

#[cfg(unix)]
#[test]
fn second_serve_on_same_data_dir_fails_with_lock_message() {
    use std::io::Read;
    use std::process::Stdio;
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    let _first = start(&data);
    let child = Command::new(env!("CARGO_BIN_EXE_stigmerd"))
        .args(["serve", "--bind", "127.0.0.1:0", "--data-dir"])
        .arg(&data)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn second serve");
    let mut second = common::Server {
        child,
        addr: String::new(),
    };
    let code = wait_for_exit(&mut second, Duration::from_secs(5));
    assert_eq!(code, Some(1), "second serve must exit 1 and not serve");
    let mut stderr = String::new();
    second
        .child
        .stderr
        .take()
        .expect("piped stderr")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    assert!(
        stderr.contains("data directory is in use by another stigmerd process; stop it first"),
        "stderr: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn database_files_are_0600_and_dir_0700() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    let server = start(&data);
    // Write once so SQLite has created its -wal and -shm files.
    let (status, _) = http(
        &server.addr,
        "POST",
        "/v1/boards/main/messages",
        &[
            ("X-Stigmer-As", "alice"),
            ("Content-Type", "application/json"),
        ],
        r#"{"channel":"eng","text":"hello"}"#,
    );
    assert_eq!(status, 201);
    let mode =
        |p: &std::path::Path| std::fs::metadata(p).expect("metadata").permissions().mode() & 0o777;
    assert_eq!(mode(&data), 0o700);
    for name in ["stigmer.db", "stigmer.db-wal", "stigmer.db-shm"] {
        assert_eq!(mode(&data.join(name)), 0o600, "{name}");
    }
}

#[cfg(unix)]
#[test]
fn lock_file_is_0600() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    let _server = start(&data);
    let mode = std::fs::metadata(data.join("stigmer.lock"))
        .expect("lock file")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "mode {mode:o}");
}

#[test]
fn serve_refuses_non_loopback_bind_in_local_mode() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = run_bounded(&["serve", "--bind", "0.0.0.0:0"], dir.path());
    assert_eq!(out.code, Some(2));
    assert!(out.stderr.contains("0.0.0.0:0"), "stderr: {}", out.stderr);
    assert!(
        out.stderr.contains("needs network mode"),
        "stderr: {}",
        out.stderr
    );
    assert!(out.stdout.is_empty());
}

#[test]
fn serve_refuses_non_loopback_in_network_mode_without_tls_or_trusted_proxy() {
    let dir = tempfile::tempdir().expect("tempdir");
    let enable = run_bounded(&["admin", "enable-auth"], dir.path());
    assert_eq!(enable.code, Some(0));
    let out = run_bounded(&["serve", "--bind", "0.0.0.0:0"], dir.path());
    assert_eq!(out.code, Some(2));
    let err = &out.stderr;
    assert!(err.contains("0.0.0.0:0"), "stderr: {err}");
    assert!(
        err.contains("requires TLS or a trusted proxy"),
        "stderr: {err}"
    );
    assert!(
        err.contains("pass --tls-cert and --tls-key, or --trusted-proxy"),
        "stderr: {err}"
    );
    assert!(out.stdout.is_empty());
}

#[test]
fn serve_refusal_on_a_missing_data_dir_creates_nothing() {
    for bind in ["0.0.0.0:0", "192.0.2.1:7878"] {
        let dir = tempfile::tempdir().expect("tempdir");
        let data = dir.path().join("data");
        let out = run_bounded(&["serve", "--bind", bind], &data);
        assert_eq!(out.code, Some(2), "{bind}: stderr: {}", out.stderr);
        assert!(out.stderr.contains(bind), "{bind}: stderr: {}", out.stderr);
        assert!(
            out.stderr.contains("needs network mode"),
            "stderr: {}",
            out.stderr
        );
        assert!(
            !data.exists(),
            "{bind}: refusal must not create the data dir"
        );
    }
}

#[test]
fn network_mode_on_loopback_serves_plain_http_and_requires_auth() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    let enable = run_bounded(&["admin", "enable-auth"], &data);
    assert_eq!(enable.code, Some(0));
    let server = start(&data);
    assert_eq!(http(&server.addr, "GET", "/healthz", &[], "").0, 200);
    let (status, _) = http(
        &server.addr,
        "GET",
        "/v1/boards/main/events?timeout_s=0",
        &[],
        "",
    );
    assert_eq!(status, 401);
}

#[test]
fn max_connections_closes_the_excess_connection() {
    use std::io::{Read, Write};
    let dir = tempfile::tempdir().expect("tempdir");
    let server = start_with(&dir.path().join("data"), &["--max-connections", "1"]);
    // A keep-alive connection that has been answered is certainly accepted and holds the slot.
    let mut first = std::net::TcpStream::connect(&server.addr).expect("connect");
    first
        .write_all(format!("GET /healthz HTTP/1.1\r\nHost: {}\r\n\r\n", server.addr).as_bytes())
        .expect("write");
    let mut buf = [0u8; 1024];
    let n = first.read(&mut buf).expect("read first response");
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"));

    let excess = raw(
        &server.addr,
        b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    );
    assert!(excess.is_empty(), "the excess connection got: {excess:?}");

    // Closing the first connection frees its slot.
    drop(first);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let reply = raw(
            &server.addr,
            b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        if reply.starts_with("HTTP/1.1 200") {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "slot never freed");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn slow_header_connection_is_closed_after_the_timeout() {
    use std::io::Write;
    let dir = tempfile::tempdir().expect("tempdir");
    let server = start_with(
        &dir.path().join("data"),
        &["--header-read-timeout-ms", "300"],
    );
    // Half a request line, then nothing; and a connection that sends no bytes at all.
    for partial in [&b"GET /healthz HTTP/1.1\r\nHost: 127.0"[..], &b""[..]] {
        let started = std::time::Instant::now();
        let mut stream = std::net::TcpStream::connect(&server.addr).expect("connect");
        stream.write_all(partial).expect("write");
        let reply = read_to_close(&mut stream);
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(3),
            "closed only after {elapsed:?}"
        );
        assert!(!reply.contains(" 200 "), "reply: {reply:?}");
    }
    // A prompt request is still served.
    let (status, _) = http(&server.addr, "GET", "/healthz", &[], "");
    assert_eq!(status, 200);
}

/// Connects to `addr` from the local address `from`, or `None` when the OS has no such address
/// (macOS configures only 127.0.0.1 on the loopback interface by default).
fn connect_from(from: &str, addr: &str) -> Option<std::net::TcpStream> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .expect("runtime");
    let stream = runtime.block_on(async {
        let socket = tokio::net::TcpSocket::new_v4().ok()?;
        socket.bind(from.parse().ok()?).ok()?;
        socket
            .connect(addr.parse().ok()?)
            .await
            .ok()?
            .into_std()
            .ok()
    })?;
    stream.set_nonblocking(false).expect("blocking");
    Some(stream)
}

fn bad_token_request(addr: &str) -> Vec<u8> {
    format!(
        "GET /v1/boards/main/events?timeout_s=0 HTTP/1.1\r\nHost: {addr}\r\n\
         Authorization: Bearer garbage\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

#[cfg(unix)]
#[test]
fn peer_address_is_always_set_in_network_mode() {
    use std::io::Write;
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    assert_eq!(run_bounded(&["admin", "enable-auth"], &data).code, Some(0));
    let mut server = start(&data);
    let auth = [("Authorization", "Bearer garbage")];
    let path = "/v1/boards/main/events?timeout_s=0";
    // The default budget is ten failures a minute per source.
    for _ in 0..10 {
        assert_eq!(http(&server.addr, "GET", path, &auth, "").0, 401);
    }
    assert_eq!(http(&server.addr, "GET", path, &auth, "").0, 429);
    match connect_from("127.0.0.2:0", &server.addr) {
        Some(mut other) => {
            other
                .write_all(&bad_token_request(&server.addr))
                .expect("write");
            let reply = read_to_close(&mut other);
            assert!(
                reply.starts_with("HTTP/1.1 401"),
                "another client must keep its own budget: {reply}"
            );
        }
        // Covered instead by serve::tests::each_connection_is_rate_limited_as_its_own_source.
        None => eprintln!("127.0.0.2 is not available here; skipping the second client"),
    }
    sigterm(&server);
    assert_eq!(wait_for_exit(&mut server, Duration::from_secs(5)), Some(0));
    let log = run_bounded(&["admin", "security-log"], &data);
    assert!(log.stdout.contains("source=127.0.0.1"), "{}", log.stdout);
    assert!(!log.stdout.contains("source=unknown"), "{}", log.stdout);
}

#[test]
fn hidden_timeout_flags_reject_out_of_range_values() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    for (flag, value) in [
        ("--header-read-timeout-ms", "0"),
        ("--header-read-timeout-ms", "60001"),
        ("--tls-reload-interval-ms", "0"),
        ("--tls-reload-interval-ms", "3600001"),
        ("--body-read-timeout-ms", "0"),
        ("--body-read-timeout-ms", "60001"),
        ("--max-connections-per-source", "0"),
        ("--max-connections-per-source", "100001"),
    ] {
        let out = run_bounded(&["serve", "--bind", "127.0.0.1:0", flag, value], &data);
        assert_eq!(out.code, Some(2), "{flag} {value}: {}", out.stderr);
        assert!(out.stderr.contains(value), "{flag} {value}: {}", out.stderr);
        assert!(out.stdout.is_empty());
        assert!(
            !data.exists(),
            "a refused start must not create the data dir"
        );
    }
}

/// A post whose body is announced but arrives in `pieces`, `gap` apart, on one connection;
/// returns the whole response and how long it took.
fn post_in_pieces(addr: &str, pieces: &[&str], gap: Duration) -> (String, Duration) {
    use std::io::Write;
    let started = std::time::Instant::now();
    let body_len: usize = pieces.iter().map(|p| p.len()).sum();
    let mut stream = std::net::TcpStream::connect(addr).expect("connect");
    stream
        .write_all(
            format!(
                "POST /v1/boards/main/messages HTTP/1.1\r\nHost: {addr}\r\n\
                 X-Stigmer-As: alice\r\nContent-Type: application/json\r\n\
                 Connection: close\r\nContent-Length: {body_len}\r\n\r\n"
            )
            .as_bytes(),
        )
        .expect("write head");
    for piece in pieces {
        std::thread::sleep(gap);
        // The server may already have given up on a stalled body and closed the connection.
        if stream.write_all(piece.as_bytes()).is_err() {
            break;
        }
    }
    let reply = read_to_close(&mut stream);
    (reply, started.elapsed())
}

#[test]
fn dripped_body_is_cut_after_the_body_read_timeout() {
    use std::io::Write;
    let dir = tempfile::tempdir().expect("tempdir");
    let server = start_with(&dir.path().join("data"), &["--body-read-timeout-ms", "300"]);
    let started = std::time::Instant::now();
    let mut stream = std::net::TcpStream::connect(&server.addr).expect("connect");
    // Complete headers announcing 100 bytes, then a few bytes, then nothing.
    stream
        .write_all(
            format!(
                "POST /v1/boards/main/messages HTTP/1.1\r\nHost: {}\r\n\
                 X-Stigmer-As: alice\r\nContent-Type: application/json\r\n\
                 Content-Length: 100\r\n\r\n{{\"chan",
                server.addr
            )
            .as_bytes(),
        )
        .expect("write");
    let reply = read_to_close(&mut stream);
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(3),
        "cut only after {elapsed:?}"
    );
    assert!(reply.starts_with("HTTP/1.1 408"), "reply: {reply:?}");
    assert!(
        reply.contains("\"code\":\"request_timeout\""),
        "reply: {reply:?}"
    );
    // Nothing was posted.
    let (_, body) = http(
        &server.addr,
        "GET",
        "/v1/boards/main/channels?prefix=eng",
        &[],
        "",
    );
    assert_eq!(body, r#"{"threads":[]}"#);
}

#[test]
fn slow_but_active_upload_under_the_body_read_timeout_succeeds() {
    let dir = tempfile::tempdir().expect("tempdir");
    let server = start_with(&dir.path().join("data"), &["--body-read-timeout-ms", "500"]);
    let pieces = [
        "{\"chan", "nel\":", "\"eng\",", "\"text", "\":\"sl", "ow up", "load\"", "}",
    ];
    let (reply, elapsed) = post_in_pieces(&server.addr, &pieces, Duration::from_millis(150));
    assert!(
        elapsed > Duration::from_millis(1000),
        "the upload took {elapsed:?}, not longer than the deadline"
    );
    assert!(reply.starts_with("HTTP/1.1 201"), "reply: {reply:?}");
    assert!(reply.contains("slow upload"), "reply: {reply:?}");
}

#[test]
fn max_connections_per_source_closes_the_excess_and_frees_slots_on_close() {
    use std::io::{Read, Write};
    let dir = tempfile::tempdir().expect("tempdir");
    let server = start_with(
        &dir.path().join("data"),
        &["--max-connections-per-source", "2"],
    );
    // Two answered keep-alive connections from 127.0.0.1 hold both of its slots.
    let mut held = Vec::new();
    for _ in 0..2 {
        let mut stream = std::net::TcpStream::connect(&server.addr).expect("connect");
        stream
            .write_all(format!("GET /healthz HTTP/1.1\r\nHost: {}\r\n\r\n", server.addr).as_bytes())
            .expect("write");
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).expect("read response");
        assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"));
        held.push(stream);
    }
    let excess = raw(
        &server.addr,
        b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
    );
    assert!(excess.is_empty(), "the excess connection got: {excess:?}");

    // Another source is not affected (where the OS has a second loopback address).
    match connect_from("127.0.0.2:0", &server.addr) {
        Some(mut other) => {
            other
                .write_all(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                .expect("write");
            let reply = read_to_close(&mut other);
            assert!(reply.starts_with("HTTP/1.1 200"), "other source: {reply:?}");
        }
        // Covered instead by serve::tests::per_source_slots_are_counted_per_source.
        None => eprintln!("127.0.0.2 is not available here; skipping the second source"),
    }

    // Closing one held connection frees its slot.
    drop(held.pop());
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let reply = raw(
            &server.addr,
            b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        if reply.starts_with("HTTP/1.1 200") {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "slot never freed");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn trusted_proxy_covering_every_address_warns_once_and_still_starts() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (server, stderr) = common::start_capturing(
        &dir.path().join("data"),
        &["--trusted-proxy", "0.0.0.0/0,::/0"],
    );
    let (status, _) = http(&server.addr, "GET", "/healthz", &[], "");
    assert_eq!(status, 200);
    let warning =
        "trusted proxy range covers every address: X-Forwarded-For can be forged by anyone";
    let text = stderr.wait_for(warning, Duration::from_secs(5));
    assert_eq!(text.matches(warning).count(), 1, "{text}");

    let dir = tempfile::tempdir().expect("tempdir");
    let (server, stderr) = common::start_capturing(
        &dir.path().join("data"),
        &["--trusted-proxy", "127.0.0.0/8"],
    );
    assert_eq!(http(&server.addr, "GET", "/healthz", &[], "").0, 200);
    assert!(
        !stderr.text().contains("covers every address"),
        "{}",
        stderr.text()
    );
}

#[test]
fn help_documents_the_per_source_cap_and_hides_the_body_timeout() {
    let out = Command::new(env!("CARGO_BIN_EXE_stigmerd"))
        .args(["serve", "--help"])
        .output()
        .expect("run help");
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(help.contains("--max-connections-per-source"), "{help}");
    assert!(help.contains("[default: 64]"), "{help}");
    assert!(!help.contains("--body-read-timeout-ms"), "{help}");
}
