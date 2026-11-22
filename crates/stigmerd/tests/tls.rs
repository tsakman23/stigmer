//! End-to-end checks of the TLS listener, certificate reload, trusted proxies and allowed hosts,
//! against the real binary.

mod common;

use std::path::Path;
use std::time::Duration;

use common::tls::{
    get, https_get, https_raw, idle_after_handshake, request, tls_error, PairFiles, TestCa, TLS12,
    TLS13,
};
use common::{http, raw, run_bounded, start, start_capturing, start_with, Server};

/// A network-mode data dir under `dir`.
fn network_data(dir: &Path) -> std::path::PathBuf {
    let data = dir.join("data");
    let out = run_bounded(&["admin", "enable-auth", "--no-main-invite"], &data);
    assert_eq!(out.code, Some(0), "{}", out.stderr);
    data
}

/// A network-mode server with TLS from a fresh CA; returns the server, CA, files and first leaf.
fn tls_server(dir: &Path, extra: &[&str]) -> (Server, TestCa, PairFiles, Vec<u8>) {
    let data = network_data(dir);
    let ca = TestCa::new();
    let leaf = ca.leaf();
    let files = PairFiles::in_dir(dir);
    files.write(&leaf);
    let mut flags = files.flags();
    flags.extend(extra.iter().map(|s| (*s).to_owned()));
    let flags: Vec<&str> = flags.iter().map(String::as_str).collect();
    let server = start_with(&data, &flags);
    (server, ca, files, leaf.der)
}

fn header<'a>(response: &'a str, name: &str) -> Option<&'a str> {
    let head = response.split("\r\n\r\n").next()?;
    head.lines().find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

#[test]
fn tls_serves_https_and_rejects_tls12_clients() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (server, ca, _files, leaf) = tls_server(dir.path(), &[]);
    let reply = https_get(&server.addr, &ca, "/healthz", &[]);
    assert!(
        reply.response.starts_with("HTTP/1.1 200"),
        "{}",
        reply.response
    );
    assert_eq!(reply.peer_cert, leaf);
    let refused = https_raw(&server.addr, ca.client(&TLS12), &get("/healthz", &[]));
    assert!(refused.is_err(), "a TLS 1.2 client must not get a response");
}

#[test]
fn listening_line_names_https_when_tls_is_on() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = network_data(dir.path());
    let ca = TestCa::new();
    let files = PairFiles::in_dir(dir.path());
    files.write(&ca.leaf());
    let mut cmd = common::serve_cmd(&data, &[]);
    cmd.args(files.flags());
    let mut child = cmd
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn");
    let mut line = String::new();
    std::io::BufRead::read_line(
        &mut std::io::BufReader::new(child.stdout.take().expect("stdout")),
        &mut line,
    )
    .expect("read line");
    let _guard = Server {
        child,
        addr: String::new(),
    };
    assert!(
        line.starts_with("listening on https://127.0.0.1:"),
        "{line}"
    );
}

#[test]
fn plain_http_to_a_tls_port_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (server, _ca, _files, _leaf) = tls_server(dir.path(), &[]);
    let reply = raw(&server.addr, &get("/healthz", &[]));
    assert!(!reply.contains("HTTP/"), "plain HTTP got: {reply:?}");
}

#[test]
fn hsts_header_present_on_tls_only() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (server, ca, _files, _leaf) = tls_server(dir.path(), &[]);
    for path in ["/healthz", "/v1/boards/main/events", "/no/such/route"] {
        let reply = https_get(&server.addr, &ca, path, &[]);
        assert_eq!(
            header(&reply.response, "strict-transport-security"),
            Some("max-age=31536000"),
            "{path}: {}",
            reply.response
        );
    }
    let plain_dir = tempfile::tempdir().expect("tempdir");
    let plain = start(&network_data(plain_dir.path()));
    let reply = raw(&plain.addr, &get("/healthz", &[]));
    assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    assert_eq!(header(&reply, "strict-transport-security"), None, "{reply}");
}

#[test]
fn tls_requires_both_cert_and_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = network_data(dir.path());
    let files = PairFiles::in_dir(dir.path());
    files.write(&TestCa::new().leaf());
    let cert = files.cert.display().to_string();
    let key = files.key.display().to_string();
    for args in [["--tls-cert", cert.as_str()], ["--tls-key", key.as_str()]] {
        let mut all = vec!["serve", "--bind", "127.0.0.1:0"];
        all.extend(args);
        let out = run_bounded(&all, &data);
        assert_eq!(out.code, Some(2), "{args:?}: {}", out.stderr);
        assert!(out.stderr.contains("--tls-"), "{}", out.stderr);
        assert!(out.stdout.is_empty());
    }
}

#[test]
fn mismatched_cert_and_key_at_startup_exits_1_without_printing_key_material() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ca = TestCa::new();
    let files = PairFiles::in_dir(dir.path());
    let other = ca.leaf();
    files.write_cert(&ca.leaf().cert_pem);
    files.write_key(&other.key_pem);
    let data = dir.path().join("data");
    let mut args = vec![
        "serve".to_owned(),
        "--bind".to_owned(),
        "127.0.0.1:0".to_owned(),
    ];
    args.extend(files.flags());
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = run_bounded(&args, &data);
    assert_eq!(out.code, Some(1), "{}", out.stderr);
    assert!(out.stderr.contains("does not match"), "{}", out.stderr);
    assert!(out.stderr.contains("key.pem"), "{}", out.stderr);
    let body: Vec<&str> = other
        .key_pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    for text in [&out.stderr, &out.stdout] {
        assert!(!text.contains("PRIVATE KEY"), "{text}");
        for line in &body {
            assert!(!text.contains(line), "key material printed: {text}");
        }
    }
    assert!(
        !data.exists(),
        "a refused start must not create the data dir"
    );
    // An unreadable key is the same kind of failure.
    std::fs::remove_file(&files.key).expect("remove key");
    let out = run_bounded(&args, &data);
    assert_eq!(out.code, Some(1), "{}", out.stderr);
    assert!(out.stderr.contains("key.pem"), "{}", out.stderr);
}

#[cfg(unix)]
#[test]
fn key_file_group_readable_warns() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("tempdir");
    let data = network_data(dir.path());
    let ca = TestCa::new();
    let files = PairFiles::in_dir(dir.path());
    files.write(&ca.leaf());
    std::fs::set_permissions(&files.key, std::fs::Permissions::from_mode(0o640)).expect("chmod");
    let flags = files.flags();
    let flags: Vec<&str> = flags.iter().map(String::as_str).collect();
    let (server, stderr) = start_capturing(&data, &flags);
    let text = stderr.wait_for("group or others", Duration::from_secs(5));
    assert!(text.contains("key.pem"), "{text}");
    // A warning only: the server still serves.
    let reply = https_get(&server.addr, &ca, "/healthz", &[]);
    assert!(reply.response.starts_with("HTTP/1.1 200"));
}

#[test]
fn m0_serve_tests_still_pass_in_local_mode() {
    // The full M0 suite is tests/serve.rs; this is the local-mode smoke check beside TLS.
    let dir = tempfile::tempdir().expect("tempdir");
    let server = start(&dir.path().join("data"));
    let (status, body) = http(
        &server.addr,
        "POST",
        "/v1/boards/main/messages",
        &[
            ("X-Stigmer-As", "alice"),
            ("Content-Type", "application/json"),
        ],
        r#"{"channel":"eng","text":"still local"}"#,
    );
    assert_eq!(status, 201, "{body}");
    let (status, body) = http(&server.addr, "GET", "/v1/boards/main/events", &[], "");
    assert_eq!(status, 200);
    assert!(body.contains(r#""actor":"alice""#), "{body}");
    let reply = raw(&server.addr, &get("/healthz", &[]));
    assert_eq!(header(&reply, "strict-transport-security"), None);
}

/// Polls new TLS connections until one presents `der`. Every handshake on the way must succeed.
fn wait_for_cert(addr: &str, ca: &TestCa, der: &[u8], within: Duration) {
    let deadline = std::time::Instant::now() + within;
    loop {
        if https_get(addr, ca, "/healthz", &[]).peer_cert == der {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "new certificate not served within {within:?}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// For `checks` polls, every new connection completes its handshake and presents `der`.
fn keeps_serving(addr: &str, ca: &TestCa, der: &[u8], checks: u32) {
    for i in 0..checks {
        let reply = https_raw(addr, ca.client(&TLS13), &get("/healthz", &[]))
            .unwrap_or_else(|e| panic!("check {i}: handshake failed: {e}"));
        assert_eq!(reply.peer_cert, der, "check {i}: a different certificate");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Joins main through the invite `enable-auth` printed; returns a member token.
fn join_main(addr: &str, ca: &TestCa, invite: &str) -> String {
    let body = format!(r#"{{"invite":"{invite}","name":"alice"}}"#);
    let req = request(
        "POST",
        "/v1/join",
        &[("Content-Type", "application/json")],
        &body,
    );
    let reply = https_raw(addr, ca.client(&TLS13), &req).expect("join");
    assert!(
        reply.response.starts_with("HTTP/1.1 201"),
        "{}",
        reply.response
    );
    let body = reply.response.split("\r\n\r\n").nth(1).expect("body");
    body.split(r#""token":""#)
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("token in join response")
        .to_owned()
}

const RELOAD_FLAGS: [&str; 2] = ["--tls-reload-interval-ms", "100"];

#[test]
fn cert_reload_serves_the_new_certificate_without_dropping_a_pending_wait() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    let enabled = run_bounded(&["admin", "enable-auth"], &data);
    let invite = enabled
        .stdout
        .lines()
        .find_map(|l| l.strip_prefix("main admin invite: "))
        .expect("invite line")
        .to_owned();
    let ca = TestCa::new();
    let first = ca.leaf();
    let files = PairFiles::in_dir(dir.path());
    files.write(&first);
    let mut flags = files.flags();
    flags.extend(RELOAD_FLAGS.iter().map(|s| (*s).to_owned()));
    let flags: Vec<&str> = flags.iter().map(String::as_str).collect();
    let server = start_with(&data, &flags);
    let token = join_main(&server.addr, &ca, &invite);
    let auth = format!("Bearer {token}");

    // A wait parked on a connection made with the first certificate.
    let waiter = {
        let addr = server.addr.clone();
        let config = ca.client(&TLS13);
        let auth = auth.clone();
        std::thread::spawn(move || {
            let req = get(
                "/v1/boards/main/events?from_now=true&timeout_s=30",
                &[("Authorization", &auth)],
            );
            https_raw(&addr, config, &req)
        })
    };
    std::thread::sleep(Duration::from_millis(300));

    let second = ca.leaf();
    files.write(&second);
    wait_for_cert(&server.addr, &ca, &second.der, Duration::from_secs(5));

    // A post through a new connection wakes the old wait, which answers normally.
    let post = request(
        "POST",
        "/v1/boards/main/messages",
        &[
            ("Authorization", &auth),
            ("Content-Type", "application/json"),
        ],
        r#"{"channel":"eng","text":"after the reload"}"#,
    );
    let posted = https_raw(&server.addr, ca.client(&TLS13), &post).expect("post");
    assert!(
        posted.response.starts_with("HTTP/1.1 201"),
        "{}",
        posted.response
    );
    let waited = waiter
        .join()
        .expect("waiter thread")
        .expect("wait survives the reload");
    assert_eq!(waited.peer_cert, first.der);
    assert!(
        waited.response.starts_with("HTTP/1.1 200"),
        "{}",
        waited.response
    );
    assert!(
        waited.response.contains(r#""timed_out":false"#),
        "{}",
        waited.response
    );
    assert!(
        waited.response.contains(r#""kind":"thread.created""#),
        "{}",
        waited.response
    );
}

#[test]
fn unparseable_replacement_pair_keeps_serving_the_old_certificate() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = network_data(dir.path());
    let ca = TestCa::new();
    let first = ca.leaf();
    let files = PairFiles::in_dir(dir.path());
    files.write(&first);
    let mut flags = files.flags();
    flags.extend(RELOAD_FLAGS.iter().map(|s| (*s).to_owned()));
    let flags: Vec<&str> = flags.iter().map(String::as_str).collect();
    let (server, stderr) = start_capturing(&data, &flags);

    files.write_cert("not a certificate\n");
    files.write_key("-----BEGIN PRIVATE KEY-----\nSECRETMATERIAL\n-----END PRIVATE KEY-----\n");
    stderr.wait_for(
        "keeping the current TLS certificate",
        Duration::from_secs(5),
    );
    // Two writes may be seen as one change or two; let both land before counting.
    std::thread::sleep(Duration::from_millis(300));
    let warned = stderr.text().matches("keeping the current").count();
    keeps_serving(&server.addr, &ca, &first.der, 10);
    let all = stderr.text();
    // Retried on every tick, but warned about once per change, not once per tick.
    assert_eq!(all.matches("keeping the current").count(), warned, "{all}");
    assert!(all.contains("cert.pem"), "{all}");
    assert!(!all.contains("SECRETMATERIAL"), "{all}");
    assert!(!all.contains("not a certificate"), "{all}");

    // The reloader is still alive: a good pair is picked up.
    let third = ca.leaf();
    files.write(&third);
    wait_for_cert(&server.addr, &ca, &third.der, Duration::from_secs(5));
}

#[test]
fn partial_write_of_cert_then_key_never_serves_a_mismatched_pair() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = network_data(dir.path());
    let ca = TestCa::new();
    let first = ca.leaf();
    let files = PairFiles::in_dir(dir.path());
    files.write(&first);
    let mut flags = files.flags();
    flags.extend(RELOAD_FLAGS.iter().map(|s| (*s).to_owned()));
    let flags: Vec<&str> = flags.iter().map(String::as_str).collect();
    let (server, stderr) = start_capturing(&data, &flags);

    // The new certificate lands first; with the old key it is a mismatched pair.
    let second = ca.leaf();
    files.write_cert(&second.cert_pem);
    let all = stderr.wait_for("does not match", Duration::from_secs(5));
    assert!(!all.contains("PRIVATE KEY"), "{all}");
    keeps_serving(&server.addr, &ca, &first.der, 10);

    // Once the key follows, the new pair is served.
    files.write_key(&second.key_pem);
    wait_for_cert(&server.addr, &ca, &second.der, Duration::from_secs(5));
}

#[test]
fn trusted_proxy_accepts_plain_http_only_from_listed_ranges() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = network_data(dir.path());
    // Loopback is outside the listed range: the connection is dropped before any HTTP.
    {
        let server = start_with(&data, &["--trusted-proxy", "10.0.0.0/8"]);
        let reply = raw(&server.addr, &get("/healthz", &[]));
        assert!(reply.is_empty(), "an unlisted peer got: {reply:?}");
    }
    // Listed (comma separated and repeated forms): served, and its forwarding is believed.
    let server = start_with(
        &data,
        &[
            "--trusted-proxy",
            "10.0.0.0/8,127.0.0.0/8",
            "--trusted-proxy",
            "fd00::/8",
        ],
    );
    let reply = raw(&server.addr, &get("/healthz", &[]));
    assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    let bad = |client: &str| {
        let reply = raw(
            &server.addr,
            &get(
                "/v1/boards/main/events?timeout_s=0",
                &[
                    ("Authorization", "Bearer garbage"),
                    ("X-Forwarded-For", client),
                ],
            ),
        );
        reply
            .split_whitespace()
            .nth(1)
            .unwrap_or_default()
            .to_owned()
    };
    for _ in 0..10 {
        assert_eq!(bad("192.0.2.1"), "401");
    }
    assert_eq!(bad("192.0.2.1"), "429");
    // Another client behind the same proxy has its own budget.
    assert_eq!(bad("192.0.2.2"), "401");
}

#[test]
fn trusted_proxy_with_tls_accepts_any_peer() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (server, ca, _files, _leaf) = tls_server(dir.path(), &["--trusted-proxy", "10.0.0.0/8"]);
    let reply = https_get(&server.addr, &ca, "/healthz", &[]);
    assert!(
        reply.response.starts_with("HTTP/1.1 200"),
        "{}",
        reply.response
    );
}

#[test]
fn allowed_host_flag_permits_that_host_and_rebinding_still_blocked() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = network_data(dir.path());
    let with_host = |addr: &str, host: &str, origin: Option<&str>| {
        let mut req = format!("GET /healthz HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
        if let Some(origin) = origin {
            req.push_str(&format!("Origin: {origin}\r\n"));
        }
        req.push_str("\r\n");
        let reply = raw(addr, req.as_bytes());
        reply
            .split_whitespace()
            .nth(1)
            .unwrap_or_default()
            .to_owned()
    };
    {
        let server = start(&data);
        assert_eq!(with_host(&server.addr, "board.example", None), "403");
    }
    let server = start_with(&data, &["--allowed-host", "board.example"]);
    assert_eq!(with_host(&server.addr, "board.example", None), "200");
    assert_eq!(with_host(&server.addr, "Board.Example:443", None), "200");
    assert_eq!(
        with_host(&server.addr, "board.example", Some("https://board.example")),
        "200"
    );
    assert_eq!(with_host(&server.addr, "evil.example", None), "403");
    assert_eq!(
        with_host(&server.addr, "board.example.evil.example", None),
        "403"
    );
    assert_eq!(
        with_host(&server.addr, "board.example", Some("https://evil.example")),
        "403"
    );
}

#[test]
fn invalid_trusted_proxy_cidr_exits_2() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = network_data(dir.path());
    for bad in ["10.0.0.0/33", "proxy.example", "10.0.0.0/8,10.1.0.0/+8"] {
        let out = run_bounded(
            &["serve", "--bind", "127.0.0.1:0", "--trusted-proxy", bad],
            &data,
        );
        assert_eq!(out.code, Some(2), "{bad}: {}", out.stderr);
        let named = bad.rsplit(',').next().unwrap_or(bad);
        assert!(out.stderr.contains(named), "{bad}: {}", out.stderr);
        assert!(out.stdout.is_empty());
    }
}

#[test]
fn non_loopback_bind_without_tls_or_proxy_exits_2_and_creates_nothing() {
    // Network mode: the message names what is missing.
    let dir = tempfile::tempdir().expect("tempdir");
    let data = network_data(dir.path());
    let before: Vec<_> = std::fs::read_dir(&data)
        .expect("data dir")
        .map(|e| e.expect("entry").file_name())
        .collect();
    let out = run_bounded(&["serve", "--bind", "0.0.0.0:0"], &data);
    assert_eq!(out.code, Some(2), "{}", out.stderr);
    assert!(out.stderr.contains("0.0.0.0:0"), "{}", out.stderr);
    assert!(out.stderr.contains("--tls-cert"), "{}", out.stderr);
    assert!(out.stderr.contains("--trusted-proxy"), "{}", out.stderr);
    assert!(out.stdout.is_empty());
    let after: Vec<_> = std::fs::read_dir(&data)
        .expect("data dir")
        .map(|e| e.expect("entry").file_name())
        .collect();
    assert_eq!(before.len(), after.len(), "{before:?} -> {after:?}");

    // A missing data dir is local mode: refused up front even with TLS or a proxy given.
    let fresh = dir.path().join("fresh");
    let files = PairFiles::in_dir(dir.path());
    files.write(&TestCa::new().leaf());
    let mut tls_args = vec![
        "serve".to_owned(),
        "--bind".to_owned(),
        "192.0.2.1:7878".to_owned(),
    ];
    tls_args.extend(files.flags());
    let tls_args: Vec<&str> = tls_args.iter().map(String::as_str).collect();
    for args in [
        &tls_args[..],
        &[
            "serve",
            "--bind",
            "0.0.0.0:0",
            "--trusted-proxy",
            "10.0.0.0/8",
        ][..],
    ] {
        let out = run_bounded(args, &fresh);
        assert_eq!(out.code, Some(2), "{args:?}: {}", out.stderr);
        assert!(out.stderr.contains("needs network mode"), "{}", out.stderr);
        assert!(
            !fresh.exists(),
            "a refused start must not create the data dir"
        );
    }
}

#[test]
fn h2_only_client_cannot_negotiate_h2_and_gets_http1_or_fails_alpn() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (server, ca, _files, _leaf) = tls_server(dir.path(), &[]);
    // Offering only h2: the server has no protocol in common and refuses the handshake.
    let err = match https_raw(
        &server.addr,
        ca.client_alpn(&[b"h2"]),
        &get("/healthz", &[]),
    ) {
        Ok(reply) => panic!("h2-only client was served: {:?}", reply.alpn),
        Err(err) => err,
    };
    assert!(
        matches!(
            tls_error(&err),
            Some(rustls::Error::AlertReceived(
                rustls::AlertDescription::NoApplicationProtocol
            ))
        ),
        "{err:?}"
    );
    // Offering both, as browsers do: HTTP/1.1 is chosen.
    let reply = https_raw(
        &server.addr,
        ca.client_alpn(&[b"h2", b"http/1.1"]),
        &get("/healthz", &[]),
    )
    .expect("tls exchange");
    assert_eq!(reply.alpn.as_deref(), Some(&b"http/1.1"[..]));
    assert!(
        reply.response.starts_with("HTTP/1.1 200"),
        "{}",
        reply.response
    );
}

#[test]
fn idle_tls_connection_is_closed_after_the_header_timeout() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (server, ca, _files, _leaf) = tls_server(dir.path(), &["--header-read-timeout-ms", "300"]);
    for protocols in [&[b"h2".as_slice(), b"http/1.1"][..], &[][..]] {
        let elapsed = idle_after_handshake(&server.addr, ca.client_alpn(protocols));
        assert!(
            elapsed < Duration::from_secs(3),
            "closed only after {elapsed:?}"
        );
    }
}

#[test]
fn tls_handshake_timeout_closes_a_client_that_sends_nothing_after_tcp_connect() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (server, _ca, _files, _leaf) = tls_server(dir.path(), &["--header-read-timeout-ms", "300"]);
    let started = std::time::Instant::now();
    let mut stream = std::net::TcpStream::connect(&server.addr).expect("connect");
    let reply = common::read_to_close(&mut stream);
    let elapsed = started.elapsed();
    assert!(reply.is_empty(), "{reply:?}");
    assert!(
        elapsed < Duration::from_secs(3),
        "closed only after {elapsed:?}"
    );
}
