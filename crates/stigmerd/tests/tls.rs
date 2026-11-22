//! End-to-end checks of the TLS listener, certificate reload, trusted proxies and allowed hosts,
//! against the real binary.

mod common;

use std::path::Path;
use std::time::Duration;

use common::tls::{get, https_get, https_raw, request, PairFiles, TestCa, TLS12, TLS13};
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
