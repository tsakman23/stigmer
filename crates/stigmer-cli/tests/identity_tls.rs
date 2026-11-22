//! https against the real stigmerd serving TLS with a throwaway CA: --ca-cert and STIGMER_CA_CERT.

mod common;

use common::fixtures::main_invite;
use common::{CliUser, Stigmerd};

#[test]
fn ca_cert_flag_trusts_a_private_ca() {
    let (server, files, _pems) = Stigmerd::tls();
    assert!(server.url.starts_with("https://"), "{}", server.url);
    let url = server.url.as_str();
    let ca = files.ca.display().to_string();
    let user = CliUser::new();
    let token = server.instance_token.clone().unwrap();

    // The private CA is not trusted by default: the handshake fails and nothing is saved.
    let refused = user.run_stdin(&["--url", url, "login", "--instance"], &token);
    assert_eq!(refused.code, 1, "{refused:?}");
    assert!(!refused.all().contains(&token));
    assert!(!user.logins_path().exists());

    let run = user.run_stdin(
        &["--url", url, "--ca-cert", &ca, "login", "--instance"],
        &token,
    );
    assert_eq!(run.code, 0, "{run:?}");
    let run = user.run_env(&["--url", url, "whoami"], &[("STIGMER_CA_CERT", &ca)]);
    assert_eq!(run.code, 0, "{run:?}");
    assert!(run.stdout.contains("instance admin"), "{run:?}");

    // Joining over https with the CA works end to end.
    let ann = CliUser::new();
    let invite = main_invite(&server);
    let run = ann.run(&[
        "--url",
        url,
        "--ca-cert",
        &ca,
        "join",
        &invite,
        "--as",
        "ann",
    ]);
    assert_eq!(run.code, 0, "{run:?}");
    let run = ann.run(&["--url", url, "--ca-cert", &ca, "post", "eng", "over tls"]);
    assert_eq!(run.code, 0, "{run:?}");
}

#[test]
fn unreadable_or_empty_ca_cert_is_a_usage_error() {
    let user = CliUser::new();
    let missing = user.home().join("missing.pem");
    let empty = user.home().join("empty.pem");
    std::fs::write(&empty, "").unwrap();
    let not_pem = user.home().join("junk.pem");
    std::fs::write(&not_pem, "hello").unwrap();
    for path in [&missing, &empty, &not_pem] {
        let path = path.display().to_string();
        let run = user.run(&["--url", "https://127.0.0.1:9", "--ca-cert", &path, "whoami"]);
        assert_eq!(run.code, 2, "{path}: {run:?}");
        assert!(run.stderr.contains("CA certificate"), "{run:?}");
        assert!(run.stderr.contains("next: "), "{run:?}");
    }
}

#[test]
fn a_ca_bundle_with_a_malformed_block_is_refused() {
    let (server, files, pems) = Stigmerd::tls();
    let good = std::fs::read_to_string(&files.ca).unwrap();
    let bundle = pems.path().join("bundle.pem");
    std::fs::write(
        &bundle,
        format!("{good}-----BEGIN CERTIFICATE-----\n%%%%\n-----END CERTIFICATE-----\n"),
    )
    .unwrap();
    let user = CliUser::new();
    let bundle = bundle.display().to_string();
    let run = user.run(&["--url", &server.url, "--ca-cert", &bundle, "whoami"]);
    assert_eq!(run.code, 2, "{run:?}");
    assert!(run.stderr.contains("malformed"), "{run:?}");
    let run = user.run_env(
        &["--url", &server.url, "whoami"],
        &[("STIGMER_CA_CERT", &bundle)],
    );
    assert_eq!(run.code, 2, "{run:?}");
}
