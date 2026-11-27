//! Connecting: a password in the connection string never shows in an error.

use stigmer_store::StoreError;
use stigmer_store_postgres::{CaBundle, PgOptions, PgStore, PgTls, DEFAULT_POLL_INTERVAL};

const PASSWORD: &str = "s3cr3t-Pa55";

fn options(tls: PgTls) -> PgOptions {
    PgOptions {
        max_connections: 2,
        tls,
        poll_interval: DEFAULT_POLL_INTERVAL,
        ca_bundle: None,
        on_poll_error: None,
    }
}

/// A self-signed CA certificate as PEM.
fn ca_pem(name: &str) -> String {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params.self_signed(&key).unwrap().pem()
}

#[test]
fn a_ca_bundle_holds_one_or_more_pem_certificates() {
    let one = CaBundle::from_pem(ca_pem("one").as_bytes()).unwrap();
    assert_eq!(one.len(), 1);
    let two = format!("{}{}", ca_pem("one"), ca_pem("two"));
    let two = CaBundle::from_pem(two.as_bytes()).unwrap();
    assert_eq!(two.len(), 2);
    assert_eq!(format!("{two:?}"), "CaBundle(2 certificates)");

    for (bad, what) in [
        (String::new(), "no certificate"),
        ("not pem at all".to_owned(), "no certificate"),
        (
            "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n".to_owned(),
            "not valid PEM",
        ),
        (
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n".to_owned(),
            "not a usable CA certificate",
        ),
    ] {
        let Err(StoreError::Backend(text)) = CaBundle::from_pem(bad.as_bytes()) else {
            panic!("{bad:?} is refused");
        };
        assert!(text.contains(what), "{bad:?}: {text}");
    }
}

#[tokio::test]
async fn a_ca_bundle_is_refused_unless_tls_is_verify_full() {
    let closed = "postgres://stigmer@127.0.0.1:1/stigmer_test";
    let ca = CaBundle::from_pem(ca_pem("ca").as_bytes()).unwrap();
    for tls in [PgTls::Disable, PgTls::Require] {
        let with_ca = PgOptions {
            ca_bundle: Some(ca.clone()),
            ..options(tls)
        };
        let Err(StoreError::Backend(text)) = PgStore::connect(closed, with_ca).await else {
            panic!("a CA bundle with {tls:?} is refused");
        };
        assert!(text.contains("verify-full"), "{tls:?}: {text}");
    }
    let with_ca = PgOptions {
        ca_bundle: Some(ca),
        ..options(PgTls::VerifyFull)
    };
    let Err(StoreError::Backend(text)) = PgStore::connect(closed, with_ca).await else {
        panic!("nothing listens on port 1");
    };
    assert!(text.contains("cannot connect"), "{text}");
}

fn assert_hides_the_password(err: &StoreError, what: &str) {
    let (display, debug) = (err.to_string(), format!("{err:?}"));
    for text in [&display, &debug] {
        assert!(!text.contains(PASSWORD), "{what}: {text}");
        assert!(!text.contains("s3cr3t"), "{what}: {text}");
    }
    assert!(matches!(err, StoreError::Backend(_)), "{what}: {err:?}");
}

#[tokio::test]
async fn connect_errors_never_contain_the_password() {
    // Port 1 on loopback: nothing listens there, so the connection is refused.
    let closed = format!("postgres://stigmer:{PASSWORD}@127.0.0.1:1/stigmer_test");
    for tls in [PgTls::Disable, PgTls::Require] {
        let err = PgStore::connect(&closed, options(tls)).await.unwrap_err();
        assert_hides_the_password(&err, "closed port");
        let text = err.to_string();
        assert!(
            text.contains("database stigmer_test on 127.0.0.1:1"),
            "names the target: {text}"
        );
    }

    let encoded = "postgres://stigmer:s3cr3t%2DPa55@127.0.0.1:1/stigmer_test";
    let err = PgStore::connect(encoded, options(PgTls::Disable))
        .await
        .unwrap_err();
    assert_hides_the_password(&err, "percent-encoded password");

    let key_value = format!("host=127.0.0.1 port=1 user=stigmer password={PASSWORD} dbname=x");
    let err = PgStore::connect(&key_value, options(PgTls::Disable))
        .await
        .unwrap_err();
    assert_hides_the_password(&err, "key-value form");

    for unparsable in [
        format!("postgres://stigmer:{PASSWORD}@127.0.0.1:notaport/db"),
        format!("postgres://stigmer:{PASSWORD}@127.0.0.1/db?sslmode=verify-full"),
        format!("postgres://stigmer:{PASSWORD}@127.0.0.1/db?unknown={PASSWORD}"),
    ] {
        let err = PgStore::connect(&unparsable, options(PgTls::Disable))
            .await
            .unwrap_err();
        assert_hides_the_password(&err, &format!("unparsable URL {}", err));
    }
}
