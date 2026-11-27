//! Connecting: a password in the connection string never shows in an error.

use stigmer_store::StoreError;
use stigmer_store_postgres::{PgOptions, PgStore, PgTls, DEFAULT_POLL_INTERVAL};

const PASSWORD: &str = "s3cr3t-Pa55";

fn options(tls: PgTls) -> PgOptions {
    PgOptions {
        max_connections: 2,
        tls,
        poll_interval: DEFAULT_POLL_INTERVAL,
    }
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
