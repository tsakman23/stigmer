//! stigmerd's TLS to Postgres against a throwaway server that accepts TLS only, with a
//! certificate from a test CA: verify-full works with that CA's bundle and fails without it.
//!
//! Needs `initdb` and `pg_ctl` (see `common::pg::pg_bin`), so it lives in `with_postgres`, which
//! CI's `check` job skips and its `postgres` job runs.

mod common;

mod with_postgres {
    use super::common::pg::{pg_bin, stigmerd, ThrowawayPg};
    use super::common::tls::TestCa;
    use super::common::{http, run_guarded, spawn_guarded, Bounded, STARTUP_TIMEOUT};

    fn migrate(url: &str, flags: &[&str]) -> Bounded {
        let mut cmd = stigmerd(&["admin", "migrate", "--database-url", url]);
        cmd.args(flags);
        run_guarded(cmd)
    }

    #[test]
    fn verify_full_succeeds_with_the_ca_bundle_and_fails_without_it() {
        let Some(bin) = pg_bin("verify_full_succeeds_with_the_ca_bundle_and_fails_without_it")
        else {
            return;
        };
        let ca = TestCa::new();
        let server = ThrowawayPg::start(&bin, &ca);
        let dir = tempfile::tempdir().unwrap();
        let ca_file = dir.path().join("ca.pem");
        std::fs::write(&ca_file, &ca.pem).unwrap();
        let ca_path = ca_file.to_str().unwrap();
        let other_file = dir.path().join("other.pem");
        std::fs::write(&other_file, &TestCa::new().pem).unwrap();
        let url = format!("postgres://stigmer@127.0.0.1:{}/postgres", server.port);

        // The CA from the flag, and from the URL's sslmode and sslrootcert.
        let out = migrate(&url, &["--db-tls", "verify-full", "--db-tls-ca", ca_path]);
        assert_eq!(out.code, Some(0), "{}", out.stderr);
        let out = migrate(&url, &["--db-tls-ca", ca_path]);
        assert_eq!(
            out.code,
            Some(0),
            "a CA bundle alone means verify-full: {}",
            out.stderr
        );
        let in_url = format!("{url}?sslmode=verify-full&sslrootcert={ca_path}");
        let out = migrate(&in_url, &[]);
        assert_eq!(out.code, Some(0), "{}", out.stderr);

        // Without the bundle the platform's roots do not know the test CA; another CA fails too.
        let out = migrate(&url, &["--db-tls", "verify-full"]);
        assert_eq!(out.code, Some(1), "{}", out.stderr);
        assert!(out.stderr.contains("cannot connect"), "{}", out.stderr);
        let out = migrate(&url, &["--db-tls-ca", other_file.to_str().unwrap()]);
        assert_eq!(out.code, Some(1), "{}", out.stderr);

        // require encrypts without checking the certificate.
        let out = migrate(&url, &["--db-tls", "require"]);
        assert_eq!(out.code, Some(0), "{}", out.stderr);

        // The loopback default is a plain connection, which this server refuses.
        let out = migrate(&url, &[]);
        assert_eq!(out.code, Some(1), "{}", out.stderr);

        // A server over verify-full serves.
        let mut cmd = stigmerd(&[
            "serve",
            "--bind",
            "127.0.0.1:0",
            "--database-url",
            &url,
            "--db-tls-ca",
            ca_path,
        ]);
        cmd.env_remove("STIGMER_DATABASE_URL");
        let served = spawn_guarded(cmd, STARTUP_TIMEOUT);
        let (status, _) = http(&served.addr, "GET", "/healthz", &[], "");
        assert_eq!(status, 200);
    }
}
