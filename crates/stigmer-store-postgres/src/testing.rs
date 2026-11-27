//! Test support, not API: the test database and a schema per test.
//!
//! Postgres tests read `STIGMER_TEST_DATABASE_URL`. Without it they skip, loudly; with `CI` set
//! a missing URL fails them instead, so a CI job can never pass by skipping. Each test works in
//! its own schema, created here and dropped when its [`TestSchema`] is dropped, so tests run in
//! parallel and leave nothing behind.

use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use stigmer_store::StoreError;

use crate::error::{backend, db};
use crate::{PgOptions, PgTls, DEFAULT_POLL_INTERVAL};

/// The variable that names the test database.
pub const DATABASE_URL_VAR: &str = "STIGMER_TEST_DATABASE_URL";

/// What a Postgres test does, given the environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TestDatabase {
    /// Run against this database URL.
    Run(String),
    /// Skip, printing this message where `cargo test` shows it.
    Skip(String),
    /// Fail with this message: `CI` is set and no database was given.
    Fail(String),
}

/// Decides from the values of [`DATABASE_URL_VAR`] and `CI` (empty counts as unset).
pub fn decide(url: Option<String>, ci: Option<String>) -> TestDatabase {
    let set = |value: Option<String>| value.filter(|v| !v.trim().is_empty());
    match (set(url), set(ci)) {
        (Some(url), _) => TestDatabase::Run(url),
        (None, Some(_)) => TestDatabase::Fail(format!(
            "{DATABASE_URL_VAR} is not set but CI is: the Postgres tests must run in CI"
        )),
        (None, None) => TestDatabase::Skip(format!(
            "SKIPPED: {DATABASE_URL_VAR} is not set, so this Postgres test did NOT run \
             (set it to a database the tests may create schemas in)"
        )),
    }
}

/// The test database URL for `test`: `Ok(None)` after printing a loud skip line, or an error
/// to fail the test with when `CI` is set and the URL is not.
pub fn database_url(test: &str) -> Result<Option<String>, String> {
    let env = |name: &str| std::env::var(name).ok();
    match decide(env(DATABASE_URL_VAR), env("CI")) {
        TestDatabase::Run(url) => Ok(Some(url)),
        TestDatabase::Fail(message) => Err(format!("{test}: {message}")),
        TestDatabase::Skip(message) => {
            // Straight to the process's stderr: `cargo test` captures `eprintln!` and would
            // hide the skip from a passing run.
            let _ = writeln!(std::io::stderr().lock(), "{test}: {message}");
            Ok(None)
        }
    }
}

/// A schema of its own on the test database, dropped (with everything in it) on drop.
pub struct TestSchema {
    name: String,
    base_url: String,
    url: String,
}

impl TestSchema {
    /// Creates a new, empty schema with a unique name on the database at `base_url`.
    pub async fn create(base_url: &str) -> Result<TestSchema, StoreError> {
        let name = unique_name();
        let schema = TestSchema {
            url: with_search_path(base_url, &name),
            base_url: base_url.to_owned(),
            name,
        };
        let client = connect(base_url).await?;
        client
            .batch_execute(&format!("CREATE SCHEMA \"{}\"", schema.name))
            .await
            .map_err(db)?;
        Ok(schema)
    }

    /// The schema's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The database URL with this schema as the search path of every connection.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Options for a store on the local test database: plain connections, a small pool.
    pub fn options(&self) -> PgOptions {
        PgOptions {
            max_connections: 8,
            tls: PgTls::Disable,
            poll_interval: DEFAULT_POLL_INTERVAL,
        }
    }

    /// A plain client whose search path is this schema, for checks a test makes in SQL.
    pub async fn client(&self) -> Result<tokio_postgres::Client, StoreError> {
        connect(&self.url).await
    }
}

impl Drop for TestSchema {
    fn drop(&mut self) {
        let (url, name) = (self.base_url.clone(), self.name.clone());
        // Drop may run inside a runtime (or while a test panics), so the schema is dropped on a
        // thread of its own with a runtime of its own.
        let dropped = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(backend)?;
            runtime.block_on(async {
                let client = connect(&url).await?;
                client
                    .batch_execute(&format!("DROP SCHEMA IF EXISTS \"{name}\" CASCADE"))
                    .await
                    .map_err(db)
            })
        })
        .join();
        if !matches!(dropped, Ok(Ok(()))) {
            let _ = writeln!(
                std::io::stderr().lock(),
                "warning: could not drop test schema {}",
                self.name
            );
        }
    }
}

/// The backend process id of `client`'s connection.
pub async fn backend_pid(client: &tokio_postgres::Client) -> Result<i32, StoreError> {
    client
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .map_err(db)?
        .try_get(0)
        .map_err(db)
}

/// How many backends are waiting, directly or behind another waiting backend, on a lock that
/// backend `blocker` holds. Lets a test hold a lock, start callers, and act only once they
/// are known to be queued: a condition to wait for, never a sleep.
pub async fn queued_behind(
    client: &tokio_postgres::Client,
    blocker: i32,
) -> Result<i64, StoreError> {
    client
        .query_one(
            "SELECT count(*) FROM pg_stat_activity w
              WHERE w.pid <> $1 AND (
                    $1 = ANY (pg_blocking_pids(w.pid))
                 OR EXISTS (SELECT 1 FROM pg_stat_activity v
                             WHERE $1 = ANY (pg_blocking_pids(v.pid))
                               AND v.pid = ANY (pg_blocking_pids(w.pid))))",
            &[&blocker],
        )
        .await
        .map_err(db)?
        .try_get(0)
        .map_err(db)
}

/// A plain connection to the test database, driven on the current runtime.
async fn connect(url: &str) -> Result<tokio_postgres::Client, StoreError> {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .map_err(db)?;
    tokio::spawn(connection);
    Ok(client)
}

/// `stigmer_test_<pid>_<nanos>_<n>`: unique across concurrent test processes and calls.
fn unique_name() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("stigmer_test_{}_{nanos}_{n}", std::process::id())
}

/// `url` with `options=-c search_path=<schema>` added to its query string.
fn with_search_path(url: &str, schema: &str) -> String {
    // The name is spliced into the URL and into SQL without escaping or percent-encoding, which
    // is safe only for a plain lowercase identifier (what `unique_name` makes).
    assert!(
        !schema.is_empty()
            && schema
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
        "test schema name must match [a-z0-9_]+: {schema:?}"
    );
    let separator = if url.contains('?') { '&' } else { '?' };
    format!("{url}{separator}options=-c%20search_path%3D{schema}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn some(value: &str) -> Option<String> {
        Some(value.to_owned())
    }

    #[test]
    fn skips_loudly_without_a_database_url_and_fails_in_ci_without_one() {
        let TestDatabase::Skip(message) = decide(None, None) else {
            panic!("no URL and no CI is a skip");
        };
        assert!(message.starts_with("SKIPPED: "), "{message}");
        assert!(message.contains(DATABASE_URL_VAR), "{message}");
        assert!(message.contains("did NOT run"), "{message}");
        assert_eq!(
            decide(some(""), some("")),
            decide(None, None),
            "empty is unset"
        );

        let TestDatabase::Fail(message) = decide(None, some("true")) else {
            panic!("CI without a URL fails");
        };
        assert!(message.contains(DATABASE_URL_VAR), "{message}");
        assert!(matches!(
            decide(some(" "), some("1")),
            TestDatabase::Fail(_)
        ));

        let url = "postgres://localhost/stigmer_test";
        assert_eq!(decide(some(url), None), TestDatabase::Run(url.to_owned()));
        assert_eq!(
            decide(some(url), some("true")),
            TestDatabase::Run(url.to_owned())
        );
    }

    #[test]
    fn schema_urls_set_the_search_path() {
        assert_eq!(
            with_search_path("postgres://h/db", "s1"),
            "postgres://h/db?options=-c%20search_path%3Ds1"
        );
        assert_eq!(
            with_search_path("postgres://h/db?sslmode=disable", "s1"),
            "postgres://h/db?sslmode=disable&options=-c%20search_path%3Ds1"
        );
        assert_ne!(unique_name(), unique_name());
    }
}
