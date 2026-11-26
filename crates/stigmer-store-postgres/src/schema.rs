//! The schema: versioned migrations and the state of a database relative to this build.
//!
//! `MIGRATIONS[i]` takes the schema from version `i` to `i + 1`, and version `n` means the same
//! logical schema as SQLite's version `n`, in Postgres types: `bigint` times and sequence
//! numbers, `bytea` hashes with a length CHECK, `text` ids in the "C" collation (so ids sort
//! by bytes, as in SQLite) and a partial unique index for idempotency keys. Each migration is one
//! numbered file in the crate's `migrations/` directory, embedded at compile time; append a new
//! file and entry, never edit a shipped one.
//!
//! The `schema_version` table records one row per applied migration. It is created by
//! [`migrate`](crate::PgStore::migrate) and is not itself a numbered migration.

use stigmer_store::StoreError;
use tokio_postgres::Transaction;

use crate::error::{backend, db};

/// Ordered migration scripts; [`migrate`](crate::PgStore::migrate) applies all pending ones in
/// one transaction.
pub(crate) const MIGRATIONS: &[&str] = &[
    // 1: boards, messages, labels and the event log. Labels keep their order in `position`
    // (SQLite uses the rowid). Hashes are the 32 bytes of the hex the API shows.
    include_str!("../migrations/0001_init.sql"),
    // 2: idempotency keys, unique per board and author.
    include_str!("../migrations/0002_idempotency.sql"),
    // 3: indexes for thread reads and the event feed. SQLite's `labels_message` index is the
    // left part of the labels primary key here.
    include_str!("../migrations/0003_indexes.sql"),
    // 4: the kind of principal that wrote each message ('local' or 'principal').
    include_str!("../migrations/0004_author_kind.sql"),
    // 5: board lifecycle: creation time, creator and archive time.
    include_str!("../migrations/0005_board_lifecycle.sql"),
    // 6: identity: instance mode, members, credentials, invites and the security log.
    include_str!("../migrations/0006_identity.sql"),
    // 7: indexes for the per-board credential and member lookups.
    include_str!("../migrations/0007_identity_indexes.sql"),
    // 8: thread summaries (ADR 0015), with the same backfill as SQLite's migration 8.
    include_str!("../migrations/0008_threads.sql"),
];

/// Creates the version table if it is missing.
pub(crate) const VERSION_TABLE: &str = "CREATE TABLE IF NOT EXISTS schema_version (
    version integer PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
)";

/// Where a database's schema stands relative to this build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaState {
    /// The schema is the one this build writes.
    Current,
    /// The schema is older: run the migrations (`stigmerd admin migrate`).
    Behind { have: u32, need: u32 },
    /// The schema is newer than this build: this server is older than the database.
    Ahead { have: u32, need: u32 },
}

/// What [`migrate`](crate::PgStore::migrate) did: the schema version before and after.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrationReport {
    pub from: u32,
    pub to: u32,
}

impl MigrationReport {
    /// The number of migrations applied (0 when the schema was already current).
    pub fn applied(&self) -> u32 {
        self.to.saturating_sub(self.from)
    }
}

/// The schema version this build writes.
pub(crate) fn latest() -> u32 {
    // At most a handful of migrations; the conversion cannot fail in practice.
    u32::try_from(MIGRATIONS.len()).unwrap_or(u32::MAX)
}

/// The state of a database at version `have`.
pub(crate) fn state(have: u32) -> SchemaState {
    let need = latest();
    match have.cmp(&need) {
        std::cmp::Ordering::Equal => SchemaState::Current,
        std::cmp::Ordering::Less => SchemaState::Behind { have, need },
        std::cmp::Ordering::Greater => SchemaState::Ahead { have, need },
    }
}

/// The schema version recorded in the database: 0 when it has no version table.
pub(crate) async fn version(tx: &Transaction<'_>) -> Result<u32, StoreError> {
    let exists: bool = tx
        .query_one("SELECT to_regclass('schema_version') IS NOT NULL", &[])
        .await
        .map_err(db)?
        .try_get(0)
        .map_err(db)?;
    if !exists {
        return Ok(0);
    }
    let have: i32 = tx
        .query_one("SELECT COALESCE(MAX(version), 0) FROM schema_version", &[])
        .await
        .map_err(db)?
        .try_get(0)
        .map_err(db)?;
    u32::try_from(have).map_err(backend)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_compares_with_the_latest_migration() {
        let need = latest();
        assert_eq!(need, 8);
        assert_eq!(state(need), SchemaState::Current);
        assert_eq!(state(0), SchemaState::Behind { have: 0, need });
        assert_eq!(state(99), SchemaState::Ahead { have: 99, need });
        let report = MigrationReport { from: 3, to: 8 };
        assert_eq!(report.applied(), 5);
    }
}
