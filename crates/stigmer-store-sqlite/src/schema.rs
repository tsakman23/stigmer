//! Schema migrations, tracked with `PRAGMA user_version`.
//!
//! `MIGRATIONS[i]` takes the schema from version `i` to `i + 1`. Each migration is one
//! numbered file in the crate's `migrations/` directory, embedded at compile time.
//!
//! Append a new numbered file and a matching `include_str!` entry; never edit a shipped one.
//! The fingerprint test in `threads/tests.rs` pins the exact bytes of every shipped migration
//! and fails on any edit. Keep comments out of the `.sql` files for the same reason; they go
//! above the `include_str!` entry here.

use rusqlite::{Connection, TransactionBehavior};
use stigmer_core::{BoardId, GENESIS_HASH};
use stigmer_store::StoreError;

use crate::backend;

/// Ordered migration scripts, each applied in its own transaction.
pub(crate) const MIGRATIONS: &[&str] = &[
    // 1: boards, messages, labels and the event log.
    include_str!("../migrations/0001_init.sql"),
    // 2: idempotency keys, unique per board and author.
    include_str!("../migrations/0002_idempotency.sql"),
    // 3: indexes for thread reads and the event feed.
    include_str!("../migrations/0003_indexes.sql"),
    // 4: the kind of principal that wrote each message. Every M0 author is a self-declared
    // local name, so existing rows and new posts are 'local'. See docs/design.md section 12,
    // call 8: M1 maps local principals to real principals with an explicit migration command.
    // Kept out of the wire format and the core types.
    include_str!("../migrations/0004_author_kind.sql"),
    // 5: board lifecycle. Boards that predate it (only `main`) keep created_at_ms 0 and no
    // creator; a board made from now on is stamped when it is created.
    include_str!("../migrations/0005_board_lifecycle.sql"),
    // 6: identity (docs/superpowers/specs/2026-11-22-m1-networked-board-design.md, section 6).
    // Every data directory starts, or stays after an upgrade, in local mode. Roles live on
    // principals (board memberships), not on credentials. Secrets are stored only as their
    // 32-byte sha256; a credential with no board is the instance-admin credential.
    include_str!("../migrations/0006_identity.sql"),
    // 7: indexes for the per-board credential and member lookups.
    include_str!("../migrations/0007_identity_indexes.sql"),
    // 8: thread summaries (ADR 0015), one row per thread root, maintained by the post
    // transaction. The backfill gives every existing thread exactly the row the write path would
    // have produced: replies counted from messages, first_seq the root's event, last_seq the
    // thread's latest event, last_at_ms the time of that latest message (by sequence, not the
    // largest time), preview the first 200 characters of the root text. A root without an event
    // leaves a NULL and fails the migration rather than dropping the thread from listings.
    include_str!("../migrations/0008_threads.sql"),
];

/// Brings the database up to the latest schema and makes sure board `main` exists.
pub(crate) fn migrate(conn: &mut Connection) -> Result<(), StoreError> {
    loop {
        // Read the version inside the write transaction so two processes cannot both apply a step.
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(backend)?;
        let version: i64 = tx
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(backend)?;
        let applied = usize::try_from(version)
            .map_err(|_| StoreError::Backend(format!("invalid schema version {version}")))?;
        if applied > MIGRATIONS.len() {
            return Err(StoreError::Backend(format!(
                "database schema version {applied} is newer than this build supports ({})",
                MIGRATIONS.len()
            )));
        }
        let Some(sql) = MIGRATIONS.get(applied) else {
            break;
        };
        tx.execute_batch(sql).map_err(backend)?;
        tx.pragma_update(None, "user_version", version + 1)
            .map_err(backend)?;
        tx.commit().map_err(backend)?;
    }
    conn.execute(
        "INSERT OR IGNORE INTO boards (id, head_seq, head_hash, created_at_ms)
         VALUES (?1, 0, ?2, ?3)",
        (
            BoardId::main().as_str(),
            GENESIS_HASH,
            stigmer_core::now_ms(),
        ),
    )
    .map_err(backend)?;
    Ok(())
}

#[cfg(test)]
mod tests;
