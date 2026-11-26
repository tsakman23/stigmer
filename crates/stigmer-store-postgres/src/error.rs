//! Turning database failures into `StoreError`s.
//!
//! A uniqueness violation (SQLSTATE 23505) becomes the same typed conflict SQLite reports,
//! chosen by the name of the constraint that was violated; anything else is a backend error
//! carrying the driver's message. Driver messages never contain the connection string, so they
//! cannot leak its password; the one place a URL is at hand, `PgStore::connect`, redacts its
//! own messages (see `pool`).

use std::fmt::Display;

use stigmer_store::{ConflictKind, Entity, StoreError};
use tokio_postgres::error::SqlState;

/// A `NotFound` error for the `entity` named by `id`.
pub(crate) fn not_found(entity: Entity, id: impl Display) -> StoreError {
    StoreError::NotFound {
        entity,
        id: id.to_string(),
    }
}

/// Wraps a failure that is not a database error (a pool, runtime or decoding failure).
pub(crate) fn backend(err: impl Display) -> StoreError {
    StoreError::Backend(err.to_string())
}

/// Maps a database error: a uniqueness violation on a known constraint is its `Conflict`, every
/// other error is `Backend`.
pub(crate) fn db(err: tokio_postgres::Error) -> StoreError {
    let conflict = err.as_db_error().and_then(|e| {
        let constraint = e.constraint()?;
        conflict_kind(e.code(), constraint)
    });
    match conflict {
        Some(kind) => StoreError::Conflict(kind),
        None => StoreError::Backend(describe(&err)),
    }
}

/// The driver's message with its causes: its own `Display` stops at "db error".
fn describe(err: &tokio_postgres::Error) -> String {
    let mut text = err.to_string();
    let mut cause = std::error::Error::source(err);
    while let Some(inner) = cause {
        let more = inner.to_string();
        if !text.ends_with(&more) {
            text = format!("{text}: {more}");
        }
        cause = inner.source();
    }
    text
}

/// The conflict a violation of `constraint` with SQLSTATE `code` stands for, if any. Only
/// uniqueness violations (23505) map, and only on the constraints whose meaning the store
/// knows: the board id, the member name on a board and the idempotency key of an author on a
/// board. The idempotency key is checked under the board's row lock before the insert, so its
/// violation is a defence in depth that reports what SQLite would have reported to a reuse.
pub(crate) fn conflict_kind(code: &SqlState, constraint: &str) -> Option<ConflictKind> {
    if *code != SqlState::UNIQUE_VIOLATION {
        return None;
    }
    match constraint {
        "boards_pkey" => Some(ConflictKind::BoardExists),
        "principals_pkey" => Some(ConflictKind::NameTaken),
        "messages_idempotency" => Some(ConflictKind::IdempotencyKeyReused),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
