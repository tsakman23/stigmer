//! Typed errors for domain validation.

use thiserror::Error;

/// A domain rule was violated while constructing a value.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CoreError {
    #[error("message text must not be empty")]
    EmptyText,
    #[error("message text exceeds {max} characters")]
    TooLong { max: usize },
    #[error("too many labels (max {max})")]
    TooManyLabels { max: usize },
    #[error("invalid label: {0}")]
    BadLabel(String),
    #[error("invalid channel path: {0}")]
    BadChannel(String),
    #[error("invalid principal: {0}")]
    BadPrincipal(String),
    #[error("invalid id: {0}")]
    BadId(String),
    #[error("invalid idempotency key: {0}")]
    BadIdempotencyKey(String),
    #[error("invalid cursor: {0}")]
    BadCursor(String),
    #[error("invalid credential")]
    BadToken,
    #[error("could not gather randomness: {0}")]
    Entropy(String),
}
