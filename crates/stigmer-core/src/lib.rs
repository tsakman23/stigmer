//! stigmer-core: domain types and validation rules. No I/O, no async.

mod error;
mod ids;

pub use error::CoreError;
pub use ids::{BoardId, MessageId, Principal};
