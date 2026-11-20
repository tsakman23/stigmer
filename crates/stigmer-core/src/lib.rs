//! stigmer-core: domain types and validation rules. No I/O, no async.

mod error;
mod ids;
mod labels;
mod message;

pub use error::CoreError;
pub use ids::{BoardId, ChannelPath, MessageId, Principal};
pub use labels::{parse_labels, Label, MAX_LABELS};
pub use message::{NewMessage, Target, MAX_MESSAGE_CHARS};
