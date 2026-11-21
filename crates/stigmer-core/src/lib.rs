//! stigmer-core: domain types and validation rules. No I/O, no async.

mod error;
mod event;
mod ids;
mod labels;
mod message;
mod model;
mod wire;

pub use error::CoreError;
pub use event::{event_hash, Cursor, Event, EventKind, GENESIS_HASH, HASH_VERSION};
pub use ids::{BoardId, ChannelPath, MessageId, Principal};
pub use labels::{parse_labels, Label, MAX_LABELS};
pub use message::{NewMessage, Target, MAX_IDEMPOTENCY_KEY_CHARS, MAX_MESSAGE_CHARS};
pub use model::{EventFilter, Message, Page, Posted, Thread, ThreadSummary};
pub use wire::{
    ChannelsResponse, ErrorBody, ErrorCode, ErrorDetail, EventsResponse, PostRequest, MAX_WAIT_SECS,
};
