//! stigmer-core: domain types and validation rules. No I/O, no async.

mod credentials;
mod error;
mod event;
mod identity;
mod ids;
mod labels;
mod message;
mod model;
mod wire;

pub use credentials::{
    generate_secret, hash_secret, hashes_match, parse_secret, secrets_match, NewSecret, SecretKind,
    TokenId,
};
pub use error::CoreError;
pub use event::{event_hash, Cursor, Event, EventKind, GENESIS_HASH, HASH_VERSION};
pub use identity::{PrincipalKind, Role};
pub use ids::{
    BoardId, ChannelPath, MessageId, Principal, MAX_CHANNEL_SEGMENTS, MAX_PRINCIPAL_CHARS,
};
pub use labels::{parse_labels, Label, MAX_LABELS};
pub use message::{NewMessage, Target, MAX_IDEMPOTENCY_KEY_CHARS, MAX_MESSAGE_CHARS};
pub use model::{EventFilter, Message, Page, Posted, Thread, ThreadSummary};
pub use wire::{
    BoardInfo, BoardsResponse, ChannelsResponse, CreateBoardRequest, ErrorBody, ErrorCode,
    ErrorDetail, EventsResponse, InviteRequest, InviteResponse, JoinRequest, JoinResponse,
    MemberInfo, MembersResponse, PostRequest, TokenInfo, TokensResponse, WhoAmI, MAX_WAIT_SECS,
};
