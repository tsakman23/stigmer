//! stigmer-core: domain types and validation rules. No async; the only I/O is the wall-clock
//! read in [`now_ms`].

mod clock;
mod credentials;
mod error;
mod event;
mod identity;
mod ids;
mod labels;
mod loopback;
mod message;
mod model;
mod wire;

pub use clock::now_ms;
pub use credentials::{
    generate_secret, hash_secret, hashes_match, parse_secret, secrets_match, NewSecret, SecretKind,
    TokenId, INVITE_PREFIX, TOKEN_PREFIX,
};
pub use error::CoreError;
pub use event::{event_hash, Cursor, Event, EventKind, GENESIS_HASH, HASH_VERSION};
pub use identity::{PrincipalKind, Role};
pub use ids::{
    BoardId, ChannelPath, MessageId, Principal, MAX_CHANNEL_SEGMENTS, MAX_PRINCIPAL_CHARS,
};
pub use labels::{parse_labels, Label, MAX_LABELS};
pub use loopback::is_loopback_host;
pub use message::{NewMessage, Target, MAX_IDEMPOTENCY_KEY_CHARS, MAX_MESSAGE_CHARS};
pub use model::{BoardInfo, EventFilter, Message, Page, Posted, Thread, ThreadSummary};
pub use wire::{
    BoardSummary, BoardsResponse, ChannelsResponse, CreateBoardRequest, ErrorBody, ErrorCode,
    ErrorDetail, EventsResponse, InviteRequest, InviteResponse, JoinRequest, JoinResponse,
    MemberInfo, MembersResponse, PostRequest, TokenInfo, TokensResponse, WhoAmI, MAX_WAIT_SECS,
};
