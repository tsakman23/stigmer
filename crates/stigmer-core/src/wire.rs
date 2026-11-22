//! Request and response bodies shared by the HTTP API and its clients.

use serde::{Deserialize, Serialize};

use std::fmt;

use crate::{
    BoardId, ChannelPath, Cursor, Event, Label, MessageId, Principal, PrincipalKind, Role,
    ThreadSummary, TokenId,
};
use serde::de::IntoDeserializer;

/// The longest a single events request may wait, in seconds; the server clamps longer
/// timeouts to this and clients plan their long-poll chunks around it.
pub const MAX_WAIT_SECS: u64 = 300;

/// Body of a post. Exactly one of `channel` (new thread) or `thread` (reply) must be present;
/// the server enforces that.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostRequest {
    pub channel: Option<ChannelPath>,
    pub thread: Option<MessageId>,
    pub text: String,
    #[serde(default)]
    pub labels: Vec<Label>,
}

/// Response of a channel listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelsResponse {
    pub threads: Vec<ThreadSummary>,
}

/// Response of an event feed read. `cursor` is where to resume; `timed_out` is true when a
/// blocking read gave up (or the server is shutting down) with nothing to return.
///
/// The read starts after the `after` query cursor, or with `from_now=true` after the board's
/// head as it stood when the request arrived (from the beginning on an empty board); the two
/// are mutually exclusive. `cursor` is the last returned event's cursor, else the starting
/// cursor (`after` or the resolved head), else the board's head, else null.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventsResponse {
    pub events: Vec<Event>,
    pub cursor: Option<Cursor>,
    pub timed_out: bool,
}

/// Machine-readable error kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidInput,
    TooLarge,
    NotFound,
    InvalidCursor,
    MethodNotAllowed,
    Conflict,
    Forbidden,
    Internal,
    Unauthorized,
    RateLimited,
    BoardArchived,
    /// A code this version does not know. Only ever produced by deserializing a newer
    /// server's response; servers never send it.
    #[serde(other)]
    Unknown,
}

/// The code and a human-readable message of an error.
///
/// `raw_code` is set only when the server sent a code this version does not know (then
/// `code` is `ErrorCode::Unknown`); it keeps the original text so clients can show it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ErrorDetail {
    pub code: ErrorCode,
    #[serde(skip)]
    pub raw_code: Option<String>,
    pub message: String,
}

impl<'de> Deserialize<'de> for ErrorDetail {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            code: String,
            message: String,
        }
        let raw = Raw::deserialize(deserializer)?;
        let code = ErrorCode::deserialize(
            IntoDeserializer::<serde::de::value::Error>::into_deserializer(raw.code.as_str()),
        )
        .map_err(serde::de::Error::custom)?;
        // A literal "unknown" is the wire name of Unknown itself; only newer values are kept.
        let raw_code = (code == ErrorCode::Unknown && raw.code != "unknown").then_some(raw.code);
        Ok(Self {
            code,
            raw_code,
            message: raw.message,
        })
    }
}

/// Every error response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: ErrorDetail,
}

/// One board in a listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoardSummary {
    pub id: BoardId,
    pub archived: bool,
    pub created_at_ms: i64,
}

/// Body of a board creation; the name becomes the board id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateBoardRequest {
    pub name: BoardId,
}

/// Response of a board listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoardsResponse {
    pub boards: Vec<BoardSummary>,
}

/// One member of a board.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberInfo {
    pub name: Principal,
    pub kind: PrincipalKind,
    pub role: Role,
    pub last_seen_ms: Option<i64>,
}

/// Response of a member listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembersResponse {
    pub members: Vec<MemberInfo>,
}

/// Token metadata; never contains the secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenInfo {
    pub id: TokenId,
    pub principal: Principal,
    pub role: Role,
    pub expires_at_ms: i64,
    pub revoked: bool,
    pub last_seen_ms: Option<i64>,
}

/// Response of a token listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokensResponse {
    pub tokens: Vec<TokenInfo>,
}

/// Body of an invite creation. `expires_in_minutes` defaults server-side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteRequest {
    pub kind: PrincipalKind,
    pub role: Role,
    #[serde(default)]
    pub expires_in_minutes: Option<u32>,
}

/// A minted invite, shown once. Debug output redacts the invite string.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteResponse {
    pub invite: String,
    pub expires_at_ms: i64,
}

impl fmt::Debug for InviteResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InviteResponse")
            .field("invite", &"<redacted>")
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

/// Body of a join: an invite and the principal name to create.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinRequest {
    pub invite: String,
    pub name: Principal,
}

impl fmt::Debug for JoinRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JoinRequest")
            .field("invite", &"<redacted>")
            .field("name", &self.name)
            .finish()
    }
}

/// The result of a join: the new token, shown once. Debug output redacts the token string.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinResponse {
    pub token: String,
    pub board: BoardId,
    pub role: Role,
    pub kind: PrincipalKind,
    pub expires_at_ms: i64,
}

impl fmt::Debug for JoinResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JoinResponse")
            .field("token", &"<redacted>")
            .field("board", &self.board)
            .field("role", &self.role)
            .field("kind", &self.kind)
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

/// Who the presented credential belongs to. `board` and `role` are absent for the
/// instance-admin credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhoAmI {
    pub principal: Principal,
    pub kind: PrincipalKind,
    pub board: Option<BoardId>,
    pub role: Option<Role>,
    pub instance_admin: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ChannelPath, Cursor, Principal, TokenId};

    #[test]
    fn post_request_rejects_unknown_fields_and_defaults_labels() {
        let ok: PostRequest = serde_json::from_str(r#"{"channel":"eng","text":"hi"}"#).unwrap();
        assert_eq!(ok.channel, Some(ChannelPath::new("eng").unwrap()));
        assert_eq!(ok.thread, None);
        assert!(ok.labels.is_empty());
        assert!(serde_json::from_str::<PostRequest>(r#"{"text":"hi","bogus":1}"#).is_err());
        assert!(serde_json::from_str::<PostRequest>(r#"{"channel":"Bad//","text":"hi"}"#).is_err());
    }

    #[test]
    fn error_body_uses_snake_case_codes() {
        let body = ErrorBody {
            error: ErrorDetail {
                code: ErrorCode::InvalidCursor,
                raw_code: None,
                message: "nope".to_owned(),
            },
        };
        assert_eq!(
            serde_json::to_string(&body).unwrap(),
            r#"{"error":{"code":"invalid_cursor","message":"nope"}}"#
        );
        assert_eq!(
            serde_json::to_string(&ErrorCode::MethodNotAllowed).unwrap(),
            r#""method_not_allowed""#
        );
        let back: ErrorBody = serde_json::from_str(&serde_json::to_string(&body).unwrap()).unwrap();
        assert_eq!(back, body);
    }

    #[test]
    fn events_response_roundtrips() {
        let resp = EventsResponse {
            events: vec![],
            cursor: Some(Cursor::from_seq(3)),
            timed_out: true,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert_eq!(serde_json::from_str::<EventsResponse>(&json).unwrap(), resp);
        let empty = ChannelsResponse { threads: vec![] };
        assert_eq!(serde_json::to_string(&empty).unwrap(), r#"{"threads":[]}"#);
    }

    #[test]
    fn error_code_unknown_deserializes_from_a_future_value() {
        let code: ErrorCode = serde_json::from_str(r#""rate_limited_v2""#).unwrap();
        assert_eq!(code, ErrorCode::Unknown);
        let body: ErrorBody =
            serde_json::from_str(r#"{"error":{"code":"brand_new","message":"m"}}"#).unwrap();
        assert_eq!(body.error.code, ErrorCode::Unknown);
        for (code, name) in [
            (ErrorCode::Unauthorized, "unauthorized"),
            (ErrorCode::RateLimited, "rate_limited"),
            (ErrorCode::BoardArchived, "board_archived"),
        ] {
            assert_eq!(serde_json::to_string(&code).unwrap(), format!("\"{name}\""));
            assert_eq!(
                serde_json::from_str::<ErrorCode>(&format!("\"{name}\"")).unwrap(),
                code
            );
        }
    }

    #[test]
    fn unknown_code_keeps_raw_text() {
        let body: ErrorBody =
            serde_json::from_str(r#"{"error":{"code":"rate_limited_v2","message":"slow"}}"#)
                .unwrap();
        assert_eq!(body.error.code, ErrorCode::Unknown);
        assert_eq!(body.error.raw_code.as_deref(), Some("rate_limited_v2"));
        assert_eq!(body.error.message, "slow");
    }

    #[test]
    fn known_code_has_no_raw_code() {
        let body: ErrorBody =
            serde_json::from_str(r#"{"error":{"code":"forbidden","message":"no"}}"#).unwrap();
        assert_eq!(body.error.code, ErrorCode::Forbidden);
        assert_eq!(body.error.raw_code, None);
        // A literal "unknown" is a known wire name for Unknown; there is nothing newer to keep.
        let lit: ErrorBody =
            serde_json::from_str(r#"{"error":{"code":"unknown","message":"x"}}"#).unwrap();
        assert_eq!(lit.error.code, ErrorCode::Unknown);
    }

    #[test]
    fn error_body_json_for_known_codes_is_unchanged() {
        for (code, name) in [
            (ErrorCode::InvalidInput, "invalid_input"),
            (ErrorCode::Unauthorized, "unauthorized"),
            (ErrorCode::BoardArchived, "board_archived"),
        ] {
            let body = ErrorBody {
                error: ErrorDetail {
                    code,
                    raw_code: None,
                    message: "m".to_owned(),
                },
            };
            assert_eq!(
                serde_json::to_string(&body).unwrap(),
                format!(r#"{{"error":{{"code":"{name}","message":"m"}}}}"#)
            );
        }
    }

    #[test]
    fn join_response_wire_shape_is_pinned() {
        let resp = JoinResponse {
            token: "stg1_0123456789abcdef_SECRET".to_owned(),
            board: BoardId::main(),
            role: Role::Member,
            kind: PrincipalKind::Agent,
            expires_at_ms: 42,
        };
        assert_eq!(
            serde_json::to_string(&resp).unwrap(),
            r#"{"token":"stg1_0123456789abcdef_SECRET","board":"main","role":"member","kind":"agent","expires_at_ms":42}"#
        );
        let back: JoinResponse =
            serde_json::from_str(&serde_json::to_string(&resp).unwrap()).unwrap();
        assert_eq!(back, resp);
    }

    #[test]
    fn join_and_invite_responses_redact_secrets_in_debug() {
        let join = JoinResponse {
            token: "stg1_0123456789abcdef_SECRETVALUE".to_owned(),
            board: BoardId::main(),
            role: Role::Admin,
            kind: PrincipalKind::Human,
            expires_at_ms: 1,
        };
        let invite = InviteResponse {
            invite: "stgi1_0123456789abcdef_SECRETVALUE".to_owned(),
            expires_at_ms: 1,
        };
        for shown in [format!("{join:?}"), format!("{invite:?}")] {
            assert!(!shown.contains("SECRETVALUE"), "{shown}");
            assert!(!shown.contains("0123456789abcdef"), "{shown}");
            assert!(shown.contains("<redacted>"), "{shown}");
        }
    }

    #[test]
    fn request_types_reject_unknown_fields_and_validate() {
        let ok: InviteRequest =
            serde_json::from_str(r#"{"kind":"agent","role":"member"}"#).unwrap();
        assert_eq!(ok.expires_in_minutes, None);
        let with: InviteRequest =
            serde_json::from_str(r#"{"kind":"human","role":"admin","expires_in_minutes":30}"#)
                .unwrap();
        assert_eq!(with.expires_in_minutes, Some(30));
        assert!(
            serde_json::from_str::<InviteRequest>(r#"{"kind":"agent","role":"member","x":1}"#)
                .is_err()
        );
        assert!(
            serde_json::from_str::<InviteRequest>(r#"{"kind":"robot","role":"member"}"#).is_err()
        );
        let join: JoinRequest = serde_json::from_str(r#"{"invite":"i","name":"bot-1"}"#).unwrap();
        assert_eq!(join.name.as_str(), "bot-1");
        assert!(
            serde_json::from_str::<JoinRequest>(r#"{"invite":"i","name":"Bad Name"}"#).is_err()
        );
        assert!(
            serde_json::from_str::<JoinRequest>(r#"{"invite":"i","name":"a","extra":1}"#).is_err()
        );
        let board: CreateBoardRequest = serde_json::from_str(r#"{"name":"ops"}"#).unwrap();
        assert_eq!(board.name.as_str(), "ops");
        assert!(serde_json::from_str::<CreateBoardRequest>(r#"{"name":"Ops!"}"#).is_err());
        assert!(serde_json::from_str::<CreateBoardRequest>(r#"{"name":"ops","x":1}"#).is_err());
    }

    #[test]
    fn listing_and_whoami_types_roundtrip_with_pinned_shapes() {
        let member = MemberInfo {
            name: Principal::new("ann").unwrap(),
            kind: PrincipalKind::Human,
            role: Role::Admin,
            last_seen_ms: None,
        };
        assert_eq!(
            serde_json::to_string(&MembersResponse {
                members: vec![member.clone()]
            })
            .unwrap(),
            r#"{"members":[{"name":"ann","kind":"human","role":"admin","last_seen_ms":null}]}"#
        );
        let token = TokenInfo {
            id: TokenId::new("0123456789abcdef").unwrap(),
            principal: Principal::new("ann").unwrap(),
            role: Role::Member,
            expires_at_ms: 9,
            revoked: false,
            last_seen_ms: Some(5),
        };
        let json = serde_json::to_string(&TokensResponse {
            tokens: vec![token.clone()],
        })
        .unwrap();
        assert_eq!(
            json,
            r#"{"tokens":[{"id":"0123456789abcdef","principal":"ann","role":"member","expires_at_ms":9,"revoked":false,"last_seen_ms":5}]}"#
        );
        assert_eq!(
            serde_json::from_str::<TokensResponse>(&json)
                .unwrap()
                .tokens,
            vec![token]
        );
        let boards = BoardsResponse {
            boards: vec![BoardSummary {
                id: BoardId::main(),
                archived: false,
                created_at_ms: 7,
            }],
        };
        assert_eq!(
            serde_json::to_string(&boards).unwrap(),
            r#"{"boards":[{"id":"main","archived":false,"created_at_ms":7}]}"#
        );
        let who = WhoAmI {
            principal: Principal::new("ann").unwrap(),
            kind: PrincipalKind::Human,
            board: Some(BoardId::main()),
            role: Some(Role::Admin),
            instance_admin: false,
        };
        let json = serde_json::to_string(&who).unwrap();
        assert_eq!(
            json,
            r#"{"principal":"ann","kind":"human","board":"main","role":"admin","instance_admin":false}"#
        );
        assert_eq!(serde_json::from_str::<WhoAmI>(&json).unwrap(), who);
    }
}
