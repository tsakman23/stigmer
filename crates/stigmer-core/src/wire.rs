//! Request and response bodies shared by the HTTP API and its clients.

use serde::{Deserialize, Serialize};

use crate::{ChannelPath, Cursor, Event, Label, MessageId, ThreadSummary};

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
    Conflict,
    Forbidden,
    Internal,
}

/// The code and a human-readable message of an error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorDetail {
    pub code: ErrorCode,
    pub message: String,
}

/// Every error response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: ErrorDetail,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ChannelPath, Cursor};

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
                message: "nope".to_owned(),
            },
        };
        assert_eq!(
            serde_json::to_string(&body).unwrap(),
            r#"{"error":{"code":"invalid_cursor","message":"nope"}}"#
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
}
