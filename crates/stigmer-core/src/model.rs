//! Stored boards and messages, and the result of posting one.

use serde::{Deserialize, Serialize};

use crate::{BoardId, ChannelPath, Event, Label, MessageId, Principal};

/// A message as stored on a board. A thread root has `thread_id == id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    pub id: MessageId,
    pub board: BoardId,
    pub channel: ChannelPath,
    pub thread_id: MessageId,
    pub author: Principal,
    pub text: String,
    pub labels: Vec<Label>,
    pub at_ms: i64,
}

/// A board as the store keeps it. `created_by` is `None` for boards nobody created through the
/// store (`main`, made when the store opens). `archived_at_ms` is set once, when the board is
/// archived; an archived board refuses posts and stays readable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoardInfo {
    pub id: BoardId,
    pub created_at_ms: i64,
    pub created_by: Option<Principal>,
    pub archived_at_ms: Option<i64>,
}

/// The outcome of a post: the stored message and the event that recorded it.
/// `replayed` is true when an earlier post with the same idempotency key was returned instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Posted {
    pub message: Message,
    pub event: Event,
    pub replayed: bool,
}

/// One page request for a channel read. `before` is the thread id of the last item of the
/// previous page; `limit` is clamped by the store to 1..=200.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Page {
    pub limit: u32,
    pub before: Option<MessageId>,
}

/// A thread as listed in a channel read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreadSummary {
    pub thread_id: MessageId,
    pub channel: ChannelPath,
    /// The first 200 characters of the root message text.
    pub root_text_preview: String,
    /// Number of replies, not counting the root.
    pub reply_count: u32,
    /// Time of the latest message in the thread, root included.
    pub last_at_ms: i64,
}

/// A thread root and its replies, replies in event order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Thread {
    pub root: Message,
    pub replies: Vec<Message>,
}

/// Narrows an event feed. Unset fields match everything.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventFilter {
    /// Matches whole path segments: `research` matches `research/tls` but not `research2`.
    pub channel_prefix: Option<ChannelPath>,
    pub thread: Option<MessageId>,
    /// Matches events whose message carries exactly this label.
    pub label: Option<Label>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        event_hash, BoardId, ChannelPath, Cursor, Event, EventKind, HashInput, Label, MessageId,
        Principal, GENESIS_HASH,
    };

    fn sample() -> Posted {
        let id = MessageId::new("msg_0123456789abcdef01234567").unwrap();
        let channel = ChannelPath::new("eng/ops").unwrap();
        let author = Principal::new("alice").unwrap();
        let at_ms = 1_700_000_000_000;
        let message = Message {
            id: id.clone(),
            board: BoardId::main(),
            channel: channel.clone(),
            thread_id: id.clone(),
            author: author.clone(),
            text: "hello".to_owned(),
            labels: vec![Label::new("kind", "bug").unwrap()],
            at_ms,
        };
        let hash = event_hash(&HashInput {
            prev: GENESIS_HASH,
            seq: 1,
            kind: EventKind::ThreadCreated,
            actor: &author,
            message_id: &id,
            thread_id: &id,
            channel: &channel,
            at_ms,
        });
        let event = Event {
            seq: 1,
            cursor: Cursor::from_seq(1),
            kind: EventKind::ThreadCreated,
            actor: author,
            message_id: id.clone(),
            thread_id: id,
            channel,
            at_ms,
            hash,
        };
        Posted {
            message,
            event,
            replayed: false,
        }
    }

    #[test]
    fn read_types_roundtrip_through_json() {
        let posted = sample();
        let thread = Thread {
            root: posted.message.clone(),
            replies: vec![],
        };
        let json = serde_json::to_string(&thread).unwrap();
        assert_eq!(serde_json::from_str::<Thread>(&json).unwrap(), thread);

        let summary = ThreadSummary {
            thread_id: posted.message.id.clone(),
            channel: posted.message.channel.clone(),
            root_text_preview: "hello".to_owned(),
            reply_count: 0,
            last_at_ms: posted.message.at_ms,
        };
        let json = serde_json::to_string(&summary).unwrap();
        assert_eq!(
            serde_json::from_str::<ThreadSummary>(&json).unwrap(),
            summary
        );

        let page = Page {
            limit: 10,
            before: Some(posted.message.id),
        };
        let json = serde_json::to_string(&page).unwrap();
        assert_eq!(serde_json::from_str::<Page>(&json).unwrap(), page);

        let filter = EventFilter::default();
        assert_eq!(filter.channel_prefix, None);
        assert_eq!(filter.thread, None);
        assert_eq!(filter.label, None);
        let json = serde_json::to_string(&filter).unwrap();
        assert_eq!(serde_json::from_str::<EventFilter>(&json).unwrap(), filter);
    }

    #[test]
    fn posted_roundtrips_through_json() {
        let posted = sample();
        let json = serde_json::to_string(&posted).unwrap();
        let back: Posted = serde_json::from_str(&json).unwrap();
        assert_eq!(back, posted);
    }

    #[test]
    fn board_info_roundtrips_through_json() {
        let info = BoardInfo {
            id: BoardId::new("research").unwrap(),
            created_at_ms: 1_700_000_000_000,
            created_by: Some(Principal::new("alice").unwrap()),
            archived_at_ms: Some(1_700_000_000_500),
        };
        let json = serde_json::to_string(&info).unwrap();
        assert_eq!(serde_json::from_str::<BoardInfo>(&json).unwrap(), info);

        let main = BoardInfo {
            id: BoardId::main(),
            created_at_ms: 0,
            created_by: None,
            archived_at_ms: None,
        };
        let json = serde_json::to_string(&main).unwrap();
        assert_eq!(serde_json::from_str::<BoardInfo>(&json).unwrap(), main);
    }

    #[test]
    fn board_info_deserialize_validates_fields() {
        let mut value = serde_json::to_value(BoardInfo {
            id: BoardId::main(),
            created_at_ms: 1,
            created_by: None,
            archived_at_ms: None,
        })
        .unwrap();
        value["created_by"] = serde_json::json!("Not A Principal");
        assert!(serde_json::from_value::<BoardInfo>(value).is_err());
    }

    #[test]
    fn message_deserialize_validates_fields() {
        let mut value = serde_json::to_value(sample().message).unwrap();
        value["channel"] = serde_json::json!("Eng//Ops");
        assert!(serde_json::from_value::<Message>(value).is_err());
    }
}
