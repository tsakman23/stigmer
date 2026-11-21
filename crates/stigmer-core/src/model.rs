//! Stored messages and the result of posting one.

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

/// The outcome of a post: the stored message and the event that recorded it.
/// `replayed` is true when an earlier post with the same idempotency key was returned instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Posted {
    pub message: Message,
    pub event: Event,
    pub replayed: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        event_hash, BoardId, ChannelPath, Cursor, Event, EventKind, Label, MessageId, Principal,
        GENESIS_HASH,
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
        let hash = event_hash(
            GENESIS_HASH,
            1,
            EventKind::ThreadCreated,
            &author,
            &id,
            &channel,
            at_ms,
        );
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
    fn posted_roundtrips_through_json() {
        let posted = sample();
        let json = serde_json::to_string(&posted).unwrap();
        let back: Posted = serde_json::from_str(&json).unwrap();
        assert_eq!(back, posted);
    }

    #[test]
    fn message_deserialize_validates_fields() {
        let mut value = serde_json::to_value(sample().message).unwrap();
        value["channel"] = serde_json::json!("Eng//Ops");
        assert!(serde_json::from_value::<Message>(value).is_err());
    }
}
