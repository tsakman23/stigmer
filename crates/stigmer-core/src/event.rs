//! Events and the hash chain.

use std::fmt;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

use crate::{ChannelPath, CoreError, MessageId, Principal};

/// Previous-hash value for the first event in a chain: 64 zeros.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Version of the event hash input format. Bump if `event_hash` ever changes.
pub const HASH_VERSION: u32 = 1;

/// An opaque position in the event log: `ev_` + base64url(no padding) of `v1:{seq}`.
/// Sequences start at 1. Clients must treat the value as opaque.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct Cursor(String);

impl Cursor {
    const PREFIX: &'static str = "ev_";
    const VERSION: &'static str = "v1:";

    /// Encodes a sequence number as a cursor.
    pub fn from_seq(seq: u64) -> Self {
        let payload = format!("{}{seq}", Self::VERSION);
        Self(format!(
            "{}{}",
            Self::PREFIX,
            URL_SAFE_NO_PAD.encode(payload)
        ))
    }

    /// Decodes the sequence number, rejecting anything that is not a valid v1 cursor.
    pub fn seq(&self) -> Result<u64, CoreError> {
        let bad = || CoreError::BadCursor(self.0.clone());
        let encoded = self.0.strip_prefix(Self::PREFIX).ok_or_else(bad)?;
        let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| bad())?;
        let payload = String::from_utf8(bytes).map_err(|_| bad())?;
        let digits = payload.strip_prefix(Self::VERSION).ok_or_else(bad)?;
        // Reject signs and whitespace that `u64::from_str` might otherwise accept ("+5").
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad());
        }
        match digits.parse::<u64>() {
            Ok(seq) if seq >= 1 => Ok(seq),
            _ => Err(bad()),
        }
    }

    /// The cursor as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Cursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Cursor {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let cursor = Cursor(String::deserialize(deserializer)?);
        cursor.seq().map_err(serde::de::Error::custom)?;
        Ok(cursor)
    }
}

/// What happened. Serialized as dotted names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventKind {
    #[serde(rename = "thread.created")]
    ThreadCreated,
    #[serde(rename = "message.replied")]
    MessageReplied,
}

impl EventKind {
    /// Every kind, for parsing and exhaustive checks.
    pub const ALL: &'static [EventKind] = &[EventKind::ThreadCreated, EventKind::MessageReplied];

    /// The kind whose wire name is `name`, if any.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|kind| kind.as_str() == name)
    }

    /// The wire name, also used as hash input.
    pub fn as_str(self) -> &'static str {
        match self {
            EventKind::ThreadCreated => "thread.created",
            EventKind::MessageReplied => "message.replied",
        }
    }
}

/// One entry in the tamper-evident log. Holds no message text, only references.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub seq: u64,
    pub cursor: Cursor,
    pub kind: EventKind,
    pub actor: Principal,
    pub message_id: MessageId,
    pub thread_id: MessageId,
    pub channel: ChannelPath,
    pub at_ms: i64,
    pub hash: String,
}

/// Lowercase hex sha256 of `{prev}:{seq}:{kind}:{actor}:{message_id}:{channel}:{at_ms}`.
pub fn event_hash(
    prev: &str,
    seq: u64,
    kind: EventKind,
    actor: &Principal,
    message_id: &MessageId,
    channel: &ChannelPath,
    at_ms: i64,
) -> String {
    let input = format!(
        "{prev}:{seq}:{}:{actor}:{message_id}:{channel}:{at_ms}",
        kind.as_str()
    );
    let digest = Sha256::digest(input.as_bytes());
    let mut hex = String::with_capacity(64);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_kind_all_lists_every_kind_and_parses_back() {
        // Exhaustive match: adding a variant stops compiling here until ALL is revisited.
        for kind in EventKind::ALL {
            match kind {
                EventKind::ThreadCreated | EventKind::MessageReplied => {}
            }
            assert_eq!(EventKind::from_name(kind.as_str()), Some(*kind));
        }
        assert_eq!(EventKind::ALL.len(), 2);
        assert_eq!(EventKind::from_name("thread.deleted"), None);
        assert_eq!(EventKind::from_name(""), None);
    }

    #[test]
    fn cursor_roundtrips_seq() {
        for seq in [1u64, 2, 255, 1_000_000, u64::MAX] {
            let c = Cursor::from_seq(seq);
            assert!(c.as_str().starts_with("ev_"));
            assert_eq!(c.seq().unwrap(), seq);
            let json = serde_json::to_string(&c).unwrap();
            assert_eq!(json, format!("\"{}\"", c));
            let back: Cursor = serde_json::from_str(&json).unwrap();
            assert_eq!(back, c);
        }
    }

    fn raw_cursor(payload: &str) -> String {
        use base64::Engine;
        format!(
            "ev_{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload)
        )
    }

    #[test]
    fn cursor_rejects_garbage_and_wrong_version() {
        let bad = [
            "".to_owned(),
            "garbage".to_owned(),
            "ev_".to_owned(),
            "ev_!!!not-base64".to_owned(),
            "xx_".to_owned() + &raw_cursor("v1:5")[3..],
            raw_cursor("v2:5"),
            raw_cursor("5"),
            raw_cursor("v1:abc"),
            raw_cursor("v1:-3"),
            raw_cursor("v1:"),
            raw_cursor("v1:0"),
        ];
        for b in bad {
            let json = serde_json::to_string(&b).unwrap();
            assert!(
                serde_json::from_str::<Cursor>(&json).is_err(),
                "deserialize {b}"
            );
            assert!(
                matches!(Cursor(b.clone()).seq(), Err(CoreError::BadCursor(_))),
                "{b}"
            );
        }
    }

    const MSG: &str = "msg_0123456789abcdef01234567";

    fn hash_with(
        prev: &str,
        seq: u64,
        kind: EventKind,
        actor: &str,
        msg: &str,
        channel: &str,
        at_ms: i64,
    ) -> String {
        event_hash(
            prev,
            seq,
            kind,
            &Principal::new(actor).unwrap(),
            &MessageId::new(msg).unwrap(),
            &ChannelPath::new(channel).unwrap(),
            at_ms,
        )
    }

    fn base() -> String {
        hash_with(
            GENESIS_HASH,
            1,
            EventKind::ThreadCreated,
            "alice",
            MSG,
            "eng/ops",
            1_700_000_000_000,
        )
    }

    #[test]
    fn event_hash_is_64_hex_and_changes_with_any_field() {
        let h = base();
        assert_eq!(h.len(), 64);
        assert!(h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        let other_msg = "msg_ffffffffffffffffffffffff";
        let variants = [
            hash_with(
                "1".repeat(64).as_str(),
                1,
                EventKind::ThreadCreated,
                "alice",
                MSG,
                "eng/ops",
                1_700_000_000_000,
            ),
            hash_with(
                GENESIS_HASH,
                2,
                EventKind::ThreadCreated,
                "alice",
                MSG,
                "eng/ops",
                1_700_000_000_000,
            ),
            hash_with(
                GENESIS_HASH,
                1,
                EventKind::MessageReplied,
                "alice",
                MSG,
                "eng/ops",
                1_700_000_000_000,
            ),
            hash_with(
                GENESIS_HASH,
                1,
                EventKind::ThreadCreated,
                "bob",
                MSG,
                "eng/ops",
                1_700_000_000_000,
            ),
            hash_with(
                GENESIS_HASH,
                1,
                EventKind::ThreadCreated,
                "alice",
                other_msg,
                "eng/ops",
                1_700_000_000_000,
            ),
            hash_with(
                GENESIS_HASH,
                1,
                EventKind::ThreadCreated,
                "alice",
                MSG,
                "eng/dev",
                1_700_000_000_000,
            ),
            hash_with(
                GENESIS_HASH,
                1,
                EventKind::ThreadCreated,
                "alice",
                MSG,
                "eng/ops",
                1_700_000_000_001,
            ),
        ];
        for v in variants {
            assert_ne!(v, h);
        }
        assert_eq!(base(), h, "hash is deterministic");
    }

    #[test]
    fn event_hash_chains_from_genesis() {
        assert_eq!(GENESIS_HASH.len(), 64);
        assert!(GENESIS_HASH.bytes().all(|b| b == b'0'));
        let first = base();
        let second = hash_with(
            &first,
            2,
            EventKind::MessageReplied,
            "bob",
            MSG,
            "eng/ops",
            1_700_000_000_500,
        );
        assert_ne!(second, first);
        let tampered = hash_with(
            GENESIS_HASH,
            2,
            EventKind::MessageReplied,
            "bob",
            MSG,
            "eng/ops",
            1_700_000_000_500,
        );
        assert_ne!(second, tampered, "the previous hash feeds the next");
    }

    #[test]
    fn event_hash_format_is_pinned() {
        // sha256 of exactly:
        // 0000000000000000000000000000000000000000000000000000000000000000:1:thread.created:alice:msg_0123456789abcdef01234567:eng/ops:1700000000000
        assert_eq!(
            base(),
            "9b7ba6cec6253a7c7f25af56396d37e38325689136dc82dd746e5334db73987b"
        );
    }

    #[test]
    fn event_kind_serializes_dotted_and_event_roundtrips() {
        assert_eq!(
            serde_json::to_string(&EventKind::ThreadCreated).unwrap(),
            "\"thread.created\""
        );
        assert_eq!(
            serde_json::to_string(&EventKind::MessageReplied).unwrap(),
            "\"message.replied\""
        );
        assert_eq!(EventKind::ThreadCreated.as_str(), "thread.created");
        assert_eq!(EventKind::MessageReplied.as_str(), "message.replied");
        let event = Event {
            seq: 1,
            cursor: Cursor::from_seq(1),
            kind: EventKind::ThreadCreated,
            actor: Principal::new("alice").unwrap(),
            message_id: MessageId::new(MSG).unwrap(),
            thread_id: MessageId::new(MSG).unwrap(),
            channel: ChannelPath::new("eng/ops").unwrap(),
            at_ms: 1_700_000_000_000,
            hash: base(),
        };
        let back: Event = serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
        assert_eq!(back, event);
    }
}
