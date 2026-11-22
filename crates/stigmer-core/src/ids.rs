//! Identifiers and validated string newtypes.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use crate::CoreError;

/// Implements accessors, `Display` and a validating `Deserialize` for a string newtype.
macro_rules! string_newtype {
    ($name:ident) => {
        impl $name {
            /// The underlying string.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let raw = String::deserialize(deserializer)?;
                $name::new(&raw).map_err(serde::de::Error::custom)
            }
        }
    };
}

/// Longest principal name, in characters.
pub const MAX_PRINCIPAL_CHARS: usize = 64;

/// Most segments a channel path may have.
pub const MAX_CHANNEL_SEGMENTS: usize = 8;

/// True when every char is in `[a-z0-9._-]`.
pub(crate) fn is_slug_char(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-')
}

/// Identifies a board. M0 has a single board, `main`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct BoardId(String);

impl BoardId {
    /// Validates and wraps a board id (`[a-z0-9._-]{1,64}`, not only dots: `.` and `..` are
    /// path segments, not names).
    pub fn new(raw: &str) -> Result<Self, CoreError> {
        if !(1..=64).contains(&raw.chars().count()) || !raw.chars().all(is_slug_char) {
            return Err(CoreError::BadId(raw.to_owned()));
        }
        if raw.chars().all(|c| c == '.') {
            return Err(CoreError::DotsOnlyBoard(raw.to_owned()));
        }
        Ok(Self(raw.to_owned()))
    }

    /// The default board.
    pub fn main() -> Self {
        Self("main".to_owned())
    }
}
string_newtype!(BoardId);

/// Identifies a message: `msg_` followed by 24 lowercase hex digits.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct MessageId(String);

impl MessageId {
    const PREFIX: &'static str = "msg_";
    const HEX_LEN: usize = 24;

    /// Validates and wraps an existing message id.
    pub fn new(raw: &str) -> Result<Self, CoreError> {
        let valid = raw.strip_prefix(Self::PREFIX).is_some_and(|hex| {
            hex.len() == Self::HEX_LEN
                && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        });
        if valid {
            Ok(Self(raw.to_owned()))
        } else {
            Err(CoreError::BadId(raw.to_owned()))
        }
    }

    /// Generates a new random id (96 bits from the OS RNG).
    pub fn generate() -> Result<Self, CoreError> {
        let mut bytes = [0u8; Self::HEX_LEN / 2];
        getrandom::fill(&mut bytes).map_err(|e| CoreError::Entropy(e.to_string()))?;
        let mut id = String::from(Self::PREFIX);
        for b in bytes {
            id.push_str(&format!("{b:02x}"));
        }
        Ok(Self(id))
    }
}
string_newtype!(MessageId);

/// A channel path such as `eng/ops`: 1 to `MAX_CHANNEL_SEGMENTS` (8) segments of `[a-z0-9._-]+` joined by `/`,
/// at most 128 bytes in total (the charset is ASCII, so bytes and chars agree). No leading or trailing slash.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct ChannelPath(String);

impl ChannelPath {
    const MAX_BYTES: usize = 128;

    /// Validates and wraps a channel path.
    pub fn new(raw: &str) -> Result<Self, CoreError> {
        let valid = raw.len() <= Self::MAX_BYTES
            && raw.split('/').count() <= MAX_CHANNEL_SEGMENTS
            && raw
                .split('/')
                .all(|seg| !seg.is_empty() && seg.chars().all(is_slug_char));
        if valid {
            Ok(Self(raw.to_owned()))
        } else {
            Err(CoreError::BadChannel(raw.to_owned()))
        }
    }
}
string_newtype!(ChannelPath);

/// Identifies who wrote a message: a person or an agent (`[a-z0-9._-]`, 1 to
/// `MAX_PRINCIPAL_CHARS` (64) characters).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct Principal(String);

impl Principal {
    /// Validates and wraps a principal name.
    pub fn new(raw: &str) -> Result<Self, CoreError> {
        if (1..=MAX_PRINCIPAL_CHARS).contains(&raw.chars().count()) && raw.chars().all(is_slug_char)
        {
            Ok(Self(raw.to_owned()))
        } else {
            Err(CoreError::BadPrincipal(raw.to_owned()))
        }
    }
}
string_newtype!(Principal);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_id_roundtrips_and_has_msg_prefix() {
        let id = MessageId::generate().unwrap();
        assert!(id.as_str().starts_with("msg_"));
        assert_eq!(id.as_str().len(), 4 + 24);
        let parsed = MessageId::new(id.as_str()).unwrap();
        assert_eq!(parsed, id);
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"{}\"", id));
        let back: MessageId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, id);
    }

    #[test]
    fn generated_message_ids_differ() {
        assert_ne!(
            MessageId::generate().unwrap(),
            MessageId::generate().unwrap()
        );
    }

    #[test]
    fn message_id_rejects_malformed_values() {
        for bad in [
            "",
            "msg_",
            "msg_ABCDEF0123456789abcdef01",
            "msg_0123",
            "id_0123456789abcdef01234567",
            "msg_0123456789abcdef0123456789",
        ] {
            assert!(
                matches!(MessageId::new(bad), Err(CoreError::BadId(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn board_id_rejects_names_made_only_of_dots() {
        let all_dots = ".".repeat(64);
        for bad in [".", "..", "...", all_dots.as_str()] {
            let err = BoardId::new(bad).unwrap_err();
            assert_eq!(err, CoreError::DotsOnlyBoard(bad.to_owned()), "{bad}");
            assert!(err.to_string().contains("only of dots"), "{err}");
        }
        assert!(serde_json::from_str::<BoardId>("\"..\"").is_err());
        for good in ["a.", ".a", "a..b", "v1.2", "..x"] {
            assert!(BoardId::new(good).is_ok(), "{good}");
        }
    }

    #[test]
    fn board_id_main_is_main() {
        assert_eq!(BoardId::main().as_str(), "main");
        assert_eq!(BoardId::main().to_string(), "main");
    }

    #[test]
    fn principal_accepts_valid_and_rejects_invalid() {
        assert_eq!(
            Principal::new("alice.dev-1_x").unwrap().as_str(),
            "alice.dev-1_x"
        );
        assert!(Principal::new(&"a".repeat(64)).is_ok());
        for bad in ["", "Alice", "a b", "a/b", &"a".repeat(65)] {
            assert!(
                matches!(Principal::new(bad), Err(CoreError::BadPrincipal(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn deserialize_validates() {
        assert!(serde_json::from_str::<Principal>("\"Bad Name\"").is_err());
        assert!(serde_json::from_str::<MessageId>("\"nope\"").is_err());
        assert!(serde_json::from_str::<BoardId>("\"\"").is_err());
        assert_eq!(
            serde_json::from_str::<Principal>("\"bob\"")
                .unwrap()
                .as_str(),
            "bob"
        );
    }

    #[test]
    fn channel_path_rejects_uppercase_empty_segment_and_depth_9() {
        assert!(ChannelPath::new("a/b/c.d_e-f/0").is_ok());
        assert!(ChannelPath::new("a/b/c/d/e/f/g/h").is_ok());
        for bad in [
            "Eng",
            "a//b",
            "",
            "/a",
            "a/",
            "a/b/c/d/e/f/g/h/i",
            "a b",
            "a/B",
        ] {
            assert!(
                matches!(ChannelPath::new(bad), Err(CoreError::BadChannel(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn channel_path_total_length_limit_is_128() {
        assert!(ChannelPath::new(&"a".repeat(128)).is_ok());
        assert!(ChannelPath::new(&"a".repeat(129)).is_err());
    }

    #[test]
    fn channel_path_deserialize_validates() {
        assert!(serde_json::from_str::<ChannelPath>("\"a//b\"").is_err());
        assert_eq!(
            serde_json::from_str::<ChannelPath>("\"eng/ops\"")
                .unwrap()
                .as_str(),
            "eng/ops"
        );
    }
}
