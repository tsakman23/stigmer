//! Events and the hash chain.

use std::fmt;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Deserializer, Serialize};

use crate::CoreError;

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
