//! Labels: `key=value` metadata attached to messages.

use serde::{Deserialize, Serialize};

use crate::ids::is_slug_char;
use crate::CoreError;

/// Maximum number of labels on one message.
pub const MAX_LABELS: usize = 32;
const MAX_KEY_CHARS: usize = 64;
const MAX_VALUE_CHARS: usize = 256;

/// A `key=value` label. Keys are `[a-z0-9._-]{1,64}`; values are 1 to 256 chars.
///
/// Fields are public for reading; build values with [`Label::new`] so the rules hold.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "RawLabel")]
pub struct Label {
    pub key: String,
    pub value: String,
}

#[derive(Deserialize)]
struct RawLabel {
    key: String,
    value: String,
}

impl TryFrom<RawLabel> for Label {
    type Error = CoreError;

    fn try_from(raw: RawLabel) -> Result<Self, Self::Error> {
        Label::new(&raw.key, &raw.value)
    }
}

impl Label {
    /// Validates and builds a label.
    pub fn new(key: &str, value: &str) -> Result<Self, CoreError> {
        let key_ok =
            (1..=MAX_KEY_CHARS).contains(&key.chars().count()) && key.chars().all(is_slug_char);
        if !key_ok {
            return Err(CoreError::BadLabel(format!("invalid key {key:?}")));
        }
        if !(1..=MAX_VALUE_CHARS).contains(&value.chars().count()) {
            return Err(CoreError::BadLabel(format!(
                "value for {key:?} must be 1 to {MAX_VALUE_CHARS} characters"
            )));
        }
        Ok(Self {
            key: key.to_owned(),
            value: value.to_owned(),
        })
    }
}

/// Parses `key=value` strings, splitting each on the first `=`.
pub fn parse_labels(raw: &[String]) -> Result<Vec<Label>, CoreError> {
    if raw.len() > MAX_LABELS {
        return Err(CoreError::TooManyLabels { max: MAX_LABELS });
    }
    raw.iter()
        .map(|item| {
            let (key, value) = item
                .split_once('=')
                .ok_or_else(|| CoreError::BadLabel(format!("expected key=value, got {item:?}")))?;
            Label::new(key, value)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_labels_splits_on_first_equals() {
        let labels = parse_labels(&raw(&["a=b=c"])).unwrap();
        assert_eq!(
            labels,
            vec![Label {
                key: "a".into(),
                value: "b=c".into()
            }]
        );
    }

    #[test]
    fn parse_labels_keeps_order() {
        let labels = parse_labels(&raw(&["kind=bug", "prio=high"])).unwrap();
        assert_eq!(labels[0].key, "kind");
        assert_eq!(labels[1].key, "prio");
    }

    #[test]
    fn parse_labels_rejects_missing_equals_and_empty_parts() {
        for bad in ["novalue", "=v", "k=", "", "UPPER=v", "k k=v"] {
            assert!(
                matches!(parse_labels(&raw(&[bad])), Err(CoreError::BadLabel(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn label_value_limit_is_256_chars() {
        assert!(Label::new("k", &"x".repeat(256)).is_ok());
        assert!(matches!(
            Label::new("k", &"x".repeat(257)),
            Err(CoreError::BadLabel(_))
        ));
        assert!(Label::new("k", &"🙂".repeat(256)).is_ok());
    }

    #[test]
    fn label_key_limit_is_64_chars() {
        assert!(Label::new(&"k".repeat(64), "v").is_ok());
        assert!(Label::new(&"k".repeat(65), "v").is_err());
    }

    #[test]
    fn thirty_two_labels_accepted_and_33_rejected_with_too_many_labels() {
        let ok: Vec<String> = (0..32).map(|i| format!("k{i}=v")).collect();
        assert_eq!(parse_labels(&ok).unwrap().len(), 32);
        let too_many: Vec<String> = (0..33).map(|i| format!("k{i}=v")).collect();
        assert_eq!(
            parse_labels(&too_many),
            Err(CoreError::TooManyLabels { max: MAX_LABELS })
        );
    }
}
