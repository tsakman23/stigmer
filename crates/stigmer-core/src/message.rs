//! New-message input and its validation rules.

use serde::{Deserialize, Serialize};

use crate::{BoardId, ChannelPath, CoreError, Label, MessageId, Principal, MAX_LABELS};

/// Maximum message length, counted in Unicode scalar values (chars), not bytes.
pub const MAX_MESSAGE_CHARS: usize = 10_000;

/// Maximum idempotency key length in characters.
pub const MAX_IDEMPOTENCY_KEY_CHARS: usize = 128;

/// Where a new message goes: a fresh thread in a channel, or a reply in a thread.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Target {
    NewThread { channel: ChannelPath },
    Reply { thread: MessageId },
}

/// A message about to be posted. Build with [`NewMessage::new`] so text and labels are validated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NewMessage {
    pub board: BoardId,
    pub target: Target,
    pub author: Principal,
    pub text: String,
    pub labels: Vec<Label>,
    pub idempotency_key: Option<String>,
}

impl NewMessage {
    /// Validates text (1 to [`MAX_MESSAGE_CHARS`] chars), labels (at most [`MAX_LABELS`], each valid)
    /// and the idempotency key when present (1 to [`MAX_IDEMPOTENCY_KEY_CHARS`] chars of `[A-Za-z0-9._:-]`).
    pub fn new(
        board: BoardId,
        target: Target,
        author: Principal,
        text: String,
        labels: Vec<Label>,
        idempotency_key: Option<String>,
    ) -> Result<Self, CoreError> {
        if text.is_empty() {
            return Err(CoreError::EmptyText);
        }
        if text.chars().count() > MAX_MESSAGE_CHARS {
            return Err(CoreError::TooLong {
                max: MAX_MESSAGE_CHARS,
            });
        }
        if labels.len() > MAX_LABELS {
            return Err(CoreError::TooManyLabels { max: MAX_LABELS });
        }
        // Label fields are public, so re-check each one.
        for label in &labels {
            Label::new(&label.key, &label.value)?;
        }
        if let Some(key) = &idempotency_key {
            let allowed = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-');
            if key.is_empty()
                || key.chars().count() > MAX_IDEMPOTENCY_KEY_CHARS
                || !key.chars().all(allowed)
            {
                return Err(CoreError::BadIdempotencyKey(key.clone()));
            }
        }
        Ok(Self {
            board,
            target,
            author,
            text,
            labels,
            idempotency_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(text: &str, labels: Vec<Label>) -> Result<NewMessage, CoreError> {
        NewMessage::new(
            BoardId::main(),
            Target::NewThread {
                channel: ChannelPath::new("eng/ops").unwrap(),
            },
            Principal::new("alice").unwrap(),
            text.to_owned(),
            labels,
            None,
        )
    }

    #[test]
    fn text_of_10000_chars_is_accepted() {
        assert!(build(&"a".repeat(10_000), vec![]).is_ok());
    }

    #[test]
    fn text_of_10001_chars_is_rejected_with_too_long() {
        assert_eq!(
            build(&"a".repeat(10_001), vec![]).unwrap_err(),
            CoreError::TooLong {
                max: MAX_MESSAGE_CHARS
            }
        );
    }

    #[test]
    fn emoji_text_counts_chars_not_bytes() {
        assert!(build(&"🙂".repeat(10_000), vec![]).is_ok());
        assert_eq!(
            build(&"🙂".repeat(10_001), vec![]).unwrap_err(),
            CoreError::TooLong {
                max: MAX_MESSAGE_CHARS
            }
        );
    }

    #[test]
    fn empty_text_is_rejected() {
        assert_eq!(build("", vec![]).unwrap_err(), CoreError::EmptyText);
    }

    #[test]
    fn thirty_three_labels_rejected_with_too_many_labels() {
        let label = Label::new("k", "v").unwrap();
        assert!(build("hi", vec![label.clone(); 32]).is_ok());
        assert_eq!(
            build("hi", vec![label; 33]).unwrap_err(),
            CoreError::TooManyLabels { max: MAX_LABELS }
        );
    }

    #[test]
    fn hand_built_invalid_label_is_rejected() {
        let bad = Label {
            key: "Bad Key".into(),
            value: "v".into(),
        };
        assert!(matches!(
            build("hi", vec![bad]),
            Err(CoreError::BadLabel(_))
        ));
    }

    #[test]
    fn target_deserialize_rejects_bad_channel_and_thread() {
        let ok: Target = serde_json::from_str(r#"{"NewThread":{"channel":"eng/ops"}}"#).unwrap();
        assert!(matches!(ok, Target::NewThread { .. }));
        assert!(serde_json::from_str::<Target>(r#"{"NewThread":{"channel":"Eng//Ops"}}"#).is_err());
        assert!(serde_json::from_str::<Target>(r#"{"Reply":{"thread":"nope"}}"#).is_err());
        let good = r#"{"Reply":{"thread":"msg_0123456789abcdef01234567"}}"#;
        assert!(matches!(
            serde_json::from_str::<Target>(good).unwrap(),
            Target::Reply { .. }
        ));
    }

    fn build_keyed(key: &str) -> Result<NewMessage, CoreError> {
        NewMessage::new(
            BoardId::main(),
            Target::NewThread {
                channel: ChannelPath::new("eng/ops").unwrap(),
            },
            Principal::new("alice").unwrap(),
            "hi".to_owned(),
            vec![],
            Some(key.to_owned()),
        )
    }

    #[test]
    fn empty_idempotency_key_is_rejected() {
        assert!(matches!(
            build_keyed(""),
            Err(CoreError::BadIdempotencyKey(_))
        ));
    }

    #[test]
    fn idempotency_key_of_129_chars_is_rejected_and_128_accepted() {
        assert!(build_keyed(&"k".repeat(128)).is_ok());
        assert!(matches!(
            build_keyed(&"k".repeat(129)),
            Err(CoreError::BadIdempotencyKey(_))
        ));
    }

    #[test]
    fn idempotency_key_with_a_space_is_rejected() {
        assert!(matches!(
            build_keyed("has space"),
            Err(CoreError::BadIdempotencyKey(_))
        ));
        assert!(build_keyed("Az09._:-").is_ok());
    }

    #[test]
    fn valid_reply_keeps_all_fields() {
        let thread = MessageId::generate().unwrap();
        let msg = NewMessage::new(
            BoardId::main(),
            Target::Reply {
                thread: thread.clone(),
            },
            Principal::new("bot").unwrap(),
            "ack".to_owned(),
            vec![Label::new("k", "v").unwrap()],
            Some("key-1".to_owned()),
        )
        .unwrap();
        assert_eq!(msg.target, Target::Reply { thread });
        assert_eq!(msg.text, "ack");
        assert_eq!(msg.idempotency_key.as_deref(), Some("key-1"));
    }
}
