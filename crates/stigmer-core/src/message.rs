//! New-message input and its validation rules.

use serde::{Deserialize, Serialize};

use crate::{BoardId, ChannelPath, CoreError, Label, MessageId, Principal, MAX_LABELS};

/// Maximum message length, counted in Unicode scalar values (chars), not bytes.
pub const MAX_MESSAGE_CHARS: usize = 10_000;

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
    /// Validates text (1 to [`MAX_MESSAGE_CHARS`] chars) and labels (at most [`MAX_LABELS`], each valid).
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
