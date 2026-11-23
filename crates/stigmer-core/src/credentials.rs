//! Credential secrets: generation, parsing, hashing and constant-time comparison.
//!
//! A token is `stg1_<id>_<secret>` and an invite is `stgi1_<id>_<secret>`: `id` is 8 random
//! bytes as 16 lowercase hex chars (a lookup key, not a secret) and `secret` is 32 random bytes
//! as 43 base64url chars. Only `sha256(secret)` is ever stored. Nothing here logs, displays or
//! echoes a secret.

use std::fmt;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

use crate::CoreError;

/// What every token starts with.
pub const TOKEN_PREFIX: &str = "stg1_";
/// What every invite starts with.
pub const INVITE_PREFIX: &str = "stgi1_";

const ID_BYTES: usize = 8;
const SECRET_BYTES: usize = 32;
const ID_CHARS: usize = ID_BYTES * 2;
const SECRET_CHARS: usize = 43;

/// The public, non-secret id of a token or invite: 16 lowercase hex chars.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct TokenId(String);

impl TokenId {
    /// Validates and wraps an id. The error never echoes the input.
    pub fn new(raw: &str) -> Result<Self, CoreError> {
        let valid =
            raw.len() == ID_CHARS && raw.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if valid {
            Ok(Self(raw.to_owned()))
        } else {
            Err(CoreError::BadToken)
        }
    }

    /// The id as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TokenId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for TokenId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        TokenId::new(&raw).map_err(|_| serde::de::Error::custom("invalid token id"))
    }
}

/// Which kind of credential a secret string is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretKind {
    Token,
    Invite,
}

impl SecretKind {
    fn prefix(self) -> &'static str {
        match self {
            SecretKind::Token => TOKEN_PREFIX,
            SecretKind::Invite => INVITE_PREFIX,
        }
    }
}

/// A freshly generated credential. `full` is the only copy of the secret and is shown to its
/// owner once; the store keeps `id` and `hash`.
#[derive(Clone)]
pub struct NewSecret {
    pub id: TokenId,
    pub full: String,
    pub hash: [u8; 32],
}

impl fmt::Debug for NewSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewSecret")
            .field("id", &self.id)
            .field("full", &"<redacted>")
            .field("hash", &"<redacted>")
            .finish()
    }
}

/// Generates a credential from the OS RNG: `<prefix><id>_<secret>`.
pub fn generate_secret(kind: SecretKind) -> Result<NewSecret, CoreError> {
    let mut id_bytes = [0u8; ID_BYTES];
    let mut secret_bytes = [0u8; SECRET_BYTES];
    getrandom::fill(&mut id_bytes).map_err(|e| CoreError::Entropy(e.to_string()))?;
    getrandom::fill(&mut secret_bytes).map_err(|e| CoreError::Entropy(e.to_string()))?;
    let mut id = String::with_capacity(ID_CHARS);
    for b in id_bytes {
        id.push_str(&format!("{b:02x}"));
    }
    let secret = URL_SAFE_NO_PAD.encode(secret_bytes);
    let hash = hash_secret(&secret);
    let full = format!("{}{id}_{secret}", kind.prefix());
    Ok(NewSecret {
        id: TokenId(id),
        full,
        hash,
    })
}

/// Splits a credential string into its id and secret part. Any malformed input, including a
/// credential of the other kind, is `CoreError::BadToken`, which never contains the input.
pub fn parse_secret(kind: SecretKind, raw: &str) -> Result<(TokenId, String), CoreError> {
    let rest = raw.strip_prefix(kind.prefix()).ok_or(CoreError::BadToken)?;
    if rest.len() != ID_CHARS + 1 + SECRET_CHARS || !rest.is_char_boundary(ID_CHARS) {
        return Err(CoreError::BadToken);
    }
    let (id, tail) = rest.split_at(ID_CHARS);
    let secret = tail.strip_prefix('_').ok_or(CoreError::BadToken)?;
    let decoded = URL_SAFE_NO_PAD
        .decode(secret)
        .map_err(|_| CoreError::BadToken)?;
    if decoded.len() != SECRET_BYTES {
        return Err(CoreError::BadToken);
    }
    Ok((TokenId::new(id)?, secret.to_owned()))
}

/// sha256 of the secret part (not the prefix or id).
pub fn hash_secret(secret: &str) -> [u8; 32] {
    Sha256::digest(secret.as_bytes()).into()
}

/// Constant-time equality of two hashes: XOR-folds all 32 bytes with no early exit.
pub fn hashes_match(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    diff == 0
}

/// True when `secret` hashes to `stored`, compared in constant time.
pub fn secrets_match(secret: &str, stored: &[u8; 32]) -> bool {
    hashes_match(&hash_secret(secret), stored)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET_43: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn generated_token_has_the_stg1_shape() {
        let s = generate_secret(SecretKind::Token).unwrap();
        let rest = s.full.strip_prefix("stg1_").unwrap();
        let (id, secret) = rest.split_once('_').unwrap();
        assert_eq!(id.len(), 16);
        assert!(id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        assert_eq!(id, s.id.as_str());
        assert_eq!(secret.len(), 43);
        let (pid, psecret) = parse_secret(SecretKind::Token, &s.full).unwrap();
        assert_eq!(pid, s.id);
        assert_eq!(psecret, secret);
        assert_eq!(s.hash, hash_secret(&psecret));
    }

    #[test]
    fn invite_prefix_differs_from_token_prefix_and_cross_parse_fails() {
        let invite = generate_secret(SecretKind::Invite).unwrap();
        let token = generate_secret(SecretKind::Token).unwrap();
        assert!(invite.full.starts_with("stgi1_"));
        assert!(token.full.starts_with("stg1_"));
        assert!(parse_secret(SecretKind::Invite, &invite.full).is_ok());
        assert_eq!(
            parse_secret(SecretKind::Token, &invite.full),
            Err(CoreError::BadToken)
        );
        assert_eq!(
            parse_secret(SecretKind::Invite, &token.full),
            Err(CoreError::BadToken)
        );
    }

    #[test]
    fn parse_secret_rejects_garbage_without_echoing_it() {
        let good_id = "0123456789abcdef";
        let bad = [
            "".to_owned(),
            "stg1_".to_owned(),
            "hunter2-super-secret".to_owned(),
            format!("stg1_{good_id}"),
            format!("stg1_{good_id}_{}", &SECRET_43[..42]),
            format!("stg1_{good_id}_{SECRET_43}A"),
            format!("stg1_{good_id}-{SECRET_43}"),
            format!("stg1_{}_{SECRET_43}", good_id.to_uppercase()),
            format!("stg1_0123456789abcde_{SECRET_43}"),
            format!("stg1_{good_id}_{}!", &SECRET_43[..42]),
            // Non-canonical trailing bits in the last base64 char.
            format!("stg1_{good_id}_{}B", &SECRET_43[..42]),
        ];
        for raw in bad {
            let err = parse_secret(SecretKind::Token, &raw).unwrap_err();
            assert_eq!(err, CoreError::BadToken, "{raw}");
            let shown = format!("{err} {err:?}");
            assert!(raw.is_empty() || !shown.contains(&raw), "{raw}");
            assert!(!shown.contains("hunter2"));
        }
        assert!(parse_secret(SecretKind::Token, &format!("stg1_{good_id}_{SECRET_43}")).is_ok());
    }

    #[test]
    fn token_id_validates_and_never_echoes() {
        assert!(TokenId::new("0123456789abcdef").is_ok());
        for bad in [
            "",
            "0123456789ABCDEF",
            "0123456789abcde",
            "0123456789abcdeg",
        ] {
            assert_eq!(TokenId::new(bad), Err(CoreError::BadToken));
        }
        let id: TokenId = serde_json::from_str("\"0123456789abcdef\"").unwrap();
        assert_eq!(id.to_string(), "0123456789abcdef");
        assert!(serde_json::from_str::<TokenId>("\"nope\"").is_err());
    }

    #[test]
    fn hash_is_sha256_of_the_secret_only() {
        // printf %s test-secret | shasum -a 256
        let expected = "9caf06bb4436cdbfa20af9121a626bc1093c4f54b31c0fa937957856135345b6";
        let hex: String = hash_secret("test-secret")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(hex, expected);
    }

    #[test]
    fn secrets_match_is_true_for_equal_and_false_for_different_secrets() {
        let stored = hash_secret("alpha");
        assert!(secrets_match("alpha", &stored));
        assert!(!secrets_match("alphb", &stored));
        assert!(!secrets_match("", &stored));
    }

    #[test]
    fn hashes_match_is_true_for_equal_and_false_for_one_bit_difference() {
        let a = hash_secret("alpha");
        assert!(hashes_match(&a, &a));
        for byte in 0..32 {
            for bit in 0..8 {
                let mut b = a;
                b[byte] ^= 1 << bit;
                assert!(!hashes_match(&a, &b), "byte {byte} bit {bit}");
            }
        }
    }

    #[test]
    fn two_generated_secrets_differ() {
        let a = generate_secret(SecretKind::Token).unwrap();
        let b = generate_secret(SecretKind::Token).unwrap();
        assert!(a.full != b.full, "secrets must differ");
        assert_ne!(a.id, b.id);
        assert_ne!(a.hash, b.hash);
    }

    #[test]
    fn new_secret_debug_redacts_the_secret() {
        let s = generate_secret(SecretKind::Token).unwrap();
        let shown = format!("{s:?}");
        // Not rsplit('_'): a base64url secret can contain '_', which would leave a needle of a
        // character or two that the debug text can contain by chance.
        let (_, secret) = parse_secret(SecretKind::Token, &s.full).unwrap();
        assert!(!shown.contains(&secret));
        assert!(!shown.contains(&s.full));
        assert!(shown.contains(s.id.as_str()));
    }
}
