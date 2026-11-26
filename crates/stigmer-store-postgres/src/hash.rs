//! Event and head hashes: 64 lowercase hex characters in the API, 32 bytes in the database.

use stigmer_store::StoreError;

/// Bytes in a stored hash.
pub(crate) const HASH_BYTES: usize = 32;

/// The 32 bytes a 64-character lowercase hex hash stands for.
pub(crate) fn to_bytes(hex: &str) -> Result<Vec<u8>, StoreError> {
    let invalid = || StoreError::Backend(format!("not a 64-character lowercase hex hash: {hex:?}"));
    if hex.len() != HASH_BYTES * 2 {
        return Err(invalid());
    }
    hex.as_bytes()
        .chunks(2)
        .map(|pair| match pair {
            [high, low] => Some(nibble(*high)? << 4 | nibble(*low)?),
            _ => None,
        })
        .collect::<Option<Vec<u8>>>()
        .ok_or_else(invalid)
}

fn nibble(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stigmer_core::GENESIS_HASH;

    #[test]
    fn hashes_decode_to_their_bytes() {
        let hash = "00ff10a9".repeat(8);
        let bytes = to_bytes(&hash).unwrap();
        assert_eq!(bytes.len(), HASH_BYTES);
        assert_eq!(&bytes[..4], &[0x00, 0xff, 0x10, 0xa9]);
        assert_eq!(to_bytes(GENESIS_HASH).unwrap(), vec![0; HASH_BYTES]);
    }

    #[test]
    fn malformed_hashes_are_refused() {
        assert!(to_bytes("abc").is_err());
        assert!(to_bytes(&"AB".repeat(32)).is_err(), "uppercase");
        assert!(to_bytes(&"zz".repeat(32)).is_err());
    }
}
