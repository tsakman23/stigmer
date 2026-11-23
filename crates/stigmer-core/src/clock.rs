//! The wall clock: the only I/O in stigmer-core. Everything else takes time as a parameter.

use std::time::{SystemTime, UNIX_EPOCH};

/// Milliseconds since the Unix epoch. Never panics: a clock set before 1970 reads 0, and one
/// past what an `i64` holds (year 292 million) reads `i64::MAX`.
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2020-01-01T00:00:00Z.
    const JAN_2020_MS: i64 = 1_577_836_800_000;

    #[test]
    fn now_is_after_2020_and_does_not_go_backwards_within_a_second() {
        let first = now_ms();
        let second = now_ms();
        assert!(first > JAN_2020_MS, "{first}");
        assert!(second >= first, "{second} < {first}");
        assert!(second - first < 1_000, "{second} - {first}");
    }
}
