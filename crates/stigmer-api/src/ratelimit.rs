//! In-memory token buckets for failed authentications, and throttling of their log rows.
//!
//! A bucket holds up to `per_minute` tokens and refills continuously at `per_minute` per
//! minute. Each failure takes one token; a key with less than one token left is limited until it
//! refills. Buckets that have refilled completely are dropped, so idle keys cost nothing.

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::{Mutex, PoisonError};

use stigmer_core::TokenId;

const MINUTE_MS: i64 = 60_000;

/// Where a request comes from, for limiting and the security log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Source {
    Ip(IpAddr),
    /// The server did not say; every such request shares this one source.
    Unknown,
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Source::Ip(ip) => write!(f, "{ip}"),
            Source::Unknown => f.write_str("unknown"),
        }
    }
}

/// What a bucket is kept for.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum Key {
    Source(Source),
    Token(TokenId),
}

/// A security log row kind that is written at most once per source per minute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Logged {
    AuthFailed,
    RateLimited,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    at_ms: i64,
}

#[derive(Default)]
struct Inner {
    buckets: HashMap<Key, Bucket>,
    logged: HashMap<(Source, Logged), i64>,
    pruned_at_ms: i64,
}

/// Failure buckets for a set of keys, all with the same rate.
pub(crate) struct FailureLimiter {
    per_minute: u32,
    inner: Mutex<Inner>,
}

impl FailureLimiter {
    pub(crate) fn new(per_minute: u32) -> Self {
        Self {
            per_minute,
            inner: Mutex::new(Inner::default()),
        }
    }

    /// `Err(seconds)` when any of `keys` has no failure left: the time until all of them do.
    pub(crate) fn check(&self, keys: &[Key], now_ms: i64) -> Result<(), u64> {
        let mut inner = self.lock();
        self.prune(&mut inner, now_ms);
        let wait_ms = keys
            .iter()
            .filter_map(|key| inner.buckets.get(key))
            .map(|bucket| self.wait_ms(self.refilled(*bucket, now_ms)))
            .max()
            .unwrap_or(0);
        if wait_ms == 0 {
            Ok(())
        } else {
            Err(wait_ms.div_ceil(1000).max(1))
        }
    }

    /// Takes one failure from each of `keys`.
    pub(crate) fn record_failure(&self, keys: &[Key], now_ms: i64) {
        let mut inner = self.lock();
        let full = self.full(now_ms);
        for key in keys {
            let bucket = inner.buckets.get(key).copied().unwrap_or(full);
            let mut bucket = Bucket {
                tokens: self.refilled(bucket, now_ms),
                at_ms: now_ms,
            };
            bucket.tokens = (bucket.tokens - 1.0).max(0.0);
            inner.buckets.insert(key.clone(), bucket);
        }
    }

    /// True, at most once a minute per source and kind, when a log row should be written.
    pub(crate) fn should_log(&self, source: Source, kind: Logged, now_ms: i64) -> bool {
        let mut inner = self.lock();
        match inner.logged.get(&(source, kind)) {
            Some(&last) if now_ms.saturating_sub(last) < MINUTE_MS => false,
            _ => {
                inner.logged.insert((source, kind), now_ms);
                true
            }
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // The maps hold no invariant a panicking holder could break halfway.
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn full(&self, now_ms: i64) -> Bucket {
        Bucket {
            tokens: f64::from(self.per_minute),
            at_ms: now_ms,
        }
    }

    fn refilled(&self, bucket: Bucket, now_ms: i64) -> f64 {
        let elapsed = now_ms.saturating_sub(bucket.at_ms).max(0) as f64;
        let per_ms = f64::from(self.per_minute) / MINUTE_MS as f64;
        (bucket.tokens + elapsed * per_ms).min(f64::from(self.per_minute))
    }

    /// Milliseconds until a bucket holding `tokens` has one whole token; 0 if it has.
    fn wait_ms(&self, tokens: f64) -> u64 {
        if tokens >= 1.0 {
            return 0;
        }
        if self.per_minute == 0 {
            return MINUTE_MS as u64;
        }
        let per_ms = f64::from(self.per_minute) / MINUTE_MS as f64;
        ((1.0 - tokens) / per_ms).ceil() as u64
    }

    /// At most once a minute: drops buckets that have refilled completely and log marks older
    /// than a minute.
    fn prune(&self, inner: &mut Inner, now_ms: i64) {
        if now_ms.saturating_sub(inner.pruned_at_ms) < MINUTE_MS {
            return;
        }
        inner.pruned_at_ms = now_ms;
        let cap = f64::from(self.per_minute);
        let buckets = std::mem::take(&mut inner.buckets);
        inner.buckets = buckets
            .into_iter()
            .filter(|(_, bucket)| self.refilled(*bucket, now_ms) < cap)
            .collect();
        inner
            .logged
            .retain(|_, last| now_ms.saturating_sub(*last) < MINUTE_MS);
    }

    #[cfg(test)]
    fn tracked(&self) -> (usize, usize) {
        let inner = self.lock();
        (inner.buckets.len(), inner.logged.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Key {
        Key::Source(Source::Ip(s.parse().unwrap()))
    }

    #[test]
    fn allows_per_minute_failures_then_limits_until_refilled() {
        let limiter = FailureLimiter::new(6);
        let keys = [ip("192.0.2.1")];
        for _ in 0..6 {
            assert_eq!(limiter.check(&keys, 0), Ok(()));
            limiter.record_failure(&keys, 0);
        }
        // Six a minute refill one every 10 s.
        assert_eq!(limiter.check(&keys, 0), Err(10));
        assert_eq!(limiter.check(&keys, 9_001), Err(1));
        assert_eq!(limiter.check(&keys, 10_000), Ok(()));
        assert_eq!(limiter.check(&[ip("192.0.2.2")], 0), Ok(()));
    }

    #[test]
    fn any_limited_key_limits_the_request() {
        let limiter = FailureLimiter::new(1);
        let token = Key::Token(TokenId::new("0123456789abcdef").unwrap());
        limiter.record_failure(std::slice::from_ref(&token), 0);
        assert_eq!(limiter.check(&[ip("192.0.2.1"), token], 0), Err(60));
    }

    #[test]
    fn zero_per_minute_limits_from_the_first_failure() {
        let limiter = FailureLimiter::new(0);
        let keys = [ip("192.0.2.1")];
        assert_eq!(limiter.check(&keys, 0), Ok(()));
        limiter.record_failure(&keys, 0);
        assert_eq!(limiter.check(&keys, 0), Err(60));
    }

    #[test]
    fn log_marks_are_once_a_minute_per_source_and_kind() {
        let limiter = FailureLimiter::new(10);
        let a = Source::Ip("192.0.2.1".parse().unwrap());
        assert!(limiter.should_log(a, Logged::AuthFailed, 0));
        assert!(!limiter.should_log(a, Logged::AuthFailed, 59_999));
        assert!(limiter.should_log(a, Logged::RateLimited, 1));
        assert!(limiter.should_log(Source::Unknown, Logged::AuthFailed, 1));
        assert!(limiter.should_log(a, Logged::AuthFailed, 60_000));
    }

    #[test]
    fn idle_buckets_and_old_log_marks_are_pruned() {
        let limiter = FailureLimiter::new(2);
        limiter.record_failure(&[ip("192.0.2.1")], 0);
        limiter.should_log(Source::Unknown, Logged::AuthFailed, 0);
        assert_eq!(limiter.tracked(), (1, 1));
        // Refilled (one failure at 2 a minute is back after 30 s) and a minute old.
        limiter.check(&[], 60_000).unwrap();
        assert_eq!(limiter.tracked(), (0, 0));
    }

    #[test]
    fn clock_going_backwards_does_not_refill() {
        let limiter = FailureLimiter::new(1);
        let keys = [ip("192.0.2.1")];
        limiter.record_failure(&keys, 10_000);
        assert_eq!(limiter.check(&keys, 0), Err(60));
    }
}
