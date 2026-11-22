//! Request limits.

use std::time::Duration;

/// How much a router lets clients do at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Events requests that may wait (`timeout_s > 0`) at the same time; more get 429.
    pub max_waits: usize,
    /// Failed authentications allowed per source address per minute.
    pub auth_failures_per_minute: u32,
    /// Join attempts allowed per source address per minute.
    pub join_per_minute: u32,
    /// Most sources a limiter tracks at once (IPv6 grouped by /64). When full, a source it is not
    /// tracking yet is refused (429) until idle entries are pruned.
    pub max_tracked_sources: usize,
    /// Longest a request body may go without sending anything while it is read; a body that
    /// stalls longer is cut off with 408 `request_timeout`.
    pub body_read_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_waits: 256,
            auth_failures_per_minute: 10,
            join_per_minute: 10,
            max_tracked_sources: 10_000,
            body_read_timeout: Duration::from_secs(10),
        }
    }
}
