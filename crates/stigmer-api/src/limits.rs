//! Request limits.

/// How much a router lets clients do at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Events requests that may wait (`timeout_s > 0`) at the same time; more get 429.
    pub max_waits: usize,
    /// Failed authentications allowed per source address, and per token id, per minute.
    pub auth_failures_per_minute: u32,
    /// Join attempts allowed per source address per minute.
    pub join_per_minute: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_waits: 256,
            auth_failures_per_minute: 10,
            join_per_minute: 10,
        }
    }
}
