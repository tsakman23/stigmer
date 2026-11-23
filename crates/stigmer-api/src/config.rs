//! How a router is set up: mode, host allow-list, trusted proxies, limits and the clock.

use std::fmt;
use std::sync::Arc;

use stigmer_store::Mode;

use crate::ipnet::IpNet;
use crate::limits::Limits;

/// The current time in ms since the Unix epoch. Injected so tests control expiry.
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

/// Receives a one-line warning (no secrets) for something that failed but did not fail the
/// request, such as a security log write after a completed mutation. Defaults to stderr.
pub type Warn = Arc<dyn Fn(&str) + Send + Sync>;

/// Everything the router needs to know besides the store, the authorizer and shutdown.
#[derive(Clone)]
pub struct ApiConfig {
    /// Local: no authentication, author from `X-Stigmer-As`. Network: a bearer token on every
    /// board route.
    pub mode: Mode,
    /// Host names accepted in `Host` and `Origin` besides loopback (exact, any case, any
    /// port). Everything else is refused, to block DNS rebinding.
    pub allowed_hosts: Vec<String>,
    /// Peers whose `X-Forwarded-For` is believed. A request from any other peer is
    /// attributed to the peer itself.
    pub trusted_proxies: Vec<IpNet>,
    pub limits: Limits,
    /// Reads the time for credential expiry and last-seen stamps.
    pub clock: Clock,
    /// Where best-effort failures are reported.
    pub warn: Warn,
}

impl ApiConfig {
    /// Local mode (M0 behaviour): default limits, loopback hosts only, no trusted proxies, the
    /// system clock.
    pub fn local() -> Self {
        Self::with_mode(Mode::Local)
    }

    /// Network mode: default limits, loopback hosts only, no trusted proxies, the system clock.
    pub fn network() -> Self {
        Self::with_mode(Mode::Network)
    }

    fn with_mode(mode: Mode) -> Self {
        Self {
            mode,
            allowed_hosts: Vec::new(),
            trusted_proxies: Vec::new(),
            limits: Limits::default(),
            clock: Arc::new(stigmer_core::now_ms),
            warn: Arc::new(|line| eprintln!("stigmer: warning: {line}")),
        }
    }
}

impl fmt::Debug for ApiConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiConfig")
            .field("mode", &self.mode)
            .field("allowed_hosts", &self.allowed_hosts)
            .field("trusted_proxies", &self.trusted_proxies)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}
