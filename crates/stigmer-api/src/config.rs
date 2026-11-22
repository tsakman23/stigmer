//! How a router is set up: the instance mode and the clock.

use std::fmt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use stigmer_store::Mode;

/// The current time in ms since the Unix epoch. Injected so tests control expiry.
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

/// Everything the router needs to know besides the store, the authorizer and shutdown.
#[derive(Clone)]
pub struct ApiConfig {
    /// Local: no authentication, author from `X-Stigmer-As`. Network: a bearer token on every
    /// board route.
    pub mode: Mode,
    /// Reads the time for credential expiry and last-seen stamps.
    pub clock: Clock,
}

impl ApiConfig {
    /// Local mode (M0 behaviour) with the system clock.
    pub fn local() -> Self {
        Self::with_mode(Mode::Local)
    }

    /// Network mode with the system clock.
    pub fn network() -> Self {
        Self::with_mode(Mode::Network)
    }

    fn with_mode(mode: Mode) -> Self {
        Self {
            mode,
            clock: Arc::new(system_time_ms),
        }
    }
}

impl fmt::Debug for ApiConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiConfig")
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

/// Milliseconds since the Unix epoch; 0 for a clock set before 1970, `i64::MAX` past year 292
/// million.
fn system_time_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}
