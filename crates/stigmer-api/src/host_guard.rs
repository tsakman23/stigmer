//! Rejects requests whose Host or Origin names anything but this machine or an allowed host.
//!
//! Binding to loopback is not enough on its own: a web page on another site can
//! point its own domain at 127.0.0.1 (DNS rebinding) and talk to the board from
//! the browser. Such requests carry the foreign name in Host or Origin. A board served under a
//! real name adds that name to the allow-list; every other name stays refused.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::header::{HOST, ORIGIN};
use axum::http::HeaderMap;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use stigmer_core::ErrorCode;

use crate::error::ApiError;

/// Host names accepted besides loopback, as configured.
#[derive(Debug, Clone, Default)]
pub(crate) struct AllowedHosts(Arc<[String]>);

impl AllowedHosts {
    pub(crate) fn new(names: &[String]) -> Self {
        Self(names.iter().cloned().collect())
    }

    /// Loopback, or exactly one of the allowed names in any case.
    fn admits(&self, host: &str) -> bool {
        admits_loopback(host) || self.0.iter().any(|name| host.eq_ignore_ascii_case(name))
    }

    /// True when `authority` is an admitted host, optionally followed by `:port`. Anything
    /// else, including userinfo, paths or longer names, is refused.
    fn admits_authority(&self, authority: &str) -> bool {
        split_authority(authority).is_some_and(|host| self.admits(host))
    }

    /// An Origin is `scheme://authority` with nothing after the authority.
    fn admits_origin(&self, origin: &str) -> bool {
        match origin.split_once("://") {
            Some((_scheme, authority)) => self.admits_authority(authority),
            None => false,
        }
    }
}

/// Middleware: 403 unless Host (when present) and Origin (when present) name loopback or an
/// allowed host.
pub(crate) async fn require_allowed_host(
    State(allowed): State<AllowedHosts>,
    request: Request,
    next: Next,
) -> Response {
    if headers_name_allowed_hosts(&allowed, request.headers()) {
        next.run(request).await
    } else {
        ApiError::new(ErrorCode::Forbidden, "host or origin is not allowed").into_response()
    }
}

fn headers_name_allowed_hosts(allowed: &AllowedHosts, headers: &HeaderMap) -> bool {
    let host_ok = match headers.get(HOST) {
        None => true,
        Some(value) => value.to_str().is_ok_and(|v| allowed.admits_authority(v)),
    };
    let origin_ok = match headers.get(ORIGIN) {
        None => true,
        Some(value) => value.to_str().is_ok_and(|v| allowed.admits_origin(v)),
    };
    host_ok && origin_ok
}

/// The loopback spellings the guard admits. `stigmer_core::is_loopback_host` decides what is
/// loopback; the guard is narrower on purpose and admits only `localhost` and the two addresses
/// a loopback-bound server listens on, so other 127.0.0.0/8 literals and IPv4-mapped forms such
/// as `[::ffff:127.0.0.1]` stay refused, as they were in M0.
fn admits_loopback(host: &str) -> bool {
    stigmer_core::is_loopback_host(host)
        && (host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "[::1]")
}

/// The host of `host[:port]` or `[v6][:port]`, or `None` when the port is malformed.
fn split_authority(authority: &str) -> Option<&str> {
    let (host, port) = if authority.starts_with('[') {
        match authority.split_once(']') {
            Some((host, rest)) => (&authority[..=host.len()], rest),
            None => return None,
        }
    } else {
        match authority.find(':') {
            Some(i) => authority.split_at(i),
            None => (authority, ""),
        }
    };
    let port_ok = match port.strip_prefix(':') {
        Some(digits) => !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()),
        None => port.is_empty(),
    };
    port_ok.then_some(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_loopback_authority(authority: &str) -> bool {
        AllowedHosts::default().admits_authority(authority)
    }

    fn is_loopback_origin(origin: &str) -> bool {
        AllowedHosts::default().admits_origin(origin)
    }

    #[test]
    fn allowed_names_match_exactly_in_any_case_with_any_port() {
        let allowed = AllowedHosts::new(&["board.example.com".to_owned()]);
        for ok in [
            "board.example.com",
            "Board.Example.Com:443",
            "localhost:7878",
            "[::1]",
        ] {
            assert!(allowed.admits_authority(ok), "{ok}");
        }
        for bad in [
            "example.com",
            "board.example.com.evil.example",
            "x.board.example.com",
            "board.example.com:",
            "user@board.example.com",
            "board.example.com/x",
        ] {
            assert!(!allowed.admits_authority(bad), "{bad}");
        }
        assert!(allowed.admits_origin("https://board.example.com"));
        assert!(!allowed.admits_origin("https://board.example.com.evil.example"));
    }

    #[test]
    fn loopback_authorities_are_accepted() {
        for ok in [
            "127.0.0.1",
            "127.0.0.1:7878",
            "[::1]",
            "[::1]:80",
            "localhost",
            "LocalHost:1",
        ] {
            assert!(is_loopback_authority(ok), "{ok}");
        }
    }

    #[test]
    fn lookalike_and_foreign_authorities_are_refused() {
        for bad in [
            "",
            "attacker.example",
            "127.0.0.1.evil.example",
            "localhost.evil.example",
            "evil.localhost",
            "127.0.0.2",
            "0.0.0.0",
            "[::1",
            "[::2]",
            "[::1]x",
            "::1",
            "localhost:",
            "localhost:80x",
            "localhost:80:80",
            "localhost@evil.example",
            "user@localhost",
            "localhost/path",
        ] {
            assert!(!is_loopback_authority(bad), "{bad}");
        }
    }

    #[test]
    fn origins_are_checked_by_their_host() {
        assert!(is_loopback_origin("http://localhost:7878"));
        assert!(is_loopback_origin("https://127.0.0.1"));
        assert!(is_loopback_origin("http://[::1]:7878"));
        for bad in [
            "null",
            "localhost",
            "http://attacker.example",
            "http://localhost@evil.example",
            "http://localhost:80@evil.example",
            "http://127.0.0.1.evil.example",
            "http://localhost.evil.example:7878",
            "http://localhost/",
        ] {
            assert!(!is_loopback_origin(bad), "{bad}");
        }
    }
}
