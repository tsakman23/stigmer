//! Rejects requests whose Host or Origin names anything but this machine.
//!
//! Binding to loopback is not enough on its own: a web page on another site can
//! point its own domain at 127.0.0.1 (DNS rebinding) and talk to the board from
//! the browser. Such requests carry the foreign name in Host or Origin.

use axum::extract::Request;
use axum::http::header::{HOST, ORIGIN};
use axum::http::HeaderMap;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use stigmer_core::ErrorCode;

use crate::error::ApiError;

/// Middleware: 403 unless Host (when present) and Origin (when present) name loopback.
pub(crate) async fn require_loopback_host(request: Request, next: Next) -> Response {
    if headers_name_loopback(request.headers()) {
        next.run(request).await
    } else {
        ApiError::new(ErrorCode::Forbidden, "host or origin is not loopback").into_response()
    }
}

fn headers_name_loopback(headers: &HeaderMap) -> bool {
    let host_ok = match headers.get(HOST) {
        None => true,
        Some(value) => value.to_str().is_ok_and(is_loopback_authority),
    };
    let origin_ok = match headers.get(ORIGIN) {
        None => true,
        Some(value) => value.to_str().is_ok_and(is_loopback_origin),
    };
    host_ok && origin_ok
}

/// An Origin is `scheme://authority` with nothing after the authority.
fn is_loopback_origin(origin: &str) -> bool {
    match origin.split_once("://") {
        Some((_scheme, authority)) => is_loopback_authority(authority),
        None => false,
    }
}

/// True when `authority` is exactly `127.0.0.1`, `[::1]` or `localhost`
/// (any case), optionally followed by `:port`. Anything else, including
/// userinfo, paths or longer names, is refused.
fn is_loopback_authority(authority: &str) -> bool {
    let (host, port) = if authority.starts_with('[') {
        match authority.split_once(']') {
            Some((host, rest)) => (&authority[..=host.len()], rest),
            None => return false,
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
    let host_ok = host == "127.0.0.1" || host == "[::1]" || host.eq_ignore_ascii_case("localhost");
    port_ok && host_ok
}

#[cfg(test)]
mod tests {
    use super::*;

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
