//! What a failure to talk to the server means: transient (worth retrying) or permanent.
//!
//! Transient: the connection was refused, reset or dropped, a timeout, or the host could not be
//! resolved or reached. Permanent: TLS and certificate failures, a malformed URL, and any other
//! protocol error; retrying those can never succeed, so `tail` stops on them.

use std::io::ErrorKind;

use crate::exit::{CliError, Exit};

/// The error codes of transient failures; every other code is permanent.
pub(crate) const TRANSIENT_CODES: [&str; 3] = ["unavailable", "network", "request_timeout"];

const TLS_HINT: &str = "for a private CA pass --ca-cert <file> (or set STIGMER_CA_CERT); \
otherwise check the server's certificate and the host name in --url";

/// True for an I/O failure of the connection itself (not of TLS on top of it).
fn is_transient_io(io: &std::io::Error) -> bool {
    matches!(
        io.kind(),
        ErrorKind::ConnectionRefused
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::NotConnected
            | ErrorKind::BrokenPipe
            | ErrorKind::UnexpectedEof
            | ErrorKind::TimedOut
            | ErrorKind::Interrupted
            | ErrorKind::AddrNotAvailable
            | ErrorKind::NetworkDown
            | ErrorKind::NetworkUnreachable
            | ErrorKind::HostUnreachable
    )
}

/// An I/O error that carries a rustls error (a failed handshake or certificate check).
fn wraps_tls(io: &std::io::Error) -> bool {
    io.get_ref()
        .is_some_and(|inner| inner.is::<rustls::Error>())
}

/// The report for a request to `base` that failed before any HTTP response.
pub(crate) fn network_error(base: &str, err: ureq::Error) -> CliError {
    let transient = |message: String| {
        CliError::new(
            Exit::Failure,
            "network",
            message,
            format!(
                "check --url or STIGMER_URL (now {base}); start the server with: stigmerd serve"
            ),
        )
    };
    match err {
        ureq::Error::Io(io) if wraps_tls(&io) => tls_error(base, &io),
        ureq::Error::Io(io) if io.kind() == ErrorKind::ConnectionRefused => CliError::new(
            Exit::Failure,
            "unavailable",
            format!("cannot connect to {base}: connection refused"),
            "start the server with: stigmerd serve",
        ),
        ureq::Error::Io(io) if is_transient_io(&io) => {
            transient(format!("request to {base} failed: {io}"))
        }
        ureq::Error::Timeout(_) => CliError::new(
            Exit::Failure,
            "request_timeout",
            format!("request to {base} timed out"),
            "check that stigmerd is running and responsive, then retry",
        ),
        ureq::Error::HostNotFound | ureq::Error::ConnectionFailed => {
            transient(format!("request to {base} failed: {err}"))
        }
        ureq::Error::Rustls(_)
        | ureq::Error::Tls(_)
        | ureq::Error::Pem(_)
        | ureq::Error::TlsRequired
        | ureq::Error::RequireHttpsOnly(_) => tls_error(base, &err),
        ureq::Error::BadUri(_) | ureq::Error::Http(_) => CliError::new(
            Exit::Failure,
            "bad_url",
            format!("cannot use the URL {base}: {err}"),
            "pass a URL such as https://board.example.com to --url (or STIGMER_URL)",
        ),
        other => CliError::new(
            Exit::Failure,
            "protocol",
            format!("request to {base} failed: {other}"),
            "check that --url points at a stigmer server",
        ),
    }
}

fn tls_error(base: &str, err: &dyn std::fmt::Display) -> CliError {
    CliError::new(
        Exit::Failure,
        "tls",
        format!("TLS with {base} failed: {err}"),
        TLS_HINT,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code(err: ureq::Error) -> &'static str {
        network_error("https://h", err).code
    }

    fn io(kind: ErrorKind) -> ureq::Error {
        ureq::Error::Io(std::io::Error::new(kind, "x"))
    }

    #[test]
    fn connection_failures_and_timeouts_are_transient() {
        for (err, expected) in [
            (io(ErrorKind::ConnectionRefused), "unavailable"),
            (io(ErrorKind::ConnectionReset), "network"),
            (io(ErrorKind::UnexpectedEof), "network"),
            (io(ErrorKind::TimedOut), "network"),
            (io(ErrorKind::HostUnreachable), "network"),
            (ureq::Error::HostNotFound, "network"),
            (ureq::Error::ConnectionFailed, "network"),
            (
                ureq::Error::Timeout(ureq::Timeout::Global),
                "request_timeout",
            ),
        ] {
            let shown = err.to_string();
            let got = code(err);
            assert_eq!(got, expected, "{shown}");
            assert!(TRANSIENT_CODES.contains(&got), "{shown}");
        }
    }

    #[test]
    fn tls_url_and_protocol_failures_are_permanent() {
        let wrapped = ureq::Error::Io(std::io::Error::new(
            ErrorKind::InvalidData,
            rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer),
        ));
        let bad_request = ureq::http::Request::builder()
            .uri("http://exa mple")
            .body(())
            .unwrap_err();
        for (err, expected) in [
            (wrapped, "tls"),
            (
                ureq::Error::Rustls(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::Expired,
                )),
                "tls",
            ),
            (ureq::Error::Tls("handshake failed"), "tls"),
            (ureq::Error::TlsRequired, "tls"),
            (ureq::Error::RequireHttpsOnly("http://h".into()), "tls"),
            (ureq::Error::BadUri("nope".into()), "bad_url"),
            (ureq::Error::Http(bad_request), "bad_url"),
            (io(ErrorKind::InvalidData), "protocol"),
            (io(ErrorKind::Other), "protocol"),
            (ureq::Error::TooManyRedirects, "protocol"),
            (ureq::Error::RedirectFailed, "protocol"),
            (ureq::Error::StatusCode(500), "protocol"),
        ] {
            let shown = err.to_string();
            let got = code(err);
            assert_eq!(got, expected, "{shown}");
            assert!(!TRANSIENT_CODES.contains(&got), "{shown}");
        }
        let tls = network_error("https://h", ureq::Error::Tls("x"));
        assert!(tls
            .render(false)
            .contains("next: for a private CA pass --ca-cert"));
    }
}
