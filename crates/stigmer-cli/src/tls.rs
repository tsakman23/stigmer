//! Transport security: when a credential may go over plain HTTP.

use std::net::IpAddr;

use ureq::http::Uri;

use crate::exit::CliError;

/// Refuses to send a credential (token or invite) over plain HTTP to a host that is not
/// loopback, unless `insecure` (`--insecure`) says the network is trusted.
pub(crate) fn check_credential_transport(url: &str, insecure: bool) -> Result<(), CliError> {
    let uri: Uri = url.parse().map_err(|_| {
        CliError::usage(
            format!("invalid --url {url:?}"),
            "pass a URL such as https://board.example.com",
        )
    })?;
    if uri.scheme_str() == Some("https") || insecure {
        return Ok(());
    }
    let host = uri.host().unwrap_or_default();
    if is_loopback_host(host) {
        return Ok(());
    }
    Err(CliError::usage(
        format!("refusing to send a credential over plain http to {host}"),
        "use an https:// URL (or --insecure for a trusted network)",
    ))
}

/// `localhost`, 127.0.0.0/8 or ::1 (brackets allowed).
fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    bare.parse::<IpAddr>()
        .is_ok_and(|ip| ip.to_canonical().is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exit::Exit;

    #[test]
    fn plain_http_is_refused_only_for_remote_hosts() {
        for ok in [
            "http://127.0.0.1:7878",
            "http://127.9.9.9",
            "http://localhost:7878/",
            "http://LOCALHOST",
            "http://[::1]:7878",
            "https://board.example.com",
            "https://10.0.0.1:443",
        ] {
            assert_eq!(check_credential_transport(ok, false), Ok(()), "{ok}");
        }
        for refused in [
            "http://board.example.com",
            "http://10.0.0.1:7878",
            "http://[::2]:7878",
            "http://localhost.example.com",
            "http://128.0.0.1",
        ] {
            let err = check_credential_transport(refused, false).unwrap_err();
            assert_eq!(err.exit, Exit::Usage, "{refused}");
        }
    }

    #[test]
    fn insecure_flag_allows_plain_http_to_a_remote_host() {
        assert_eq!(
            check_credential_transport("http://board.example.com:7878", true),
            Ok(())
        );
        assert_eq!(check_credential_transport("http://10.0.0.1", true), Ok(()));
    }

    #[test]
    fn a_bad_url_is_a_usage_error() {
        let err = check_credential_transport("not a url", false).unwrap_err();
        assert_eq!(err.exit, Exit::Usage);
    }
}
