//! Whether a host names this machine.

use std::net::IpAddr;

/// True when `host` is `localhost` (any case), an IPv4 address in 127.0.0.0/8, or `::1`
/// (bare or in brackets), including an IPv4-mapped loopback such as `::ffff:127.0.0.1`.
///
/// `host` is only the host: callers strip userinfo and port first. Nothing is matched by
/// prefix or suffix, so `127.0.0.1.evil.example`, `evil-localhost` and `localhost.` are not
/// loopback.
pub fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    let bare = match host.strip_prefix('[') {
        Some(rest) => match rest.strip_suffix(']') {
            Some(inner) => inner,
            None => return false,
        },
        None => host,
    };
    bare.parse::<IpAddr>()
        .is_ok_and(|ip| ip.to_canonical().is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_hosts() {
        for host in [
            "localhost",
            "LocalHost",
            "LOCALHOST",
            "127.0.0.1",
            "127.0.0.2",
            "127.255.255.254",
            "::1",
            "[::1]",
            "0:0:0:0:0:0:0:1",
            "::ffff:127.0.0.1",
            "[::ffff:127.0.0.1]",
            "[::ffff:127.9.9.9]",
        ] {
            assert!(is_loopback_host(host), "{host}");
        }
    }

    #[test]
    fn other_and_look_alike_hosts() {
        for host in [
            "",
            "128.0.0.1",
            "10.0.0.1",
            "0.0.0.0",
            "::",
            "::2",
            "[::2]",
            "::ffff:10.0.0.1",
            "[::1",
            "::1]",
            "[[::1]]",
            "127.0.0.1.evil.example",
            "localhost.evil.example",
            "evil.localhost",
            "evil-localhost",
            "localhost.",
            "localhost:7878",
            "127.0.0.1:7878",
            "[::1]:7878",
            "user@localhost",
            "localhost@evil.example",
            "board.example.com",
        ] {
            assert!(!is_loopback_host(host), "{host}");
        }
    }
}
