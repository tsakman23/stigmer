//! HTTP API tests against an in-memory SQLite store.

use std::net::SocketAddr;

use stigmer_api::require_loopback;

#[test]
fn require_loopback_accepts_127_0_0_1_and_ipv6_loopback() {
    for addr in ["127.0.0.1:7878", "127.8.9.10:1", "[::1]:7878"] {
        let addr: SocketAddr = addr.parse().unwrap();
        assert!(require_loopback(&addr).is_ok(), "{addr}");
    }
}

#[test]
fn require_loopback_rejects_0_0_0_0_and_192_168_1_5_with_message_naming_the_address() {
    for raw in ["0.0.0.0:7878", "192.168.1.5:7878", "[::]:7878"] {
        let addr: SocketAddr = raw.parse().unwrap();
        let err = require_loopback(&addr).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("refusing to bind {raw}: this board is loopback only")
        );
    }
}
