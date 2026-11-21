//! Refuses to serve anywhere but the local machine.

use std::net::SocketAddr;

use thiserror::Error;

/// The requested bind address is not a loopback address.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("refusing to bind {0}: this board is loopback only")]
pub struct BindError(SocketAddr);

/// Accepts 127.0.0.0/8 and ::1 only.
pub fn require_loopback(addr: &SocketAddr) -> Result<(), BindError> {
    if addr.ip().is_loopback() {
        Ok(())
    } else {
        Err(BindError(*addr))
    }
}
