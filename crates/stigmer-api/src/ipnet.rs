//! A CIDR range of IP addresses, for the trusted proxy list.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use thiserror::Error;

/// An address range such as `10.0.0.0/8` or `fd00::/8`; a bare address is a range of one.
///
/// Write IPv4 ranges in IPv4 form: addresses are compared after IPv4-mapped IPv6 addresses
/// (`::ffff:a.b.c.d`) are turned back into IPv4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

/// A string that is not an address range.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("not an IP address range: {0:?}")]
pub struct IpNetError(String);

impl IpNet {
    /// The range of `prefix` leading bits of `addr`; the prefix may not exceed the address
    /// length (32 for IPv4, 128 for IPv6).
    pub fn new(addr: IpAddr, prefix: u8) -> Result<Self, IpNetError> {
        if prefix > max_prefix(addr) {
            return Err(IpNetError(format!("{addr}/{prefix}")));
        }
        Ok(Self { addr, prefix })
    }

    /// True when `ip` is inside the range.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip.to_canonical()) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = mask32(self.prefix);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = mask128(self.prefix);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

fn max_prefix(addr: IpAddr) -> u8 {
    match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

fn mask32(prefix: u8) -> u32 {
    u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0)
}

fn mask128(prefix: u8) -> u128 {
    u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0)
}

impl FromStr for IpNet {
    type Err = IpNetError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bad = || IpNetError(s.to_owned());
        let (addr, prefix) = match s.split_once('/') {
            Some((addr, prefix)) => {
                let addr: IpAddr = addr.parse().map_err(|_| bad())?;
                // Digits only: `u8::from_str` would also take a leading `+`.
                if prefix.is_empty() || !prefix.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(bad());
                }
                (addr, prefix.parse().map_err(|_| bad())?)
            }
            None => {
                let addr: IpAddr = s.parse().map_err(|_| bad())?;
                (addr, max_prefix(addr))
            }
        };
        Self::new(addr, prefix).map_err(|_| bad())
    }
}

impl fmt::Display for IpNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn parses_ranges_and_bare_addresses() {
        assert_eq!(net("10.0.0.0/8").to_string(), "10.0.0.0/8");
        assert_eq!(net("192.0.2.7").to_string(), "192.0.2.7/32");
        assert_eq!(net("fd00::/8").to_string(), "fd00::/8");
        assert_eq!(net("::1").to_string(), "::1/128");
        assert_eq!(net("0.0.0.0/0").to_string(), "0.0.0.0/0");
        for bad in [
            "",
            "10.0.0.0/",
            "10.0.0.0/33",
            "fd00::/129",
            "10.0.0.0/+8",
            "10.0.0.0/a",
            "host.example",
            "10.0.0/8",
            "10.0.0.0/8/8",
        ] {
            assert!(bad.parse::<IpNet>().is_err(), "{bad}");
        }
    }

    #[test]
    fn contains_matches_the_prefix_bits_only() {
        let ten = net("10.0.0.0/8");
        assert!(ten.contains(ip("10.0.0.1")));
        assert!(ten.contains(ip("10.255.255.255")));
        assert!(!ten.contains(ip("11.0.0.0")));
        assert!(!ten.contains(ip("9.255.255.255")));
        assert!(!ten.contains(ip("::1")));
        let one = net("192.0.2.7");
        assert!(one.contains(ip("192.0.2.7")));
        assert!(!one.contains(ip("192.0.2.8")));
        assert!(net("0.0.0.0/0").contains(ip("203.0.113.9")));
        let v6 = net("fd00::/8");
        assert!(v6.contains(ip("fd12:3456::1")));
        assert!(!v6.contains(ip("fe80::1")));
        assert!(!v6.contains(ip("10.0.0.1")));
        assert!(net("::/0").contains(ip("2001:db8::1")));
    }

    #[test]
    fn ipv4_mapped_addresses_match_ipv4_ranges() {
        assert!(net("10.0.0.0/8").contains(ip("::ffff:10.1.2.3")));
        assert!(!net("10.0.0.0/8").contains(ip("::ffff:11.1.2.3")));
    }
}
