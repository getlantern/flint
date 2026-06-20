//! Answer validation — reject poisoned/bogus DoH answers.
//!
//! DoH's encryption stops a censor from *poisoning the answer in flight*, but a blocked or hostile
//! resolver can still return garbage, and an on-path injector for the plaintext fallback returns
//! sentinel bogons (Iran's `10.10.34.x`, or `0.0.0.0`/loopback for a public name). This layer drops
//! bogon addresses; if nothing real remains, the answer is rejected so the smart-dialer moves on.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Why a set of answers was rejected.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ValidateError {
    /// The response carried no address records.
    #[error("no address records in the answer")]
    Empty,
    /// Every address was a bogon — a poisoned/sentinel answer, not a real one.
    #[error("answer contained only bogon addresses (poisoned)")]
    Poisoned,
}

/// `true` if `ip` must never be a legitimate public answer: unspecified, loopback, private (RFC 1918,
/// which covers Iran's injected `10.10.34.0/24`), CGNAT, link-local, broadcast, or documentation
/// ranges (v4); unspecified, loopback, unique-local, or link-local (v6).
pub fn is_bogon(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            a.is_unspecified()
                || a.is_loopback()
                || a.is_private()
                || a.is_link_local()
                || a.is_broadcast()
                || a.is_documentation()
                || is_cgnat(a)
        }
        IpAddr::V6(a) => a.is_unspecified() || a.is_loopback() || is_ula(a) || is_v6_link_local(a),
    }
}

/// CGNAT / shared address space, `100.64.0.0/10` (RFC 6598). (`Ipv4Addr::is_shared` is unstable.)
fn is_cgnat(a: Ipv4Addr) -> bool {
    let o = a.octets();
    o[0] == 100 && (o[1] & 0xc0) == 0x40
}

/// Unique-local addresses, `fc00::/7` (RFC 4193). (`Ipv6Addr::is_unique_local` is unstable.)
fn is_ula(a: Ipv6Addr) -> bool {
    (a.segments()[0] & 0xfe00) == 0xfc00
}

/// Link-local addresses, `fe80::/10`. (`Ipv6Addr::is_unicast_link_local` is unstable.)
fn is_v6_link_local(a: Ipv6Addr) -> bool {
    (a.segments()[0] & 0xffc0) == 0xfe80
}

/// Keep only the non-bogon addresses. Errors if there were none to begin with ([`ValidateError::Empty`])
/// or if every address was a bogon ([`ValidateError::Poisoned`]).
pub fn validate_answers(answers: Vec<IpAddr>) -> Result<Vec<IpAddr>, ValidateError> {
    if answers.is_empty() {
        return Err(ValidateError::Empty);
    }
    let good: Vec<IpAddr> = answers.into_iter().filter(|ip| !is_bogon(*ip)).collect();
    if good.is_empty() {
        return Err(ValidateError::Poisoned);
    }
    Ok(good)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn flags_known_bogons() {
        for s in [
            "10.10.34.34", // Iran's injected sentinel (within 10/8)
            "0.0.0.0",
            "127.0.0.1",
            "192.168.1.1",
            "169.254.0.1",
            "100.64.0.1", // CGNAT
            "::1",
            "fe80::1",
            "fc00::1",
        ] {
            assert!(is_bogon(ip(s)), "{s} should be a bogon");
        }
    }

    #[test]
    fn accepts_real_public_addresses() {
        for s in ["1.1.1.1", "8.8.8.8", "93.184.216.34", "2606:4700::1111"] {
            assert!(!is_bogon(ip(s)), "{s} should be public");
        }
    }

    #[test]
    fn validate_drops_bogons_and_keeps_public() {
        let got = validate_answers(vec![ip("10.10.34.34"), ip("1.1.1.1")]).unwrap();
        assert_eq!(got, vec![ip("1.1.1.1")]);
    }

    #[test]
    fn validate_rejects_all_bogon_and_empty() {
        assert_eq!(
            validate_answers(vec![ip("10.10.34.34")]),
            Err(ValidateError::Poisoned)
        );
        assert_eq!(validate_answers(vec![]), Err(ValidateError::Empty));
    }
}
