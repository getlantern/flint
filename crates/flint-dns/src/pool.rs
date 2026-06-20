//! The resilient DoH resolver pool (design §6).
//!
//! Curated for **diversity across operators, ASNs, and jurisdictions**, not raw count — blocking
//! `1.1.1.1`/`8.8.8.8` is one cheap censor rule, so the pool's value is the spread. Each entry is the
//! **raw-IP** form (no bootstrap-DNS chicken-and-egg: these operators put IP SANs in their certs and
//! present the resolver hostname as both SNI and DoH `:authority`). CDN-edge-fronted entries and
//! Ed25519-signed pool updates are layered on top later (design §6).

use std::net::SocketAddr;

use flint_dial::BootstrapStrategy;

/// One DoH resolver, addressed for a raw-IP dial.
#[derive(Debug, Clone)]
pub struct Resolver {
    /// Short operator label (logs / metrics; never a secret).
    pub name: &'static str,
    /// The TCP endpoint to dial (the resolver IP, port 443).
    pub target: SocketAddr,
    /// The SNI to present in the ClientHello (the resolver hostname, covered by its cert).
    pub sni: &'static str,
    /// The DoH `:authority` (HTTP host) — the resolver hostname.
    pub host: &'static str,
    /// The DoH path (RFC 8484), almost always `/dns-query`.
    pub path: &'static str,
}

impl Resolver {
    /// The bootstrap-dial strategy for this resolver: boring Chrome-mimicry to its IP, presenting its
    /// hostname as SNI, with no wire shaping (the dialer layers shaping on per network).
    pub fn strategy(&self) -> BootstrapStrategy {
        BootstrapStrategy::boring_chrome(self.target, self.sni)
    }
}

/// Build a raw-IP resolver entry from octets + a hostname (infallible — no parse/`unwrap`).
const fn v4(name: &'static str, ip: [u8; 4], host: &'static str) -> Resolver {
    Resolver {
        name,
        target: SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])),
            443,
        ),
        sni: host,
        host,
        path: "/dns-query",
    }
}

/// The default diverse pool (raw-IP DoH). Spread across operators, hosting ASNs, and jurisdictions
/// (US clouds, Swiss Quad9, Swedish Mullvad) — see the design's provider survey. Quad9 uses the
/// **no-threat-blocking** `9.9.9.10` so a flagged config host is never `NXDOMAIN`'d out from under us.
pub fn default_pool() -> Vec<Resolver> {
    vec![
        v4("cloudflare", [1, 1, 1, 1], "cloudflare-dns.com"),
        v4("cloudflare2", [1, 0, 0, 1], "cloudflare-dns.com"),
        v4("google", [8, 8, 8, 8], "dns.google"),
        v4("google2", [8, 8, 4, 4], "dns.google"),
        v4("quad9", [9, 9, 9, 10], "dns.quad9.net"),
        v4("mullvad", [194, 242, 2, 2], "dns.mullvad.net"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_pool_is_diverse_and_well_formed() {
        let pool = default_pool();
        assert!(pool.len() >= 5);
        for r in &pool {
            assert_eq!(r.target.port(), 443);
            assert!(r.target.ip().is_ipv4());
            assert!(!r.sni.is_empty() && r.host == r.sni);
            assert_eq!(r.path, "/dns-query");
            assert_eq!(r.strategy().engine.kind(), "boring-chrome");
        }
        // Operator diversity (not all one provider).
        let hosts: std::collections::HashSet<_> = pool.iter().map(|r| r.host).collect();
        assert!(hosts.len() >= 4, "pool should span several operators");
    }
}
