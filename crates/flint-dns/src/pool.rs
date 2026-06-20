//! The resilient DoH resolver pool (design §6).
//!
//! Curated for **diversity across operators, ASNs, and jurisdictions**, not raw count — blocking
//! `1.1.1.1`/`8.8.8.8` is one cheap censor rule, so the pool's value is the spread. Two endpoint forms
//! are included (both dial a fixed IP — no bootstrap-DNS chicken-and-egg, since these operators put IP
//! SANs in their certs):
//!
//! - **raw-IP**: dial the resolver's own dedicated IP, presenting its hostname as SNI + DoH
//!   `:authority`.
//! - **CDN-edge** (the design's spearhead): dial the resolver over a **high-collateral CDN range**
//!   (e.g. Cloudflare DoH on `104.16/12`, which serves millions of sites) instead of the well-known
//!   dedicated IP — blocking that range is collateral-expensive. Same real SNI/host (not domain
//!   fronting), just a far harder-to-block address.
//!
//! Ed25519-signed pool updates are layered on later (design §6).

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

/// Build a resolver entry from octets, an SNI, and a DoH `:authority` host (infallible — no
/// parse/`unwrap`). When `sni == host` this is a plain dial (raw-IP or CDN-edge, depending on the IP);
/// when `sni != host` it is a fronted dial (camouflage SNI, real host in `:authority`). Domain
/// fronting is blocked by some CDNs (Cloudflare/Google), so the default pool prefers `sni == host`
/// CDN-edge entries.
const fn entry(name: &'static str, ip: [u8; 4], sni: &'static str, host: &'static str) -> Resolver {
    Resolver {
        name,
        target: SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])),
            443,
        ),
        sni,
        host,
        path: "/dns-query",
    }
}

/// A plain raw-IP / CDN-edge entry (SNI == DoH host).
const fn v4(name: &'static str, ip: [u8; 4], host: &'static str) -> Resolver {
    entry(name, ip, host, host)
}

/// The default diverse pool (CDN-edge + raw-IP DoH). Spread across operators, hosting ASNs, and
/// jurisdictions (US clouds, Swiss Quad9, Swedish Mullvad) — see the design's provider survey. The
/// CDN-edge Cloudflare entries lead (the high-collateral spearhead). Quad9 uses the
/// **no-threat-blocking** `9.9.9.10` so a flagged config host is never `NXDOMAIN`'d out from under us.
pub fn default_pool() -> Vec<Resolver> {
    vec![
        // CDN-edge spearhead: Cloudflare DoH over its high-collateral CDN range (104.16/12), not the
        // well-known 1.1.1.1 — same cert/SNI/host, far costlier for a censor to block.
        v4("cloudflare-edge", [104, 16, 249, 249], "cloudflare-dns.com"),
        v4(
            "cloudflare-edge2",
            [104, 16, 248, 249],
            "cloudflare-dns.com",
        ),
        // Raw-IP forms (dedicated resolver anycast).
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

    #[test]
    fn pool_includes_a_cdn_edge_entry() {
        // At least one entry dials Cloudflare's high-collateral CDN range (104.16/12) rather than a
        // dedicated resolver IP — the design's spearhead.
        let pool = default_pool();
        assert!(
            pool.iter().any(|r| matches!(r.target.ip(),
                std::net::IpAddr::V4(a) if a.octets()[0] == 104 && a.octets()[1] == 16)),
            "pool should include a CDN-edge entry"
        );
    }

    #[test]
    fn fronted_entry_separates_sni_from_authority() {
        // The struct supports domain fronting: a camouflage SNI with the real DoH host in :authority.
        let r = entry("fronted", [104, 16, 0, 1], "front.example", "doh.example");
        assert_eq!(r.sni, "front.example");
        assert_eq!(r.host, "doh.example");
        assert_ne!(r.sni, r.host);
    }
}
