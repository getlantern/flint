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
//!   instead of its well-known dedicated IP — e.g. Cloudflare answers `cloudflare-dns.com` DoH on
//!   *any* live edge IP across its announced ranges (`104.16.0.0/13`, `104.24.0.0/14`,
//!   `172.64.0.0/13`, `162.158.0.0/15`, `141.101.64.0/18`, …), each carrying millions of sites, so
//!   blocking them is collateral-expensive.
//!   Same real SNI/host (not domain fronting), just far harder-to-block addresses. This is
//!   Cloudflare-specific (its resolver shares the general CDN edge); see [`default_pool`].
//!
//! Ed25519-signed pool updates are layered on later (design §6).

use std::net::SocketAddr;

use flint_dial::BootstrapStrategy;

/// One DoH resolver, addressed for a fixed-IP dial. Fields are **owned** (not `&'static str`) so a
/// pool can be decoded from an Ed25519-signed update at runtime (see [`crate::signed`]), not only
/// baked in. Serializable for that signed-blob payload.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Resolver {
    /// Short operator label (logs / metrics; never a secret).
    pub name: String,
    /// The TCP endpoint to dial (the resolver IP, port 443).
    pub target: SocketAddr,
    /// The SNI to present in the ClientHello (the resolver hostname, covered by its cert).
    pub sni: String,
    /// The DoH `:authority` (HTTP host) — the resolver hostname.
    pub host: String,
    /// The DoH path (RFC 8484), almost always `/dns-query`.
    pub path: String,
}

impl Resolver {
    /// The bootstrap-dial strategy for this resolver: boring Chrome-mimicry to its IP, presenting its
    /// hostname as SNI, with no wire shaping (the dialer layers shaping on per network).
    pub fn strategy(&self) -> BootstrapStrategy {
        BootstrapStrategy::boring_chrome(self.target, self.sni.clone())
    }
}

/// Build a resolver entry from octets, an SNI, and a DoH `:authority` host (infallible — no
/// parse/`unwrap`). When `sni == host` this is a plain dial (raw-IP or CDN-edge, depending on the IP);
/// when `sni != host` it is a fronted dial (camouflage SNI, real host in `:authority`). Domain
/// fronting is blocked by some CDNs (Cloudflare/Google), so the default pool prefers `sni == host`
/// CDN-edge entries.
fn entry(name: &str, ip: [u8; 4], sni: &str, host: &str) -> Resolver {
    Resolver {
        name: name.to_owned(),
        target: SocketAddr::from((ip, 443)),
        sni: sni.to_owned(),
        host: host.to_owned(),
        path: "/dns-query".to_owned(),
    }
}

/// A plain raw-IP / CDN-edge entry (SNI == DoH host).
fn v4(name: &str, ip: [u8; 4], host: &str) -> Resolver {
    entry(name, ip, host, host)
}

/// The default diverse pool (CDN-edge + raw-IP DoH). Spread across operators, hosting ASNs, and
/// jurisdictions (US clouds, Swiss Quad9, Swedish Mullvad) — see the design's provider survey. The
/// CDN-edge Cloudflare entries lead (the high-collateral spearhead). Quad9 uses the
/// **no-threat-blocking** `9.9.9.10` so a flagged config host is never `NXDOMAIN`'d out from under us.
pub fn default_pool() -> Vec<Resolver> {
    vec![
        // CDN-edge spearhead: Cloudflare runs its DoH resolver on the *same* global anycast edge that
        // fronts millions of unrelated sites, so `cloudflare-dns.com` DoH answers on **any** live
        // Cloudflare edge IP given the right SNI/host — not just the well-known 1.1.1.1. We spread the
        // entries across **five** of Cloudflare's distinct announced ranges (104.16.0.0/13,
        // 104.24.0.0/14, 172.64.0.0/13, 162.158.0.0/15, 141.101.64.0/18), **three IPs each**, so a
        // censor must block every range and eat the collateral of each (each carries a huge slice of
        // the web). All verified live 2026-06-24; these are representative anycast edges — the 104.16
        // pair (edge1/edge2) are the official `cloudflare-dns.com` A-records, the rest are live edges
        // harvested from unrelated CF-fronted sites (a wider verified set is in
        // `cloudflare-doh-edges-reference.txt`). The pool races and per-network-caches the winner, so
        // churn of any single IP is absorbed (three per range gives redundancy; note reachability is
        // anycast-vantage-dependent, so more spread helps clients in different regions). NB: this
        // edge-spread trick is Cloudflare-specific: Google (`dns.google`, 8.8.x) and AliDNS
        // (`dns.alidns.com`, 223.5.x) serve DoH only on dedicated anycast, not a shared CDN, so they
        // stay raw-IP below.
        // 104.16.0.0/13 (edge1/edge2 = the official cloudflare-dns.com A-records):
        v4(
            "cloudflare-edge1",
            [104, 16, 249, 249],
            "cloudflare-dns.com",
        ),
        v4(
            "cloudflare-edge2",
            [104, 16, 248, 249],
            "cloudflare-dns.com",
        ),
        v4("cloudflare-edge3", [104, 18, 0, 50], "cloudflare-dns.com"),
        // 104.24.0.0/14:
        v4("cloudflare-edge4", [104, 26, 5, 189], "cloudflare-dns.com"),
        v4("cloudflare-edge5", [104, 26, 4, 189], "cloudflare-dns.com"),
        v4("cloudflare-edge6", [104, 25, 102, 4], "cloudflare-dns.com"),
        // 172.64.0.0/13:
        v4("cloudflare-edge7", [172, 67, 68, 111], "cloudflare-dns.com"),
        v4("cloudflare-edge8", [172, 65, 251, 78], "cloudflare-dns.com"),
        v4("cloudflare-edge9", [172, 66, 0, 37], "cloudflare-dns.com"),
        // 162.158.0.0/15:
        v4(
            "cloudflare-edge10",
            [162, 159, 136, 232],
            "cloudflare-dns.com",
        ),
        v4(
            "cloudflare-edge11",
            [162, 159, 152, 4],
            "cloudflare-dns.com",
        ),
        v4(
            "cloudflare-edge12",
            [162, 159, 128, 61],
            "cloudflare-dns.com",
        ),
        // 141.101.64.0/18:
        v4(
            "cloudflare-edge13",
            [141, 101, 90, 100],
            "cloudflare-dns.com",
        ),
        v4(
            "cloudflare-edge14",
            [141, 101, 90, 101],
            "cloudflare-dns.com",
        ),
        v4(
            "cloudflare-edge15",
            [141, 101, 90, 102],
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
        let hosts: std::collections::HashSet<_> = pool.iter().map(|r| r.host.as_str()).collect();
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
