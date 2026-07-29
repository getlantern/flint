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

use flint_dial::{BootstrapStrategy, WirePlan};

/// Which DNS protocol a resolver speaks — the **DNS axis** of a proxyless strategy.
///
/// [`Doh`](Kind::Doh) and [`Dot`](Kind::Dot) are encrypted, so a censor can only *block* the
/// connection, never poison the answer. [`Tcp`](Kind::Tcp) and [`Udp`](Kind::Udp) are **plaintext and
/// therefore poisonable**; they earn a place in the strategy space only because some networks filter
/// encrypted DNS while leaving plaintext queries to an unfiltered resolver alone. They are deliberately
/// absent from [`default_pool`] — see that function for why.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Kind {
    /// DNS-over-HTTPS (RFC 8484) over HTTP/2, port 443. Uses `sni`, `host`, and `path`.
    #[default]
    Doh,
    /// DNS-over-TLS (RFC 7858), port 853: length-prefixed DNS inside TLS. Uses `sni`; ignores
    /// `host`/`path`.
    Dot,
    /// Plaintext DNS over TCP (RFC 1035 §4.2.2), port 53: length-prefixed. Ignores `sni`/`host`/`path`.
    Tcp,
    /// Plaintext DNS over UDP (RFC 1035), port 53. Ignores `sni`/`host`/`path`.
    Udp,
    /// The operating system's own resolver. Ignores every addressing field — useful because on many
    /// networks the system resolver is simply not interfered with, and it costs nothing to try.
    System,
}

impl Kind {
    /// True if this transport encrypts the query, so the channel itself binds the response to it (and
    /// a censor cannot forge an answer, only block). Plaintext kinds must instead rely on a random
    /// transaction ID — see [`crate::codec::build_query_with_id`].
    pub fn is_encrypted(self) -> bool {
        matches!(self, Kind::Doh | Kind::Dot)
    }

    /// True if this kind dials a TLS stream, and therefore composes with opening-handshake
    /// [`WirePlan`] shaping. Plaintext DNS has no ClientHello to fragment, and [`Kind::System`]
    /// exposes no socket at all.
    pub fn is_shapeable(self) -> bool {
        self.is_encrypted()
    }
}

/// One resolver, addressed for a fixed-IP dial. Fields are **owned** (not `&'static str`) so a
/// pool can be decoded from an Ed25519-signed update at runtime (see [`crate::signed`]), not only
/// baked in. Serializable for that signed-blob payload.
///
/// Which addressing fields apply depends on [`kind`](Self::kind) — the per-variant docs on [`Kind`]
/// say which. Prefer the typed constructors ([`Resolver::doh`], [`dot`](Resolver::dot),
/// [`udp`](Resolver::udp), [`tcp`](Resolver::tcp), [`system`](Resolver::system)) over a struct literal
/// so unused fields are never filled in with something misleading.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Resolver {
    /// Short operator label (logs / metrics; never a secret).
    pub name: String,
    /// Which DNS protocol this resolver speaks.
    pub kind: Kind,
    /// The endpoint to dial. Unused for [`Kind::System`].
    pub target: SocketAddr,
    /// The SNI to present in the ClientHello (the resolver hostname, covered by its cert). Used by the
    /// TLS-based kinds only.
    pub sni: String,
    /// The DoH `:authority` (HTTP host) — the resolver hostname. [`Kind::Doh`] only.
    pub host: String,
    /// The DoH path (RFC 8484), almost always `/dns-query`. [`Kind::Doh`] only.
    pub path: String,
}

impl Resolver {
    /// The bootstrap-dial strategy for this resolver: boring Chrome-mimicry to its IP, presenting its
    /// hostname as SNI, with **no** wire shaping. Shorthand for [`strategy_with`](Self::strategy_with)
    /// and a default [`WirePlan`].
    pub fn strategy(&self) -> BootstrapStrategy {
        self.strategy_with(WirePlan::default())
    }

    /// The bootstrap-dial strategy with opening-handshake shaping `wire` composed onto it.
    ///
    /// This is the composition seam between the two axes: the resolver says *where and how* to reach
    /// DNS, `wire` says *how to shape the opening handshake* getting there. That is what makes
    /// "DoH lookups carried over a fragmented, jittered ClientHello" expressible — the same shaping
    /// vocabulary used for a destination dial, applied to the DNS dial itself.
    ///
    /// Shaping is only meaningful for the TLS-based kinds ([`Kind::is_shapeable`]); for plaintext or
    /// system resolvers there is no ClientHello and `wire` is ignored by the query path.
    pub fn strategy_with(&self, wire: WirePlan) -> BootstrapStrategy {
        BootstrapStrategy::boring_chrome(self.target, self.sni.clone()).with_wire(wire)
    }

    /// A DNS-over-HTTPS resolver at `target`, presenting `sni`, querying `host``path`.
    pub fn doh(
        name: impl Into<String>,
        target: SocketAddr,
        sni: impl Into<String>,
        host: impl Into<String>,
        path: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            kind: Kind::Doh,
            target,
            sni: sni.into(),
            host: host.into(),
            path: path.into(),
        }
    }

    /// A DNS-over-TLS resolver at `target` (conventionally port 853), presenting `sni`.
    pub fn dot(name: impl Into<String>, target: SocketAddr, sni: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind: Kind::Dot,
            target,
            sni: sni.into(),
            host: String::new(),
            path: String::new(),
        }
    }

    /// A plaintext DNS-over-TCP resolver at `target` (conventionally port 53).
    pub fn tcp(name: impl Into<String>, target: SocketAddr) -> Self {
        Self::plain(name, Kind::Tcp, target)
    }

    /// A plaintext DNS-over-UDP resolver at `target` (conventionally port 53).
    pub fn udp(name: impl Into<String>, target: SocketAddr) -> Self {
        Self::plain(name, Kind::Udp, target)
    }

    fn plain(name: impl Into<String>, kind: Kind, target: SocketAddr) -> Self {
        Self {
            name: name.into(),
            kind,
            target,
            sni: String::new(),
            host: String::new(),
            path: String::new(),
        }
    }

    /// The OS resolver. Carries no addressing at all; `target` is an explicit unused placeholder.
    pub fn system() -> Self {
        Self {
            name: "system".to_owned(),
            kind: Kind::System,
            target: SocketAddr::from(([0, 0, 0, 0], 0)),
            sni: String::new(),
            host: String::new(),
            path: String::new(),
        }
    }
}

/// Build a resolver entry from octets, an SNI, and a DoH `:authority` host (infallible — no
/// parse/`unwrap`). When `sni == host` this is a plain dial (raw-IP or CDN-edge, depending on the IP);
/// when `sni != host` it is a fronted dial (camouflage SNI, real host in `:authority`). Domain
/// fronting is blocked by some CDNs (Cloudflare/Google), so the default pool prefers `sni == host`
/// CDN-edge entries.
fn entry(name: &str, ip: [u8; 4], sni: &str, host: &str) -> Resolver {
    Resolver::doh(name, SocketAddr::from((ip, 443)), sni, host, "/dns-query")
}

/// A plain raw-IP / CDN-edge entry (SNI == DoH host).
fn v4(name: &str, ip: [u8; 4], host: &str) -> Resolver {
    entry(name, ip, host, host)
}

/// The default diverse pool (CDN-edge + raw-IP DoH). Spread across operators, hosting ASNs, and
/// jurisdictions (US clouds, Swiss Quad9, Swedish Mullvad) — see the design's provider survey. The
/// CDN-edge Cloudflare entries lead (the high-collateral spearhead). Quad9 uses the
/// **no-threat-blocking** `9.9.9.10` so a flagged config host is never `NXDOMAIN`'d out from under us.
///
/// **Encrypted kinds only, on purpose.** [`Kind::Udp`]/[`Kind::Tcp`]/[`Kind::System`] answers are
/// poisonable, and nothing in [`crate::resolve`] proves an answer is *correct* — [`crate::validate`]
/// only rejects bogons, so a censor returning a plausible wrong IP would pass. Plaintext resolvers are
/// therefore safe to try only where the answer gets verified end-to-end by actually completing a TLS
/// handshake with a valid certificate against the resolved address (the proxyless strategy search).
/// Callers who want them must add them explicitly rather than getting them by default here.
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
