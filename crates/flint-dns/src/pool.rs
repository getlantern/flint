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
use std::sync::Arc;

use flint_dial::{BootstrapStrategy, CertVerification, WirePlan};

/// Which DNS protocol a resolver speaks — the **DNS axis** of a proxyless strategy.
///
/// [`Doh`](Kind::Doh) and [`Dot`](Kind::Dot) encrypt the query, so an observer cannot read or rewrite
/// it *in flight*. [`Tcp`](Kind::Tcp) and [`Udp`](Kind::Udp) are **plaintext and therefore poisonable
/// by anyone on the path**; they earn a place in the strategy space only because some networks filter
/// encrypted DNS while leaving plaintext queries to an unfiltered resolver alone. They are deliberately
/// absent from [`default_pool`] — see that function for why.
///
/// **Encryption is not authentication**, so the encrypted kinds are also *authenticated*: every TLS
/// resolver dial verifies the certificate chain and hostname ([`Resolver::tls_strategy_with`]). Without
/// that, an on-path attacker could terminate the handshake with any certificate and return forged
/// answers over a perfectly encrypted channel — the very poisoning DoH exists to prevent. With it, the
/// encrypted kinds resist an active on-path MITM as well as passive reading and off-path forgery.
///
/// The plaintext kinds cannot be authenticated at all, which is the real reason they sit outside
/// [`default_pool`]: their answers are only trustworthy once something downstream proves them, which is
/// what the proxyless search does by requiring a verified handshake to the resolved address.
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
    /// True if this transport encrypts the query, so the channel binds the response to it and an
    /// **off-path** attacker cannot forge an answer. Plaintext kinds must instead rely on a random
    /// transaction ID — see [`crate::codec::build_query_with_id`].
    ///
    /// An **on-path** attacker is held off by authentication rather than encryption: these kinds dial
    /// with certificate and hostname verification ([`Resolver::tls_strategy_with`]), so a MITM cannot
    /// substitute its own answers either.
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

/// How a TLS dial is **shaped** and **trusted**.
///
/// Bundling the two keeps the resolve signatures stable as knobs are added, and makes the trust
/// decision something a caller states rather than something it inherits by accident — which is exactly
/// how the resolver dial went unauthenticated before (see [`Resolver::tls_strategy_with`]).
///
/// Named for the resolver dial it was introduced for, but deliberately not specific to it: `flint-dns`
/// applies it to resolver dials and `flint-proxyless` to destination dials as well, so that both legs
/// of a proxyless connection are shaped and anchored from one value. Read every field as applying to
/// whichever TLS peer the policy is used against.
#[derive(Debug, Clone, Default)]
pub struct DialPolicy {
    /// Opening-handshake shaping (the shaping axis; see [`Resolver::tls_strategy_with`]).
    pub wire: WirePlan,
    /// PEM trust anchors used to verify the peer's certificate.
    ///
    /// Empty (the default) means the platform's default store — on desktop the system roots, and on
    /// mobile whatever the embedder has pointed `SSL_CERT_FILE`/`SSL_CERT_DIR` at, since Android and
    /// iOS keep their trust roots where OpenSSL's default paths cannot see them. An embedder that
    /// bundles its own anchor set can pin it here instead.
    ///
    /// `Arc` because one root set is shared across many dials — every resolver in a pool, every
    /// candidate in a search — so cloning it per dial is a refcount bump, not a copy of the PEM data.
    pub roots: Arc<[String]>,
}

impl DialPolicy {
    /// A policy with shaping `wire` and the platform default trust store.
    pub fn shaped(wire: WirePlan) -> Self {
        Self {
            wire,
            roots: Arc::from(Vec::new()),
        }
    }

    /// Pin the PEM trust anchors (builder style). Empty means the platform default store.
    pub fn with_roots(mut self, roots: Arc<[String]>) -> Self {
        self.roots = roots;
        self
    }
}

impl Resolver {
    /// The TLS dial strategy for this resolver — boring Chrome-mimicry to its IP presenting its
    /// hostname as SNI, **certificate-verified** — with no wire shaping, or `None` if this [`Kind`] has
    /// no TLS dial. Shorthand for [`tls_strategy_with`](Self::tls_strategy_with) and a default
    /// [`DialPolicy`].
    pub fn tls_strategy(&self) -> Option<BootstrapStrategy> {
        self.tls_strategy_with(&DialPolicy::default())
    }

    /// The TLS dial strategy under `policy` — its shaping composed on and its trust anchors applied —
    /// or `None` if this [`Kind`] has no TLS dial to describe.
    ///
    /// This is the composition seam between the two axes: the resolver says *where and how* to reach
    /// DNS, `policy.wire` says *how to shape the opening handshake* getting there. That is what makes
    /// "DoH lookups carried over a fragmented, jittered ClientHello" expressible — the same shaping
    /// vocabulary used for a destination dial, applied to the DNS dial itself.
    ///
    /// # The dial is verified, and the identity is the SNI
    ///
    /// Verification is [`CertVerification::Roots`] — chain **and** hostname — never
    /// [`None`](flint_dial::CertVerification::None). Encryption without authentication bought nothing
    /// here: an on-path attacker could terminate the handshake with any certificate and hand back
    /// forged answers, which is precisely the poisoning DoH is supposed to prevent.
    ///
    /// The verified identity is [`sni`](Self::sni), not [`host`](Self::host), because the SNI is by
    /// definition the name whose certificate the server will present. For the ordinary raw-IP and
    /// CDN-edge entries the two are equal, so this is just "verify the resolver hostname" — and it
    /// works despite dialing a bare IP because the identity checked is the hostname, not the address.
    /// For a *fronted* entry (`sni != host`) the front's certificate is what arrives, so that is what
    /// gets authenticated; the real resolver is then addressed by `:authority` **inside** the verified
    /// channel, which is the trust model domain fronting always relies on.
    ///
    /// Returns `None` for every non-TLS kind ([`Kind::is_shapeable`]): plaintext TCP/UDP dial no TLS at
    /// all, and [`Kind::System`] carries no endpoint (its `target` is an unused placeholder, so a
    /// strategy would describe a dial to `0.0.0.0:0`). Handing back `Option` keeps that invalid
    /// combination unrepresentable at the call site instead of trusting each caller to check `kind`
    /// first — the same reason the constructors above exist.
    pub fn tls_strategy_with(&self, policy: &DialPolicy) -> Option<BootstrapStrategy> {
        if !self.kind.is_shapeable() {
            return None;
        }
        Some(
            BootstrapStrategy::boring_chrome(self.target, self.sni.clone())
                .with_wire(policy.wire.clone())
                .with_verification(CertVerification::Roots {
                    roots_pem: policy.roots.clone(),
                    hostname: self.sni.clone(),
                }),
        )
    }

    /// A DNS-over-HTTPS resolver at `target`, presenting `sni`, querying `path` on `host`.
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

/// An IPv6 raw-IP entry (SNI == DoH host), addressed as `[u16; 8]` groups so it stays infallible —
/// same reason [`entry`] takes octets rather than parsing a string.
fn v6(name: &str, ip: [u16; 8], host: &str) -> Resolver {
    Resolver::doh(name, SocketAddr::from((ip, 443)), host, host, "/dns-query")
}

/// The default diverse pool (CDN-edge + raw-IP DoH). Spread across operators, hosting ASNs, and
/// jurisdictions (US clouds, Swiss Quad9, Swedish Mullvad) — see the design's provider survey. The
/// CDN-edge Cloudflare entries lead (the high-collateral spearhead). Quad9 uses the
/// **no-threat-blocking** `9.9.9.10` so a flagged config host is never `NXDOMAIN`'d out from under us.
///
/// **Encrypted kinds only, on purpose.** [`Kind::Udp`]/[`Kind::Tcp`]/[`Kind::System`] answers are
/// poisonable by anyone on the path, and nothing in [`crate::resolve`] proves an answer is *correct* —
/// [`crate::validate`] only rejects bogons, so a censor returning a plausible wrong IP would pass.
/// Plaintext resolvers are therefore safe to try only where the answer gets verified end-to-end by
/// actually completing a TLS handshake with a valid certificate against the resolved address (the
/// proxyless strategy search). Callers who want them must add them explicitly rather than getting them
/// by default here.
///
/// The entries below are, by contrast, both encrypted *and* authenticated — every dial verifies the
/// certificate chain and hostname ([`Resolver::tls_strategy_with`]) — so a poisoned answer cannot reach
/// [`crate::validate`] in the first place. See [`Kind`].
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
        // IPv6 raw-IP forms. Without these the pool is unreachable on a **v6-only** network, which
        // fails strategy selection outright rather than degrading — every candidate needs a resolver
        // it can actually reach, so a v4-only pool means no proxyless strategy exists at all there.
        //
        // On a v4-only network these cost almost nothing: the connect fails immediately with
        // "no route to host" rather than timing out, so the entry loses its race and frees its window
        // slot straight away.
        //
        // Addresses confirmed against live AAAA records on 2026-07-30 (`dig AAAA <host>`). Note this
        // is weaker than the "verified live" claim on the v4 entries above: those were confirmed to
        // *answer DoH*, whereas these were confirmed only to be the right addresses — the vantage
        // point used had no IPv6 egress. A v6-capable check should confirm they serve DoH with a valid
        // certificate before they are relied on. Until then they can only help: a non-answering entry
        // simply loses the race, exactly as a blocked one would.
        v6(
            "cloudflare-v6",
            [0x2606, 0x4700, 0, 0, 0, 0, 0x6810, 0xf8f9],
            "cloudflare-dns.com",
        ),
        v6(
            "cloudflare-v6-2",
            [0x2606, 0x4700, 0, 0, 0, 0, 0x6810, 0xf9f9],
            "cloudflare-dns.com",
        ),
        v6(
            "google-v6",
            [0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888],
            "dns.google",
        ),
        v6(
            "google-v6-2",
            [0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844],
            "dns.google",
        ),
        // `2620:fe::10`, the v6 counterpart of the 9.9.9.10 **no-threat-blocking** service — matching
        // the v4 entry above. `dns.quad9.net` itself resolves to `2620:fe::fe`, which is the
        // *blocking* variant, so taking the hostname's AAAA record here would have quietly switched
        // this entry's filtering behaviour relative to its v4 twin.
        v6(
            "quad9-v6",
            [0x2620, 0x00fe, 0, 0, 0, 0, 0, 0x0010],
            "dns.quad9.net",
        ),
        v6(
            "mullvad-v6",
            [0x2a07, 0xe340, 0, 0, 0, 0, 0, 0x0002],
            "dns.mullvad.net",
        ),
    ]
}

#[cfg(test)]
mod tests {
    use flint_dial::RecordFragment;

    use super::*;

    #[test]
    fn default_pool_is_diverse_and_well_formed() {
        let pool = default_pool();
        assert!(pool.len() >= 5);
        for r in &pool {
            assert_eq!(r.target.port(), 443);
            assert!(!r.sni.is_empty() && r.host == r.sni);
            assert_eq!(r.path, "/dns-query");
            // Every default entry is an encrypted kind, so each has a TLS strategy.
            assert_eq!(r.kind, Kind::Doh);
            let strategy = r.tls_strategy().expect("a DoH resolver has a TLS strategy");
            assert_eq!(strategy.engine.kind(), "boring-chrome");
        }
        // Operator diversity (not all one provider).
        let hosts: std::collections::HashSet<_> = pool.iter().map(|r| r.host.as_str()).collect();
        assert!(hosts.len() >= 4, "pool should span several operators");
    }

    #[test]
    fn the_pool_is_dual_stack_and_every_operator_is_reachable_over_v6() {
        // A v4-only pool is unreachable on a v6-only network, which fails strategy selection outright
        // rather than degrading — so this is a reachability property, not a nicety.
        let pool = default_pool();
        let v6: Vec<_> = pool.iter().filter(|r| r.target.ip().is_ipv6()).collect();
        let v4: Vec<_> = pool.iter().filter(|r| r.target.ip().is_ipv4()).collect();
        assert!(!v4.is_empty(), "the pool must still work on v4-only");
        assert!(!v6.is_empty(), "the pool must work on v6-only");

        // Every operator reachable over v4 must also be reachable over v6, or a v6-only network
        // silently loses the operator diversity the pool exists to provide — it would fall back to
        // whichever one or two operators happened to get a v6 entry.
        let v4_hosts: std::collections::HashSet<_> = v4.iter().map(|r| r.host.as_str()).collect();
        let v6_hosts: std::collections::HashSet<_> = v6.iter().map(|r| r.host.as_str()).collect();
        assert_eq!(
            v4_hosts, v6_hosts,
            "every operator needs both families, else v6-only loses operator diversity"
        );
    }

    #[test]
    fn the_v6_quad9_entry_is_the_no_blocking_service_like_its_v4_twin() {
        // `dns.quad9.net` resolves to 2620:fe::fe, the *filtering* service. Taking the hostname's AAAA
        // would have quietly given the v6 entry different filtering behaviour from the v4 one
        // (9.9.9.10, no-block), so a flagged config host could be NXDOMAIN'd on v6 but not on v4.
        let pool = default_pool();
        let q6 = pool
            .iter()
            .find(|r| r.name == "quad9-v6")
            .expect("a v6 Quad9 entry");
        assert_eq!(
            q6.target.ip(),
            "2620:fe::10".parse::<std::net::IpAddr>().unwrap(),
            "must be the no-blocking service, not 2620:fe::fe"
        );
    }

    #[test]
    fn only_tls_kinds_have_a_dial_strategy() {
        let addr = "9.9.9.10:443".parse().unwrap();

        // TLS kinds: a strategy, carrying the SNI and any shaping asked for.
        let doh = Resolver::doh("q", addr, "dns.quad9.net", "dns.quad9.net", "/dns-query");
        let dot = Resolver::dot("q-dot", "9.9.9.10:853".parse().unwrap(), "dns.quad9.net");
        for r in [&doh, &dot] {
            let s = r
                .tls_strategy()
                .expect("a TLS kind must have a dial strategy");
            assert_eq!(s.sni, "dns.quad9.net");
            assert!(s.wire.is_noop(), "default strategy applies no shaping");
        }
        let shaped = doh
            .tls_strategy_with(&DialPolicy::shaped(WirePlan {
                record_fragment: RecordFragment::SniStraddle,
                ..Default::default()
            }))
            .expect("shaping composes onto a TLS kind");
        assert!(!shaped.wire.is_noop(), "the wire plan must be carried");

        // Non-TLS kinds have none — the invalid combination is unrepresentable, so nothing can
        // accidentally dial TLS to a plaintext resolver or to System's placeholder 0.0.0.0:0.
        let plaintext = "9.9.9.10:53".parse().unwrap();
        for r in [
            Resolver::tcp("q-tcp", plaintext),
            Resolver::udp("q-udp", plaintext),
            Resolver::system(),
        ] {
            assert!(
                r.tls_strategy().is_none(),
                "{:?} must not produce a TLS strategy",
                r.kind
            );
        }
    }

    #[test]
    fn every_tls_dial_verifies_the_certificate_against_the_sni() {
        // The regression this guards: `boring_chrome` defaults to CertVerification::None, so a
        // strategy that merely inherits it is encrypted but unauthenticated — an on-path MITM could
        // terminate the handshake with any certificate and inject answers.
        let doh = Resolver::doh(
            "q",
            "9.9.9.10:443".parse().unwrap(),
            "dns.quad9.net",
            "dns.quad9.net",
            "/dns-query",
        );
        let dot = Resolver::dot("q-dot", "9.9.9.10:853".parse().unwrap(), "dns.quad9.net");

        for r in [&doh, &dot] {
            let s = r.tls_strategy().expect("a TLS kind has a strategy");
            match &s.verification {
                CertVerification::Roots {
                    roots_pem,
                    hostname,
                } => {
                    // The identity checked is the SNI — the name whose cert the server presents.
                    assert_eq!(hostname, &r.sni);
                    assert!(!hostname.is_empty(), "a verified dial requires a hostname");
                    // Empty anchors mean the platform default store, not "skip verification".
                    assert!(roots_pem.is_empty());
                }
                CertVerification::None => {
                    panic!("{:?} dial must not be unauthenticated", r.kind)
                }
            }
        }

        // Pinned anchors are carried through instead of the platform store.
        let pinned: Arc<[String]> = Arc::from(vec!["-----BEGIN CERTIFICATE-----".to_string()]);
        let s = doh
            .tls_strategy_with(&DialPolicy::default().with_roots(pinned.clone()))
            .expect("a TLS kind has a strategy");
        match &s.verification {
            CertVerification::Roots { roots_pem, .. } => assert_eq!(roots_pem, &pinned),
            CertVerification::None => panic!("pinned roots must still verify"),
        }
    }

    /// A fronted entry (`sni != host`) authenticates the **front**, since that is whose certificate
    /// arrives; the real resolver is then addressed by `:authority` inside the verified channel.
    #[test]
    fn a_fronted_entry_verifies_the_front_not_the_doh_authority() {
        let fronted = Resolver::doh(
            "fronted",
            "104.16.249.249:443".parse().unwrap(),
            "camouflage.example",
            "cloudflare-dns.com",
            "/dns-query",
        );
        let s = fronted.tls_strategy().expect("DoH has a strategy");
        assert_eq!(s.sni, "camouflage.example");
        match &s.verification {
            CertVerification::Roots { hostname, .. } => {
                assert_eq!(
                    hostname, "camouflage.example",
                    "verifying the DoH :authority would fail — the front serves its own cert"
                );
            }
            CertVerification::None => panic!("a fronted dial must still be authenticated"),
        }
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
