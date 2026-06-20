//! The bootstrap-dial composition model: a [`BootstrapStrategy`] is the data the engine executes.

use std::net::SocketAddr;

use flint_shaping::WirePlan;
use flint_tls::Profile;

/// Which TLS engine (and ClientHello shape) a strategy dials with.
///
/// The two are deliberately *competing compositions*, not merged: exact Chrome JA4 lives in boring,
/// real ECH lives in rustls, and a single ClientHello can't have both today (design §4). The dialer
/// races them and lets the success signal choose.
#[derive(Debug, Clone)]
pub enum TlsEngine {
    /// boring2 Chrome-137 mimicry, shaped by a [`Profile`] (the default for DNS-over-TLS, §7).
    /// Realized only with the `boring` feature; otherwise the dial returns `Unsupported`.
    BoringChrome(Profile),
    /// The rustls baseline (pure-Rust, real-ECH capable). **Deferred** — boring is the mimicry
    /// default and is used as much as possible; rustls exists only for the two things boring can't do
    /// (real ECH — boring only greases — and a no-cmake/odd-platform fallback). Until it's needed, a
    /// dial with this engine returns `Unsupported` rather than silently downgrading off Chrome
    /// mimicry. Revisit for real ECH, ideally once boring2 gains it (design §11).
    Rustls,
}

impl TlsEngine {
    /// A short, stable label for logs / race attribution (never a secret).
    pub fn kind(&self) -> &'static str {
        match self {
            TlsEngine::BoringChrome(_) => "boring-chrome",
            TlsEngine::Rustls => "rustls",
        }
    }
}

/// One fully-specified bootstrap dial: where to connect, what SNI to present, which TLS engine +
/// ClientHello profile to use, and how to shape the opening handshake on the wire. Pure data — the
/// engine ([`crate::dial`]) executes it.
///
/// The `endpoint` axis from the design (raw-IP / CDN-edge-front / hostname) is captured by
/// [`target`](Self::target) (the TCP endpoint to open — a raw IP or a CDN edge IP) paired with
/// [`sni`](Self::sni) (the name presented in the ClientHello — the real host, or an innocuous
/// high-collateral name for fronting). Name resolution for a hostname endpoint is the caller's job
/// (this is the layer that *bootstraps* DNS, so the pool is curated around raw-IP / CDN-edge forms).
#[derive(Debug, Clone)]
pub struct BootstrapStrategy {
    /// The TCP endpoint to connect to (a raw resolver IP, or a CDN/cloud edge IP).
    pub target: SocketAddr,
    /// The SNI to present in the ClientHello (the real host, or a fronting name).
    pub sni: String,
    /// The TLS engine + ClientHello profile.
    pub engine: TlsEngine,
    /// Opening-handshake wire shaping (Layer B `record_fragment` + Layer C `tcp_split`). A default
    /// plan is a no-op passthrough.
    pub wire: WirePlan,
}

impl BootstrapStrategy {
    /// A boring Chrome-mimicry strategy to `target` presenting `sni`, with the default Chrome-137
    /// profile and no wire shaping. The common DNS-over-TLS starting point; layer shaping on via
    /// [`with_wire`](Self::with_wire).
    pub fn boring_chrome(target: SocketAddr, sni: impl Into<String>) -> Self {
        Self {
            target,
            sni: sni.into(),
            engine: TlsEngine::BoringChrome(Profile::default()),
            wire: WirePlan::default(),
        }
    }

    /// Set the opening-handshake wire plan (builder style).
    pub fn with_wire(mut self, wire: WirePlan) -> Self {
        self.wire = wire;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flint_shaping::RecordFragment;

    fn addr() -> SocketAddr {
        "1.1.1.1:443".parse().unwrap()
    }

    #[test]
    fn boring_chrome_builds_the_default_composition() {
        let s = BootstrapStrategy::boring_chrome(addr(), "cloudflare-dns.com");
        assert_eq!(s.sni, "cloudflare-dns.com");
        assert_eq!(s.engine.kind(), "boring-chrome");
        assert!(s.wire.is_noop());
        assert!(matches!(s.engine, TlsEngine::BoringChrome(_)));
    }

    #[test]
    fn with_wire_attaches_a_shaping_plan() {
        let wire = WirePlan {
            record_fragment: RecordFragment::SniStraddle,
            ..Default::default()
        };
        let s = BootstrapStrategy::boring_chrome(addr(), "example.com").with_wire(wire);
        assert!(!s.wire.is_noop());
        assert!(matches!(
            s.wire.record_fragment,
            RecordFragment::SniStraddle
        ));
    }

    #[test]
    fn engine_kinds_are_stable_labels() {
        assert_eq!(TlsEngine::Rustls.kind(), "rustls");
        assert_eq!(
            TlsEngine::BoringChrome(Profile::default()).kind(),
            "boring-chrome"
        );
    }
}
