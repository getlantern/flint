//! Proxyless as a raced bootstrap transport.
//!
//! The other Kindling transports reach a config endpoint *indirectly* — through a CDN front, or a direct
//! h2 dial to the origin. This one reaches it **directly with no proxy and no exit hop**, by searching
//! [`flint_proxyless`]'s `resolver × wire` space for a pairing the local network does not block: an
//! un-poisoned resolver plus opening-handshake shaping (record fragmentation, segment splitting,
//! inter-segment jitter).
//!
//! It costs no infrastructure and burns no fronting domains, which makes it a good race member rather
//! than a replacement: on an open network a direct dial wins outright, and where DNS is poisoned or the
//! ClientHello is being classified, this is the leg that survives.
//!
//! Scope: proxyless has no exit hop, so a config fetch through it leaves the user's own address for the
//! real endpoint. That is fine for bootstrap — fetching a config is not browsing — but see
//! [`flint_proxyless`] for why it must not silently stand in for a proxy path carrying user traffic.

use std::io;

use async_trait::async_trait;
use flint_proxyless::{Space, StrategyCache};
use flint_transport::ConnectionTransport;

/// The default port a config endpoint is reached on.
const DEFAULT_PORT: u16 = 443;

/// A [`ConnectionTransport`] that reaches `host` proxylessly, remembering what worked per network.
///
/// # Cold search vs the race's attempt timeout
///
/// The first connection on a new network is a **search**: up to `resolver × wire` candidates, each a DNS
/// lookup plus a TLS handshake, four at a time. That can easily outlast
/// [`RaceOptions::attempt_timeout`](flint_transport::RaceOptions::attempt_timeout), whose default is 15s
/// — and because the timeout would kill the attempt *before* a winner is recorded, the cache would never
/// populate and every subsequent attempt would fail the same way. A slow cold start would look like a
/// permanently broken transport.
///
/// Two mitigations, and it is worth using both:
///
/// - [`with_max_candidates`](Self::with_max_candidates) bounds how much of the space a single cold search
///   will try, so its worst case is predictable rather than proportional to the pool.
/// - [`warm`](Self::warm) runs the search **outside** any race, so the first in-race connect is a single
///   dial against an already-cached winner. Callers that can afford a one-off startup cost should prefer
///   this over raising the race's timeout for every transport.
pub struct ProxylessTransport {
    space: Space,
    cache: StrategyCache,
    network: String,
    port: u16,
    max_candidates: Option<usize>,
}

impl ProxylessTransport {
    /// A transport over `space`, caching its winner under the `network` fingerprint.
    ///
    /// `network` is the caller's answer to "is this the same network as last time" (gateway IP/MAC, SSID,
    /// captive-portal identity, …); a single-network app can pass a constant. Defaults to port 443 and an
    /// unbounded search.
    pub fn new(space: Space, network: impl Into<String>) -> Self {
        Self {
            space,
            cache: StrategyCache::new(),
            network: network.into(),
            port: DEFAULT_PORT,
            max_candidates: None,
        }
    }

    /// Override the destination port (default 443).
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Cap how many candidates a cold search will try, bounding its worst-case duration so it fits
    /// inside the race's per-attempt timeout. See the type docs.
    ///
    /// The cap keeps the space's enumeration order, which is wire-major — so a small cap still tries
    /// every resolver against the cheapest (no-op) plan before it starts spending on shaping.
    pub fn with_max_candidates(mut self, max: usize) -> Self {
        self.max_candidates = Some(max);
        self
    }

    /// The space this transport searches, truncated to `max_candidates` when one is set.
    fn search_space(&self) -> Space {
        match self.max_candidates {
            // A cap only has to bound the *candidate count*, and candidates are `resolvers × wires`
            // enumerated wire-major. Trimming the resolver list is therefore the honest way to cap:
            // it keeps every wire plan reachable, where trimming wires would silently drop shaping
            // strategies the network may specifically require.
            Some(max) if max > 0 && self.space.len() > max => {
                let wires = self.space.wires.len().max(1);
                let keep = (max / wires).max(1);
                let mut trimmed = self.space.clone();
                trimmed.resolvers.truncate(keep);
                trimmed
            }
            _ => self.space.clone(),
        }
    }

    /// Run the search now, outside any race, so the winner is cached before the first real connection.
    ///
    /// Returns the connection it proved with — usually dropped; the point is the populated cache. Failing
    /// here is not fatal to the caller: it means no strategy currently reaches `host`, and a later
    /// [`connect`](ConnectionTransport::connect) will search again.
    pub async fn warm(&self, host: &str) -> io::Result<()> {
        self.connect(host).await.map(drop)
    }

    /// Forget the cached winner for this network, forcing the next connect to search again.
    pub fn forget(&self) {
        self.cache.forget(&self.network);
    }
}

#[async_trait]
impl ConnectionTransport for ProxylessTransport {
    type Stream = flint_proxyless::BoxedTlsStream;

    fn name(&self) -> &str {
        "proxyless"
    }

    async fn connect(&self, host: &str) -> io::Result<Self::Stream> {
        let space = self.search_space();
        let (_strategy, stream) =
            flint_proxyless::connect_cached(&space, host, self.port, &self.cache, &self.network)
                .await
                .map_err(io::Error::other)?;
        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flint_proxyless::Resolver;

    fn resolvers(n: usize) -> Vec<Resolver> {
        (0..n)
            .map(|i| {
                Resolver::doh(
                    format!("r{i}"),
                    format!("9.9.9.{i}:443").parse().unwrap(),
                    "dns.example",
                    "dns.example",
                    "/dns-query",
                )
            })
            .collect()
    }

    #[test]
    fn the_transport_names_itself_for_race_diagnostics() {
        let t = ProxylessTransport::new(Space::new(resolvers(1)), "wifi");
        assert_eq!(ConnectionTransport::name(&t), "proxyless");
    }

    #[test]
    fn an_uncapped_search_uses_the_whole_space() {
        let space = Space::new(resolvers(6)).with_wire(Default::default());
        let t = ProxylessTransport::new(space, "wifi");
        assert_eq!(t.search_space().len(), 12);
    }

    #[test]
    fn a_cap_trims_resolvers_and_keeps_every_wire_plan() {
        // 6 resolvers × 2 wires = 12 candidates, capped to 4 → 2 resolvers × 2 wires.
        let space = Space::new(resolvers(6)).with_wire(Default::default());
        let t = ProxylessTransport::new(space, "wifi").with_max_candidates(4);
        let capped = t.search_space();
        assert_eq!(capped.len(), 4);
        assert_eq!(capped.resolvers.len(), 2);
        assert_eq!(
            capped.wires.len(),
            2,
            "capping must not drop shaping strategies the network may require"
        );
    }

    #[test]
    fn a_cap_always_leaves_at_least_one_resolver() {
        // A cap smaller than the number of wire plans must not trim the space to nothing.
        let space = Space::new(resolvers(6))
            .with_wire(Default::default())
            .with_wire(Default::default());
        let t = ProxylessTransport::new(space, "wifi").with_max_candidates(1);
        let capped = t.search_space();
        assert_eq!(capped.resolvers.len(), 1);
        assert!(!capped.is_empty());
    }

    #[tokio::test]
    async fn an_empty_space_fails_without_touching_the_network() {
        let t = ProxylessTransport::new(Space::new(Vec::new()), "wifi");
        // Not `unwrap_err`: the Ok type is a boxed trait object with no `Debug`.
        let err = match t.connect("config.example").await {
            Ok(_) => panic!("an empty space must not produce a connection"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("strategy space is empty"),
            "unexpected error: {err}"
        );
    }
}
