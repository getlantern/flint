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
/// [`RaceOptions::attempt_timeout`](flint_transport::RaceOptions::attempt_timeout), whose default is 15s —
/// and because the timeout kills the attempt *before* a winner is recorded, the cache stays empty and the
/// next attempt repeats the same search from scratch rather than benefiting from it. Whether it then
/// succeeds is down to candidate timing, so this is not a permanent failure so much as an uninformed one:
/// a transport that keeps re-running a search it never finishes looks broken.
///
/// Size the cap for the **stale-cache** case, not the cold one. A cached winner that has since been
/// blocked costs one 5s attempt before the search even begins, so the worst case is
/// `5s + ceil(candidates / 4) × 5s`. Against the 15s default that makes a cap of **4** the safe choice
/// (10s total); a cap of 8 totals exactly 15s and can be cancelled at the boundary — precisely when it
/// would otherwise have cached a new winner.
///
/// Two mitigations, and it is worth using both:
///
/// - [`with_max_candidates`](Self::with_max_candidates) is a strict upper bound on how many candidates a
///   single cold search will try, so its worst case is predictable rather than proportional to the pool.
///   It trims resolvers first and only sacrifices wire plans when the cap is smaller than the number of
///   plans — see that method for the trade-off it makes.
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

    /// Cap how many candidates a cold search will try — a **strict** upper bound, so its worst-case
    /// duration is predictable and can be kept inside the race's per-attempt timeout.
    ///
    /// `0` is treated as `1`: a cap that searched nothing could never find a strategy, so it would turn
    /// the transport off rather than bound it.
    ///
    /// Candidates are `resolvers × wire plans`, so honouring an exact count means giving something up.
    /// Resolvers are trimmed first, keeping every wire plan available for as long as the budget allows —
    /// resolver diversity is the cheaper thing to lose, since the pool is deliberately redundant while
    /// each shaping plan is a distinct evasion strategy. Only when the cap is smaller than the number of
    /// plans must plans go too, and then the *first* ones survive: enumeration is wire-major with the
    /// no-op plan first, so an aggressive cap keeps the cheapest strategies and drops the exotic ones.
    pub fn with_max_candidates(mut self, max: usize) -> Self {
        self.max_candidates = Some(max.max(1));
        self
    }

    /// The space this transport searches, trimmed so its candidate count never exceeds
    /// `max_candidates`.
    fn search_space(&self) -> Space {
        let Some(max) = self.max_candidates else {
            return self.space.clone();
        };
        // `with_max_candidates` already floors this at 1, but a struct field is not a proof.
        let max = max.max(1);
        if self.space.len() <= max {
            return self.space.clone();
        }

        let mut trimmed = self.space.clone();
        let wires = trimmed.wires.len().max(1);
        if max < wires {
            // Not enough budget for even one resolver against every plan, so plans have to give. Keep
            // the first `max` of them — wire-major order makes those the cheapest.
            trimmed.resolvers.truncate(1);
            trimmed.wires.truncate(max);
        } else {
            // `max / wires >= 1` here, so this always leaves a usable space.
            trimmed.resolvers.truncate(max / wires);
        }
        trimmed
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
    type Stream = flint_proxyless::AlpnStream;

    fn name(&self) -> &str {
        "proxyless"
    }

    async fn connect(&self, host: &str) -> io::Result<Self::Stream> {
        self.dial(host).await
    }

    /// Reports the protocol the destination actually chose.
    ///
    /// Worth overriding here specifically: this transport's shaping engine offers `h2,http/1.1`
    /// because ALPN is part of the fingerprint it exists to imitate, so what the peer picks is a
    /// property of the peer, not of this transport. A consumer that hardcodes h2 because "a modern
    /// origin picks h2" is right until it meets an edge that answers http/1.1 — and that failure does
    /// not look like a protocol mismatch, it looks like a response that never terminates.
    ///
    /// The `Vec` is allocated here rather than in [`dial`](Self::dial) so
    /// [`connect`](ConnectionTransport::connect), which would only discard it, does not pay for it.
    async fn connect_info(
        &self,
        host: &str,
    ) -> io::Result<(Self::Stream, flint_transport::ConnectionInfo)> {
        let stream = self.dial(host).await?;
        let info = flint_transport::ConnectionInfo {
            alpn: stream.alpn().map(<[u8]>::to_vec),
            // No authority override: proxyless reaches the real destination directly, so the host the
            // caller asked for is the host to address. Unlike a fronted connection there is no decoy.
            authority: None,
        };
        Ok((stream, info))
    }
}

impl ProxylessTransport {
    /// Shared body of [`connect`](ConnectionTransport::connect) and
    /// [`connect_alpn`](ConnectionTransport::connect_alpn): search, or reuse a cached winner.
    ///
    /// The returned stream still carries its negotiated ALPN — reading it is the caller's choice, so
    /// the non-reporting path costs nothing.
    async fn dial(&self, host: &str) -> io::Result<flint_proxyless::AlpnStream> {
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
    fn the_cap_is_a_strict_upper_bound_at_every_size() {
        // The regression this guards: an earlier version kept one resolver but every wire plan, so a cap
        // below the plan count produced *more* candidates than requested — silently defeating the
        // cold-start bound the knob exists to provide.
        let space = Space::new(resolvers(6))
            .with_wire(Default::default())
            .with_wire(Default::default()); // 3 plans → 18 candidates uncapped
        assert_eq!(Space::len(&space), 18);

        for max in 1..=20 {
            let capped = ProxylessTransport::new(space.clone(), "wifi")
                .with_max_candidates(max)
                .search_space();
            assert!(
                capped.len() <= max,
                "cap {max} produced {} candidates",
                capped.len()
            );
            assert!(!capped.is_empty(), "cap {max} left nothing to search");
        }
    }

    #[test]
    fn a_cap_below_the_plan_count_keeps_the_cheapest_plans() {
        // 3 plans, cap of 2: one resolver and the first two plans. Wire-major order puts the no-op plan
        // first, so an aggressive cap keeps the cheap strategies and drops the exotic ones.
        let space = Space::new(resolvers(6))
            .with_wire(Default::default())
            .with_wire(Default::default());
        let capped = ProxylessTransport::new(space, "wifi")
            .with_max_candidates(2)
            .search_space();
        assert_eq!(capped.len(), 2);
        assert_eq!(capped.resolvers.len(), 1);
        assert_eq!(capped.wires.len(), 2);
    }

    #[test]
    fn a_zero_cap_is_treated_as_one_rather_than_disabling_the_search() {
        let space = Space::new(resolvers(4));
        let capped = ProxylessTransport::new(space, "wifi")
            .with_max_candidates(0)
            .search_space();
        assert_eq!(capped.len(), 1, "a cap of 0 must not search nothing");
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
