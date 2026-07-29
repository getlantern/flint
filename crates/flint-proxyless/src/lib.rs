//! Proxyless circumvention: reach the **real destination** directly, with no proxy and no exit hop.
//!
//! Ported in spirit from the Outline SDK smart dialer (`x/smart`), whose "proxyless" dialer is a
//! search over `DNS strategy × TLS strategy`. Here those are flint's two existing axes:
//!
//! - the **DNS axis** — a [`Resolver`] ([`flint_dns::Kind`]: DoH, DoT, plaintext TCP/UDP, system),
//!   which decides how an address is learned;
//! - the **shaping axis** — a [`WirePlan`], which decides how the opening handshake looks on the wire
//!   (record fragmentation, segment splitting, inter-segment jitter).
//!
//! A [`Strategy`] is one point in that product; a [`Space`] declares the candidates to search. Since
//! the axes are independent, the space is a genuine cartesian product that [`find`] can enumerate,
//! rather than a hand-written list of combinations.
//!
//! # What makes this sound: the certificate is the oracle
//!
//! A censor can block a connection, and can answer a plaintext DNS query with whatever it likes, but
//! it **cannot produce a valid certificate for the destination**. So the test for "did this strategy
//! actually work" is not "did DNS return something" or "did TCP connect" — it is *did a TLS handshake
//! to the resolved address complete against a verified certificate chain and hostname*. [`probe`]
//! demands exactly that, via [`CertVerification::Roots`].
//!
//! That is what lets the poisonable resolver kinds
//! ([`Kind::Udp`](flint_dns::Kind::Udp)/[`Tcp`](flint_dns::Kind::Tcp)/[`System`](flint_dns::Kind::System))
//! participate here even though [`flint_dns::default_pool`] excludes them: a forged answer cannot
//! survive the handshake, so a poisoned resolver simply loses the race instead of silently winning it.
//! Every dial this crate performs — probe and destination alike — is verified.
//!
//! # What proxyless does not do
//!
//! There is no exit hop: traffic leaves the user's own address for the real destination. This defeats
//! *blocking*, not *observation* — an on-path censor still sees which host is being contacted, it just
//! cannot classify or cut the TLS. It is also useless against IP-level blackholing, where no shaping
//! or resolver choice helps. Treat it as a reachability tool, not an anonymity one, and do not
//! silently substitute it for a proxy path a user believes is carrying their traffic.

#![forbid(unsafe_code)]

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use flint_dial::{BootstrapStrategy, CertVerification};
use flint_dns::TYPE_A;

// Re-exported because they are unavoidable in this crate's own API: a caller cannot build a [`Space`]
// without [`Resolver`] and [`WirePlan`], cannot read a [`Strategy`] without [`DialPolicy`], and cannot
// name what [`dial`] returns without [`BoxedTlsStream`]. Requiring a direct `flint-dns`/`flint-dial`
// dependency just to spell this crate's types would be a papercut.
pub use flint_dial::{BoxedTlsStream, WirePlan};
pub use flint_dns::{DialPolicy, Resolver};

pub mod cache;

pub use cache::StrategyCache;

/// How many candidate strategies are probed concurrently.
///
/// Deliberately small. The product of resolvers and wire plans can run to dozens of candidates, and
/// each probe is a real DNS lookup plus a real TLS handshake — firing all of them at once would be
/// slow, wasteful, and conspicuous on exactly the networks that are watching. [`race_windowed`] keeps
/// this many in flight and refills as each finishes, so the common case (an early candidate works)
/// never touches the tail.
///
/// [`race_windowed`]: flint_dial::race_windowed
const PROBE_WINDOW: usize = 4;

/// The port a probe connects to. Proxyless verification needs a host speaking TLS, and the test
/// domains are ordinary HTTPS sites.
const PROBE_PORT: u16 = 443;

/// Per-attempt deadline on a single candidate.
///
/// Without this a candidate can hang until the OS gives up: [`flint_dial::dial`] does not bound its TCP
/// connect, and a censor's usual move is to **blackhole** rather than refuse, so a filtered address
/// stalls instead of erroring. Under windowing that is worse than slow — a stalled candidate keeps
/// holding its slot, so [`race_windowed`](flint_dial::race_windowed) never refills and the whole search
/// waits on the least responsive candidate. Bounding each attempt frees the slot and turns a blackhole
/// into an ordinary losing candidate.
///
/// Matches `flint-dns`'s per-resolver bound, and is chosen so a capped search fits inside a caller's own
/// timeout. At [`PROBE_WINDOW`] 4, N candidates finish within `ceil(N / 4) × 5s` — but a **stale cache
/// entry adds one more 5s attempt in front of that**, since the cached winner is retried before the
/// search begins. So the worst case a caller must budget for is `5s + ceil(N / 4) × 5s`, which puts a cap
/// of 4 (10s) inside the 15s default of `flint_transport::RaceOptions` and a cap of 8 exactly at it —
/// close enough to be cancelled at the boundary.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);

/// Run `attempt` under [`ATTEMPT_TIMEOUT`], reporting a timeout as an ordinary failure so a stalled
/// candidate loses its race rather than blocking it.
async fn bounded<F, T>(attempt: F) -> io::Result<T>
where
    F: Future<Output = io::Result<T>>,
{
    match tokio::time::timeout(ATTEMPT_TIMEOUT, attempt).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "proxyless candidate attempt timed out",
        )),
    }
}

/// Why a search failed.
#[derive(Debug, thiserror::Error)]
pub enum FindError {
    /// The space had no candidates to try (no resolvers, or no wire plans).
    #[error("the strategy space is empty: {resolvers} resolvers × {wires} wire plans")]
    EmptySpace {
        /// How many resolvers the space declared.
        resolvers: usize,
        /// How many wire plans the space declared.
        wires: usize,
    },
    /// No test domains were supplied, so nothing could be verified. Searching without an oracle would
    /// "succeed" instantly and prove nothing, so it is rejected rather than silently accepted.
    #[error("no test domains supplied: a search with nothing to verify against proves nothing")]
    NoTestDomains,
    /// Every candidate failed to reach every test domain.
    #[error("all {tried} candidate strategies failed to reach the test domains")]
    AllFailed {
        /// How many candidates were tried.
        tried: usize,
    },
}

/// One point in the search space: how to learn an address, and how to shape and trust the handshake.
#[derive(Debug, Clone)]
pub struct Strategy {
    /// The DNS axis — which resolver and protocol to learn the destination address from.
    pub resolver: Resolver,
    /// The shaping axis plus the trust anchors, reusing [`DialPolicy`] so the resolver dial and the
    /// destination dial are shaped and verified the same way from one value.
    pub policy: DialPolicy,
}

/// The declared candidate space: every `resolver × wire` pairing.
///
/// Keep `wires[0]` the cheapest plan (usually a default, no-op [`WirePlan`]). [`Space::strategy`]
/// enumerates **wire-major**: all resolvers against `wires[0]` first, then all against `wires[1]`, and
/// so on. That front-loads "is there any resolver that works with no shaping at all", and only starts
/// paying for shaping once plain dials have been ruled out — the same instinct as the Outline smart
/// dialer resolving DNS before it searches TLS transports.
#[derive(Debug, Clone, Default)]
pub struct Space {
    /// Candidate resolvers (the DNS axis).
    pub resolvers: Vec<Resolver>,
    /// Candidate wire plans (the shaping axis).
    pub wires: Vec<WirePlan>,
    /// PEM trust anchors for every dial this space produces. Empty means the platform default store;
    /// an embedder that bundles its own anchors (as mobile builds must) pins them here. Not an axis —
    /// trust is a deployment fact, not something to search over.
    pub roots: Arc<[String]>,
}

impl Space {
    /// A space over `resolvers` with no shaping — one wire plan, the default no-op.
    pub fn new(resolvers: Vec<Resolver>) -> Self {
        Self {
            resolvers,
            wires: vec![WirePlan::default()],
            roots: Arc::from(Vec::new()),
        }
    }

    /// Pin the PEM trust anchors used by every dial (builder style). Empty means the platform default
    /// store.
    pub fn with_roots(mut self, roots: Arc<[String]>) -> Self {
        self.roots = roots;
        self
    }

    /// Add a wire plan to the shaping axis (builder style).
    pub fn with_wire(mut self, wire: WirePlan) -> Self {
        self.wires.push(wire);
        self
    }

    /// How many candidate strategies the space contains.
    pub fn len(&self) -> usize {
        self.resolvers.len() * self.wires.len()
    }

    /// True when there is nothing to search.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The candidate at `index`, enumerated wire-major (see the type docs), or `None` if out of range.
    pub fn strategy(&self, index: usize) -> Option<Strategy> {
        let n = self.resolvers.len();
        if n == 0 || index >= self.len() {
            return None;
        }
        Some(Strategy {
            resolver: self.resolvers[index % n].clone(),
            policy: DialPolicy {
                wire: self.wires[index / n].clone(),
                roots: self.roots.clone(),
            },
        })
    }

    /// The cacheable [`Entry`](cache::Entry) naming the candidate at `index`, or `None` if out of range.
    pub fn entry_for(&self, index: usize) -> Option<cache::Entry> {
        let n = self.resolvers.len();
        if n == 0 || index >= self.len() {
            return None;
        }
        Some(cache::Entry {
            resolver: self.resolvers[index % n].name.clone(),
            wire: index / n,
        })
    }
}

/// Search `space` for a strategy that reaches **every** domain in `test_domains`, and return the first
/// one that does.
///
/// Requiring all of them, rather than any, is what keeps a fluke out of the result: one domain might be
/// reachable by accident (a stale cache entry, a permissive path) while the network is still hostile to
/// the rest. Candidates are raced with a small bounded window, so a working early candidate
/// short-circuits the remainder.
///
/// Needs the `boring` feature to actually connect; see [`probe`].
pub async fn find(space: &Space, test_domains: &[String]) -> Result<Strategy, FindError> {
    find_with(space, test_domains, |strategy, domain| async move {
        probe(&strategy, &domain).await
    })
    .await
}

/// Like [`find`], but with the verification step injected.
///
/// `probe_one` is given a candidate and one test domain, and returns `Ok(())` only if that candidate
/// genuinely reached that domain. Injecting it keeps the search *logic* — enumeration order, the
/// all-domains requirement, concurrency, failure reporting — testable without a network or a TLS
/// engine, and lets a consumer substitute a different oracle (say, an HTTP fetch that checks body
/// content) without reimplementing the search.
pub async fn find_with<F, Fut>(
    space: &Space,
    test_domains: &[String],
    probe_one: F,
) -> Result<Strategy, FindError>
where
    F: Fn(Strategy, String) -> Fut,
    Fut: Future<Output = io::Result<()>>,
{
    if space.is_empty() {
        return Err(FindError::EmptySpace {
            resolvers: space.resolvers.len(),
            wires: space.wires.len(),
        });
    }
    if test_domains.is_empty() {
        return Err(FindError::NoTestDomains);
    }

    search(space, test_domains, probe_one).await.map(|(_, s)| s)
}

/// The search itself, also yielding the winning candidate's index so a caller can turn it into a
/// [`cache::Entry`].
async fn search<F, Fut>(
    space: &Space,
    test_domains: &[String],
    probe_one: F,
) -> Result<(usize, Strategy), FindError>
where
    F: Fn(Strategy, String) -> Fut,
    Fut: Future<Output = io::Result<()>>,
{
    let total = space.len();
    let probe_one = &probe_one;
    flint_dial::race_windowed(total, PROBE_WINDOW, |i| async move {
        let strategy = space
            .strategy(i)
            .ok_or_else(|| io::Error::other(format!("candidate index {i} out of range")))?;
        probe_all(&strategy, test_domains, probe_one).await?;
        Ok(strategy)
    })
    .await
    .map_err(|_errors| FindError::AllFailed { tried: total })
}

/// Probe `strategy` against every domain, failing at the first one it cannot reach.
async fn probe_all<F, Fut>(
    strategy: &Strategy,
    test_domains: &[String],
    probe_one: &F,
) -> io::Result<()>
where
    F: Fn(Strategy, String) -> Fut,
    Fut: Future<Output = io::Result<()>>,
{
    // Every test domain must pass, so the first failure abandons this candidate immediately rather
    // than paying for the rest.
    for domain in test_domains {
        probe_one(strategy.clone(), domain.clone()).await?;
    }
    Ok(())
}

/// Like [`find`], but consults `cache` for `network` first and records the winner.
///
/// On a hit the cached strategy is **re-verified**, not trusted: a network that worked yesterday may be
/// blocking today, and the whole premise of this crate is that reachability is proven per attempt
/// rather than assumed. If that check fails the entry is forgotten and the full search runs, so a
/// strategy the censor has since caught cannot pin the client to a dead path.
///
/// This is the steady-state fast path: one DNS lookup and one handshake instead of a search.
pub async fn find_cached(
    space: &Space,
    test_domains: &[String],
    cache: &StrategyCache,
    network: &str,
) -> Result<Strategy, FindError> {
    find_cached_with(
        space,
        test_domains,
        cache,
        network,
        |strategy, domain| async move { probe(&strategy, &domain).await },
    )
    .await
}

/// Like [`find_cached`], but with the verification step injected (see [`find_with`]).
pub async fn find_cached_with<F, Fut>(
    space: &Space,
    test_domains: &[String],
    cache: &StrategyCache,
    network: &str,
    probe_one: F,
) -> Result<Strategy, FindError>
where
    F: Fn(Strategy, String) -> Fut,
    Fut: Future<Output = io::Result<()>>,
{
    if space.is_empty() {
        return Err(FindError::EmptySpace {
            resolvers: space.resolvers.len(),
            wires: space.wires.len(),
        });
    }
    if test_domains.is_empty() {
        return Err(FindError::NoTestDomains);
    }

    // Fast path: whatever last worked here, re-proven.
    if let Some(entry) = cache.winner(network) {
        match entry.resolve(space) {
            Some(strategy) if probe_all(&strategy, test_domains, &probe_one).await.is_ok() => {
                return Ok(strategy);
            }
            // Either the entry is stale against this space, or it no longer reaches the test domains.
            // Drop it so the cache self-heals instead of failing here on every call.
            _ => cache.forget(network),
        }
    }

    let (index, strategy) = search(space, test_domains, probe_one).await?;
    if let Some(entry) = space.entry_for(index) {
        cache.record(network, entry);
    }
    Ok(strategy)
}

/// Connect to `host`:`port` by searching for a strategy that reaches it, returning the winning
/// connection **and** the strategy that produced it.
///
/// Unlike [`find`], nothing is probed separately: the connection the caller wanted *is* the proof, so a
/// candidate that succeeds hands back a usable stream instead of being re-dialed afterwards. That halves
/// the handshakes, and the oracle is exactly as strong — the certificate still has to verify against
/// `host`.
///
/// The two entry points answer different questions, and both are worth having:
///
/// - [`find_cached`] asks *"what works on this network?"* against several test domains, so one
///   accidentally-open path cannot vouch for the rest. Use it to characterize a network.
/// - this asks *"just get me to this host"*, where the host is its own sufficient oracle.
///
/// `cache` is consulted first and the winner recorded, with the same discipline as [`find_cached`]: a
/// cached strategy is retried, never trusted, and dropped the moment it fails, so a strategy the censor
/// has since caught cannot pin the client to a dead path.
pub async fn connect_cached(
    space: &Space,
    host: &str,
    port: u16,
    cache: &StrategyCache,
    network: &str,
) -> Result<(Strategy, BoxedTlsStream), FindError> {
    if space.is_empty() {
        return Err(FindError::EmptySpace {
            resolvers: space.resolvers.len(),
            wires: space.wires.len(),
        });
    }

    // Fast path: retry whatever last worked here, bounded so a since-blackholed winner cannot hang the
    // caller. A failure is not fatal — it means this network has changed, so fall through to a fresh
    // search rather than giving up. A timeout counts as a failure for exactly that reason: otherwise the
    // bound would be defeated on the very path that runs most often.
    if let Some(entry) = cache.winner(network) {
        match entry.resolve(space) {
            Some(strategy) => match bounded(dial(&strategy, host, port)).await {
                Ok(stream) => return Ok((strategy, stream)),
                Err(_) => cache.forget(network),
            },
            // The entry no longer names anything in this space (pool updated, shaping list changed).
            None => cache.forget(network),
        }
    }

    let total = space.len();
    let winner = flint_dial::race_windowed(total, PROBE_WINDOW, |i| async move {
        let strategy = space
            .strategy(i)
            .ok_or_else(|| io::Error::other(format!("candidate index {i} out of range")))?;
        let stream = bounded(dial(&strategy, host, port)).await?;
        Ok((i, strategy, stream))
    })
    .await;

    match winner {
        Ok((_raced, (index, strategy, stream))) => {
            if let Some(entry) = space.entry_for(index) {
                cache.record(network, entry);
            }
            Ok((strategy, stream))
        }
        Err(_errors) => Err(FindError::AllFailed { tried: total }),
    }
}

/// Verify that `strategy` reaches `domain`: resolve it through the strategy's resolver, then complete a
/// **certificate-verified** TLS handshake to the resolved address.
///
/// The verification is the whole point — see the crate docs. A censor that poisons the lookup or
/// intercepts the connection cannot present a valid chain for `domain`, so it fails here instead of
/// being mistaken for success. The handshake is torn down immediately; only whether it completed
/// matters.
///
/// Bounded by a per-attempt deadline (5s), so a blackholed candidate loses its race instead of stalling
/// it — a censor is more likely to blackhole than to refuse.
///
/// Requires the `boring` feature; without it [`flint_dial::dial`] reports the engine unsupported.
pub async fn probe(strategy: &Strategy, domain: &str) -> io::Result<()> {
    bounded(async {
        let addr = resolve_first(strategy, domain).await?;
        let _stream = flint_dial::dial(&verified(addr, domain, &strategy.policy)).await?;
        Ok(())
    })
    .await
}

/// Dial `host`:`port` through `strategy` — the payoff once [`find`] has chosen one.
///
/// Resolves through the strategy's resolver and connects with its shaping, verifying the destination
/// certificate against `host`. Returns the established TLS stream for the caller to speak its own
/// protocol over (an HTTP/2 config fetch, say).
pub async fn dial(strategy: &Strategy, host: &str, port: u16) -> io::Result<BoxedTlsStream> {
    let ip = resolve_first(strategy, host).await?.ip();
    flint_dial::dial(&verified(SocketAddr::new(ip, port), host, &strategy.policy)).await
}

/// Resolve `host` through `strategy`'s resolver and return its first address at [`PROBE_PORT`].
async fn resolve_first(strategy: &Strategy, host: &str) -> io::Result<SocketAddr> {
    let addrs =
        flint_dns::resolve_one_with(&strategy.resolver, host, TYPE_A, &strategy.policy).await?;
    let ip = addrs.first().copied().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "resolver {} returned no address for {host}",
                strategy.resolver.name
            ),
        )
    })?;
    Ok(SocketAddr::new(ip, PROBE_PORT))
}

/// A dial strategy to `target` that **verifies** the peer against `hostname`, shaped by `policy.wire`
/// and anchored by `policy.roots`.
///
/// Nothing here is ever unverified — an unauthenticated dial would destroy the oracle this crate is
/// built on — and `flint-dns` now holds its resolver dials to the same standard, so both legs of a
/// proxyless connection are authenticated. Note the two legs verify *different* identities: the
/// resolver leg checks the resolver's SNI, this one checks the destination host.
fn verified(target: SocketAddr, hostname: &str, policy: &DialPolicy) -> BootstrapStrategy {
    BootstrapStrategy::boring_chrome(target, hostname)
        .with_wire(policy.wire.clone())
        .with_verification(CertVerification::Roots {
            roots_pem: policy.roots.clone(),
            hostname: hostname.to_owned(),
        })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use flint_dial::RecordFragment;

    use super::*;

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

    fn shaped() -> WirePlan {
        WirePlan {
            record_fragment: RecordFragment::SniStraddle,
            ..Default::default()
        }
    }

    fn domains(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn space_enumerates_the_full_product_wire_major() {
        let space = Space::new(resolvers(3)).with_wire(shaped());
        assert_eq!(space.len(), 6);

        // Wire-major: all three resolvers against the no-op plan first, then against the shaped one.
        let names: Vec<_> = (0..6)
            .map(|i| {
                let s = space.strategy(i).unwrap();
                (s.resolver.name, s.policy.wire.is_noop())
            })
            .collect();
        assert_eq!(
            names,
            vec![
                ("r0".to_string(), true),
                ("r1".to_string(), true),
                ("r2".to_string(), true),
                ("r0".to_string(), false),
                ("r1".to_string(), false),
                ("r2".to_string(), false),
            ]
        );
        assert!(
            space.strategy(6).is_none(),
            "index past the product is None"
        );
    }

    #[tokio::test]
    async fn find_returns_the_candidate_that_reaches_every_domain() {
        let space = Space::new(resolvers(3)).with_wire(shaped());
        // Only r2-with-shaping works. Anything else fails, so the search must not stop early.
        let found = find_with(
            &space,
            &domains(&["a.test", "b.test"]),
            |s, _d| async move {
                if s.resolver.name == "r2" && !s.policy.wire.is_noop() {
                    Ok(())
                } else {
                    Err(io::Error::other("blocked"))
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(found.resolver.name, "r2");
        assert!(!found.policy.wire.is_noop());
    }

    #[tokio::test]
    async fn a_candidate_must_reach_all_domains_not_just_one() {
        let space = Space::new(resolvers(2));
        // r0 reaches only the first domain — a partial pass must not win.
        let seen = Mutex::new(Vec::new());
        let found = find_with(&space, &domains(&["a.test", "b.test"]), |s, d| {
            seen.lock()
                .unwrap()
                .push((s.resolver.name.clone(), d.clone()));
            async move {
                match (s.resolver.name.as_str(), d.as_str()) {
                    ("r0", "a.test") => Ok(()),
                    ("r0", _) => Err(io::Error::other("blocked")),
                    _ => Ok(()),
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(found.resolver.name, "r1", "the partial pass must lose");
        // r0 was abandoned after its first failure rather than probing further.
        let calls = seen.lock().unwrap().clone();
        assert!(calls.contains(&("r0".to_string(), "a.test".to_string())));
        assert!(calls.contains(&("r0".to_string(), "b.test".to_string())));
    }

    #[tokio::test]
    async fn find_reports_all_failed_when_nothing_works() {
        let space = Space::new(resolvers(3)).with_wire(shaped());
        let err = find_with(&space, &domains(&["a.test"]), |_s, _d| async move {
            Err(io::Error::other("blocked"))
        })
        .await
        .unwrap_err();
        match err {
            FindError::AllFailed { tried } => assert_eq!(tried, 6),
            other => panic!("expected AllFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn find_rejects_an_empty_space_and_an_absent_oracle() {
        let empty = Space::new(Vec::new());
        assert!(matches!(
            find_with(&empty, &domains(&["a.test"]), |_, _| async { Ok(()) }).await,
            Err(FindError::EmptySpace { resolvers: 0, .. })
        ));

        // A search with no test domains would "succeed" against anything, proving nothing.
        let space = Space::new(resolvers(1));
        assert!(matches!(
            find_with(&space, &[], |_, _| async { Ok(()) }).await,
            Err(FindError::NoTestDomains)
        ));
    }

    #[tokio::test]
    async fn probing_is_bounded_by_the_window() {
        // Concurrency must stay capped: a large space should not fire every probe at once.
        let space = Space::new(resolvers(32));
        let in_flight = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        let _ = find_with(&space, &domains(&["a.test"]), |_s, _d| {
            let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(now, Ordering::SeqCst);
            async {
                tokio::task::yield_now().await;
                in_flight.fetch_sub(1, Ordering::SeqCst);
                Err::<(), io::Error>(io::Error::other("blocked"))
            }
        })
        .await;
        let observed = peak.load(Ordering::SeqCst);
        assert!(
            observed <= PROBE_WINDOW,
            "peak in-flight {observed} exceeded the window {PROBE_WINDOW}"
        );
    }

    #[tokio::test]
    async fn a_cache_hit_skips_the_search_but_still_reverifies() {
        let space = Space::new(resolvers(3)).with_wire(shaped());
        let cache = StrategyCache::new();
        cache.record(
            "wifi",
            cache::Entry {
                resolver: "r1".into(),
                wire: 1,
            },
        );

        let probed = Mutex::new(Vec::new());
        let found = find_cached_with(&space, &domains(&["a.test"]), &cache, "wifi", |s, _d| {
            probed.lock().unwrap().push(s.resolver.name.clone());
            async { Ok(()) }
        })
        .await
        .unwrap();

        assert_eq!(found.resolver.name, "r1");
        assert!(!found.policy.wire.is_noop());
        // Exactly one probe: the cached candidate was re-verified, and no search ran.
        assert_eq!(probed.lock().unwrap().clone(), vec!["r1".to_string()]);
    }

    #[tokio::test]
    async fn a_cached_strategy_that_stopped_working_is_dropped_and_researched() {
        let space = Space::new(resolvers(3));
        let cache = StrategyCache::new();
        cache.record(
            "wifi",
            cache::Entry {
                resolver: "r0".into(),
                wire: 0,
            },
        );

        // r0 is now blocked; only r2 works. The stale entry must not pin us to r0.
        let found = find_cached_with(&space, &domains(&["a.test"]), &cache, "wifi", |s, _d| {
            let ok = s.resolver.name == "r2";
            async move {
                if ok {
                    Ok(())
                } else {
                    Err(io::Error::other("blocked"))
                }
            }
        })
        .await
        .unwrap();

        assert_eq!(found.resolver.name, "r2");
        // The cache now points at the new winner rather than the dead one.
        assert_eq!(
            cache.winner("wifi"),
            Some(cache::Entry {
                resolver: "r2".into(),
                wire: 0
            })
        );
    }

    #[tokio::test]
    async fn a_successful_search_records_the_winner_for_next_time() {
        let space = Space::new(resolvers(2)).with_wire(shaped());
        let cache = StrategyCache::new();
        assert_eq!(cache.winner("wifi"), None);

        find_cached_with(&space, &domains(&["a.test"]), &cache, "wifi", |s, _d| {
            // Only the shaped plan on r1 works — index 3 in wire-major order.
            let ok = s.resolver.name == "r1" && !s.policy.wire.is_noop();
            async move {
                if ok {
                    Ok(())
                } else {
                    Err(io::Error::other("blocked"))
                }
            }
        })
        .await
        .unwrap();

        assert_eq!(
            cache.winner("wifi"),
            Some(cache::Entry {
                resolver: "r1".into(),
                wire: 1
            })
        );
    }

    /// The real thing: search a live network and reach live sites. Ignored by default — needs egress
    /// and the `boring` engine.
    #[tokio::test]
    #[ignore = "live: requires network egress and the boring TLS engine"]
    async fn live_find_reaches_real_domains() {
        let space = Space::new(flint_dns::default_pool()).with_wire(shaped());
        let found = find(&space, &domains(&["example.com", "www.wikipedia.org"]))
            .await
            .expect("a strategy should reach both domains from an unfiltered network");
        let stream = dial(&found, "example.com", 443)
            .await
            .expect("the winning strategy should dial the destination");
        drop(stream);
    }
}
