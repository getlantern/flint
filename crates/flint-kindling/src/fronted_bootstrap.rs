//! Self-bootstrapping fronted one-shot HTTP — the Kindling entry point for reaching
//! the control-plane API through a CDN edge the censor can't block.
//!
//! Where [`crate::Kindling`] races long-lived byte-stream transports, this is a
//! stateless request/response: scan working fronts from the user's *own* network
//! (Shir-o-Khorshid; no server front list required), race them to a verified-TLS
//! edge, and run a single h2 request through the winner. The winning front is cached
//! so a later request skips the scan. A server-delivered front list, when present,
//! is only an accelerator — the local scan self-heals a fully-blocked list, which is
//! the whole point: a censor can't poison the system resolver's Akamai answers
//! without breaking domestic banking/government sites.

use std::io;
use std::sync::Mutex;

use flint_fronted::scanner::{all_candidates, ScanTargets};
use flint_fronted::{
    dial_fronts_alpn, h2_oneshot, DialOptions, FrontResolver, HttpResponse, MaterializedFront,
    OneshotRequest, SystemResolver,
};
use tokio::sync::OnceCell;

/// A scanned-front one-shot fronted requester for a single inner host (e.g. the
/// config API). The scan is lazy and memoized; the winning front is cached across
/// requests. Generic over the resolver so tests can inject a mock; production uses
/// the system resolver (the load-bearing local-DNS Akamai discovery).
pub struct FrontedBootstrap<R = SystemResolver> {
    /// Inner `Host` the fronts route to, and the h2 `:authority` of each request.
    fronted_host: String,
    resolver: R,
    targets: ScanTargets,
    seed: u64,
    options: DialOptions,
    /// Candidate fronts from the scan, built once on first request.
    fronts: OnceCell<Vec<MaterializedFront>>,
    /// Last front that carried a request — tried alone first to skip the scan.
    cached: Mutex<Option<MaterializedFront>>,
}

impl FrontedBootstrap<SystemResolver> {
    /// Bootstrap to `fronted_host` using the system (ISP) resolver for Akamai edge
    /// discovery — the truthful, geo-local answers a censor can't safely poison.
    pub fn new(fronted_host: impl Into<String>) -> Self {
        Self::with_resolver(fronted_host, SystemResolver::new())
    }
}

impl<R: FrontResolver> FrontedBootstrap<R> {
    pub fn with_resolver(fronted_host: impl Into<String>, resolver: R) -> Self {
        let fronted_host = fronted_host.into();
        let targets = ScanTargets::for_host(fronted_host.clone());
        Self {
            fronted_host,
            resolver,
            targets,
            seed: 0,
            options: DialOptions::default(),
            fronts: OnceCell::new(),
            cached: Mutex::new(None),
        }
    }

    /// Override the scan targets (extra Akamai edge hosts, decoy SNIs, sample counts).
    pub fn with_targets(mut self, targets: ScanTargets) -> Self {
        self.targets = targets;
        self
    }

    /// Seed for the deterministic CloudFront/Aliyun prefix sampling (vary per client
    /// for IP diversity; the Akamai local-DNS path is unaffected).
    pub fn with_seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }

    pub fn with_dial_options(mut self, options: DialOptions) -> Self {
        self.options = options;
        self
    }

    pub fn fronted_host(&self) -> &str {
        &self.fronted_host
    }

    /// Scanned candidate fronts (memoized): Akamai edges resolved through the system
    /// resolver plus CloudFront/Aliyun prefix samples.
    async fn candidate_fronts(&self) -> &[MaterializedFront] {
        self.fronts
            .get_or_init(|| async {
                all_candidates(&self.resolver, &self.targets, self.seed)
                    .await
                    .iter()
                    .map(|c| MaterializedFront {
                        front: c.to_front(),
                        addrs: vec![c.addr],
                    })
                    .collect()
            })
            .await
    }

    /// Front `req` through a scanned edge and return the response. Tries the cached
    /// winning front first; on failure (or none) scans + races all candidates and
    /// caches the winner. `req`'s `Host`/`:authority` is the **winning front's**
    /// `fronted_host` — CDN-specific, since CloudFront/Aliyun route by a different
    /// inner host than Akamai.
    pub async fn request(&self, req: &OneshotRequest) -> io::Result<HttpResponse> {
        let host = self.fronted_host.clone();
        let options = self.options.clone();
        let req = req.clone();
        self.request_with(move |fronts| {
            let host = host.clone();
            let options = options.clone();
            let req = req.clone();
            async move {
                let conn = dial_fronts_alpn(&host, &fronts, options)
                    .await
                    .map_err(io::Error::other)?;
                // Address the request to — and cache — the *winning* front taken
                // straight from the connection: its own inner host (a CloudFront/
                // Aliyun front routes by a different host than Akamai) and the exact
                // addr that won. Don't index back into `fronts` by candidate_index:
                // that indexes the flattened front×addr dial list, not the `fronts`
                // slice, so it can pick the wrong front if a front carries >1 addr.
                let win = MaterializedFront {
                    front: conn.front.clone(),
                    addrs: vec![conn.addr],
                };
                let inner = conn.fronted_host().to_owned();
                let resp = h2_oneshot(conn.stream, &inner, &req).await?;
                Ok((win, resp))
            }
        })
        .await
    }

    /// Orchestration shared by production and tests. `dial` performs the actual
    /// fronted dial + request over a slice of fronts, returning the **winning
    /// front** (to cache) and the response — injectable so the cache/evict logic is
    /// testable without boring/network. The winner is carried out of the dial
    /// rather than indexed back into the slice, so caching can't alias the wrong
    /// front (see `request`).
    async fn request_with<F, Fut>(&self, dial: F) -> io::Result<HttpResponse>
    where
        F: Fn(Vec<MaterializedFront>) -> Fut,
        Fut: std::future::Future<Output = io::Result<(MaterializedFront, HttpResponse)>>,
    {
        self.attempt_with(dial).await
    }

    /// The cached-front-then-rescan orchestration, over whatever a successful attempt produces.
    ///
    /// Generic in the output because two callers need the same front handling for different results:
    /// [`request`](Self::request) yields an [`HttpResponse`], while
    /// [`connect_info`](flint_transport::ConnectionTransport::connect_info) yields a live stream. The
    /// winner is carried out of the attempt rather than indexed back into the slice, so caching cannot
    /// alias the wrong front (see `request`).
    async fn attempt_with<F, Fut, T>(&self, dial: F) -> io::Result<T>
    where
        F: Fn(Vec<MaterializedFront>) -> Fut,
        Fut: std::future::Future<Output = io::Result<(MaterializedFront, T)>>,
    {
        // 1. Reuse the front that worked last time, if any.
        let cached = self.locked_cache().clone();
        if let Some(front) = cached {
            match dial(vec![front.clone()]).await {
                Ok((_, resp)) => return Ok(resp),
                Err(_) => {
                    // Stale edge — drop it and rescan, but only if the cache still points at the
                    // entry we just retried: a concurrent request may have cached a newer winner
                    // while this dial was in flight, and clobbering it would force a needless race.
                    let mut guard = self.locked_cache();
                    if guard.as_ref() == Some(&front) {
                        *guard = None;
                    }
                }
            }
        }
        // 2. Scan once, race the full candidate set, cache the winner.
        let fronts = self.candidate_fronts().await.to_vec();
        if fronts.is_empty() {
            return Err(io::Error::other(
                "fronted bootstrap: scan produced no candidate fronts",
            ));
        }
        let (win, resp) = dial(fronts).await?;
        *self.locked_cache() = Some(win);
        Ok(resp)
    }

    fn locked_cache(&self) -> std::sync::MutexGuard<'_, Option<MaterializedFront>> {
        self.cached.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[async_trait::async_trait]
impl<R> flint_transport::ConnectionTransport for FrontedBootstrap<R>
where
    R: FrontResolver + Send + Sync,
{
    type Stream = flint_fronted::AlpnStream;

    fn name(&self) -> &str {
        "fronted-scan"
    }

    async fn connect(&self, host: &str) -> io::Result<Self::Stream> {
        self.connect_info(host).await.map(|(stream, _)| stream)
    }

    /// Scan (or reuse a cached winner), then hand the raced connection up with the two facts the
    /// winning edge decides: its negotiated ALPN, and the authority a request must carry.
    ///
    /// `host` is ignored: this transport is constructed *for* one inner host, and its whole job is
    /// finding an edge that re-originates to that host. Honouring a different argument would mean
    /// fronting to somewhere the scan never verified.
    ///
    /// **One honest difference from [`request`](Self::request).** There, a cached front is evicted
    /// when the *request* fails, so an edge that connects but does not re-originate gets dropped.
    /// Here the caller performs the request, so success means only that TLS completed — a
    /// non-re-originating edge would stay cached and keep losing at the HTTP layer. Callers that can
    /// tell should call [`forget_cached_front`](Self::forget_cached_front) on a bad response; the
    /// alternative, evicting on every connect, would throw away the caching this exists for.
    async fn connect_info(
        &self,
        host: &str,
    ) -> io::Result<(Self::Stream, flint_transport::ConnectionInfo)> {
        debug_assert!(
            host == self.fronted_host,
            "FrontedBootstrap is built for one inner host; the race asked for a different one"
        );
        let options = self.options.clone();
        let inner = self.fronted_host.clone();
        self.attempt_with(move |fronts| {
            let options = options.clone();
            let inner = inner.clone();
            async move {
                let conn = dial_fronts_alpn(&inner, &fronts, options)
                    .await
                    .map_err(io::Error::other)?;
                // Cache the winner taken straight from the connection — never indexed back into
                // `fronts`, which would alias the wrong front when one carries several addrs.
                let win = MaterializedFront {
                    front: conn.front.clone(),
                    addrs: vec![conn.addr],
                };
                let info = flint_transport::ConnectionInfo {
                    alpn: conn.stream.alpn().map(<[u8]>::to_vec),
                    // Per-provider: Akamai, CloudFront and Aliyun each route by a different inner
                    // host, so the caller cannot know this before the race resolves.
                    authority: Some(conn.fronted_host().to_owned()),
                };
                Ok((win, (conn.stream, info)))
            }
        })
        .await
    }
}

impl<R: FrontResolver> FrontedBootstrap<R> {
    /// Drop the cached winning front so the next attempt rescans.
    ///
    /// For the connection path: a caller that discovers the edge connected but did not front
    /// correctly (a wrong-looking HTTP response) can say so, restoring the eviction that
    /// [`request`](Self::request) gets for free by owning the request itself.
    pub fn forget_cached_front(&self) {
        *self.locked_cache() = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::collections::{BTreeSet, HashMap};
    use std::net::IpAddr;
    use std::sync::Arc;

    struct MockResolver(HashMap<String, Vec<IpAddr>>);

    #[async_trait]
    impl FrontResolver for MockResolver {
        async fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>> {
            self.0
                .get(host)
                .cloned()
                .ok_or_else(|| io::Error::other("no record"))
        }
    }

    type BoxedDialFut = std::pin::Pin<
        Box<dyn std::future::Future<Output = io::Result<(MaterializedFront, HttpResponse)>>>,
    >;

    fn akamai_resolver() -> MockResolver {
        let mut m = HashMap::new();
        m.insert(
            "a248.e.akamai.net".to_string(),
            vec![IpAddr::from([23, 1, 1, 1])],
        );
        MockResolver(m)
    }

    fn resp(status: u16) -> HttpResponse {
        HttpResponse {
            status,
            headers: Vec::new(),
            body: b"ok".to_vec(),
        }
    }

    // Records the front-slice length of every dial so tests can assert "raced the
    // full set" vs "reused the single cached front".
    fn recording_dialer(
        calls: Arc<Mutex<Vec<usize>>>,
        fail_single: bool,
    ) -> impl Fn(Vec<MaterializedFront>) -> BoxedDialFut {
        move |fronts: Vec<MaterializedFront>| {
            let calls = calls.clone();
            Box::pin(async move {
                let n = fronts.len();
                calls.lock().unwrap().push(n);
                if fail_single && n == 1 {
                    Err(io::Error::other("cached front dead"))
                } else {
                    // Return the winning front itself (the first raced) — the
                    // production path likewise carries the winner out of the dial.
                    Ok((fronts[0].clone(), resp(200)))
                }
            })
        }
    }

    /// `attempt_with` is what the connection path reuses, so pin that it is genuinely the same
    /// orchestration: cached front tried alone, evicted on failure, full set raced, winner re-cached.
    /// If `connect_info` ever grew its own copy of this logic, the scanner would quietly stop caching
    /// on the connection path and rescan on every fetch.
    #[tokio::test]
    async fn the_connection_path_shares_the_cache_orchestration() {
        // Same three-provider setup as the sibling cache tests, so "raced the full set" is
        // distinguishable from "reused one cached front".
        let b = FrontedBootstrap::with_resolver("meek.test", akamai_resolver()).with_targets(
            ScanTargets::for_host("meek.test")
                .with_cloudfront_host("meek.cf.test")
                .with_aliyun_host("meek.aliyun.test"),
        );
        let calls = Arc::new(Mutex::new(Vec::new()));

        // A dial that yields a stream-shaped value rather than an HttpResponse, exactly as
        // `connect_info` does — the point is that `attempt_with` does not care which.
        let dial = {
            let calls = calls.clone();
            move |fronts: Vec<MaterializedFront>| {
                let calls = calls.clone();
                Box::pin(async move {
                    calls.lock().unwrap().push(fronts.len());
                    let win = fronts[0].clone();
                    let authority = win.front.fronted_host.clone();
                    Ok((win, authority))
                })
                    as std::pin::Pin<
                        Box<
                            dyn std::future::Future<
                                    Output = io::Result<(MaterializedFront, String)>,
                                > + Send,
                        >,
                    >
            }
        };

        // First attempt scans and caches; second reuses the single cached front.
        let first = b.attempt_with(&dial).await.expect("first attempt");
        let second = b.attempt_with(&dial).await.expect("second attempt");
        assert_eq!(first, second, "same winning front both times");
        let seen = calls.lock().unwrap().clone();
        assert!(
            seen[0] > 1,
            "first attempt races the scanned set, got {seen:?}"
        );
        assert_eq!(
            seen[1], 1,
            "second attempt reuses the cached front, got {seen:?}"
        );

        // And the escape hatch the connection path needs, since it cannot see the HTTP outcome.
        b.forget_cached_front();
        b.attempt_with(&dial).await.expect("third attempt");
        let seen = calls.lock().unwrap().clone();
        assert!(
            seen[2] > 1,
            "forget_cached_front must force a rescan, got {seen:?}"
        );
    }

    #[tokio::test]
    async fn scans_all_three_providers() {
        let b = FrontedBootstrap::with_resolver("meek.test", akamai_resolver()).with_targets(
            ScanTargets::for_host("meek.test")
                .with_cloudfront_host("meek.cf.test")
                .with_aliyun_host("meek.aliyun.test"),
        );
        let fronts = b.candidate_fronts().await;
        let providers: BTreeSet<&str> = fronts.iter().map(|f| f.front.provider.as_str()).collect();
        assert!(providers.contains("akamai"), "missing akamai");
        assert!(providers.contains("cloudfront"), "missing cloudfront");
        assert!(providers.contains("aliyun"), "missing aliyun");
    }

    #[tokio::test]
    async fn caches_winning_front_and_skips_scan_next_time() {
        let b = FrontedBootstrap::with_resolver("meek.test", akamai_resolver()).with_targets(
            ScanTargets::for_host("meek.test")
                .with_cloudfront_host("meek.cf.test")
                .with_aliyun_host("meek.aliyun.test"),
        );
        let calls = Arc::new(Mutex::new(Vec::new()));
        let dialer = recording_dialer(calls.clone(), false);

        assert_eq!(b.request_with(&dialer).await.unwrap().status, 200);
        assert_eq!(b.request_with(&dialer).await.unwrap().status, 200);

        let lens = calls.lock().unwrap().clone();
        assert_eq!(lens.len(), 2);
        assert!(lens[0] > 1, "first call should race the full candidate set");
        assert_eq!(lens[1], 1, "second call should reuse the cached front only");
    }

    #[tokio::test]
    async fn evicts_bad_cached_front_then_falls_back_to_scan() {
        let b = FrontedBootstrap::with_resolver("meek.test", akamai_resolver()).with_targets(
            ScanTargets::for_host("meek.test")
                .with_cloudfront_host("meek.cf.test")
                .with_aliyun_host("meek.aliyun.test"),
        );
        let calls = Arc::new(Mutex::new(Vec::new()));
        let dialer = recording_dialer(calls.clone(), true);

        // 1st: races the full set, caches the winner.
        assert_eq!(b.request_with(&dialer).await.unwrap().status, 200);
        // 2nd: the single cached front fails -> evicted -> full-set race succeeds.
        assert_eq!(b.request_with(&dialer).await.unwrap().status, 200);

        let lens = calls.lock().unwrap().clone();
        assert_eq!(
            lens.len(),
            3,
            "expected full-race, cached retry, then fallback race"
        );
        assert!(lens[0] > 1);
        assert_eq!(lens[1], 1);
        assert!(lens[2] > 1);
        assert!(b.locked_cache().is_some(), "re-cached the working front");
    }
}
