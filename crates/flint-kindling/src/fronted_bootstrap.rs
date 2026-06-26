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
    /// caches the winner. `req`'s `Host`/`:authority` is taken from `fronted_host`.
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
                let idx = conn.candidate_index;
                let resp = h2_oneshot(conn.stream, &host, &req).await?;
                Ok((idx, resp))
            }
        })
        .await
    }

    /// Orchestration shared by production and tests. `dial` performs the actual
    /// fronted dial + request over a slice of fronts, returning the winning index
    /// (into that slice) and the response — injectable so the cache/evict logic is
    /// testable without boring/network.
    async fn request_with<F, Fut>(&self, dial: F) -> io::Result<HttpResponse>
    where
        F: Fn(Vec<MaterializedFront>) -> Fut,
        Fut: std::future::Future<Output = io::Result<(usize, HttpResponse)>>,
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
        let (idx, resp) = dial(fronts.clone()).await?;
        if let Some(win) = fronts.get(idx) {
            *self.locked_cache() = Some(win.clone());
        }
        Ok(resp)
    }

    fn locked_cache(&self) -> std::sync::MutexGuard<'_, Option<MaterializedFront>> {
        self.cached.lock().unwrap_or_else(|e| e.into_inner())
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

    type BoxedDialFut =
        std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<(usize, HttpResponse)>>>>;

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
                    Ok((0usize, resp(200)))
                }
            })
        }
    }

    #[tokio::test]
    async fn scans_all_three_providers() {
        let b = FrontedBootstrap::with_resolver("meek.test", akamai_resolver());
        let fronts = b.candidate_fronts().await;
        let providers: BTreeSet<&str> = fronts.iter().map(|f| f.front.provider.as_str()).collect();
        assert!(providers.contains("akamai"), "missing akamai");
        assert!(providers.contains("cloudfront"), "missing cloudfront");
        assert!(providers.contains("aliyun"), "missing aliyun");
    }

    #[tokio::test]
    async fn caches_winning_front_and_skips_scan_next_time() {
        let b = FrontedBootstrap::with_resolver("meek.test", akamai_resolver());
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
        let b = FrontedBootstrap::with_resolver("meek.test", akamai_resolver());
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
