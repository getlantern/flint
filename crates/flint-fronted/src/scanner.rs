//! Vantage-point CDN front scanner.
//!
//! Discovers working domain-fronting edges **from the user's own network**, the
//! Shir-o-Khorshid model: a censor can't block Akamai/CloudFront/Aliyun without
//! breaking domestic sites, so their edge IPs stay reachable and the user's own
//! resolver returns truthful, geo-local ones. This is what lets the transport
//! bootstrap with NO server-delivered config — a server front list is only an
//! accelerator.
//!
//! Two stages, mirroring radiance's `fronted/scanner`:
//!   1. **Candidate generation** (this module's pure/DNS parts): Akamai edge
//!      hostnames resolved through the *system* resolver ([`crate::SystemResolver`]),
//!      and CloudFront IPs sampled from an embedded prefix list. Each candidate
//!      carries the SNI to send (empty, or a decoy for Akamai), the inner
//!      `fronted_host` it routes to, and the hostname its cert must verify against.
//!   2. **Probe + rank**: a two-stage check (TLS dial with the candidate's SNI +
//!      cert verification, then an HTTP request expecting 2xx), ranked by latency.
//!      The probe is generic over the dial step so it's testable without network.
//!
//! A discovered [`Front`] feeds straight into [`crate::FrontPool::from`] /
//! [`crate::FrontedTlsDialer`] / the meek polling client.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use flint_dial::CertVerification;

use crate::{Front, FrontEndpoint, FrontResolver};

/// Canonical Akamai edge hostnames. The first is the universal one; the rest are
/// commonly-reachable alternates (also the SNIs `cdn-ip-finder` ships). Resolving
/// these through the system resolver yields geo-local edge IPs.
pub const DEFAULT_AKAMAI_EDGE_HOSTS: &[&str] = &[
    "a248.e.akamai.net",
    "a77.net.akamai.net",
    "ds-aksb.akamaized.net",
];

/// A scan candidate: one edge IP plus how to front through it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub provider: String,
    /// Edge IP + port to dial.
    pub addr: SocketAddr,
    /// SNI to present (empty = omit the SNI extension; Host-routed).
    pub sni: String,
    /// Hostname the edge cert must verify against (never the decoy SNI).
    pub verify_hostname: String,
    /// Inner `Host` the front routes to (the meek endpoint).
    pub fronted_host: String,
}

impl Candidate {
    /// The [`Front`] this candidate represents, for dialing/meek once probed.
    pub fn to_front(&self) -> Front {
        Front {
            provider: self.provider.clone(),
            // The edge's canonical domain (for Akamai the verify hostname, e.g.
            // a248.e.akamai.net) — not the inner fronted_host, which is separate.
            domain: self.verify_hostname.clone(),
            endpoint: FrontEndpoint::Ip(self.addr),
            sni: self.sni.clone(),
            fronted_host: self.fronted_host.clone(),
            verification: CertVerification::Roots {
                roots_pem: std::sync::Arc::from([] as [String; 0]),
                hostname: self.verify_hostname.clone(),
            },
        }
    }
}

/// What to scan for. Defaults cover Akamai (primary) + CloudFront; Aliyun and
/// extra Akamai edge hosts are configurable. Seeds are data-driven so Google/Azure
/// can be added without code changes.
#[derive(Debug, Clone)]
pub struct ScanTargets {
    /// Inner host the fronts must route to (e.g. the meek endpoint).
    pub fronted_host: String,
    /// Akamai edge hostnames to resolve via the system resolver.
    pub akamai_edge_hosts: Vec<String>,
    /// Cert hostname for Akamai candidates (empty SNI ⇒ verify against this).
    pub akamai_verify_hostname: String,
    /// Decoy SNIs to also try per Akamai IP (in addition to empty SNI). Empty =
    /// only the no-SNI variant.
    pub akamai_decoy_snis: Vec<String>,
    /// Sample this many CloudFront IPs from the embedded prefix list (0 = skip).
    pub cloudfront_samples: usize,
    /// Cert hostname CloudFront candidates verify against (empty SNI ⇒ the edge
    /// presents its default cert, NOT one for the inner host). `None` falls back to
    /// `fronted_host`, which only verifies if the meek endpoint's CloudFront
    /// distribution serves a cert valid for it — set this to the edge cert identity
    /// (e.g. a `*.cloudfront.net` name) for a real CloudFront deployment.
    pub cloudfront_verify_hostname: Option<String>,
    /// Sample this many Alibaba Cloud (Aliyun) CDN IPs from the embedded prefix
    /// list (0 = skip).
    pub aliyun_samples: usize,
    /// Cert hostname Aliyun candidates verify against; see
    /// [`Self::cloudfront_verify_hostname`]. `None` falls back to `fronted_host`.
    pub aliyun_verify_hostname: Option<String>,
    /// Aliyun edge hostnames to also resolve via the system resolver (in addition
    /// to prefix sampling; empty = none).
    pub aliyun_edge_hosts: Vec<String>,
    pub port: u16,
}

impl ScanTargets {
    /// Targets for fronting to `fronted_host`, Akamai-primary with the canonical
    /// edge hosts and a modest CloudFront sample.
    pub fn for_host(fronted_host: impl Into<String>) -> Self {
        Self {
            fronted_host: fronted_host.into(),
            akamai_edge_hosts: DEFAULT_AKAMAI_EDGE_HOSTS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            akamai_verify_hostname: "a248.e.akamai.net".into(),
            akamai_decoy_snis: Vec::new(),
            cloudfront_samples: 16,
            cloudfront_verify_hostname: None,
            aliyun_samples: 16,
            aliyun_verify_hostname: None,
            aliyun_edge_hosts: Vec::new(),
            port: 443,
        }
    }
}

/// Resolve Akamai edge hostnames through the system resolver and build one
/// candidate per (IP × SNI-choice). The empty-SNI variant is always included
/// (Host-routed); decoy SNIs are added when configured. IPs are de-duplicated
/// across all edge hostnames.
pub async fn akamai_candidates<R: FrontResolver>(
    resolver: &R,
    targets: &ScanTargets,
) -> Vec<Candidate> {
    let mut ips: BTreeSet<IpAddr> = BTreeSet::new();
    for host in &targets.akamai_edge_hosts {
        if let Ok(resolved) = resolver.resolve(host).await {
            ips.extend(resolved);
        }
    }
    let mut out = Vec::new();
    for ip in ips {
        let addr = SocketAddr::new(ip, targets.port);
        // Empty SNI first (no SNI extension), then any decoys.
        let mut snis = vec![String::new()];
        snis.extend(targets.akamai_decoy_snis.iter().cloned());
        for sni in snis {
            out.push(Candidate {
                provider: "akamai".into(),
                addr,
                sni,
                verify_hostname: targets.akamai_verify_hostname.clone(),
                fronted_host: targets.fronted_host.clone(),
            });
        }
    }
    out
}

/// Sample CloudFront edge IPs from the embedded prefix list and build empty-SNI
/// candidates. With empty SNI the edge presents its own default cert, so the
/// verify hostname is `cloudfront_verify_hostname` if set, else `fronted_host`
/// (see that field's docs — `fronted_host` only verifies for a CloudFront meek
/// deployment whose cert covers it).
pub fn cloudfront_candidates(targets: &ScanTargets, seed: u64) -> Vec<Candidate> {
    sample_prefix_candidates(
        "cloudfront",
        cloudfront_prefixes(),
        targets,
        targets.cloudfront_samples,
        targets
            .cloudfront_verify_hostname
            .as_deref()
            .unwrap_or(&targets.fronted_host),
        seed,
    )
}

/// Sample Alibaba Cloud (Aliyun) CDN edge IPs from the embedded prefix list,
/// plus resolve any configured Aliyun edge hostnames via the system resolver.
/// Empty SNI; verify hostname is `aliyun_verify_hostname` if set, else `fronted_host`.
pub async fn aliyun_candidates<R: FrontResolver>(
    resolver: &R,
    targets: &ScanTargets,
    seed: u64,
) -> Vec<Candidate> {
    let verify = targets
        .aliyun_verify_hostname
        .as_deref()
        .unwrap_or(&targets.fronted_host);
    let mut out = sample_prefix_candidates(
        "aliyun",
        aliyun_prefixes(),
        targets,
        targets.aliyun_samples,
        verify,
        seed,
    );
    let mut ips: BTreeSet<IpAddr> = BTreeSet::new();
    for host in &targets.aliyun_edge_hosts {
        if let Ok(resolved) = resolver.resolve(host).await {
            ips.extend(resolved);
        }
    }
    for ip in ips {
        out.push(Candidate {
            provider: "aliyun".into(),
            addr: SocketAddr::new(ip, targets.port),
            sni: String::new(),
            verify_hostname: verify.to_string(),
            fronted_host: targets.fronted_host.clone(),
        });
    }
    out
}

/// Weighted sampling of `samples` IPs from `prefixes` (a /14 is more likely than
/// a /22), building empty-SNI candidates for `provider`, verified against
/// `verify_hostname`. Deterministic for a given seed (seedable for tests).
fn sample_prefix_candidates(
    provider: &str,
    prefixes: &[Prefix],
    targets: &ScanTargets,
    samples: usize,
    verify_hostname: &str,
    seed: u64,
) -> Vec<Candidate> {
    if samples == 0 || prefixes.is_empty() {
        return Vec::new();
    }
    let total_weight: u64 = prefixes.iter().map(|p| 1u64 << (32 - p.bits)).sum();
    if total_weight == 0 {
        return Vec::new();
    }
    let mut rng = SplitMix64::new(seed);
    let mut seen: BTreeSet<Ipv4Addr> = BTreeSet::new();
    let mut out = Vec::new();
    // Cap attempts so a small list with many requested samples still terminates.
    let max_attempts = samples.saturating_mul(8).max(64);
    for _ in 0..max_attempts {
        if out.len() >= samples {
            break;
        }
        let pick = rng.next_u64() % total_weight;
        let mut acc = 0u64;
        let prefix = prefixes
            .iter()
            .find(|p| {
                acc += 1u64 << (32 - p.bits);
                pick < acc
            })
            .copied()
            .unwrap_or(prefixes[0]);
        let span = 1u32 << (32 - prefix.bits);
        // Avoid network/broadcast at the very edges for larger blocks.
        let host = if span > 2 {
            1 + (rng.next_u64() as u32 % (span - 2))
        } else {
            rng.next_u64() as u32 % span
        };
        let ip = Ipv4Addr::from(prefix.base + host);
        if !seen.insert(ip) {
            continue;
        }
        out.push(Candidate {
            provider: provider.to_string(),
            addr: SocketAddr::new(IpAddr::V4(ip), targets.port),
            sni: String::new(),
            verify_hostname: verify_hostname.to_string(),
            fronted_host: targets.fronted_host.clone(),
        });
    }
    out
}

/// All candidates for the targets, from every enabled source (Akamai local-DNS,
/// CloudFront prefix sampling, Aliyun prefix sampling + hostnames). The Aliyun
/// sampler is offset off the same seed so it doesn't mirror CloudFront's picks.
pub async fn all_candidates<R: FrontResolver>(
    resolver: &R,
    targets: &ScanTargets,
    seed: u64,
) -> Vec<Candidate> {
    let mut out = akamai_candidates(resolver, targets).await;
    out.extend(cloudfront_candidates(targets, seed));
    out.extend(aliyun_candidates(resolver, targets, seed ^ 0xA11BABA).await);
    out
}

/// A probed, working front and how long the probe took (for ranking).
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub candidate: Candidate,
    pub latency: Duration,
}

/// Probe every candidate with `probe` (TLS dial + HTTP 2xx, timed), keep the ones
/// that succeed, and return them **ranked by latency** (fastest first). `probe`
/// returns the measured latency on success. Concurrency is bounded by `window`.
///
/// The probe is injected so this is testable without boring/network; production
/// passes a closure that dials the candidate's [`Front`] and issues an HTTP probe.
pub async fn scan<P, Fut>(candidates: Vec<Candidate>, window: usize, probe: P) -> Vec<ScanResult>
where
    P: Fn(Candidate) -> Fut,
    Fut: std::future::Future<Output = Option<Duration>> + 'static,
{
    use futures::stream::{FuturesUnordered, StreamExt};
    use std::pin::Pin;
    type Probed = Pin<Box<dyn std::future::Future<Output = (Candidate, Option<Duration>)>>>;
    let window = window.max(1);
    let mut results = Vec::new();
    let mut iter = candidates.into_iter();
    let mut inflight: FuturesUnordered<Probed> = FuturesUnordered::new();
    let spawn = |c: Candidate| -> Probed {
        let fut = probe(c.clone());
        Box::pin(async move { (c, fut.await) })
    };
    for c in iter.by_ref().take(window) {
        inflight.push(spawn(c));
    }
    while let Some((candidate, outcome)) = inflight.next().await {
        if let Some(latency) = outcome {
            results.push(ScanResult { candidate, latency });
        }
        if let Some(c) = iter.next() {
            inflight.push(spawn(c));
        }
    }
    results.sort_by_key(|r| r.latency);
    results
}

// ---- internals: embedded CloudFront prefixes + a small deterministic RNG ----

#[derive(Debug, Clone, Copy)]
struct Prefix {
    base: u32,
    bits: u8,
}

/// A small, representative slice of AWS CloudFront IPv4 ranges. Enough to bootstrap
/// without a server list; expand from the AWS published prefix list as needed.
fn cloudfront_prefixes() -> &'static [Prefix] {
    // base = u32 of the network address; bits = prefix length.
    const P: &[Prefix] = &[
        Prefix {
            base: u32::from_be_bytes([13, 32, 0, 0]),
            bits: 15,
        },
        Prefix {
            base: u32::from_be_bytes([13, 224, 0, 0]),
            bits: 14,
        },
        Prefix {
            base: u32::from_be_bytes([52, 84, 0, 0]),
            bits: 15,
        },
        Prefix {
            base: u32::from_be_bytes([52, 222, 0, 0]),
            bits: 15,
        },
        Prefix {
            base: u32::from_be_bytes([54, 182, 0, 0]),
            bits: 16,
        },
        Prefix {
            base: u32::from_be_bytes([54, 192, 0, 0]),
            bits: 16,
        },
        Prefix {
            base: u32::from_be_bytes([54, 230, 0, 0]),
            bits: 16,
        },
        Prefix {
            base: u32::from_be_bytes([54, 239, 128, 0]),
            bits: 18,
        },
        Prefix {
            base: u32::from_be_bytes([99, 84, 0, 0]),
            bits: 16,
        },
        Prefix {
            base: u32::from_be_bytes([143, 204, 0, 0]),
            bits: 16,
        },
        Prefix {
            base: u32::from_be_bytes([205, 251, 192, 0]),
            bits: 19,
        },
    ];
    P
}

/// A representative slice of Alibaba Cloud (Aliyun) **international** ranges that
/// front Alibaba CDN/DCDN edges — the ones reachable from outside CN. Enough to
/// bootstrap without a server list; refine from Alibaba's published prefix list
/// (the `47.235.0.0`–`47.254.0.0` and `8.208.0.0/13` international blocks are the
/// CDN-bearing ones) as needed.
fn aliyun_prefixes() -> &'static [Prefix] {
    const P: &[Prefix] = &[
        Prefix {
            base: u32::from_be_bytes([8, 208, 0, 0]),
            bits: 13,
        },
        Prefix {
            base: u32::from_be_bytes([47, 52, 0, 0]),
            bits: 14,
        },
        Prefix {
            base: u32::from_be_bytes([47, 74, 0, 0]),
            bits: 15,
        },
        Prefix {
            base: u32::from_be_bytes([47, 88, 0, 0]),
            bits: 14,
        },
        Prefix {
            base: u32::from_be_bytes([47, 235, 0, 0]),
            bits: 16,
        },
        Prefix {
            base: u32::from_be_bytes([47, 236, 0, 0]),
            bits: 14,
        },
        Prefix {
            base: u32::from_be_bytes([47, 240, 0, 0]),
            bits: 14,
        },
        Prefix {
            base: u32::from_be_bytes([47, 244, 0, 0]),
            bits: 15,
        },
        Prefix {
            base: u32::from_be_bytes([47, 246, 0, 0]),
            bits: 16,
        },
        Prefix {
            base: u32::from_be_bytes([47, 250, 0, 0]),
            bits: 15,
        },
        Prefix {
            base: u32::from_be_bytes([47, 254, 0, 0]),
            bits: 16,
        },
        Prefix {
            base: u32::from_be_bytes([106, 11, 0, 0]),
            bits: 16,
        },
    ];
    P
}

/// SplitMix64 — a tiny, dependency-free deterministic PRNG for sampling. Not for
/// crypto; only to spread sample picks across prefixes reproducibly (seedable for
/// tests).
struct SplitMix64(u64);

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self(seed)
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::collections::HashMap;

    struct MockResolver(HashMap<String, Vec<IpAddr>>);

    #[async_trait]
    impl FrontResolver for MockResolver {
        async fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>> {
            self.0
                .get(host)
                .cloned()
                .ok_or_else(|| std::io::Error::other("no record"))
        }
    }

    #[tokio::test]
    async fn akamai_candidates_dedup_ips_and_apply_sni_strategy() {
        let mut map = HashMap::new();
        map.insert(
            "a248.e.akamai.net".to_string(),
            vec![IpAddr::from([23, 1, 1, 1]), IpAddr::from([23, 1, 1, 2])],
        );
        // Overlapping IP across a second edge host must be de-duplicated.
        map.insert(
            "a77.net.akamai.net".to_string(),
            vec![IpAddr::from([23, 1, 1, 2])],
        );
        let resolver = MockResolver(map);

        let mut targets = ScanTargets::for_host("meek.dsa.akamai.getiantem.org");
        targets.akamai_edge_hosts = vec!["a248.e.akamai.net".into(), "a77.net.akamai.net".into()];
        targets.akamai_decoy_snis = vec!["www.microsoft.com".into()];

        let cands = akamai_candidates(&resolver, &targets).await;
        // 2 unique IPs × (empty SNI + 1 decoy) = 4 candidates.
        assert_eq!(cands.len(), 4);
        // Empty-SNI variant present; cert always verifies against the edge host.
        assert!(cands.iter().any(|c| c.sni.is_empty()));
        assert!(cands
            .iter()
            .all(|c| c.verify_hostname == "a248.e.akamai.net"));
        assert!(cands
            .iter()
            .all(|c| c.fronted_host == "meek.dsa.akamai.getiantem.org"));
        // verify hostname is never the decoy SNI
        assert!(cands
            .iter()
            .all(|c| c.verify_hostname != "www.microsoft.com"));
    }

    #[test]
    fn cloudfront_sampling_is_deterministic_and_in_range() {
        let targets = ScanTargets::for_host("meek.dsa.akamai.getiantem.org");
        let a = cloudfront_candidates(&targets, 42);
        let b = cloudfront_candidates(&targets, 42);
        assert_eq!(a, b, "same seed must reproduce the same sample");
        assert_eq!(a.len(), targets.cloudfront_samples);
        // Every sampled IP must fall inside an embedded prefix.
        for c in &a {
            let ip = match c.addr.ip() {
                IpAddr::V4(v4) => u32::from(v4),
                _ => panic!("cloudfront candidates are v4"),
            };
            assert!(
                cloudfront_prefixes().iter().any(|p| {
                    let mask = !0u32 << (32 - p.bits);
                    (ip & mask) == p.base
                }),
                "sampled IP {} outside all prefixes",
                c.addr.ip()
            );
            assert!(c.sni.is_empty());
        }
    }

    #[test]
    fn aliyun_sampling_is_deterministic_and_in_range() {
        let mut targets = ScanTargets::for_host("meek.dsa.akamai.getiantem.org");
        targets.aliyun_samples = 12;
        let a =
            sample_prefix_candidates("aliyun", aliyun_prefixes(), &targets, 12, "verify.test", 99);
        let b =
            sample_prefix_candidates("aliyun", aliyun_prefixes(), &targets, 12, "verify.test", 99);
        assert_eq!(a, b);
        assert_eq!(a.len(), 12);
        for c in &a {
            assert_eq!(c.provider, "aliyun");
            let ip = match c.addr.ip() {
                IpAddr::V4(v4) => u32::from(v4),
                _ => panic!("v4"),
            };
            assert!(
                aliyun_prefixes().iter().any(|p| {
                    let mask = !0u32 << (32 - p.bits);
                    (ip & mask) == p.base
                }),
                "sampled aliyun IP {} outside all prefixes",
                c.addr.ip()
            );
        }
    }

    #[tokio::test]
    async fn all_candidates_covers_all_three_providers() {
        let mut map = HashMap::new();
        map.insert(
            "a248.e.akamai.net".to_string(),
            vec![IpAddr::from([23, 9, 9, 9])],
        );
        let resolver = MockResolver(map);
        let mut targets = ScanTargets::for_host("meek.dsa.akamai.getiantem.org");
        targets.akamai_edge_hosts = vec!["a248.e.akamai.net".into()];
        let cands = all_candidates(&resolver, &targets, 1234).await;
        let providers: BTreeSet<&str> = cands.iter().map(|c| c.provider.as_str()).collect();
        assert!(providers.contains("akamai"), "missing akamai");
        assert!(providers.contains("cloudfront"), "missing cloudfront");
        assert!(providers.contains("aliyun"), "missing aliyun");
    }

    #[tokio::test]
    async fn scan_keeps_successes_ranked_by_latency() {
        let targets = ScanTargets::for_host("meek.test");
        let cands = cloudfront_candidates(&targets, 7);
        assert!(cands.len() >= 4);
        // Mock probe: fail one provider-less subset, vary latency by last octet.
        let results = scan(cands.clone(), 4, |c| async move {
            let last = match c.addr.ip() {
                IpAddr::V4(v4) => v4.octets()[3],
                _ => 0,
            };
            if last % 3 == 0 {
                None // simulate an unreachable edge
            } else {
                Some(Duration::from_millis(last as u64))
            }
        })
        .await;
        // Sorted ascending by latency.
        for w in results.windows(2) {
            assert!(w[0].latency <= w[1].latency);
        }
        // None of the "failed" ones survive.
        assert!(results.iter().all(|r| match r.candidate.addr.ip() {
            IpAddr::V4(v4) => v4.octets()[3] % 3 != 0,
            _ => true,
        }));
    }
}
