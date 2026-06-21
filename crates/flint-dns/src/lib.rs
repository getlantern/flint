//! Resilient DNS-over-HTTPS: un-poisoned answers in censored regions (design §6).
//!
//! The first [`flint_dial`] consumer. [`resolve`] races a diverse [`pool`] of DoH resolvers, each
//! reached by a composable bootstrap dial (boring Chrome-mimicry TLS), runs a [`codec`]-built A/AAAA
//! query over [`doh`] (HTTP/2), [`validate`]s the answer (drops poison/bogons), and returns the first
//! resolver that yields a real answer. Because DoH is encrypted transport, a censor can't poison an
//! answer — only block a connection — so "uncensored DNS" reduces to "reach *one* resolver", which is
//! exactly what the raced bootstrap dials are for.
//!
//! Build pieces: [`codec`] (minimal A/AAAA wire codec), [`validate`] (poison rejection), [`pool`]
//! (the diverse resolver set), [`doh`] (DoH-over-h2), and [`resolve`] (the smart-dialer). Per-network
//! caching of the winning composition and Ed25519-signed pool updates are follow-ups (design §6).
#![forbid(unsafe_code)]

use std::io;
use std::net::IpAddr;
use std::time::Duration;

pub mod cache;
pub mod codec;
pub mod doh;
pub mod pool;
pub mod signed;
pub mod validate;

pub use cache::ResolverCache;
pub use codec::{TYPE_A, TYPE_AAAA};
pub use pool::{default_pool, Resolver};
pub use signed::{load_signed_pool, PoolUpdate};

/// Why a resolution failed.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    /// Every resolver in the pool failed to produce a validated answer.
    #[error("all {tried} resolvers failed to return a validated answer")]
    AllFailed {
        /// How many resolvers were tried.
        tried: usize,
    },
}

/// How many DoH dials race at once inside [`resolve`]. The pool may grow to hundreds of raw resolver
/// IPs (design §3.1); the window caps in-flight attempts regardless of list length. Today's pool fits
/// in one window, so it's effectively all-at-once.
const DEFAULT_WINDOW: usize = 16;

/// Per-resolver attempt deadline. `flint_dial::dial` doesn't bound its TCP connect, so a filtered
/// resolver IP would blackhole the connect and (worse, under windowing) hold its window slot. Bounding
/// each attempt frees the slot so the window refills, and makes the all-fail case return promptly
/// instead of hanging on the slowest resolver.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);

/// Resolve `name`/`qtype` through a single `resolver`: dial it (composable bootstrap dial), run the
/// DoH query, parse, and validate. Returns the validated public addresses, or an `io::Error` (which
/// the smart-dialer funnels into the race's per-resolver failures).
pub async fn resolve_one(resolver: &Resolver, name: &str, qtype: u16) -> io::Result<Vec<IpAddr>> {
    let query = codec::build_query(name, qtype).map_err(io::Error::other)?;
    let stream = flint_dial::dial(&resolver.strategy()).await?;
    let response = doh::query(stream, &resolver.host, &resolver.path, &query).await?;
    let answers = codec::parse_response(&response).map_err(io::Error::other)?;
    validate::validate_answers(answers).map_err(io::Error::other)
}

/// Resolve `name`/`qtype` resiliently: race every resolver in `pool` and return the first that yields
/// a **validated** answer. Slower resolvers are cancelled once one succeeds. Errors only if all fail.
pub async fn resolve(
    name: &str,
    qtype: u16,
    pool: &[Resolver],
) -> Result<Vec<IpAddr>, ResolveError> {
    match flint_dial::race_windowed(pool.len(), DEFAULT_WINDOW, |i| async move {
        match tokio::time::timeout(ATTEMPT_TIMEOUT, resolve_one(&pool[i], name, qtype)).await {
            Ok(result) => result,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "resolver attempt timed out",
            )),
        }
    })
    .await
    {
        Ok((_winner, addrs)) => Ok(addrs),
        Err(_errors) => Err(ResolveError::AllFailed { tried: pool.len() }),
    }
}

/// Like [`resolve`], but caches the winning resolver per network ([`ResolverCache`]). On a cache hit
/// it tries the known-good resolver for `network` first (one shot, no race); on a miss or that
/// resolver failing, it races the full pool and records the new winner. `network` is the caller's
/// network fingerprint (see [`ResolverCache`]). This is the steady-state fast path.
pub async fn resolve_cached(
    name: &str,
    qtype: u16,
    pool: &[Resolver],
    cache: &ResolverCache,
    network: &str,
) -> Result<Vec<IpAddr>, ResolveError> {
    // Fast path: the resolver that last worked on this network — bounded by the same per-attempt
    // timeout as the pool race, so a now-blackholed/filtered cached winner can't hang here
    // indefinitely. A timeout is treated exactly like a failure: forget the winner and fall through
    // to the full re-race (otherwise ATTEMPT_TIMEOUT would be defeated on the cached path).
    if let Some(winner) = cache.winner(network) {
        if let Some(resolver) = pool.iter().find(|r| r.name == winner) {
            if let Ok(Ok(addrs)) =
                tokio::time::timeout(ATTEMPT_TIMEOUT, resolve_one(resolver, name, qtype)).await
            {
                return Ok(addrs);
            }
            // The cached winner failed or timed out — drop it and fall through to a full re-race.
            cache.forget(network);
        } else {
            // The cached winner is no longer in `pool` (pool updated/reordered) — drop the stale
            // entry so the cache self-heals instead of missing the lookup on every call.
            cache.forget(network);
        }
    }
    // Slow path: race the whole pool and remember whoever wins.
    match flint_dial::race_windowed(pool.len(), DEFAULT_WINDOW, |i| async move {
        match tokio::time::timeout(ATTEMPT_TIMEOUT, resolve_one(&pool[i], name, qtype)).await {
            Ok(result) => result,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "resolver attempt timed out",
            )),
        }
    })
    .await
    {
        Ok((winner, addrs)) => {
            cache.record(network, &pool[winner].name);
            Ok(addrs)
        }
        Err(_errors) => Err(ResolveError::AllFailed { tried: pool.len() }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolve_on_an_empty_pool_fails() {
        // No network: an empty pool races nothing → AllFailed{0}. Proves resolve still funnels an
        // all-fail race into ResolveError (now via the windowed, timeout-bounded path).
        let err = resolve("example.com", TYPE_A, &[]).await.unwrap_err();
        assert!(matches!(err, ResolveError::AllFailed { tried: 0 }));
    }

    #[tokio::test]
    async fn resolve_cached_on_an_empty_pool_fails_without_network() {
        // No cached winner + empty pool → race nothing → AllFailed{0}. No network touched.
        let cache = ResolverCache::new();
        let err = resolve_cached("example.com", TYPE_A, &[], &cache, "net-key")
            .await
            .unwrap_err();
        assert!(matches!(err, ResolveError::AllFailed { tried: 0 }));
    }

    /// Live end-to-end resolution through the real default pool. Requires the `boring` feature and
    /// network egress, so it is `#[ignore]`d in CI — run with
    /// `cargo test -p flint-dns --features boring -- --ignored`.
    #[cfg(feature = "boring")]
    #[tokio::test]
    #[ignore = "live: requires network egress to public DoH resolvers"]
    async fn resolves_a_real_name_through_the_pool() {
        let ips = resolve("one.one.one.one", TYPE_A, &default_pool())
            .await
            .expect("resolve via the pool");
        assert!(!ips.is_empty());
        assert!(ips.iter().all(|ip| !validate::is_bogon(*ip)));
    }
}
