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

pub mod codec;
pub mod doh;
pub mod pool;
pub mod validate;

pub use codec::{TYPE_A, TYPE_AAAA};
pub use pool::{default_pool, Resolver};

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

/// Resolve `name`/`qtype` through a single `resolver`: dial it (composable bootstrap dial), run the
/// DoH query, parse, and validate. Returns the validated public addresses, or an `io::Error` (which
/// the smart-dialer funnels into the race's per-resolver failures).
pub async fn resolve_one(resolver: &Resolver, name: &str, qtype: u16) -> io::Result<Vec<IpAddr>> {
    let query = codec::build_query(name, qtype).map_err(io::Error::other)?;
    let stream = flint_dial::dial(&resolver.strategy()).await?;
    let response = doh::query(stream, resolver.host, resolver.path, &query).await?;
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
    match flint_dial::race_with(pool.len(), |i| resolve_one(&pool[i], name, qtype)).await {
        Ok((_winner, addrs)) => Ok(addrs),
        Err(_errors) => Err(ResolveError::AllFailed { tried: pool.len() }),
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "boring")]
    use super::*;

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
