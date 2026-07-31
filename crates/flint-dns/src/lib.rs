//! Resilient DNS: un-poisoned answers in censored regions (design §6).
//!
//! The first [`flint_dial`] consumer. [`resolve`] races a diverse [`pool`] of resolvers, each reached
//! by a composable bootstrap dial (boring Chrome-mimicry TLS), runs a [`codec`]-built A/AAAA query,
//! [`validate`]s the answer (drops poison/bogons), and returns the first resolver that yields a real
//! answer. Because an encrypted transport keeps a censor from *rewriting* an answer in flight — mostly
//! leaving it the blunter option of blocking the connection — "uncensored DNS" largely reduces to
//! "reach *one* resolver", which is exactly what the raced bootstrap dials are for.
//!
//! **Encrypted is not enough on its own, so the dial is also authenticated:** every TLS resolver dial
//! verifies the certificate chain and hostname ([`Resolver::tls_strategy_with`]). Otherwise an on-path
//! attacker could terminate TLS with any certificate and inject answers, and [`validate`] would catch a
//! clumsy sentinel but not a plausible attacker-chosen address. Trust anchors come from
//! [`DialPolicy::roots`] — empty means the platform default store, which on mobile is whatever the
//! embedder pointed `SSL_CERT_FILE` at.
//!
//! **Two independent axes.** A resolver's [`Kind`] picks the DNS protocol and endpoint (DoH, DoT,
//! plaintext TCP/UDP, or the system resolver); a [`WirePlan`] picks how the opening handshake looks on
//! the wire (record fragmentation, segment splitting, inter-segment jitter). [`resolve_one_with`]
//! composes them via [`DialPolicy`], so a DoH lookup can itself be carried over a fragmented, jittered
//! ClientHello — the same shaping vocabulary used for a destination dial, aimed at the DNS dial.
//! Encrypted kinds are the trustworthy ones; the plaintext kinds are poisonable and stay out of
//! [`default_pool`] (see there).
//!
//! Build pieces: [`codec`] (minimal A/AAAA wire codec), [`validate`] (poison rejection), [`pool`]
//! (the diverse resolver set + the [`Kind`] axis), [`doh`] (DoH-over-h2), [`plain`] (DoT/TCP framing +
//! UDP), and [`resolve`] (the smart-dialer). Per-network caching of the winning composition and
//! Ed25519-signed pool updates are follow-ups (design §6).
#![forbid(unsafe_code)]

use std::io;
use std::net::IpAddr;
use std::time::Duration;

use ring::rand::{SecureRandom, SystemRandom};

pub mod cache;
pub mod codec;
pub mod doh;
pub mod plain;
pub mod pool;
pub mod signed;
pub mod validate;

pub use cache::ResolverCache;
pub use codec::{TYPE_A, TYPE_AAAA};
pub use flint_dial::WirePlan;
pub use pool::{default_pool, DialPolicy, Kind, Resolver};
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

/// Whether a resolve error indicts the **resolver** rather than the name.
///
/// `false` means the resolver did its job and the name simply does not resolve — NXDOMAIN, or an
/// answer carrying no usable address. A caller must not read that as reason to distrust the resolver:
/// users mistype hosts and visit dead domains constantly, and discarding a working resolver every time
/// one does would throw away a good strategy for an entirely normal event.
///
/// `true` means the resolver could not be reached, timed out, or answered in a way that cannot be
/// believed (SERVFAIL, a malformed or mismatched response, bogon-only records). Those *are* grounds to
/// stop using it and pick another.
///
/// This distinction is the whole reason the resolve paths map failures onto meaningful
/// [`io::ErrorKind`]s instead of flattening everything to `Other` — without it a caller sees one
/// undifferentiated error and cannot tell a broken network from a typo.
///
/// **[`Kind::System`] is the exception.** `getaddrinfo` reports "no such host" and "the network is
/// down" through the same opaque failure, so a system-resolver error is reported as indicting. That
/// errs toward re-selecting, which is the safe direction: moving off the OS resolver is cheap, and it
/// is the right move whenever the network really has changed.
pub fn indicts_resolver(err: &io::Error) -> bool {
    err.kind() != io::ErrorKind::NotFound
}

/// Map a wire/codec failure onto an [`io::Error`] whose kind carries the distinction
/// [`indicts_resolver`] depends on.
fn codec_err(e: codec::DnsError) -> io::Error {
    let kind = match e {
        // The resolver answered authoritatively: this name has no address. Not its fault.
        codec::DnsError::Rcode(3) => io::ErrorKind::NotFound,
        // A name we could not even encode is our bug, not the resolver's.
        codec::DnsError::BadName => io::ErrorKind::InvalidInput,
        // Everything else — SERVFAIL/REFUSED, truncated, not-a-response, a mismatched transaction ID —
        // is the resolver failing to give a usable answer.
        _ => io::ErrorKind::InvalidData,
    };
    io::Error::new(kind, e)
}

/// Map an answer-validation failure the same way.
fn validate_err(e: validate::ValidateError) -> io::Error {
    let kind = match e {
        // Answered, but with nothing usable — the name, not the resolver.
        validate::ValidateError::Empty => io::ErrorKind::NotFound,
        // Bogons only. The resolver answered and the answer is a lie, which is very much about the
        // resolver (or whoever is speaking for it).
        validate::ValidateError::Poisoned => io::ErrorKind::InvalidData,
    };
    io::Error::new(kind, e)
}

/// Resolve `name`/`qtype` through a single `resolver`: reach it over whatever transport its
/// [`Kind`] names, run the query, parse, and validate. Returns the validated public addresses, or an
/// `io::Error` (which the smart-dialer funnels into the race's per-resolver failures).
///
/// Applies no shaping and trusts the platform default store; see [`resolve_one_with`].
pub async fn resolve_one(resolver: &Resolver, name: &str, qtype: u16) -> io::Result<Vec<IpAddr>> {
    resolve_one_with(resolver, name, qtype, &DialPolicy::default()).await
}

/// Like [`resolve_one`], but under an explicit [`DialPolicy`] — shaping composed onto the dial that
/// reaches the resolver, and the trust anchors used to verify it.
///
/// This is the seam that makes the two axes independent: `resolver` picks *which DNS protocol and
/// endpoint*, `policy.wire` picks *how the opening handshake looks on the wire* (record fragmentation,
/// segment splitting, inter-segment jitter). So a DoH lookup can itself be carried over a fragmented,
/// jittered ClientHello — the same shaping vocabulary applied to a destination dial, pointed at the DNS
/// dial.
///
/// `policy.wire` is ignored for kinds that expose no ClientHello to shape ([`Kind::is_shapeable`]), and
/// `policy.roots` for those that run no TLS at all.
///
/// Transaction IDs: DoH uses ID 0 per RFC 8484 §4.1, since its own framing binds the response. Every
/// other transport draws a random ID and verifies it on return — mandatory for the plaintext kinds,
/// harmless for DoT.
pub async fn resolve_one_with(
    resolver: &Resolver,
    name: &str,
    qtype: u16,
    policy: &DialPolicy,
) -> io::Result<Vec<IpAddr>> {
    let answers = match resolver.kind {
        Kind::Doh => {
            let query = codec::build_query(name, qtype).map_err(codec_err)?;
            let stream = flint_dial::dial(&tls_strategy(resolver, policy)?).await?;
            let response = doh::query(stream, &resolver.host, &resolver.path, &query).await?;
            codec::parse_response(&response).map_err(codec_err)?
        }
        Kind::Dot => {
            let id = random_id()?;
            let query = codec::build_query_with_id(name, qtype, id).map_err(codec_err)?;
            let stream = flint_dial::dial(&tls_strategy(resolver, policy)?).await?;
            let response = plain::query_stream(stream, &query).await?;
            codec::parse_response_with_id(&response, id).map_err(codec_err)?
        }
        Kind::Tcp => {
            let id = random_id()?;
            let query = codec::build_query_with_id(name, qtype, id).map_err(codec_err)?;
            let stream = tokio::net::TcpStream::connect(resolver.target).await?;
            let response = plain::query_stream(stream, &query).await?;
            codec::parse_response_with_id(&response, id).map_err(codec_err)?
        }
        Kind::Udp => {
            let id = random_id()?;
            let query = codec::build_query_with_id(name, qtype, id).map_err(codec_err)?;
            let response = plain::query_udp(resolver.target, &query).await?;
            codec::parse_response_with_id(&response, id).map_err(codec_err)?
        }
        Kind::System => system_lookup(name, qtype).await?,
    };
    validate::validate_answers(answers).map_err(validate_err)
}

/// The TLS strategy for a resolver whose kind is known to be TLS-based.
///
/// The `Doh`/`Dot` match arms have already established that, so `None` here would mean
/// [`Kind::is_shapeable`] and this dispatch disagree — a bug, not a runtime condition. Surfacing it as
/// an error rather than unwrapping keeps that impossible case from becoming a panic.
fn tls_strategy(
    resolver: &Resolver,
    policy: &DialPolicy,
) -> io::Result<flint_dial::BootstrapStrategy> {
    resolver.tls_strategy_with(policy).ok_or_else(|| {
        io::Error::other(format!(
            "resolver {} has kind {:?}, which has no TLS dial strategy",
            resolver.name, resolver.kind
        ))
    })
}

/// A CSPRNG-drawn DNS transaction ID. Uses `ring` like the rest of flint rather than adding an RNG.
fn random_id() -> io::Result<u16> {
    let mut bytes = [0u8; 2];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| io::Error::other("CSPRNG failure drawing a DNS transaction ID"))?;
    Ok(u16::from_be_bytes(bytes))
}

/// Resolve through the OS resolver, keeping only the family `qtype` asked for.
///
/// Worth trying because plenty of networks do not interfere with DNS at all, and it costs no
/// connection of our own. Trust it exactly as much as any plaintext answer: the OS resolver usually
/// speaks unencrypted DNS to a network-provided server, so the result is poisonable.
async fn system_lookup(name: &str, qtype: u16) -> io::Result<Vec<IpAddr>> {
    let addrs = tokio::net::lookup_host((name, 0u16)).await?;
    Ok(addrs
        .map(|addr| addr.ip())
        .filter(|ip| match qtype {
            TYPE_A => ip.is_ipv4(),
            TYPE_AAAA => ip.is_ipv6(),
            // Not a family query — the codec only builds A/AAAA, so this is unreachable in practice.
            _ => true,
        })
        .collect())
}

/// Resolve `name`/`qtype` resiliently: race every resolver in `pool` and return the first that yields
/// a **validated** answer. Slower resolvers are cancelled once one succeeds. Errors only if all fail.
///
/// Uses a default [`DialPolicy`] — no shaping, platform default trust store. See [`resolve_with`] to
/// pin trust anchors or apply shaping.
pub async fn resolve(
    name: &str,
    qtype: u16,
    pool: &[Resolver],
) -> Result<Vec<IpAddr>, ResolveError> {
    resolve_with(name, qtype, pool, &DialPolicy::default()).await
}

/// Like [`resolve`], but under an explicit [`DialPolicy`].
pub async fn resolve_with(
    name: &str,
    qtype: u16,
    pool: &[Resolver],
    policy: &DialPolicy,
) -> Result<Vec<IpAddr>, ResolveError> {
    match flint_dial::race_windowed(pool.len(), DEFAULT_WINDOW, |i| async move {
        match tokio::time::timeout(
            ATTEMPT_TIMEOUT,
            resolve_one_with(&pool[i], name, qtype, policy),
        )
        .await
        {
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
    resolve_cached_with(name, qtype, pool, cache, network, &DialPolicy::default()).await
}

/// Like [`resolve_cached`], but under an explicit [`DialPolicy`].
pub async fn resolve_cached_with(
    name: &str,
    qtype: u16,
    pool: &[Resolver],
    cache: &ResolverCache,
    network: &str,
    policy: &DialPolicy,
) -> Result<Vec<IpAddr>, ResolveError> {
    // Fast path: the resolver that last worked on this network — bounded by the same per-attempt
    // timeout as the pool race, so a now-blackholed/filtered cached winner can't hang here
    // indefinitely. A timeout is treated exactly like a failure: forget the winner and fall through
    // to the full re-race (otherwise ATTEMPT_TIMEOUT would be defeated on the cached path).
    if let Some(winner) = cache.winner(network) {
        if let Some(resolver) = pool.iter().find(|r| r.name == winner) {
            if let Ok(Ok(addrs)) = tokio::time::timeout(
                ATTEMPT_TIMEOUT,
                resolve_one_with(resolver, name, qtype, policy),
            )
            .await
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
        match tokio::time::timeout(
            ATTEMPT_TIMEOUT,
            resolve_one_with(&pool[i], name, qtype, policy),
        )
        .await
        {
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

    #[test]
    fn a_name_that_does_not_resolve_does_not_indict_the_resolver() {
        // The distinction that matters: a user mistyping a host must not cost a working resolver.
        for e in [
            codec_err(codec::DnsError::Rcode(3)),         // NXDOMAIN
            validate_err(validate::ValidateError::Empty), // answered, no usable records
        ] {
            assert_eq!(e.kind(), io::ErrorKind::NotFound, "{e}");
            assert!(!indicts_resolver(&e), "{e} must not blame the resolver");
        }
    }

    #[test]
    fn a_resolver_that_misbehaves_is_indicted() {
        for e in [
            codec_err(codec::DnsError::Rcode(2)), // SERVFAIL
            codec_err(codec::DnsError::Truncated),
            codec_err(codec::DnsError::NotAResponse),
            codec_err(codec::DnsError::IdMismatch { got: 1, want: 2 }),
            // Bogons only: the resolver answered, and the answer is a lie.
            validate_err(validate::ValidateError::Poisoned),
        ] {
            assert!(indicts_resolver(&e), "{e} should blame the resolver");
        }

        // Transport failures are the clearest case of all — they never reach the codec.
        for kind in [io::ErrorKind::TimedOut, io::ErrorKind::ConnectionRefused] {
            assert!(indicts_resolver(&io::Error::new(kind, "unreachable")));
        }
    }

    #[test]
    fn an_unencodable_name_is_our_bug_not_a_resolver_failure() {
        // Still "indicts" (it is not a NotFound), but the kind records who to blame: nothing was ever
        // sent, so no resolver was involved.
        assert_eq!(
            codec_err(codec::DnsError::BadName).kind(),
            io::ErrorKind::InvalidInput
        );
    }

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
