//! System (OS/ISP) DNS resolution for front discovery.
//!
//! The vantage-point front scanner (and Akamai-edge fronting in general) depends
//! on resolving CDN edge hostnames through the **user's own resolver**: a censor
//! returns truthful, geo-local Akamai/CloudFront/Aliyun edge IPs because blocking
//! those CDNs would break domestic banking/government sites. flint's other
//! resolver ([`crate::FlintDnsResolver`]) is DoH-based, which defeats this — it
//! bypasses the local resolver whose answers we specifically want. This resolver
//! uses `getaddrinfo` (the platform stub resolver) via `spawn_blocking` so it
//! sees exactly what the device's network hands back.

use std::io;
use std::net::{IpAddr, ToSocketAddrs};

use async_trait::async_trait;

use std::time::Duration;

use crate::FrontResolver;

/// Cap on a single `getaddrinfo` call. A stuck OS resolver must not hang the whole
/// scan/dial path; on timeout the blocking thread is left to finish on its own
/// (best-effort) and the lookup returns an error so the scan moves on.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// Resolves hostnames through the OS/ISP resolver (`getaddrinfo`). IP literals
/// pass through unchanged.
#[derive(Debug, Clone, Default)]
pub struct SystemResolver;

impl SystemResolver {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl FrontResolver for SystemResolver {
    async fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        // `getaddrinfo` is blocking; keep it off the async runtime. Port 0 is a
        // placeholder — only the resolved IPs are kept.
        let host = host.to_owned();
        let handle = tokio::task::spawn_blocking(move || {
            (host.as_str(), 0u16)
                .to_socket_addrs()
                .map(|it| it.map(|sa| sa.ip()).collect::<Vec<IpAddr>>())
        });
        // Bound the lookup: a hung resolver shouldn't stall the scan. Dropping the
        // handle on timeout detaches the blocking thread (it can't be aborted), so
        // it finishes harmlessly in the background.
        match tokio::time::timeout(RESOLVE_TIMEOUT, handle).await {
            Ok(joined) => joined.map_err(io::Error::other)?,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "system resolver timed out",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolves_an_ip_literal_without_network() {
        let ips = SystemResolver::new().resolve("1.2.3.4").await.unwrap();
        assert_eq!(ips, vec![IpAddr::from([1, 2, 3, 4])]);
    }
}
