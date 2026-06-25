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

use crate::FrontResolver;

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
        let addrs = tokio::task::spawn_blocking(move || {
            (host.as_str(), 0u16)
                .to_socket_addrs()
                .map(|it| it.map(|sa| sa.ip()).collect::<Vec<IpAddr>>())
        })
        .await
        .map_err(io::Error::other)??;
        Ok(addrs)
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
