//! Per-network caching of the winning resolver (design §6).
//!
//! Racing the whole pool on every lookup is wasteful once one resolver is known to work on the
//! current network, so [`resolve_cached`](crate::resolve_cached) tries the cached winner first and
//! only re-races on a miss/failure. The cache is keyed on a **network fingerprint** the *caller*
//! supplies — flint stays platform-agnostic and lets the consumer decide what "the same network"
//! means (gateway IP/MAC, SSID, captive-portal identity, …); a single-network app can pass a constant.

use std::collections::HashMap;
use std::sync::Mutex;

/// Remembers which resolver last succeeded on each network. Cheap to share behind an `Arc` (it is
/// `Send + Sync`); resolution is one shot in steady state once a winner is cached.
#[derive(Debug, Default)]
pub struct ResolverCache {
    // network fingerprint -> winning resolver `name`. We store the stable name (not an index) so the
    // cache survives pool reordering / signed updates.
    winners: Mutex<HashMap<String, String>>,
}

impl ResolverCache {
    /// An empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// The resolver `name` that last succeeded on `network`, if any.
    pub fn winner(&self, network: &str) -> Option<String> {
        self.lock().get(network).cloned()
    }

    /// Record `resolver` as the winner on `network` (overwrites any previous winner).
    pub fn record(&self, network: &str, resolver: &str) {
        self.lock().insert(network.to_owned(), resolver.to_owned());
    }

    /// Forget the winner for `network` (e.g. after it starts failing), so the next lookup re-races.
    pub fn forget(&self, network: &str) {
        self.lock().remove(network);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, String>> {
        // Recover from a poisoned lock rather than panicking — the cache is best-effort.
        self.winners.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remembers_and_overwrites_per_network() {
        let cache = ResolverCache::new();
        assert_eq!(cache.winner("net-a"), None);

        cache.record("net-a", "cloudflare-edge");
        cache.record("net-b", "quad9");
        assert_eq!(cache.winner("net-a").as_deref(), Some("cloudflare-edge"));
        assert_eq!(cache.winner("net-b").as_deref(), Some("quad9"));

        // A new winner on the same network replaces the old one.
        cache.record("net-a", "mullvad");
        assert_eq!(cache.winner("net-a").as_deref(), Some("mullvad"));

        cache.forget("net-a");
        assert_eq!(cache.winner("net-a"), None);
        assert_eq!(cache.winner("net-b").as_deref(), Some("quad9")); // unaffected
    }
}
