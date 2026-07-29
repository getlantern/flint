//! Per-network caching of the winning proxyless strategy.
//!
//! Searching the whole space costs a DNS lookup plus a TLS handshake per candidate, so doing it on
//! every launch is exactly the kind of repeated, conspicuous traffic pattern worth avoiding. Once a
//! strategy is known to work on the current network, reuse it and only re-search when it stops working.
//!
//! Keyed on a **network fingerprint** the caller supplies, matching
//! [`flint_dns::ResolverCache`] — flint stays platform-agnostic and lets the consumer decide what "the
//! same network" means (gateway IP/MAC, SSID, captive-portal identity, …); a single-network app can
//! pass a constant.
//!
//! What is stored is a `(resolver name, wire index)` pair rather than a [`Strategy`]:
//! both are plain values a caller can persist to disk with any encoding it already uses, and the
//! resolver `name` is stable across pool reordering or a signed pool update. Resolving the pair back
//! into a strategy against the current [`Space`] is [`Entry::resolve`], which returns
//! `None` if the space no longer contains it — so a stale entry self-heals into a re-search instead of
//! a wrong dial.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::{Space, Strategy};

/// A cached winner: which resolver, and which wire plan of the space it was found in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The winning resolver's stable [`name`](flint_dns::Resolver::name).
    pub resolver: String,
    /// The index into the space's `wires` that won.
    pub wire: usize,
}

impl Entry {
    /// Rebuild the [`Strategy`] this entry names against `space`, or `None` if `space` no longer holds
    /// it (the pool was updated, the shaping list changed, …).
    pub fn resolve(&self, space: &Space) -> Option<Strategy> {
        let resolver = space.resolvers.iter().find(|r| r.name == self.resolver)?;
        let wire = space.wires.get(self.wire)?;
        Some(Strategy {
            resolver: resolver.clone(),
            wire: wire.clone(),
        })
    }
}

/// Remembers the winning strategy per network. Cheap to share behind an `Arc` (it is `Send + Sync`).
#[derive(Debug, Default)]
pub struct StrategyCache {
    winners: Mutex<HashMap<String, Entry>>,
}

impl StrategyCache {
    /// An empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// The entry that last succeeded on `network`, if any.
    pub fn winner(&self, network: &str) -> Option<Entry> {
        self.lock().get(network).cloned()
    }

    /// Record `entry` as the winner on `network` (overwrites any previous winner).
    pub fn record(&self, network: &str, entry: Entry) {
        self.lock().insert(network.to_owned(), entry);
    }

    /// Forget the winner for `network` — call this when the cached strategy starts failing, so the next
    /// search does not keep retrying something the network has since blocked.
    pub fn forget(&self, network: &str) {
        self.lock().remove(network);
    }

    /// Every `(network, entry)` pair, for a caller that wants to persist the cache.
    pub fn entries(&self) -> Vec<(String, Entry)> {
        self.lock()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Entry>> {
        // Recover from a poisoned lock rather than panicking — the cache is best-effort.
        self.winners.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use flint_dial::{RecordFragment, WirePlan};
    use flint_dns::Resolver;

    use super::*;

    fn space() -> Space {
        Space::new(vec![
            Resolver::doh(
                "alpha",
                "9.9.9.10:443".parse().unwrap(),
                "dns.example",
                "dns.example",
                "/dns-query",
            ),
            Resolver::udp("beta", "9.9.9.11:53".parse().unwrap()),
        ])
        .with_wire(WirePlan {
            record_fragment: RecordFragment::SniStraddle,
            ..Default::default()
        })
    }

    #[test]
    fn records_and_forgets_per_network() {
        let cache = StrategyCache::new();
        let entry = Entry {
            resolver: "beta".into(),
            wire: 1,
        };
        assert_eq!(cache.winner("wifi-a"), None);

        cache.record("wifi-a", entry.clone());
        assert_eq!(cache.winner("wifi-a"), Some(entry));
        // Networks are independent.
        assert_eq!(cache.winner("wifi-b"), None);

        cache.forget("wifi-a");
        assert_eq!(cache.winner("wifi-a"), None);
    }

    #[test]
    fn an_entry_resolves_back_into_its_strategy() {
        let space = space();
        let strategy = Entry {
            resolver: "beta".into(),
            wire: 1,
        }
        .resolve(&space)
        .expect("beta with wire 1 is in the space");
        assert_eq!(strategy.resolver.name, "beta");
        assert!(!strategy.wire.is_noop(), "wire 1 is the shaped plan");
    }

    #[test]
    fn a_stale_entry_resolves_to_none_rather_than_the_wrong_strategy() {
        let space = space();
        // Resolver dropped from the pool (e.g. a signed pool update removed it).
        assert!(Entry {
            resolver: "gone".into(),
            wire: 0
        }
        .resolve(&space)
        .is_none());
        // Wire index beyond the current shaping list.
        assert!(Entry {
            resolver: "alpha".into(),
            wire: 99
        }
        .resolve(&space)
        .is_none());
    }
}
