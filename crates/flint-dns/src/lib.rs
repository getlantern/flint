//! Resilient DNS-over-HTTPS: un-poisoned answers in censored regions.
//!
//! The first `BootstrapDial` consumer. A diverse, signed-updatable resolver pool (spread across
//! providers, ASNs, and jurisdictions) is raced as `(resolver × strategy)` compositions; the first
//! *validated* answer wins and the winning composition is cached per network. Includes a minimal
//! A/AAAA query/response codec to protect the binary budget. See `docs/design.md` §6.
#![forbid(unsafe_code)]

// TODO(extraction step 5): resilient DoH resolver (race -> validate -> cache) + minimal DNS codec.
