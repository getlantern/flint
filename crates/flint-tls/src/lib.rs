//! Chrome-mimicry TLS: a browser-identical ClientHello so a bootstrap dial blends with ordinary
//! browser HTTPS to the same CDN/resolver.
//!
//! Homes spark's `core::transport::anytls::tls::configure` + `profile::Profile` (the boring2
//! Chrome-137 connector, JA4 == real Chrome), the `gambit` ClientHello genome (`ClientHello`,
//! `Records`), and `ja4` computation. The boring engine is **feature-gated** (`boring`) so the
//! default build stays rustls/ring-only. See `docs/extraction-plan.md` step 3.

// TODO(extraction step 3): move the Chrome-CH connector, gambit, and ja4 here from spark.
