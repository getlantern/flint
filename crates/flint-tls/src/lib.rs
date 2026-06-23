//! Chrome-mimicry TLS for bootstrap dialing: emit a **browser-identical ClientHello** so a dial
//! blends with ordinary browser HTTPS to the same CDN/resolver.
//!
//! Three pure, always-compiled pieces plus a feature-gated connector:
//!
//! - [`gambit`] — the portable, signed **ClientHello genome** (ADR 0006): deltas over a genuine-Chrome
//!   anchor across Layer A (ClientHello content), Layer B (records), and Layer C (the
//!   [`flint_shaping`] wire plan), in a detached-Ed25519 envelope with anti-rollback.
//! - [`profile`] — the boring **executor mapping**: resolve a genome's knobs onto the on/off
//!   connector decisions boring can express ([`Profile`]), surfacing what it can't.
//! - [`ja4`] — FoxIO **JA4** fingerprinting of a raw ClientHello, for anchor/drift control.
//! - [`connector`] *(feature `boring`)* — the boring2 Chrome-137 TLS connector that applies a
//!   [`Profile`]; [`connect`] preserves the no-verify bootstrap carrier behavior, while
//!   [`connect_with`] can verify a peer certificate chain and hostname independently from SNI.
//!   [`anchor`] *(feature `boring`)* captures its ClientHello and pins the JA4.
//!
//! The `boring` feature gates the only part that needs the C/cmake BoringSSL build, so the base build
//! is pure-Rust. Extracted from spark's `core::transport` (`anytls::tls`/`profile`, `gambit`, `ja4`,
//! `anytls::anchor`).
#![cfg_attr(not(feature = "boring"), forbid(unsafe_code))]

pub mod gambit;
pub mod ja4;
pub mod profile;

#[cfg(feature = "boring")]
pub mod anchor;
#[cfg(feature = "boring")]
pub mod connector;

pub use profile::Profile;

/// Certificate verification policy for a TLS connection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum CertVerification {
    /// Do not verify the peer certificate or hostname.
    #[default]
    None,
    /// Verify the peer certificate against the supplied PEM roots, or system roots when empty, and
    /// verify the certificate for `hostname`. The hostname is the identity being verified and is
    /// intentionally separate from ClientHello SNI.
    Roots {
        roots_pem: Vec<String>,
        hostname: String,
    },
}

#[cfg(feature = "boring")]
pub use connector::{configure, connect, connect_with};
