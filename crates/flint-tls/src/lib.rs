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
//!   [`Profile`]; [`anchor`] *(feature `boring`)* captures its ClientHello and pins the JA4.
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

#[cfg(feature = "boring")]
pub use connector::{configure, connect};
