//! The composable `BootstrapDial` engine (design §4).
//!
//! A bootstrap TLS connection is **data, not code**: a [`BootstrapStrategy`] is a tuple over
//! independent, swappable axes — `endpoint × TLS-engine + ClientHello-profile × SNI × wire-shaping` —
//! that this engine *executes* into a TLS byte stream. A consumer ([`flint-dns`], domain fronting, a
//! signed cloud-blob fetch, …) then runs its protocol over that stream.
//!
//! - [`BootstrapStrategy`] / [`TlsEngine`] — the composition model (`strategy`).
//! - [`dial`] / [`dial_over`] — execute one strategy: wire-shape the opening handshake
//!   ([`flint_shaping`]) then run the chosen TLS engine. The **boring Chrome** engine (feature
//!   `boring`, reusing [`flint_tls`]) is the default for DNS-over-TLS; the rustls baseline is a
//!   documented follow-up.
//! - [`race`] / [`race_with`] — happy-eyeballs: race a set of strategies, first success wins.
//!
//! Capability gating ("two competing compositions" — boring Chrome-JA4 vs rustls real-ECH) is
//! expressed by the engine choice: a strategy whose engine isn't realizable in this build dials to an
//! explicit `Unsupported` error rather than silently degrading.
#![forbid(unsafe_code)]

use tokio::io::{AsyncRead, AsyncWrite};

mod engine;
mod race;
mod strategy;

pub use engine::{dial, dial_over};
pub use race::{probe_windowed, race, race_windowed, race_with};
pub use strategy::{BootstrapStrategy, TlsEngine};

/// A boxed, type-erased TLS byte stream — the output of a successful dial.
pub type BoxedTlsStream = Box<dyn TlsStream>;

/// Marker for a stream usable as a dial result: async read+write, movable across tasks. Blanket-impl'd
/// over any `AsyncRead + AsyncWrite + Unpin + Send + 'static`.
pub trait TlsStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + ?Sized> TlsStream for T {}
