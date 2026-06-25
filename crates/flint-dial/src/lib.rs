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

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

mod engine;
mod race;
mod strategy;

pub use engine::{dial, dial_alpn, dial_over, dial_over_alpn};
pub use flint_tls::CertVerification;
pub use race::{probe_windowed, race, race_windowed, race_with};
pub use strategy::{BootstrapStrategy, TlsEngine};

/// A boxed, type-erased TLS byte stream — the output of a successful dial.
pub type BoxedTlsStream = Box<dyn TlsStream>;

/// Marker for a stream usable as a dial result: async read+write, movable across tasks. Blanket-impl'd
/// over any `AsyncRead + AsyncWrite + Unpin + Send + 'static`.
pub trait TlsStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + ?Sized> TlsStream for T {}

/// A dialed TLS stream that also carries the **ALPN protocol the server
/// negotiated** (e.g. `b"h2"` or `b"http/1.1"`). The boring Chrome engine offers
/// `h2,http/1.1`; the edge picks one, and a consumer (e.g. the meek client) reads
/// it back here to choose its HTTP version per connection rather than guessing.
/// Wraps a [`BoxedTlsStream`] and forwards all I/O to it.
pub struct AlpnStream {
    inner: BoxedTlsStream,
    alpn: Option<Vec<u8>>,
}

impl AlpnStream {
    pub fn new(inner: BoxedTlsStream, alpn: Option<Vec<u8>>) -> Self {
        Self { inner, alpn }
    }

    /// The negotiated ALPN protocol (e.g. `b"h2"`, `b"http/1.1"`), or `None` if
    /// none was negotiated.
    pub fn alpn(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
    }

    /// Drop the ALPN annotation, yielding the underlying stream.
    pub fn into_inner(self) -> BoxedTlsStream {
        self.inner
    }
}

impl AsyncRead for AlpnStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for AlpnStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
