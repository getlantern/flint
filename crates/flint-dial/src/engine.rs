//! Executing a [`BootstrapStrategy`] into a TLS byte stream.

use std::io;

use flint_shaping::WirePlan;
#[cfg(feature = "boring")]
use flint_shaping::{RecordFragmentingStream, SegmentShapingStream};
use flint_tls::Profile;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::{BootstrapStrategy, BoxedTlsStream, TlsEngine};

/// Execute `strategy`: open a TCP connection to its target, then dial TLS over it ([`dial_over`]).
/// Sets `TCP_NODELAY` when the wire plan asks for it (so each shaped segment leaves as its own packet).
pub async fn dial(strategy: &BootstrapStrategy) -> io::Result<BoxedTlsStream> {
    let tcp = TcpStream::connect(strategy.target).await?;
    if strategy.wire.tcp_nodelay {
        let _ = tcp.set_nodelay(true);
    }
    dial_over(tcp, strategy).await
}

/// Execute `strategy` over an already-connected byte `stream` (the caller controls how the TCP is
/// opened — e.g. spark injecting socket protection, or a test injecting an in-memory pipe). Applies
/// the wire shaping, then runs the strategy's TLS engine.
pub async fn dial_over<S>(stream: S, strategy: &BootstrapStrategy) -> io::Result<BoxedTlsStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    match &strategy.engine {
        TlsEngine::BoringChrome(profile) => {
            dial_boring(stream, &strategy.sni, profile, &strategy.wire).await
        }
        TlsEngine::Rustls => {
            drop(stream);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "flint-dial: the rustls baseline engine is not yet implemented",
            ))
        }
    }
}

/// Wrap `stream` with the opening-handshake shaping per `wire`: record fragmentation (Layer B)
/// outermost over segment shaping (Layer C), so the ClientHello is re-framed into records first and
/// those bytes are then split across TCP segments (see `flint_shaping`).
#[cfg(feature = "boring")]
fn shape<S>(stream: S, wire: &WirePlan) -> RecordFragmentingStream<SegmentShapingStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    RecordFragmentingStream::new(
        SegmentShapingStream::new(stream, wire.clone()),
        wire.clone(),
    )
}

#[cfg(feature = "boring")]
async fn dial_boring<S>(
    stream: S,
    sni: &str,
    profile: &Profile,
    wire: &WirePlan,
) -> io::Result<BoxedTlsStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let tls = flint_tls::connect(shape(stream, wire), sni, profile).await?;
    Ok(Box::new(tls))
}

#[cfg(not(feature = "boring"))]
async fn dial_boring<S>(
    stream: S,
    _sni: &str,
    _profile: &Profile,
    _wire: &WirePlan,
) -> io::Result<BoxedTlsStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    drop(stream);
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "flint-dial: the BoringChrome engine requires the `boring` feature",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // The Ok arm (a boxed TLS stream) isn't `Debug`, so match rather than `unwrap_err`.
    fn assert_unsupported(res: io::Result<BoxedTlsStream>) {
        match res {
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::Unsupported),
            Ok(_) => panic!("expected an Unsupported error"),
        }
    }

    /// Without the `boring` feature, a BoringChrome dial fails cleanly (Unsupported) rather than
    /// silently degrading — and consumes the stream. (With `boring`, this path does a real handshake,
    /// exercised live by flint-dns.)
    #[cfg(not(feature = "boring"))]
    #[tokio::test]
    async fn boring_engine_without_feature_is_unsupported() {
        let (client, _server) = tokio::io::duplex(64);
        let s = BootstrapStrategy::boring_chrome("1.1.1.1:443".parse().unwrap(), "example.com");
        assert_unsupported(dial_over(client, &s).await);
    }

    #[tokio::test]
    async fn rustls_engine_is_unsupported_for_now() {
        let (client, _server) = tokio::io::duplex(64);
        let s = BootstrapStrategy {
            engine: TlsEngine::Rustls,
            ..BootstrapStrategy::boring_chrome("1.1.1.1:443".parse().unwrap(), "example.com")
        };
        assert_unsupported(dial_over(client, &s).await);
    }
}
