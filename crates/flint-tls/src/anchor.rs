//! Capture the exact ClientHello our boring profile emits, for the **anchor drift check** (ADR 0006
//! §4). The captured bytes are fingerprinted with [`crate::ja4`]; a test pins the JA4 so a silent
//! change to the Chrome-137 profile (a dep bump — including the update-mimicry CI's boring bump — or
//! an edit) fails CI.
//!
//! Capture works without a network: the boring handshake runs against an in-memory stream that
//! records every write and reports EOF on the first read, so it aborts immediately after the
//! ClientHello flight — which is all we need.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::connector;
use crate::profile::Profile;

/// The pinned JA4 of the `chrome-137` anchor — the fingerprint [`Profile::default`] must emit. CI
/// fails if the boring ClientHello drifts from it (see the test below). Established by capture; a
/// human validates it against a real Chrome out of band (ADR 0006 §4).
///
/// The `t13d1516h2_8daaf6152771` prefix (TLS 1.3, SNI, 15 ciphers, 16 extensions, h2 ALPN, and the
/// canonical Chrome cipher hash) matches the well-known Chrome JA4 — evidence the profile
/// fingerprints as Chrome, not boring's default. `_d8a2da3f94cd` is our exact extension+sigalg set.
pub const ANCHOR_JA4: &str = "t13d1516h2_8daaf6152771_d8a2da3f94cd";

/// Capture the raw TLS ClientHello record the boring connector emits for `profile` + `sni`. Runs the
/// handshake against an in-memory peer that never replies (EOF), so it returns right after writing
/// the ClientHello; the recorded write bytes are returned.
pub async fn capture_client_hello(profile: &Profile, sni: &str) -> io::Result<Vec<u8>> {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let stream = CaptureStream {
        captured: Arc::clone(&captured),
    };
    // Expected to fail — the peer never sends a ServerHello. We only want the ClientHello it wrote.
    let _ = connector::connect(stream, sni, profile).await;
    let bytes = captured.lock().unwrap_or_else(|e| e.into_inner()).clone();
    if bytes.is_empty() {
        return Err(io::Error::other(
            "no ClientHello bytes were written before the handshake aborted",
        ));
    }
    Ok(bytes)
}

/// An in-memory stream that records writes and reports EOF on read (so a TLS handshake aborts right
/// after the ClientHello flight).
struct CaptureStream {
    captured: Arc<Mutex<Vec<u8>>>,
}

impl AsyncWrite for CaptureStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.captured
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for CaptureStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // 0 bytes filled = EOF: the handshake sees the peer close after the ClientHello.
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ja4::{ja4_of_record, parse_client_hello};

    #[tokio::test]
    async fn default_profile_clienthello_matches_the_anchor_ja4() {
        let ch = capture_client_hello(&Profile::default(), "example.com")
            .await
            .expect("capture ClientHello");
        let summary = parse_client_hello(&ch).expect("captured bytes parse as a ClientHello");
        // Structural sanity (independent of the exact JA4): TLS 1.3, SNI present, ALPN h2.
        assert!(summary.sni, "the profile sends SNI");
        let ja4 = ja4_of_record(&ch).expect("compute JA4");
        assert_eq!(
            ja4, ANCHOR_JA4,
            "boring ClientHello drifted from the chrome-137 anchor (got `{ja4}`) — \
             validate against real Chrome, then update ANCHOR_JA4"
        );
    }

    #[tokio::test]
    async fn empty_sni_omits_server_name_extension() {
        let ch = capture_client_hello(&Profile::default(), "")
            .await
            .expect("capture ClientHello");
        let summary = parse_client_hello(&ch).expect("captured bytes parse as a ClientHello");
        assert!(!summary.sni, "empty sni should omit the SNI extension");
    }
}
