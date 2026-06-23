//! Layer B (`record_fragment`): re-emit the ClientHello as multiple TLS records.
//!
//! [`RecordFragmentingStream`] wraps a byte stream and shapes only the **opening write** (the TLS
//! ClientHello record): it re-frames that single record's payload into *N* records, each with its own
//! `16 03 01 <len>` header, leaving the inner handshake-message bytes untouched (the peer concatenates
//! record payloads per RFC 8446 §5.1). Because the fragmentation lives in the record structure — above
//! TCP — it survives censor TCP reassembly, defeating DPI that inspects only the first record or does
//! not reassemble a handshake message across records. Transparent for the rest of the connection.
//!
//! Engine-agnostic: neither boring2 nor rustls fragments the ClientHello across records natively, so
//! this shim is the right layer for it, and it composes under either engine. A handful of middleboxes
//! mishandle a fragmented ClientHello — handled operationally by a dialer that only keeps a tactic
//! which raises the success rate.
//!
//! Assumption (as for Layer C): the ClientHello arrives whole in the first `poll_write`. Anything that
//! is not a single TLS handshake record at offset 0 is passed through unshaped.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::sni;
use crate::{RecordFragment, WirePlan};

/// TLS `content_type` for a handshake record.
const HANDSHAKE: u8 = 0x16;
/// TLS record header length: `content_type(1) + legacy_version(2) + length(2)`.
const RECORD_HEADER_LEN: usize = 5;

/// The fragmented opening write, being drained to the inner stream.
struct Pending {
    /// The re-framed bytes (N record headers + payload chunks) to write to the inner stream.
    out: Vec<u8>,
    /// How far `out` has been written.
    off: usize,
    /// The length of the *original* opening write, returned to the caller once `out` is fully drained.
    orig_len: usize,
}

/// Wraps a stream and fragments its opening ClientHello across TLS records per a [`WirePlan`]'s
/// Layer B ([`RecordFragment`]); transparent thereafter.
pub struct RecordFragmentingStream<S> {
    inner: S,
    frag: RecordFragment,
    shaped: bool,
    pending: Option<Pending>,
}

impl<S> RecordFragmentingStream<S> {
    /// Wrap `inner`, fragmenting its first write per `plan`'s Layer B (`record_fragment`).
    pub fn new(inner: S, plan: WirePlan) -> Self {
        Self {
            inner,
            frag: plan.record_fragment,
            shaped: false,
            pending: None,
        }
    }
}

/// Resolve payload-relative cut offsets for the record's `payload` under `frag`. Returns an empty vec
/// when nothing should be fragmented (the caller then passes the write through unshaped).
fn payload_cuts(frag: &RecordFragment, buf: &[u8], payload: &[u8]) -> Vec<usize> {
    match frag {
        RecordFragment::None => Vec::new(),
        RecordFragment::Chunks(n) => {
            let n = *n;
            if n == 0 {
                return Vec::new();
            }
            let mut cuts = Vec::new();
            let mut at = n;
            while at < payload.len() {
                cuts.push(at);
                at += n;
            }
            cuts
        }
        // `ranges` sorts, dedups, and clamps to `(0, payload_len)`, so an offset == 0 or
        // >= payload_len is dropped and an empty list yields no cut.
        RecordFragment::Offsets(offs) => offs.clone(),
        RecordFragment::SniStraddle => match sni::sni_host_range(buf) {
            // `off` is absolute in `buf`; the payload starts at RECORD_HEADER_LEN, so the host's
            // payload-relative midpoint is `(off - RECORD_HEADER_LEN) + len/2`. Cut there so the host
            // value straddles the two records.
            Some((off, len)) if len >= 2 && off >= RECORD_HEADER_LEN => {
                vec![(off - RECORD_HEADER_LEN) + len / 2]
            }
            _ => Vec::new(),
        },
    }
}

/// Turn payload-relative cut offsets into ordered, in-bounds `[start, end)` ranges over `total` bytes.
fn ranges(mut cuts: Vec<usize>, total: usize) -> Vec<(usize, usize)> {
    cuts.retain(|&c| c > 0 && c < total);
    cuts.sort_unstable();
    cuts.dedup();
    let mut out = Vec::with_capacity(cuts.len() + 1);
    let mut prev = 0;
    for c in cuts {
        out.push((prev, c));
        prev = c;
    }
    out.push((prev, total));
    out
}

/// Re-frame `buf` (expected to be a single TLS handshake record) into multiple records per `frag`.
/// Returns `None` to pass `buf` through unshaped: when `buf` is not a single handshake record, or the
/// plan yields fewer than two fragments.
fn build_fragmented(frag: &RecordFragment, buf: &[u8]) -> Option<Vec<u8>> {
    if buf.len() < RECORD_HEADER_LEN || buf[0] != HANDSHAKE {
        return None;
    }
    let record_len = ((buf[3] as usize) << 8) | (buf[4] as usize);
    let payload_end = RECORD_HEADER_LEN + record_len;
    // Require the first write to be exactly one record (the common case for a CH writer). Anything
    // else (short, or trailing bytes past the record) is passed through rather than mis-parsed.
    if payload_end != buf.len() {
        return None;
    }
    let version = [buf[1], buf[2]];
    let payload = &buf[RECORD_HEADER_LEN..payload_end];

    let segs = ranges(payload_cuts(frag, buf, payload), payload.len());
    if segs.len() < 2 {
        return None;
    }

    let mut out = Vec::with_capacity(buf.len() + (segs.len() - 1) * RECORD_HEADER_LEN);
    for (start, end) in segs {
        let chunk = &payload[start..end];
        out.push(HANDSHAKE);
        out.extend_from_slice(&version);
        out.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        out.extend_from_slice(chunk);
    }
    Some(out)
}

impl<S: AsyncWrite + Unpin> AsyncWrite for RecordFragmentingStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        let RecordFragmentingStream {
            inner,
            frag,
            shaped,
            pending,
        } = me;

        if *shaped {
            return Pin::new(inner).poll_write(cx, buf);
        }
        if pending.is_none() {
            match build_fragmented(frag, buf) {
                Some(out) => {
                    *pending = Some(Pending {
                        out,
                        off: 0,
                        orig_len: buf.len(),
                    });
                }
                None => {
                    // Not fragmentable — pass through and stop shaping.
                    *shaped = true;
                    return Pin::new(inner).poll_write(cx, buf);
                }
            }
        }

        // Drain the re-framed bytes to the inner stream.
        loop {
            let p = pending.as_mut().unwrap();
            if p.off >= p.out.len() {
                let orig_len = p.orig_len;
                *pending = None;
                *shaped = true;
                return Poll::Ready(Ok(orig_len));
            }
            match Pin::new(&mut *inner).poll_write(cx, &p.out[p.off..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(0)) => {
                    *pending = None;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "record fragmenter: inner stream accepted 0 bytes",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    pending.as_mut().unwrap().off += n;
                    continue;
                }
                Poll::Ready(Err(e)) => {
                    *pending = None;
                    return Poll::Ready(Err(e));
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for RecordFragmentingStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sni;
    use crate::{RecordFragment, SegmentSplit, WirePlan};
    use std::sync::{Arc, Mutex};
    use tokio::io::AsyncWriteExt;

    /// A sink that records each `poll_write` as a separate buffer and accepts everything immediately.
    #[derive(Clone, Default)]
    struct Recorder {
        writes: Arc<Mutex<Vec<Vec<u8>>>>,
    }
    impl AsyncWrite for Recorder {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.writes.lock().unwrap().push(buf.to_vec());
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn plan(frag: RecordFragment) -> WirePlan {
        WirePlan {
            segment_split: SegmentSplit::None,
            inter_segment_delay: Default::default(),
            tcp_nodelay: false,
            record_fragment: frag,
        }
    }

    /// Parse a stream of concatenated TLS records into their payloads, asserting each is a well-formed
    /// handshake record and the buffer ends exactly on a record boundary.
    fn record_payloads(mut b: &[u8]) -> Vec<Vec<u8>> {
        let mut payloads = Vec::new();
        while !b.is_empty() {
            assert!(b.len() >= RECORD_HEADER_LEN, "dangling record header");
            assert_eq!(b[0], HANDSHAKE, "fragment is not a handshake record");
            let len = ((b[3] as usize) << 8) | (b[4] as usize);
            assert!(
                b.len() >= RECORD_HEADER_LEN + len,
                "record runs past buffer"
            );
            payloads.push(b[RECORD_HEADER_LEN..RECORD_HEADER_LEN + len].to_vec());
            b = &b[RECORD_HEADER_LEN + len..];
        }
        payloads
    }

    fn flatten(writes: &Arc<Mutex<Vec<Vec<u8>>>>) -> Vec<u8> {
        writes.lock().unwrap().iter().flatten().copied().collect()
    }

    #[tokio::test]
    async fn chunks_fragment_the_clienthello_into_multiple_records() {
        let ch = sni::tests_support::clienthello_with_sni(b"example.com");
        let original_payload = ch[RECORD_HEADER_LEN..].to_vec();

        let rec = Recorder::default();
        let writes = rec.writes.clone();
        let mut s = RecordFragmentingStream::new(rec, plan(RecordFragment::Chunks(16)));
        s.write_all(&ch).await.unwrap();

        let payloads = record_payloads(&flatten(&writes));
        assert!(payloads.len() >= 2, "must produce multiple records");
        for p in &payloads {
            assert!(!p.is_empty() && p.len() <= 16, "chunk size respected");
        }
        // The receiver concatenates record payloads to recover the original handshake message bytes.
        assert_eq!(payloads.concat(), original_payload);
    }

    #[tokio::test]
    async fn sni_straddle_splits_the_hostname_across_two_records() {
        let host = b"example.com";
        let ch = sni::tests_support::clienthello_with_sni(host);
        let (off, len) = sni::sni_host_range(&ch).unwrap();
        let original_payload = ch[RECORD_HEADER_LEN..].to_vec();

        let rec = Recorder::default();
        let writes = rec.writes.clone();
        let mut s = RecordFragmentingStream::new(rec, plan(RecordFragment::SniStraddle));
        s.write_all(&ch).await.unwrap();

        let payloads = record_payloads(&flatten(&writes));
        assert_eq!(
            payloads.len(),
            2,
            "SNI straddle produces exactly two records"
        );
        assert_eq!(payloads.concat(), original_payload, "payload preserved");

        // The cut (payload coordinates) lands strictly inside the host value, so the hostname is split.
        let host_start = off - RECORD_HEADER_LEN;
        let cut = host_start + len / 2;
        assert_eq!(payloads[0].len(), cut);
        assert!(
            host_start < cut && cut < host_start + len,
            "record boundary is inside the hostname"
        );
    }

    #[tokio::test]
    async fn offsets_fragments_the_clienthello_at_given_cuts() {
        // A fake ClientHello record: 16 03 01 <len:2> <payload>. Offsets are into the *payload*.
        let payload = (0..30u8).collect::<Vec<_>>();
        let mut rec = vec![0x16, 0x03, 0x01, 0x00, payload.len() as u8];
        rec.extend_from_slice(&payload);

        let recorder = Recorder::default();
        let writes = recorder.writes.clone();
        let mut s =
            RecordFragmentingStream::new(recorder, plan(RecordFragment::Offsets(vec![10, 20])));
        s.write_all(&rec).await.unwrap();

        let payloads = record_payloads(&flatten(&writes));
        assert_eq!(payloads.len(), 3);
        assert_eq!(payloads.concat(), payload);
        assert_eq!(payloads[0].len(), 10);
        assert_eq!(payloads[1].len(), 10);
        assert_eq!(payloads[2].len(), 10);
    }

    #[tokio::test]
    async fn non_handshake_buffer_passes_through_unchanged() {
        let rec = Recorder::default();
        let writes = rec.writes.clone();
        let mut s = RecordFragmentingStream::new(rec, plan(RecordFragment::Chunks(2)));
        s.write_all(b"not a tls record").await.unwrap();
        assert_eq!(*writes.lock().unwrap(), vec![b"not a tls record".to_vec()]);
    }

    #[tokio::test]
    async fn noop_plan_passes_the_clienthello_through_unchanged() {
        let ch = sni::tests_support::clienthello_with_sni(b"example.com");
        let rec = Recorder::default();
        let writes = rec.writes.clone();
        let mut s = RecordFragmentingStream::new(rec, plan(RecordFragment::None));
        s.write_all(&ch).await.unwrap();
        assert_eq!(*writes.lock().unwrap(), vec![ch]);
    }

    #[tokio::test]
    async fn passthrough_after_the_opening_write() {
        let ch = sni::tests_support::clienthello_with_sni(b"example.com");
        let rec = Recorder::default();
        let writes = rec.writes.clone();
        let mut s = RecordFragmentingStream::new(rec, plan(RecordFragment::Chunks(16)));
        s.write_all(&ch).await.unwrap(); // fragmented into >= 2 records
        s.write_all(b"BULKDATA").await.unwrap(); // passthrough: one write, verbatim

        let w = writes.lock().unwrap();
        assert_eq!(w.last().unwrap(), b"BULKDATA");
        // Everything before the final bulk write reconstructs the original ClientHello payload.
        let framed: Vec<u8> = w[..w.len() - 1].iter().flatten().copied().collect();
        assert_eq!(record_payloads(&framed).concat(), ch[RECORD_HEADER_LEN..]);
    }
}
