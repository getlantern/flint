//! Layer C (`tcp_split`): split the opening write into separate, flushed TCP segments.
//!
//! [`SegmentShapingStream`] wraps a byte stream and shapes only the **opening write** (the TLS
//! ClientHello): it splits that write into separate, flushed TCP segments — optionally at the **SNI
//! boundary** so the hostname straddles a segment edge, defeating SNI-keyword DPI — with an optional
//! inter-segment delay. Once the opening write is shaped, it is a zero-overhead passthrough for the
//! rest of the connection (the bulk path is untouched).
//!
//! Assumption: the ClientHello arrives in the first `poll_write` (true for the boring/`uTLS` writers
//! we wrap). A ClientHello split across multiple writes is shaped only on its first write — a v1
//! limitation, not a correctness issue.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use ring::rand::{SecureRandom, SystemRandom};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{sleep, Sleep};

use crate::sni;
use crate::{DelaySpec, SegmentSplit, WirePlan};

/// An in-progress segmentation of the opening write.
struct Pending {
    data: Vec<u8>,
    segs: Vec<(usize, usize)>,
    seg: usize,
    off: usize,
    delay: Option<Pin<Box<Sleep>>>,
}

/// Wraps a stream and shapes its opening write per a [`WirePlan`]'s Layer C; transparent thereafter.
pub struct SegmentShapingStream<S> {
    inner: S,
    plan: WirePlan,
    shaped: bool,
    pending: Option<Pending>,
    rng: SystemRandom,
}

impl<S> SegmentShapingStream<S> {
    /// Wrap `inner`, shaping its first write per `plan`'s Layer C (`segment_split` / delay).
    pub fn new(inner: S, plan: WirePlan) -> Self {
        Self {
            inner,
            plan,
            shaped: false,
            pending: None,
            rng: SystemRandom::new(),
        }
    }
}

/// Resolve the split points within the opening write `buf`.
fn cuts_for(split: &SegmentSplit, buf: &[u8]) -> Vec<usize> {
    match split {
        SegmentSplit::None => Vec::new(),
        SegmentSplit::SniBoundary => match sni::sni_host_range(buf) {
            // Split mid-hostname so the SNI value spans two segments.
            Some((off, len)) if len >= 2 => vec![off + len / 2],
            _ => Vec::new(),
        },
        SegmentSplit::Explicit(offs) => offs.clone(),
    }
}

/// Turn split offsets into ordered, in-bounds `[start, end)` segment ranges covering `total` bytes.
fn segments(mut cuts: Vec<usize>, total: usize) -> Vec<(usize, usize)> {
    cuts.retain(|&c| c > 0 && c < total);
    cuts.sort_unstable();
    cuts.dedup();
    let mut segs = Vec::with_capacity(cuts.len() + 1);
    let mut prev = 0;
    for c in cuts {
        segs.push((prev, c));
        prev = c;
    }
    segs.push((prev, total));
    segs
}

fn pick_delay(plan: &WirePlan, rng: &SystemRandom) -> Option<Duration> {
    match plan.inter_segment_delay {
        DelaySpec::None => None,
        DelaySpec::Fixed(d) => Some(d),
        DelaySpec::Jitter { min, max } => {
            let span = max.saturating_sub(min).as_millis() as u64;
            if span == 0 {
                return Some(min);
            }
            let mut b = [0u8; 8];
            // Best-effort: on RNG failure fall back to the floor delay.
            if rng.fill(&mut b).is_err() {
                return Some(min);
            }
            Some(min + Duration::from_millis(u64::from_le_bytes(b) % (span + 1)))
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for SegmentShapingStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        let SegmentShapingStream {
            inner,
            plan,
            shaped,
            pending,
            rng,
        } = me;

        if *shaped {
            return Pin::new(inner).poll_write(cx, buf);
        }
        if pending.is_none() {
            let cuts = cuts_for(&plan.segment_split, buf);
            let segs = segments(cuts, buf.len());
            if segs.len() < 2 {
                // Nothing to split — pass through and stop shaping.
                *shaped = true;
                return Pin::new(inner).poll_write(cx, buf);
            }
            *pending = Some(Pending {
                data: buf.to_vec(),
                segs,
                seg: 0,
                off: 0,
                delay: None,
            });
        }

        loop {
            // 1. Honor an active inter-segment delay.
            if let Some(mut d) = pending.as_mut().unwrap().delay.take() {
                match d.as_mut().poll(cx) {
                    Poll::Pending => {
                        pending.as_mut().unwrap().delay = Some(d);
                        return Poll::Pending;
                    }
                    Poll::Ready(()) => {}
                }
            }

            // 2. Snapshot the current segment (released before any &mut *pending below).
            let (start, end, seg, off, nsegs, total) = {
                let p = pending.as_ref().unwrap();
                let (s, e) = p.segs[p.seg];
                (s, e, p.seg, p.off, p.segs.len(), p.data.len())
            };

            // 3. Write the rest of the current segment.
            if off < end - start {
                let res = {
                    let p = pending.as_ref().unwrap();
                    Pin::new(&mut *inner).poll_write(cx, &p.data[start + off..end])
                };
                match res {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(0)) => {
                        *pending = None;
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "handshake shaper: inner stream accepted 0 bytes",
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

            // 4. Segment fully written — flush it so it leaves as its own packet.
            match Pin::new(&mut *inner).poll_flush(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => {
                    *pending = None;
                    return Poll::Ready(Err(e));
                }
                Poll::Ready(Ok(())) => {}
            }

            // 5. Advance, or finish.
            if seg + 1 < nsegs {
                let delay = pick_delay(plan, rng).map(|d| Box::pin(sleep(d)));
                let p = pending.as_mut().unwrap();
                p.seg += 1;
                p.off = 0;
                p.delay = delay;
                continue;
            }
            *pending = None;
            *shaped = true;
            return Poll::Ready(Ok(total));
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for SegmentShapingStream<S> {
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
    use crate::RecordFragment;
    use std::sync::{Arc, Mutex};
    use tokio::io::AsyncWriteExt;

    /// A sink that records each `poll_write` as a separate buffer (so tests can see segment
    /// boundaries) and accepts everything immediately.
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

    fn plan(split: SegmentSplit) -> WirePlan {
        WirePlan {
            segment_split: split,
            inter_segment_delay: DelaySpec::None,
            tcp_nodelay: false,
            record_fragment: RecordFragment::None,
        }
    }

    #[tokio::test]
    async fn splits_the_opening_write_at_explicit_offsets() {
        let rec = Recorder::default();
        let writes = rec.writes.clone();
        let mut s = SegmentShapingStream::new(rec, plan(SegmentSplit::Explicit(vec![3, 7])));
        s.write_all(b"0123456789").await.unwrap();
        assert_eq!(
            *writes.lock().unwrap(),
            vec![b"012".to_vec(), b"3456".to_vec(), b"789".to_vec()]
        );
    }

    #[tokio::test]
    async fn passthrough_after_the_opening_write() {
        let rec = Recorder::default();
        let writes = rec.writes.clone();
        let mut s = SegmentShapingStream::new(rec, plan(SegmentSplit::Explicit(vec![2])));
        s.write_all(b"HELLO").await.unwrap(); // shaped: [HE][LLO]
        s.write_all(b"BULKDATA").await.unwrap(); // passthrough: one write
        let w = writes.lock().unwrap();
        assert_eq!(w[0], b"HE");
        assert_eq!(w[1], b"LLO");
        assert_eq!(w[2], b"BULKDATA");
        assert_eq!(w.len(), 3);
    }

    #[tokio::test]
    async fn noop_plan_is_a_single_write() {
        let rec = Recorder::default();
        let writes = rec.writes.clone();
        let mut s = SegmentShapingStream::new(rec, plan(SegmentSplit::None));
        s.write_all(b"0123456789").await.unwrap();
        assert_eq!(*writes.lock().unwrap(), vec![b"0123456789".to_vec()]);
    }

    #[tokio::test]
    async fn sni_boundary_splits_inside_the_hostname() {
        let host = b"example.com";
        let ch = sni::tests_support::clienthello_with_sni(host);
        let (off, len) = sni::sni_host_range(&ch).unwrap();

        let rec = Recorder::default();
        let writes = rec.writes.clone();
        let mut s = SegmentShapingStream::new(rec, plan(SegmentSplit::SniBoundary));
        s.write_all(&ch).await.unwrap();

        let w = writes.lock().unwrap();
        assert_eq!(w.len(), 2, "SNI split must produce exactly two segments");
        // The boundary lands inside the hostname: the first segment ends mid-host.
        let cut = off + len / 2;
        assert_eq!(w[0].len(), cut);
        assert_eq!(w[0].len() + w[1].len(), ch.len());
    }
}
