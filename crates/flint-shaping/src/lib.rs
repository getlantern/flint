//! Wire-shaping primitives for opening-handshake evasion (ADR 0006 Phase 1, generalized).
//!
//! Two orthogonal, composable levers shape *only* the opening write (the TLS ClientHello) and then
//! pass through untouched for the rest of the connection:
//!
//! - [`SegmentShapingStream`] — **Layer C, `tcp_split`**: split the opening *byte stream* across TCP
//!   segments (optionally at the SNI boundary, with an inter-segment delay). The ClientHello stays a
//!   single TLS record; this defeats DPI that matches the SNI within one packet, but a censor that
//!   reassembles TCP sees the original record again.
//! - [`RecordFragmentingStream`] — **Layer B, `record_fragment`**: re-emit the ClientHello as
//!   *multiple TLS records*, each with its own `16 03 01 <len>` header. Because fragmentation lives in
//!   the record structure (above TCP), it survives censor TCP reassembly; it defeats DPI that inspects
//!   only the first record or doesn't reassemble a handshake message across records (RFC 8446 §5.1).
//!
//! Both read a single [`WirePlan`] (the genome carrying Layer B + Layer C). Compose them by stacking:
//! put record fragmentation **outermost** (closest to the TLS engine) over segment shaping, so the CH
//! is re-framed into records first and those bytes are then split across TCP segments —
//! `RecordFragmentingStream::new(SegmentShapingStream::new(socket, plan), plan)`. A default plan is a
//! no-op passthrough, so shaping is strictly opt-in.
//!
//! Extracted from spark's `core::transport::shaping`. Unlike that module, [`WirePlan`] here is
//! **config-agnostic** (no `from_config` over spark's `ShapingConfig`): a consumer constructs it
//! directly or maps its own config onto the public fields.
#![forbid(unsafe_code)]

use std::time::Duration;

pub mod sni;

mod record_fragment;
mod tcp_split;

pub use record_fragment::RecordFragmentingStream;
pub use tcp_split::SegmentShapingStream;

/// How to split the opening write into TCP segments (Layer C; absolute byte offsets into that write).
#[derive(Debug, Clone, Default)]
pub enum SegmentSplit {
    /// No splitting — a transparent passthrough.
    #[default]
    None,
    /// Split mid-hostname so the SNI value straddles a segment boundary.
    SniBoundary,
    /// Split at these explicit byte offsets.
    Explicit(Vec<usize>),
}

/// The delay inserted between segments of the opening write (Layer C).
#[derive(Debug, Clone, Default)]
pub enum DelaySpec {
    /// No delay.
    #[default]
    None,
    /// A fixed delay.
    Fixed(Duration),
    /// A uniformly random delay in `[min, max]`.
    Jitter {
        /// The floor of the random delay.
        min: Duration,
        /// The ceiling of the random delay.
        max: Duration,
    },
}

/// How to fragment the ClientHello across TLS records (Layer B).
#[derive(Debug, Clone, Default)]
pub enum RecordFragment {
    /// No fragmentation — the ClientHello stays a single record.
    #[default]
    None,
    /// Fragment into exactly two records cut so the SNI host value straddles the record boundary.
    /// Falls back to no fragmentation when the buffer carries no locatable SNI host.
    SniStraddle,
    /// Fragment the ClientHello's record payload into chunks of at most `usize` bytes each.
    Chunks(usize),
    /// Fragment the ClientHello's record payload at these absolute payload byte offsets, emitting a
    /// separate TLS record per piece. Offsets are sorted+deduped and clamped to `(0, payload_len)`;
    /// an empty (or all-zero) list is a no-op. (Gambit Layer B `records.split_offsets`.)
    Offsets(Vec<usize>),
}

/// The opening-handshake shaping genome: how to frame and time the ClientHello on the wire.
///
/// Layer C ([`segment_split`](Self::segment_split), [`inter_segment_delay`](Self::inter_segment_delay),
/// [`tcp_nodelay`](Self::tcp_nodelay)) is realized by [`SegmentShapingStream`]; Layer B
/// ([`record_fragment`](Self::record_fragment)) by [`RecordFragmentingStream`].
#[derive(Debug, Clone, Default)]
pub struct WirePlan {
    /// Where to split the opening write into separate segments (Layer C).
    pub segment_split: SegmentSplit,
    /// The delay between those segments (Layer C).
    pub inter_segment_delay: DelaySpec,
    /// Whether the integration site should set `TCP_NODELAY` on the underlying socket so each flushed
    /// segment leaves as its own packet. Applied where the concrete socket is available (not in the
    /// generic stream wrapper, which only relies on a flush per segment).
    pub tcp_nodelay: bool,
    /// How to fragment the ClientHello across TLS records (Layer B).
    pub record_fragment: RecordFragment,
}

impl WirePlan {
    /// True if the plan does no shaping at all (then both stream wrappers are pure passthroughs).
    ///
    /// This detects *structural* no-ops only. For `Offsets`, an offset of 0 is always dropped at
    /// runtime (a cut at the start fragments nothing), so all-zero (or empty) offsets are a no-op;
    /// offsets that fall out of bounds of a *specific* payload also drop at runtime, but that
    /// depends on the payload length and so isn't detected here.
    pub fn is_noop(&self) -> bool {
        let record_noop = match &self.record_fragment {
            RecordFragment::None => true,
            RecordFragment::Offsets(offs) => offs.iter().all(|&o| o == 0),
            _ => false,
        };
        matches!(self.segment_split, SegmentSplit::None) && record_noop
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_noop_detects_structural_record_noops() {
        let plan = |rf| WirePlan {
            record_fragment: rf,
            ..Default::default()
        };
        assert!(plan(RecordFragment::None).is_noop());
        assert!(plan(RecordFragment::Offsets(vec![])).is_noop());
        // Offset 0 is always dropped at runtime, so all-zero offsets do no fragmentation.
        assert!(plan(RecordFragment::Offsets(vec![0])).is_noop());
        assert!(plan(RecordFragment::Offsets(vec![0, 0])).is_noop());
        // A non-zero cut is real shaping.
        assert!(!plan(RecordFragment::Offsets(vec![10])).is_noop());
        assert!(!plan(RecordFragment::Offsets(vec![0, 10])).is_noop());
    }
}
