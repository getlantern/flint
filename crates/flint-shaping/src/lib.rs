//! Wire-shaping primitives for opening-handshake evasion.
//!
//! - `tcp_split` (Layer C): split the byte stream across TCP segments; the ClientHello stays one TLS
//!   record. Extracted from spark's `core::transport::shaping` (`WirePlan`, `SegmentShapingStream`).
//! - `record_fragment` (Layer B, NEW): re-emit the ClientHello as *multiple TLS records* so a censor
//!   that inspects only the first record / doesn't reassemble across records can't match the SNI.
//!   Survives censor TCP reassembly (it is above TCP). See `docs/design.md` §5.
//!
//! Both are orthogonal and composable, under either TLS engine. See `docs/extraction-plan.md` step 2.
#![forbid(unsafe_code)]

// TODO(extraction step 2): move `shaping` here from spark; then add the `record_fragment` shim.
