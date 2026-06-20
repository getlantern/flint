//! The gambit genome (ADR 0006 P2) — the portable, signed specification of a flow's *opening*.
//!
//! A [`Gambit`] is data, not code: deltas over a genuine-Chrome anchor across three layers —
//! ClientHello content (A), TLS record framing (B), and TCP segment/timing (C). It is delivered
//! inside a [`SignedGambit`] envelope (detached **Ed25519** over the canonical encoding + a monotonic
//! `version` for anti-rollback) and gated by [`Capability`] tags an executor must satisfy. See
//! `docs/handshake-gambit-design.md` §2 (the locked v1 schema).
//!
//! This module is the **decode + verify + gate** contract and the bridge of Layer C to the Phase 1
//! shaper ([`Gambit::wire_plan`]). Applying the Layer-A ClientHello knobs to the boring connector is
//! the [`crate::profile`] executor mapping.
//!
//! Canonical encoding for signing is **postcard** (the project's binary codec). Cross-fleet (Go,
//! uTLS) canonicalization is a deliberately open question (design doc §6).

use std::collections::HashMap;

use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};

use flint_shaping::{DelaySpec, SegmentSplit, WirePlan};

/// Errors decoding, verifying, or gating a gambit.
#[derive(Debug, thiserror::Error)]
pub enum GambitError {
    /// The gambit's `version` is not strictly above the accepted floor (anti-rollback).
    #[error("gambit version {got} is not newer than the accepted floor {floor}")]
    Rollback { got: u64, floor: u64 },
    /// The envelope's `key_id` is not among the pinned keys.
    #[error("unknown signing key id `{0}`")]
    UnknownKey(String),
    /// The Ed25519 signature did not verify against the pinned key.
    #[error("gambit signature verification failed")]
    BadSignature,
    /// Canonical encoding of the gambit failed.
    #[error("gambit canonical encoding failed: {0}")]
    Encode(String),
    /// The gambit requires capabilities the target executor does not advertise.
    #[error("gambit requires unsupported capabilities: {0:?}")]
    Unsupported(Vec<Capability>),
}

/// Ed25519 public keys pinned in the binary, keyed by `key_id`.
pub type PinnedKeys = HashMap<String, Vec<u8>>;

/// The genuine-Chrome handshake a gambit's deltas are relative to (the fidelity floor).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
pub enum Anchor {
    #[default]
    #[serde(rename = "chrome-137")]
    Chrome137,
}

/// Capability tags (closed vocabulary). An executor declines a gambit whose `requires` it can't meet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    Ech,
    Alps,
    PqKem,
    SessionIdInject,
    RawClienthello,
}

/// An ordering knob: reproduce Chrome's per-connection permutation from a seed, or pin an order.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Perm {
    PermuteSeed(u32),
    Explicit(Vec<u16>),
}

/// ECH mode for the ClientHello.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EchMode {
    Off,
    #[default]
    Grease,
    Real,
}

/// `legacy_session_id` handling (`inject` requires the `session_id_inject` capability).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", tag = "mode", content = "hex")]
pub enum SessionId {
    Random,
    Resumption,
    Inject(String),
}

/// Layer A — ClientHello content (deltas over the anchor). Modeled + round-tripped here; applied to
/// the boring connector in [`crate::profile`].
///
/// `Option` fields are absent-by-default deltas. postcard (the canonical signing codec) is *not*
/// self-describing — fields are read positionally — so `skip_serializing_if` is deliberately absent:
/// it would drop bytes the deserializer still expects. postcard already encodes each `Option` as a
/// 1-byte present/absent discriminant, so the encoding stays compact and deterministic regardless.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClientHello {
    pub extension_order: Option<Perm>,
    pub cipher_order: Option<Perm>,
    pub grease_seed: Option<u32>,
    /// Pad the ClientHello to this many bytes.
    pub padding_target: Option<u16>,
    pub ech: Option<EchMode>,
    pub alps: Option<bool>,
    /// Offer the post-quantum group X25519MLKEM768 (requires `pq_kem`).
    pub pq_kem: Option<bool>,
    pub session_id: Option<SessionId>,
}

/// Layer B — TLS record framing.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Records {
    pub size_limit: Option<u16>,
    pub split_offsets: Vec<usize>,
}

/// Layer C — TCP segment + timing. Bridges to the Phase 1 shaper via [`Wire::to_wire_plan`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Wire {
    /// `"none"`, `"sni_boundary"`, or comma-separated byte offsets.
    pub segment_split: String,
    pub delay_ms: Option<u64>,
    /// `[min_ms, max_ms]` uniform jitter (takes precedence over `delay_ms` if both are set).
    pub delay_jitter_ms: Option<[u64; 2]>,
    pub tcp_nodelay: bool,
}

impl Default for Wire {
    fn default() -> Self {
        Self {
            segment_split: "none".to_owned(),
            delay_ms: None,
            delay_jitter_ms: None,
            tcp_nodelay: true,
        }
    }
}

impl Wire {
    /// Bridge Layer C to the native [`WirePlan`] the shaper consumes. (Layer B `record_fragment` is
    /// carried separately by the dialer; this maps only the segment/timing knobs.)
    pub fn to_wire_plan(&self) -> WirePlan {
        use std::time::Duration;
        let segment_split = match self.segment_split.trim() {
            "" | "none" => SegmentSplit::None,
            "sni_boundary" => SegmentSplit::SniBoundary,
            list => SegmentSplit::Explicit(
                list.split(',')
                    .filter_map(|s| s.trim().parse().ok())
                    .collect(),
            ),
        };
        let inter_segment_delay = match (self.delay_jitter_ms, self.delay_ms) {
            (Some([min, max]), _) => DelaySpec::Jitter {
                min: Duration::from_millis(min),
                max: Duration::from_millis(max.max(min)),
            },
            (None, Some(ms)) => DelaySpec::Fixed(Duration::from_millis(ms)),
            (None, None) => DelaySpec::None,
        };
        WirePlan {
            segment_split,
            inter_segment_delay,
            tcp_nodelay: self.tcp_nodelay,
            ..Default::default()
        }
    }
}

/// A delivered opening move: deltas over an anchor across the three layers, plus its capability
/// requirements and monotonic version.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Gambit {
    /// Schema version (v1 = the locked schema in the design doc).
    pub genome_version: u32,
    /// Monotonic anti-rollback counter (must exceed the accepted floor on verify).
    pub version: u64,
    /// Identifier, for server-side fitness attribution.
    pub id: String,
    #[serde(default)]
    pub anchor: Anchor,
    #[serde(default)]
    pub clienthello: ClientHello,
    #[serde(default)]
    pub records: Records,
    #[serde(default)]
    pub wire: Wire,
    #[serde(default)]
    pub requires: Vec<Capability>,
}

impl Gambit {
    /// Layer C as the native shaper plan.
    pub fn wire_plan(&self) -> WirePlan {
        self.wire.to_wire_plan()
    }

    /// `Ok` iff every required capability is advertised by the executor; else the missing ones.
    pub fn check_supported(&self, supported: &[Capability]) -> Result<(), GambitError> {
        let missing: Vec<Capability> = self
            .requires
            .iter()
            .copied()
            .filter(|c| !supported.contains(c))
            .collect();
        if missing.is_empty() {
            Ok(())
        } else {
            Err(GambitError::Unsupported(missing))
        }
    }
}

/// The delivery envelope: a gambit + the key it's signed under + a detached Ed25519 signature over
/// the gambit's canonical (postcard) encoding.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedGambit {
    pub gambit: Gambit,
    pub key_id: String,
    pub sig: Vec<u8>,
}

impl SignedGambit {
    /// The canonical bytes a signature covers: the postcard encoding of the gambit.
    fn canonical(gambit: &Gambit) -> Result<Vec<u8>, GambitError> {
        postcard::to_stdvec(gambit).map_err(|e| GambitError::Encode(e.to_string()))
    }

    /// Verify the signature against the pinned key for `key_id` and the anti-rollback `floor`,
    /// returning the gambit on success. (Capability gating is the executor's call —
    /// [`Gambit::check_supported`].)
    pub fn verify(&self, keys: &PinnedKeys, floor: u64) -> Result<&Gambit, GambitError> {
        let key = keys
            .get(&self.key_id)
            .ok_or_else(|| GambitError::UnknownKey(self.key_id.clone()))?;
        let msg = Self::canonical(&self.gambit)?;
        UnparsedPublicKey::new(&ED25519, key)
            .verify(&msg, &self.sig)
            .map_err(|_| GambitError::BadSignature)?;
        if self.gambit.version <= floor {
            return Err(GambitError::Rollback {
                got: self.gambit.version,
                floor,
            });
        }
        Ok(&self.gambit)
    }
}

/// Version byte of the [`GambitContext`] header passed to a Path-B `compute_gambit` module.
pub const GAMBIT_CONTEXT_VERSION: u8 = 1;

/// Encoded length of the v1 [`GambitContext`] header.
pub const GAMBIT_CONTEXT_LEN: usize = 16;

/// The per-connection context handed to a Path-B gambit-compute module (ADR 0006 P3) — the *input*
/// to `compute_gambit`, as the [`Gambit`] is its output.
///
/// A small **fixed-offset little-endian** header (not postcard), so the guest reads fields by offset
/// with no decoder and new fields append at stable offsets, their presence gated by the version
/// byte. v1 layout ([`GAMBIT_CONTEXT_LEN`] bytes):
///
/// | offset | field        | type                                   |
/// |--------|--------------|----------------------------------------|
/// | 0      | `version`    | `u8` (= [`GAMBIT_CONTEXT_VERSION`])     |
/// | 1..8   | reserved (0) | —                                      |
/// | 8..16  | `unix_secs`  | `u64` LE — host wall-clock at connect  |
///
/// Design (ADR 0006 §6): carry only what the sandbox **cannot** self-source. The module already has
/// a CSPRNG (`host_rand`) and persistent state across connections (its own rotation counter), so the
/// one genuinely host-only per-connection fact is the wall clock — and supplying it from the host
/// keeps it *pinnable* for tests and the offline discovery-loop evaluator. Static deployment facts
/// (server, SNI) go via the module's `init` config; connection-outcome feedback is a separate future
/// export, not this input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GambitContext {
    /// Host wall-clock at connection time, in Unix seconds.
    pub unix_secs: u64,
}

impl GambitContext {
    /// Encode the v1 fixed-offset header.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![0u8; GAMBIT_CONTEXT_LEN];
        buf[0] = GAMBIT_CONTEXT_VERSION;
        buf[8..16].copy_from_slice(&self.unix_secs.to_le_bytes());
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn sample() -> Gambit {
        Gambit {
            genome_version: 1,
            version: 7,
            id: "g_test".to_owned(),
            anchor: Anchor::Chrome137,
            clienthello: ClientHello {
                extension_order: Some(Perm::PermuteSeed(91823)),
                padding_target: Some(700),
                ech: Some(EchMode::Grease),
                pq_kem: Some(true),
                ..Default::default()
            },
            records: Records::default(),
            wire: Wire {
                segment_split: "sni_boundary".to_owned(),
                delay_jitter_ms: Some([5, 25]),
                ..Default::default()
            },
            requires: vec![Capability::Ech, Capability::PqKem],
        }
    }

    /// (gambit, pinned-keys, signed-envelope) signed by a fresh test keypair under "k1".
    fn signed(g: Gambit) -> (SignedGambit, PinnedKeys) {
        let rng = SystemRandom::new();
        let doc = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap();
        let pubkey = kp.public_key().as_ref().to_vec();
        let sig = kp
            .sign(&SignedGambit::canonical(&g).unwrap())
            .as_ref()
            .to_vec();
        let keys = PinnedKeys::from([("k1".to_owned(), pubkey)]);
        (
            SignedGambit {
                gambit: g,
                key_id: "k1".to_owned(),
                sig,
            },
            keys,
        )
    }

    #[test]
    fn round_trips_through_postcard() {
        let g = sample();
        let bytes = postcard::to_stdvec(&g).unwrap();
        let back: Gambit = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(g, back);
    }

    #[test]
    fn gambit_context_encodes_the_v1_header() {
        let ctx = GambitContext {
            unix_secs: 0x0102_0304_0506_0708,
        };
        let bytes = ctx.encode();
        assert_eq!(bytes.len(), GAMBIT_CONTEXT_LEN);
        assert_eq!(bytes[0], GAMBIT_CONTEXT_VERSION);
        assert_eq!(&bytes[1..8], &[0u8; 7]); // reserved
        assert_eq!(
            u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            0x0102_0304_0506_0708
        );
    }

    #[test]
    fn verifies_a_good_signature_above_the_floor() {
        let (sg, keys) = signed(sample());
        assert_eq!(sg.verify(&keys, 6).unwrap().version, 7);
    }

    #[test]
    fn rejects_tamper_unknown_key_and_rollback() {
        let (sg, keys) = signed(sample());

        // tamper: mutate the gambit after signing → signature no longer matches.
        let mut tampered = sg.clone();
        tampered.gambit.version = 99;
        assert!(matches!(
            tampered.verify(&keys, 0),
            Err(GambitError::BadSignature)
        ));

        // unknown key id.
        let mut wrong_key = sg.clone();
        wrong_key.key_id = "nope".to_owned();
        assert!(matches!(
            wrong_key.verify(&keys, 0),
            Err(GambitError::UnknownKey(_))
        ));

        // anti-rollback: version 7 is not above floor 7.
        assert!(matches!(
            sg.verify(&keys, 7),
            Err(GambitError::Rollback { got: 7, floor: 7 })
        ));
    }

    #[test]
    fn capability_gating() {
        let g = sample(); // requires Ech + PqKem
        assert!(g
            .check_supported(&[Capability::Ech, Capability::PqKem, Capability::Alps])
            .is_ok());
        assert!(matches!(
            g.check_supported(&[Capability::Ech]),
            Err(GambitError::Unsupported(m)) if m == vec![Capability::PqKem]
        ));
    }

    #[test]
    fn wire_layer_bridges_to_a_shaper_plan() {
        let g = sample();
        let plan = g.wire_plan();
        assert!(matches!(plan.segment_split, SegmentSplit::SniBoundary));
        assert!(matches!(plan.inter_segment_delay, DelaySpec::Jitter { .. }));
        assert!(plan.tcp_nodelay);
    }
}
