//! Resolve a gambit's Layer-A (ClientHello) + Layer-B (records) knobs onto the **boring/btls
//! executor** (ADR 0006 P2; design doc §3).
//!
//! The genome ([`crate::gambit`]) is the portable interchange format; this module is the
//! boring-specific *executor mapping* — it turns the data-only deltas into the on/off connector
//! decisions [`crate::connector::connect`] applies, and records the knobs boring2 4.15 **cannot**
//! realize today so the caller can log them (they are never silently dropped — they await the P4
//! byte-builder / a patched fork).
//!
//! What boring2 4.15 expresses (verified against the crate source): GREASE on/off, extension
//! permutation on/off (no seed control), the supported-groups list (so PQ X25519MLKEM768 is
//! includable), `record_size_limit`, ECH grease, ALPS. What it does **not**: explicit extension/
//! cipher order by id, an exact GREASE/permutation seed, ClientHello padding-to-length,
//! `legacy_session_id` injection, and TLS-record split offsets.
//!
//! Pure data mapping — no boring dependency. The resulting [`Profile`] (plain on/off values) is what
//! [`crate::connector`] applies to the boring connector under the `boring` feature.

use crate::gambit::{Capability, ClientHello, EchMode, Gambit, GambitError, Perm, Records};

/// Capabilities the boring/btls executor can satisfy today (design doc §3). Notably **not**
/// `raw_clienthello` — that is uTLS-now / spark-P4, so a gambit requiring it is declined here and the
/// caller falls back to its best portable gambit.
pub const BORING_CAPABILITIES: &[Capability] = &[
    Capability::Ech,
    Capability::Alps,
    Capability::PqKem,
    Capability::SessionIdInject,
];

/// Resolved boring connector decisions. Defaults are the byte-exact **Chrome-137 anchor**, so an
/// empty/None genome reproduces today's hardcoded handshake (the live-gate baseline).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    /// Emit GREASE values (Chrome: on).
    pub grease: bool,
    /// Randomly permute the extension order per connection (Chrome: on).
    pub permute_extensions: bool,
    /// Offer the post-quantum group X25519MLKEM768 in supported_groups (Chrome 137: on).
    pub pq_kem: bool,
    /// Send the ECH-grease extension (Chrome: on).
    pub ech_grease: bool,
    /// Offer ALPS (`application_settings`, new codepoint) for h2 (Chrome: on).
    pub alps: bool,
    /// `record_size_limit` extension value; `None` = don't send it (the anchor default).
    pub record_size_limit: Option<u16>,
    /// Explicit extension order by id (gambit `extension_order: Explicit`). `None` ⇒ boring's own
    /// (seed-uncontrolled) permute, per `permute_extensions`.
    pub extension_order: Option<Vec<u16>>,
    /// Explicit cipher order by id (gambit `cipher_order: Explicit`). `None` ⇒ the pinned Chrome list.
    pub cipher_order: Option<Vec<u16>>,
    /// Injected `legacy_session_id` (gambit `session_id: Inject`). `None` ⇒ boring default.
    pub session_id: Option<[u8; 32]>,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            grease: true,
            permute_extensions: true,
            pq_kem: true,
            ech_grease: true,
            alps: true,
            record_size_limit: None,
            extension_order: None,
            cipher_order: None,
            session_id: None,
        }
    }
}

/// The outcome of resolving a genome onto boring: the [`Profile`] plus the knobs boring cannot fully
/// realize today (each either *ignored* or *approximated* — the message says which). The caller logs
/// these; they are deliberately surfaced rather than silently dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// The connector decisions to apply.
    pub profile: Profile,
    /// Human-readable notes on knobs not fully honored by boring2 4.15.
    pub unrealizable: Vec<&'static str>,
}

impl Profile {
    /// Resolve a genome's Layer-A (`ch`) + Layer-B (`rec`) knobs onto boring. Pure: applies what
    /// boring2 can express, collects the rest into [`Resolved::unrealizable`]. Does **not** gate on
    /// capabilities — that is [`Profile::for_boring`] (the signed-gambit entry point).
    pub fn resolve(ch: &ClientHello, rec: &Records) -> Resolved {
        let mut p = Profile::default();
        let mut un = Vec::new();

        match ch.ech {
            None | Some(EchMode::Grease) => p.ech_grease = true,
            Some(EchMode::Off) => p.ech_grease = false,
            Some(EchMode::Real) => {
                p.ech_grease = true;
                un.push("ech.real ignored (no ECHConfig wiring yet; using grease)");
            }
        }

        if let Some(on) = ch.alps {
            p.alps = on;
        }
        if let Some(on) = ch.pq_kem {
            p.pq_kem = on;
        }

        // boring controls GREASE/permutation as on/off only — the requested *seed* is honored in
        // spirit (the feature is enabled) but not byte-for-byte.
        if ch.grease_seed.is_some() {
            p.grease = true;
            un.push("grease seed approximated (boring: GREASE on/off only, seed uncontrolled)");
        }
        match &ch.extension_order {
            None => {}
            Some(Perm::PermuteSeed(_)) => {
                p.permute_extensions = true;
                un.push("extension_order seed approximated (boring: permute on/off only)");
            }
            Some(Perm::Explicit(ids)) => p.extension_order = Some(ids.clone()),
        }
        match &ch.cipher_order {
            None => {}
            Some(Perm::PermuteSeed(_)) => {
                un.push("cipher_order.permute ignored (boring has no cipher permutation)")
            }
            Some(Perm::Explicit(ids)) => p.cipher_order = Some(ids.clone()),
        }
        if ch.padding_target.is_some() {
            un.push("padding_target ignored (no boring2 4.15 API; needs P4 byte-builder)");
        }
        if let Some(crate::gambit::SessionId::Inject(hex)) = &ch.session_id {
            match decode_hex_32(hex) {
                Some(id) => p.session_id = Some(id),
                None => un.push("session_id.inject ignored (must be 64 hex chars)"),
            }
        }

        if let Some(limit) = rec.size_limit {
            p.record_size_limit = Some(limit);
        }

        Resolved {
            profile: p,
            unrealizable: un,
        }
    }

    /// Resolve a **signed-and-verified** gambit onto boring, first gating its `requires` against
    /// [`BORING_CAPABILITIES`]. Returns `Err` (declines the gambit) if it needs a capability boring
    /// lacks (`session_id_inject` / `raw_clienthello`); the caller then falls back to its best
    /// portable gambit.
    pub fn for_boring(g: &Gambit) -> Result<Resolved, GambitError> {
        g.check_supported(BORING_CAPABILITIES)?;
        Ok(Self::resolve(&g.clienthello, &g.records))
    }
}

/// Decode exactly 32 bytes of hex (64 chars), or `None`. (`legacy_session_id` is 32 bytes.)
fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gambit::SessionId;

    #[test]
    fn empty_genome_resolves_to_the_chrome_137_baseline() {
        let r = Profile::resolve(&ClientHello::default(), &Records::default());
        assert_eq!(r.profile, Profile::default());
        assert!(r.unrealizable.is_empty());
    }

    #[test]
    fn honors_the_expressible_knobs() {
        let ch = ClientHello {
            ech: Some(EchMode::Off),
            alps: Some(false),
            pq_kem: Some(false),
            ..Default::default()
        };
        let rec = Records {
            size_limit: Some(1300),
            ..Default::default()
        };
        let r = Profile::resolve(&ch, &rec);
        assert!(!r.profile.ech_grease);
        assert!(!r.profile.alps);
        assert!(!r.profile.pq_kem);
        assert_eq!(r.profile.record_size_limit, Some(1300));
        assert!(r.unrealizable.is_empty());
    }

    #[test]
    fn flags_the_unrealizable_knobs_without_dropping_them_silently() {
        let ch = ClientHello {
            cipher_order: Some(Perm::PermuteSeed(3)),
            padding_target: Some(700),
            session_id: Some(SessionId::Inject("ab".into())),
            grease_seed: Some(42),
            ..Default::default()
        };
        let r = Profile::resolve(&ch, &Records::default());
        // Expressible defaults still hold...
        assert!(r.profile.grease);
        // ...and every unrealizable knob is surfaced.
        assert_eq!(r.unrealizable.len(), 4);
        assert!(r
            .unrealizable
            .iter()
            .any(|m| m.contains("cipher_order.permute")));
        assert!(r.unrealizable.iter().any(|m| m.contains("padding_target")));
        assert!(r
            .unrealizable
            .iter()
            .any(|m| m.contains("session_id.inject")));
        assert!(r.unrealizable.iter().any(|m| m.contains("grease seed")));
    }

    #[test]
    fn for_boring_declines_a_gambit_needing_an_unsupported_capability() {
        let g = Gambit {
            genome_version: 1,
            version: 1,
            id: "g".into(),
            anchor: Default::default(),
            clienthello: ClientHello::default(),
            records: Records::default(),
            wire: Default::default(),
            requires: vec![Capability::RawClienthello],
        };
        assert!(matches!(
            Profile::for_boring(&g),
            Err(GambitError::Unsupported(m)) if m == vec![Capability::RawClienthello]
        ));
    }

    #[test]
    fn realizes_explicit_orders_and_session_id() {
        use crate::gambit::{Perm, SessionId};
        let ch = ClientHello {
            extension_order: Some(Perm::Explicit(vec![0x0000, 0x0017, 0x002b])),
            cipher_order: Some(Perm::Explicit(vec![0x1301, 0x1302])),
            session_id: Some(SessionId::Inject(
                "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".into(),
            )),
            ..Default::default()
        };
        let r = Profile::resolve(&ch, &Records::default());
        assert_eq!(
            r.profile.extension_order.as_deref(),
            Some(&[0x0000u16, 0x0017, 0x002b][..])
        );
        assert_eq!(
            r.profile.cipher_order.as_deref(),
            Some(&[0x1301u16, 0x1302][..])
        );
        assert_eq!(r.profile.session_id.unwrap().len(), 32);
        assert!(!r
            .unrealizable
            .iter()
            .any(|m| m.contains("extension_order.explicit")));
        assert!(!r
            .unrealizable
            .iter()
            .any(|m| m.contains("session_id.inject")));
    }

    #[test]
    fn permute_seed_stays_approximated() {
        use crate::gambit::Perm;
        let ch = ClientHello {
            extension_order: Some(Perm::PermuteSeed(7)),
            ..Default::default()
        };
        let r = Profile::resolve(&ch, &Records::default());
        assert!(r.profile.extension_order.is_none());
        assert!(r.profile.permute_extensions);
        assert!(r
            .unrealizable
            .iter()
            .any(|m| m.contains("extension_order seed approximated")));
    }

    #[test]
    fn boring_now_advertises_session_id_inject() {
        assert!(BORING_CAPABILITIES.contains(&Capability::SessionIdInject));
        assert!(!BORING_CAPABILITIES.contains(&Capability::RawClienthello));
    }

    #[test]
    fn inject_with_a_bad_hex_pin_is_flagged_not_realized() {
        use crate::gambit::SessionId;
        let ch = ClientHello {
            session_id: Some(SessionId::Inject("xyz".into())),
            ..Default::default()
        };
        let r = Profile::resolve(&ch, &Records::default());
        assert!(r.profile.session_id.is_none());
        assert!(r
            .unrealizable
            .iter()
            .any(|m| m.contains("session_id.inject")));
    }

    #[test]
    fn for_boring_accepts_a_gambit_within_capabilities() {
        let g = Gambit {
            genome_version: 1,
            version: 1,
            id: "g".into(),
            anchor: Default::default(),
            clienthello: ClientHello {
                pq_kem: Some(true),
                ..Default::default()
            },
            records: Records::default(),
            wire: Default::default(),
            requires: vec![Capability::Ech, Capability::PqKem],
        };
        let r = Profile::for_boring(&g).expect("within boring capabilities");
        assert!(r.profile.pq_kem);
    }
}
