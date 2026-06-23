//! BoringSSL TLS connector emitting a **Chrome ClientHello** (feature `boring`, ADR 0001).
//!
//! Produces a raw TLS byte stream configured to fingerprint as Chrome — cipher/curve/sigalg order,
//! GREASE, extension permutation, brotli certificate compression, ALPS (new codepoint), and ECH grease
//! — not as boring's default. The profile values are the current Chrome (137) tables from `wreq-util`
//! (`emulation/device/chrome.rs`); the boring2 application mirrors `wreq`'s `tls/conn/boring.rs` +
//! `tls/ext.rs`.
//!
//! Certificate verification is **skipped**: a bootstrap dial authenticates its payload out of band
//! (e.g. an Ed25519-signed config, or the carrier protocol's own auth), and TLS here is the camouflage
//! carrier. Fingerprint freshness is covered by the JA4 drift check ([`crate::anchor`]) and the
//! update-mimicry CI.

use std::borrow::Cow;
use std::io;

use boring2::ssl::{
    CertCompressionAlgorithm, ConnectConfiguration, ExtensionType, SslConnector, SslCurve,
    SslMethod, SslVerifyMode,
};
use foreign_types_shared::ForeignTypeRef; // brings `as_ptr` onto boring2's `SslRef`
use tokio_boring2::SslStream;

use crate::profile::Profile;

/// TLS 1.2 wire version, for `SSL_SESSION_set_protocol_version` (forces boring's `kID` path so the
/// fabricated session's id is emitted as the ClientHello `legacy_session_id`). See [`inject_session_id`].
const TLS1_2_VERSION: u16 = 0x0303;
/// A week, so the fabricated `kID` session is always "time-valid" when offered (else boring may drop
/// it as expired and never stamp its id). Matches spark's proven recipe.
const SESSION_TIMEOUT_SECS: u32 = 7 * 24 * 3600;

/// Chrome's TLS 1.3 + ECDHE/RSA cipher order (`wreq-util` `CIPHER_LIST`).
const CHROME_CIPHERS: &str = "TLS_AES_128_GCM_SHA256:\
    TLS_AES_256_GCM_SHA384:\
    TLS_CHACHA20_POLY1305_SHA256:\
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:\
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:\
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:\
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:\
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:\
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:\
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:\
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:\
    TLS_RSA_WITH_AES_128_GCM_SHA256:\
    TLS_RSA_WITH_AES_256_GCM_SHA384:\
    TLS_RSA_WITH_AES_128_CBC_SHA:\
    TLS_RSA_WITH_AES_256_CBC_SHA";

/// Chrome's signature algorithms (`wreq-util` `SIGALGS_LIST`).
const CHROME_SIGALGS: &str = "ecdsa_secp256r1_sha256:\
    rsa_pss_rsae_sha256:\
    rsa_pkcs1_sha256:\
    ecdsa_secp384r1_sha384:\
    rsa_pss_rsae_sha384:\
    rsa_pkcs1_sha384:\
    rsa_pss_rsae_sha512:\
    rsa_pkcs1_sha512";

/// Chrome's supported groups, post-quantum first (`wreq-util` `CURVES_3`).
const CHROME_CURVES: &[SslCurve] = &[
    SslCurve::X25519_MLKEM768,
    SslCurve::X25519,
    SslCurve::SECP256R1,
    SslCurve::SECP384R1,
];

/// The same groups without the post-quantum X25519MLKEM768 — used when a gambit turns `pq_kem` off
/// (the only Layer-A supported-groups delta boring can express).
const CHROME_CURVES_NO_PQ: &[SslCurve] =
    &[SslCurve::X25519, SslCurve::SECP256R1, SslCurve::SECP384R1];

/// ALPN as Chrome sends it: `h2`, then `http/1.1` (wire form: length-prefixed).
const ALPN_H2_HTTP11: &[u8] = b"\x02h2\x08http/1.1";

fn ssl(e: boring2::error::ErrorStack, what: &str) -> io::Error {
    io::Error::other(format!("flint-tls boring {what}: {e}"))
}

/// TLS-connect over an established byte stream with a Chrome ClientHello, using `sni` for SNI.
///
/// `profile` carries the gambit-resolved on/off knobs (ADR 0006 P2): GREASE, extension permutation,
/// the PQ supported-group, `record_size_limit`, ECH grease, and ALPS. The cipher/sigalg lists, cert
/// compression, ALPN, OCSP, and SCT are the fixed Chrome-137 anchor — boring exposes no knob for
/// them, and [`Profile`]'s defaults reproduce the genuine Chrome handshake (so [`Profile::default`]
/// ⇒ byte-identical to the prior hardcode).
///
/// Generic over the carrier so a [`flint_shaping::SegmentShapingStream`] /
/// [`flint_shaping::RecordFragmentingStream`] can sit between boring and the socket (ADR 0006 Phase 1)
/// to fragment the ClientHello.
pub async fn connect<S>(stream: S, sni: &str, profile: &Profile) -> io::Result<SslStream<S>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    tokio_boring2::connect(configure(profile)?, sni, stream)
        .await
        .map_err(|e| io::Error::other(format!("flint-tls handshake: {e}")))
}

/// Build the per-connection Chrome [`ConnectConfiguration`] — everything up to, but not including,
/// the handshake. Split out from [`connect`] so a caller that must mutate the `Ssl` before the
/// handshake (e.g. a transport injecting a `legacy_session_id`) can do so on the returned config and
/// then drive [`tokio_boring2::connect`] itself.
pub fn configure(profile: &Profile) -> io::Result<ConnectConfiguration> {
    let mut b = SslConnector::builder(SslMethod::tls()).map_err(|e| ssl(e, "builder"))?;
    // The cert is neither trusted nor pinned — bootstrap auth is out of band (see module docs).
    b.set_verify(SslVerifyMode::NONE);
    // Chrome ClientHello shaping (gambit-resolved on/off knobs over the fixed anchor).
    b.set_grease_enabled(profile.grease);
    // Extension order: an explicit gambit list pins the permutation; otherwise boring's own
    // (seed-uncontrolled) permute, per the profile.
    match &profile.extension_order {
        Some(ids) => b
            .set_extension_permutation(&ids_to_extension_types(ids))
            .map_err(|e| ssl(e, "ext-permutation"))?,
        None => b.set_permute_extensions(profile.permute_extensions),
    }
    let curves = if profile.pq_kem {
        CHROME_CURVES
    } else {
        CHROME_CURVES_NO_PQ
    };
    b.set_curves(curves).map_err(|e| ssl(e, "curves"))?;
    b.set_sigalgs_list(CHROME_SIGALGS)
        .map_err(|e| ssl(e, "sigalgs"))?;
    // Cipher order: an explicit gambit list builds an owned ":"-joined name string in that order;
    // otherwise borrow the pinned Chrome list (no per-connection allocation in the common case).
    let cipher_list: Cow<'static, str> = match &profile.cipher_order {
        Some(ids) => {
            let list = cipher_ids_to_list(ids);
            if list.is_empty() {
                tracing::warn!(
                    "gambit cipher_order mapped to no known ciphers; using the Chrome default"
                );
                Cow::Borrowed(CHROME_CIPHERS)
            } else {
                Cow::Owned(list)
            }
        }
        None => Cow::Borrowed(CHROME_CIPHERS),
    };
    b.set_cipher_list(&cipher_list)
        .map_err(|e| ssl(e, "ciphers"))?;
    b.add_cert_compression_alg(CertCompressionAlgorithm::Brotli)
        .map_err(|e| ssl(e, "cert-compression"))?;
    b.set_alpn_protos(ALPN_H2_HTTP11)
        .map_err(|e| ssl(e, "alpn"))?;
    if let Some(limit) = profile.record_size_limit {
        b.set_record_size_limit(limit);
    }
    // Chrome also sends status_request (OCSP) and signed_certificate_timestamp (SCT).
    b.enable_ocsp_stapling();
    b.enable_signed_cert_timestamps();

    let mut config = b.build().configure().map_err(|e| ssl(e, "configure"))?;
    // Per-connection extensions Chrome sends.
    config.set_use_server_name_indication(true);
    config.set_verify_hostname(false); // paired with set_verify(NONE)
    config.set_enable_ech_grease(profile.ech_grease);
    if profile.alps {
        config
            .add_application_settings(b"h2")
            .map_err(|e| ssl(e, "alps"))?; // ALPS
        config.set_alps_use_new_codepoint(true);
    }
    if let Some(id) = &profile.session_id {
        inject_session_id(&mut config, id)?;
    }
    Ok(config)
}

/// Map gambit extension ids to boring [`ExtensionType`]s for [`set_extension_permutation`]. Every id
/// becomes an `ExtensionType` (via `From<u16>`); ids boring does not place in its permutation table
/// (`ExtensionType::index_of` ⇒ `None`) are still forwarded, but boring silently ignores them — so we
/// `warn!` to surface that the knob won't take effect for them. We never drop the dial over an
/// unmappable id (connectivity must not depend on a gambit knob).
fn ids_to_extension_types(ids: &[u16]) -> Vec<ExtensionType> {
    ids.iter()
        .map(|&id| {
            let ext = ExtensionType::from(id);
            if ExtensionType::index_of(ext).is_none() {
                tracing::warn!(
                    ext = id,
                    "gambit extension id not in boring's permutation table; forwarding it but \
                     boring will not reorder it"
                );
            }
            ext
        })
        .collect()
}

/// Build boring's `:`-joined OpenSSL cipher-name string from a gambit cipher-id list, preserving the
/// given order ([`set_cipher_list`] honors it). Only the suites in the Chrome anchor are mapped;
/// an unknown id is skipped with a `warn!` rather than failing the dial (connectivity must not depend
/// on a gambit knob).
fn cipher_ids_to_list(ids: &[u16]) -> String {
    ids.iter()
        .filter_map(|&id| match cipher_name(id) {
            Some(name) => Some(name),
            None => {
                tracing::warn!(cipher = id, "gambit cipher id not mapped; skipping");
                None
            }
        })
        .collect::<Vec<_>>()
        .join(":")
}

/// The OpenSSL/boring cipher name for a TLS cipher-suite id, for the suites in [`CHROME_CIPHERS`]
/// (the anchor's TLS 1.3 suites plus its TLS 1.2 ECDHE/RSA suites). `None` for any other id.
fn cipher_name(id: u16) -> Option<&'static str> {
    Some(match id {
        // TLS 1.3
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        // TLS 1.2 ECDHE
        0xc02b => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xc02c => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0xcca9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        0xcca8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        0xc013 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        0xc014 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        // TLS 1.2 RSA
        0x009c => "TLS_RSA_WITH_AES_128_GCM_SHA256",
        0x009d => "TLS_RSA_WITH_AES_256_GCM_SHA384",
        0x002f => "TLS_RSA_WITH_AES_128_CBC_SHA",
        0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA",
        _ => return None,
    })
}

/// Install `id` as the ClientHello `legacy_session_id` on `config` — spark's proven `kID` recipe (no
/// BoringSSL fork). Attach a fabricated TLS-1.2, id-bearing, ticketless session before the handshake:
/// boring's client emits a `kID` session's id as `legacy_session_id` even in a TLS-1.3 hello. Call
/// after [`SslConnector::configure`]/[`configure`] and before the handshake.
///
/// boring2 4.15 exposes no high-level API for this, so it drops to the `boring_sys2` FFI.
pub fn inject_session_id(config: &mut ConnectConfiguration, id: &[u8; 32]) -> io::Result<()> {
    let ssl = config.as_ptr();
    // SAFETY: `ssl` is the valid `SSL*` owned by `config` for the duration of this call. We own the
    // `SSL_SESSION` from `SSL_SESSION_new` until `SSL_set_session` takes its own (up-)reference, after
    // which we free ours. All pointers/lengths passed in are valid.
    unsafe {
        let ctx = boring_sys2::SSL_get_SSL_CTX(ssl);
        let sess = boring_sys2::SSL_SESSION_new(ctx);
        if sess.is_null() {
            return Err(io::Error::other("flint-tls: SSL_SESSION_new failed"));
        }
        // TLS 1.2 + an id + no ticket ⇒ a `kID` session, whose id boring stamps as the ClientHello's
        // `legacy_session_id` (even in a 1.3 hello).
        let ok = boring_sys2::SSL_SESSION_set_protocol_version(sess, TLS1_2_VERSION) == 1
            && boring_sys2::SSL_SESSION_set1_id(sess, id.as_ptr(), id.len()) == 1;
        if !ok {
            boring_sys2::SSL_SESSION_free(sess);
            return Err(io::Error::other("flint-tls: kID session setup failed"));
        }
        // Keep the session "time-valid" so it is offered, not dropped as expired. A clock before the
        // Unix epoch would stamp a stale time and silently drop the injection; surface that as an
        // explicit error (freeing the session we own first) rather than fail silently with `0`.
        let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => d.as_secs(),
            Err(_) => {
                boring_sys2::SSL_SESSION_free(sess);
                return Err(io::Error::other(
                    "flint-tls: system clock is before the Unix epoch",
                ));
            }
        };
        boring_sys2::SSL_SESSION_set_time(sess, now);
        boring_sys2::SSL_SESSION_set_timeout(sess, SESSION_TIMEOUT_SECS);

        let rc = boring_sys2::SSL_set_session(ssl, sess);
        boring_sys2::SSL_SESSION_free(sess); // SSL_set_session up-ref'd it; drop our reference
        if rc != 1 {
            return Err(io::Error::other("flint-tls: SSL_set_session failed"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anchor::capture_client_hello;
    use crate::ja4::{is_grease, ja4_of_record, parse_client_hello};

    /// GREASE-stripped extension ids of the ClientHello `profile` emits, in wire order.
    async fn captured_extension_order(profile: &Profile) -> Vec<u16> {
        let ch = capture_client_hello(profile, "example.com")
            .await
            .expect("capture ClientHello");
        let s = parse_client_hello(&ch).expect("parse ClientHello");
        s.extensions
            .into_iter()
            .filter(|e| !is_grease(*e))
            .collect()
    }

    #[tokio::test]
    async fn applies_explicit_order_and_injected_session_id() {
        // Discover the extensions the default Chrome profile actually emits, then request a
        // *reversed* order over them — a permutation boring can fully realize (every id is already
        // present and permutable), so the emitted order must come back reversed.
        let default_order = captured_extension_order(&Profile::default()).await;
        assert!(
            default_order.len() >= 4,
            "the Chrome profile emits several extensions"
        );
        let requested: Vec<u16> = default_order.iter().copied().rev().collect();

        let id = [0xABu8; 32];
        let profile = Profile {
            extension_order: Some(requested.clone()),
            session_id: Some(id),
            ..Profile::default()
        };

        let ch = capture_client_hello(&profile, "example.com")
            .await
            .expect("capture ClientHello");
        let s = parse_client_hello(&ch).expect("parse ClientHello");

        // 1. legacy_session_id is exactly the injected bytes.
        assert_eq!(
            s.legacy_session_id, id,
            "legacy_session_id must equal the injected bytes"
        );

        // 2. The GREASE-stripped extension order matches the requested (reversed) order.
        let got: Vec<u16> = s
            .extensions
            .iter()
            .copied()
            .filter(|e| !is_grease(*e))
            .collect();
        assert_eq!(got, requested, "extension order must follow the request");

        // 3. Still a TLS 1.3 hello (supported_versions offers 0x0304).
        assert!(
            s.supported_versions
                .as_deref()
                .is_some_and(|v| v.contains(&0x0304)),
            "ClientHello must still offer TLS 1.3"
        );
    }

    #[tokio::test]
    async fn explicit_reorder_changes_wire_order_but_not_the_sorted_ja4() {
        // Baseline: permute OFF, so the wire order is boring's deterministic canonical order — this
        // isolates the explicit-order knob's effect (vs. boring's random per-connection permute).
        let canonical_profile = Profile {
            permute_extensions: false,
            ..Profile::default()
        };
        let canonical_order = captured_extension_order(&canonical_profile).await;
        let canonical_ja4 = ja4_of_record(
            &capture_client_hello(&canonical_profile, "example.com")
                .await
                .unwrap(),
        )
        .expect("canonical JA4");

        // Request the reverse of that canonical order — a permutation boring can fully realize.
        let reordered_profile = Profile {
            extension_order: Some(canonical_order.iter().copied().rev().collect()),
            ..Profile::default()
        };
        let reordered_ch = capture_client_hello(&reordered_profile, "example.com")
            .await
            .expect("capture reordered");
        let reordered_order: Vec<u16> = parse_client_hello(&reordered_ch)
            .unwrap()
            .extensions
            .into_iter()
            .filter(|e| !is_grease(*e))
            .collect();
        let reordered_ja4 = ja4_of_record(&reordered_ch).expect("reordered JA4");

        // The wire extension order genuinely shifted (the knob took effect).
        assert_ne!(
            reordered_order, canonical_order,
            "the explicit reorder must change the wire extension order"
        );
        // ...yet JA4 (which sorts extensions) is unchanged — same set, hello not corrupted.
        assert_eq!(
            reordered_ja4, canonical_ja4,
            "a pure reorder keeps the (sorted) JA4 — same extension set, not corrupted"
        );
    }

    #[test]
    fn cipher_ids_map_to_names_in_order_and_skip_unknowns() {
        // TLS 1.3 trio in a deliberate order, with an unknown id (0xdead) interleaved — skipped.
        let list = cipher_ids_to_list(&[0x1303, 0xdead, 0x1301, 0x1302]);
        assert_eq!(
            list,
            "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384",
        );
    }

    #[cfg(feature = "boring")]
    #[test]
    fn cipher_order_with_all_unknown_ids_falls_back_to_chrome() {
        // a Profile with cipher_order full of bogus ids must still produce a usable connector
        // (configure() returns Ok, i.e. set_cipher_list didn't get "").
        let profile = Profile {
            cipher_order: Some(vec![0xDEAD, 0xBEEF]),
            ..Profile::default()
        };
        assert!(configure(&profile).is_ok());
    }
}
