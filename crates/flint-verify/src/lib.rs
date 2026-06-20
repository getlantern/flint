//! Ed25519 verification of signed bootstrap blobs (config / resolver-pool / strategy updates).
//!
//! flint's bootstrap channels deliver out-of-band payloads — an updated resolver pool, a strategy
//! list, a config blob — that must be **authenticated before they are trusted**. Each ships as a
//! **signed artifact**: a small versioned manifest plus a detached **Ed25519** signature over that
//! manifest. [`SignedBlobVerifier`] checks the signature against a caller-supplied public key,
//! enforces a monotonic version floor (anti-rollback — a correctly-signed *old* blob is still an
//! attack), and only then yields the authenticated payload. A hash proves the bytes arrived intact;
//! a signature proves *we* authored them.
//!
//! This is the generic core extracted from spark's `core::transport::wasm` `ModuleVerifier` (the
//! signed-WASM-module loader). It is payload-agnostic — the `name`/`payload` fields are opaque bytes
//! here; a consumer (spark's module loader, flint's resolver-pool loader, …) interprets them after
//! verification. The 4-byte `magic` is a parameter so each consumer namespaces its own artifacts
//! (spark keeps `b"SPKW"`; a flint resolver pool can use its own).
//!
//! # Artifact layout
//!
//! ```text
//! ┌──────────── signed payload (the signature covers exactly this) ────────────┐
//! │ magic[4] │ version: u32 BE │ name_len: u16 BE │ name │ payload_len: u32 BE │ payload │
//! └────────────────────────────────────────────────────────────────────────────┘ signature: 64 bytes
//! ```
//!
//! Signing happens in trusted tooling that holds the private key; this crate only **assembles**
//! ([`signing_payload`], [`build_artifact`]) and **verifies**. The private key never lives here.
#![forbid(unsafe_code)]

use ring::signature::{UnparsedPublicKey, ED25519};

/// Ed25519 public-key length (raw, 32 bytes).
pub const PUBKEY_LEN: usize = 32;
/// Ed25519 signature length (64 bytes).
pub const SIG_LEN: usize = 64;
/// Length of the artifact `magic` tag.
pub const MAGIC_LEN: usize = 4;
/// Smallest possible artifact: the fixed header (magic + version + name_len + payload_len) with an
/// empty name and empty payload, plus the trailing signature.
const MIN_ARTIFACT_LEN: usize = MAGIC_LEN + 4 + 2 + 4 + SIG_LEN;

/// Errors from verifying a signed blob artifact.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// The artifact is shorter than a well-formed artifact can be, or a length field runs past the
    /// end of the (authenticated) payload, or trailing bytes remain after the declared fields.
    #[error("signed artifact is truncated or malformed")]
    Truncated,
    /// The payload does not start with the verifier's expected magic.
    #[error("artifact magic does not match")]
    BadMagic,
    /// The Ed25519 signature did not verify against the configured public key.
    #[error("Ed25519 signature verification failed")]
    BadSignature,
    /// The `name` field was not valid UTF-8.
    #[error("artifact name is not valid UTF-8")]
    BadName,
    /// The blob's version is older than the caller's anti-rollback floor.
    #[error("rollback rejected: version {version} is older than the floor {floor}")]
    Rollback {
        /// The version carried by the artifact.
        version: u32,
        /// The anti-rollback floor the caller required.
        floor: u32,
    },
}

/// A verified blob, borrowed from the artifact it was parsed out of. All fields are authenticated:
/// the signature was checked over the whole payload before any field was read.
#[derive(Debug, Clone, Copy)]
pub struct VerifiedBlob<'a> {
    /// The authenticated name (e.g. a resolver-pool or transport identifier).
    pub name: &'a str,
    /// The authenticated, monotonic version. The caller advances its anti-rollback floor to this.
    pub version: u32,
    /// The authenticated, opaque payload bytes.
    pub payload: &'a [u8],
}

/// Verifies delivered blob artifacts against an Ed25519 public key. Holds only the public key — never
/// a private key.
#[derive(Debug, Clone)]
pub struct SignedBlobVerifier {
    public_key: [u8; PUBKEY_LEN],
    magic: [u8; MAGIC_LEN],
}

impl SignedBlobVerifier {
    /// Create a verifier for the given Ed25519 public key (raw 32 bytes) and artifact `magic`.
    pub fn new(public_key: [u8; PUBKEY_LEN], magic: [u8; MAGIC_LEN]) -> Self {
        Self { public_key, magic }
    }

    /// Verify and parse a signed `artifact`.
    ///
    /// `min_version` is the anti-rollback floor — the highest version installed so far; an artifact
    /// carrying a lower version is rejected. The signature is checked over the whole payload
    /// **before** any field is parsed, so the length-prefixed `name`/`payload` fields are
    /// authenticated before they are acted on. The returned [`VerifiedBlob`] borrows from `artifact`.
    pub fn verify<'a>(
        &self,
        artifact: &'a [u8],
        min_version: u32,
    ) -> Result<VerifiedBlob<'a>, VerifyError> {
        if artifact.len() < MIN_ARTIFACT_LEN {
            return Err(VerifyError::Truncated);
        }
        let (payload, signature) = artifact.split_at(artifact.len() - SIG_LEN);

        // 1. Authenticate the entire payload before trusting any byte of it.
        UnparsedPublicKey::new(&ED25519, &self.public_key)
            .verify(payload, signature)
            .map_err(|_| VerifyError::BadSignature)?;

        // 2. Parse the now-authenticated payload.
        let (name, version, blob) = parse_payload(payload, &self.magic)?;

        // 3. Reject rollbacks (a correctly-signed but stale blob).
        if version < min_version {
            return Err(VerifyError::Rollback {
                version,
                floor: min_version,
            });
        }

        Ok(VerifiedBlob {
            name,
            version,
            payload: blob,
        })
    }
}

/// Assemble the bytes a signature must cover: `magic || version || name || payload`. The detached
/// signature over this is appended to form a full artifact ([`build_artifact`]).
pub fn signing_payload(
    magic: &[u8; MAGIC_LEN],
    name: &str,
    version: u32,
    payload: &[u8],
) -> Vec<u8> {
    let name = name.as_bytes();
    let mut out = Vec::with_capacity(MAGIC_LEN + 4 + 2 + name.len() + 4 + payload.len());
    out.extend_from_slice(magic);
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&(name.len() as u16).to_be_bytes());
    out.extend_from_slice(name);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Assemble a complete signed artifact. `signature` must be the detached Ed25519 signature over
/// [`signing_payload`]`(magic, name, version, payload)`.
pub fn build_artifact(
    magic: &[u8; MAGIC_LEN],
    name: &str,
    version: u32,
    payload: &[u8],
    signature: &[u8; SIG_LEN],
) -> Vec<u8> {
    let mut out = signing_payload(magic, name, version, payload);
    out.extend_from_slice(signature);
    out
}

/// Parse an authenticated payload into `(name, version, payload)`. All lengths are bounds-checked
/// against the buffer, so a length running past the end is a [`VerifyError::Truncated`].
fn parse_payload<'a>(
    payload: &'a [u8],
    magic: &[u8; MAGIC_LEN],
) -> Result<(&'a str, u32, &'a [u8]), VerifyError> {
    let mut cur = payload;
    if take(&mut cur, MAGIC_LEN)? != magic {
        return Err(VerifyError::BadMagic);
    }
    let version = take_u32(&mut cur)?;
    let name_len = take_u16(&mut cur)? as usize;
    let name = std::str::from_utf8(take(&mut cur, name_len)?).map_err(|_| VerifyError::BadName)?;
    let blob_len = take_u32(&mut cur)? as usize;
    let blob = take(&mut cur, blob_len)?;
    if !cur.is_empty() {
        return Err(VerifyError::Truncated); // trailing bytes the layout doesn't account for
    }
    Ok((name, version, blob))
}

/// Split `n` bytes off the front of `cur`, advancing it. Errors if fewer than `n` remain.
fn take<'a>(cur: &mut &'a [u8], n: usize) -> Result<&'a [u8], VerifyError> {
    if cur.len() < n {
        return Err(VerifyError::Truncated);
    }
    let (head, tail) = cur.split_at(n);
    *cur = tail;
    Ok(head)
}

/// Read a big-endian `u32` off the front of `cur`.
fn take_u32(cur: &mut &[u8]) -> Result<u32, VerifyError> {
    let b = take(cur, 4)?;
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// Read a big-endian `u16` off the front of `cur`.
fn take_u16(cur: &mut &[u8]) -> Result<u16, VerifyError> {
    let b = take(cur, 2)?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    const MAGIC: [u8; 4] = *b"FLNT";

    fn keypair() -> Ed25519KeyPair {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate key");
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse key")
    }

    fn public_key(kp: &Ed25519KeyPair) -> [u8; 32] {
        let mut k = [0u8; 32];
        k.copy_from_slice(kp.public_key().as_ref());
        k
    }

    /// Sign `(name, version, payload)` with `kp` under `MAGIC` and return the full artifact.
    fn sign(kp: &Ed25519KeyPair, name: &str, version: u32, payload: &[u8]) -> Vec<u8> {
        let signature = kp.sign(&signing_payload(&MAGIC, name, version, payload));
        let mut sig = [0u8; 64];
        sig.copy_from_slice(signature.as_ref());
        build_artifact(&MAGIC, name, version, payload, &sig)
    }

    #[test]
    fn verifies_and_returns_the_authenticated_blob() {
        let kp = keypair();
        let artifact = sign(&kp, "resolver-pool", 7, b"<signed config bytes>");
        let blob = SignedBlobVerifier::new(public_key(&kp), MAGIC)
            .verify(&artifact, 0)
            .expect("verify");
        assert_eq!(blob.name, "resolver-pool");
        assert_eq!(blob.version, 7);
        assert_eq!(blob.payload, b"<signed config bytes>");
    }

    #[test]
    fn empty_name_and_payload_round_trip() {
        let kp = keypair();
        let artifact = sign(&kp, "", 1, b"");
        let blob = SignedBlobVerifier::new(public_key(&kp), MAGIC)
            .verify(&artifact, 0)
            .expect("verify");
        assert_eq!(blob.name, "");
        assert_eq!(blob.payload, b"");
    }

    #[test]
    fn rejects_tampered_payload() {
        let kp = keypair();
        let mut artifact = sign(&kp, "pool", 1, b"abcdefgh");
        let idx = artifact.len() - 64 - 4; // a byte inside the payload region
        artifact[idx] ^= 0xff;
        assert!(matches!(
            SignedBlobVerifier::new(public_key(&kp), MAGIC).verify(&artifact, 0),
            Err(VerifyError::BadSignature)
        ));
    }

    #[test]
    fn rejects_a_different_key() {
        let signer = keypair();
        let attacker_view = keypair();
        let artifact = sign(&signer, "pool", 1, b"data");
        assert!(matches!(
            SignedBlobVerifier::new(public_key(&attacker_view), MAGIC).verify(&artifact, 0),
            Err(VerifyError::BadSignature)
        ));
    }

    #[test]
    fn rejects_wrong_magic() {
        // A correctly-signed artifact whose magic the verifier doesn't expect must reach BadMagic —
        // proving the parse runs on authenticated bytes (signature checked first), not that magic
        // gates the signature.
        let kp = keypair();
        let artifact = sign(&kp, "pool", 1, b"data");
        assert!(matches!(
            SignedBlobVerifier::new(public_key(&kp), *b"XXXX").verify(&artifact, 0),
            Err(VerifyError::BadMagic)
        ));
    }

    #[test]
    fn rejects_rollback_but_accepts_current_and_newer() {
        let kp = keypair();
        let artifact = sign(&kp, "pool", 3, b"data");
        let verifier = SignedBlobVerifier::new(public_key(&kp), MAGIC);
        // Floor 5: a v3 blob is a rollback.
        assert!(matches!(
            verifier.verify(&artifact, 5),
            Err(VerifyError::Rollback {
                version: 3,
                floor: 5
            })
        ));
        // Floor 3 (re-install of the current version) and floor 0 (older floor) are accepted.
        assert!(verifier.verify(&artifact, 3).is_ok());
        assert!(verifier.verify(&artifact, 0).is_ok());
    }

    #[test]
    fn rejects_truncated_artifact() {
        let kp = keypair();
        assert!(matches!(
            SignedBlobVerifier::new(public_key(&kp), MAGIC).verify(b"too short", 0),
            Err(VerifyError::Truncated)
        ));
    }

    #[test]
    fn rejects_trailing_bytes_after_declared_fields() {
        // A correctly-signed payload with an extra byte the layout doesn't account for is Truncated.
        let kp = keypair();
        let mut payload = signing_payload(&MAGIC, "pool", 1, b"data");
        payload.push(0xaa); // trailing junk, inside the signed region
        let signature = kp.sign(&payload);
        let mut artifact = payload;
        artifact.extend_from_slice(signature.as_ref());
        assert!(matches!(
            SignedBlobVerifier::new(public_key(&kp), MAGIC).verify(&artifact, 0),
            Err(VerifyError::Truncated)
        ));
    }
}
