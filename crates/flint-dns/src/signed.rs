//! Ed25519-signed resolver-pool updates (design §6) — built on [`flint_verify`].
//!
//! The bootstrap config can ship a fresh resolver pool without a client release: a small
//! **Ed25519-signed artifact** the client fetches (over the working DoH path, or any bootstrap
//! channel) and **verifies before trusting**. Because the payload is authenticated and anti-rollback
//! protected, the delivery channel needs only integrity of a small blob, not confidentiality.
//!
//! This is the resolver-pool *consumer* of the generic [`flint_verify::SignedBlobVerifier`]: the
//! verifier checks the magic + signature + monotonic version, and this module postcard-decodes the
//! authenticated payload into [`Resolver`]s. Signing happens in trusted tooling that holds the private
//! key ([`pool_signing_payload`] + [`build_pool_artifact`] assemble the bytes); the client only ever
//! verifies.

use flint_verify::{SignedBlobVerifier, VerifyError, SIG_LEN};

use crate::pool::Resolver;

/// Artifact magic for a flint resolver-pool update, v1. Bump (e.g. `FRP2`) on a schema change so an
/// old client rejects a new-format pool rather than mis-decoding it.
pub const POOL_MAGIC: [u8; 4] = *b"FRP1";

/// Errors loading a signed pool update.
#[derive(Debug, thiserror::Error)]
pub enum SignedPoolError {
    /// The artifact failed signature / magic / anti-rollback verification.
    #[error(transparent)]
    Verify(#[from] VerifyError),
    /// The authenticated payload did not decode as a resolver pool.
    #[error("resolver-pool decode failed: {0}")]
    Codec(String),
}

/// A verified pool update: the resolvers plus the artifact's monotonic version. The caller advances
/// its anti-rollback floor to [`version`](Self::version) after accepting it.
#[derive(Debug, Clone)]
pub struct PoolUpdate {
    /// The authenticated resolver list.
    pub resolvers: Vec<Resolver>,
    /// The artifact's version (the new anti-rollback floor).
    pub version: u32,
}

/// Verify a signed pool `artifact` against `public_key` and the anti-rollback `min_version`, then
/// decode the authenticated payload into a [`PoolUpdate`]. Verification happens **before** any byte of
/// the pool is decoded.
pub fn load_signed_pool(
    artifact: &[u8],
    public_key: [u8; 32],
    min_version: u32,
) -> Result<PoolUpdate, SignedPoolError> {
    let blob = SignedBlobVerifier::new(public_key, POOL_MAGIC).verify(artifact, min_version)?;
    let resolvers: Vec<Resolver> =
        postcard::from_bytes(blob.payload).map_err(|e| SignedPoolError::Codec(e.to_string()))?;
    Ok(PoolUpdate {
        resolvers,
        version: blob.version,
    })
}

/// Tooling helper: the bytes a signature must cover for a pool update `(name, version, resolvers)`.
/// Trusted tooling signs this with the pool private key, then calls [`build_pool_artifact`] with the
/// resulting 64-byte signature. (No private key is involved here.)
pub fn pool_signing_payload(
    name: &str,
    version: u32,
    resolvers: &[Resolver],
) -> Result<Vec<u8>, SignedPoolError> {
    let payload =
        postcard::to_stdvec(resolvers).map_err(|e| SignedPoolError::Codec(e.to_string()))?;
    Ok(flint_verify::signing_payload(
        &POOL_MAGIC,
        name,
        version,
        &payload,
    ))
}

/// Tooling helper: assemble the full signed artifact from `(name, version, resolvers)` and the
/// detached Ed25519 `signature` over [`pool_signing_payload`].
pub fn build_pool_artifact(
    name: &str,
    version: u32,
    resolvers: &[Resolver],
    signature: &[u8; SIG_LEN],
) -> Result<Vec<u8>, SignedPoolError> {
    let payload =
        postcard::to_stdvec(resolvers).map_err(|e| SignedPoolError::Codec(e.to_string()))?;
    Ok(flint_verify::build_artifact(
        &POOL_MAGIC,
        name,
        version,
        &payload,
        signature,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn keypair() -> Ed25519KeyPair {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate");
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse")
    }

    fn public_key(kp: &Ed25519KeyPair) -> [u8; 32] {
        let mut k = [0u8; 32];
        k.copy_from_slice(kp.public_key().as_ref());
        k
    }

    fn sample_pool() -> Vec<Resolver> {
        vec![
            Resolver {
                name: "edge".into(),
                target: "104.16.249.249:443".parse().unwrap(),
                sni: "cloudflare-dns.com".into(),
                host: "cloudflare-dns.com".into(),
                path: "/dns-query".into(),
            },
            Resolver {
                name: "quad9".into(),
                target: "9.9.9.10:443".parse().unwrap(),
                sni: "dns.quad9.net".into(),
                host: "dns.quad9.net".into(),
                path: "/dns-query".into(),
            },
        ]
    }

    /// Sign `(version, pool)` with `kp` under the pool magic, returning the full artifact.
    fn sign(kp: &Ed25519KeyPair, version: u32, pool: &[Resolver]) -> Vec<u8> {
        let payload = pool_signing_payload("default", version, pool).unwrap();
        let mut sig = [0u8; SIG_LEN];
        sig.copy_from_slice(kp.sign(&payload).as_ref());
        build_pool_artifact("default", version, pool, &sig).unwrap()
    }

    #[test]
    fn verifies_and_decodes_a_signed_pool() {
        let kp = keypair();
        let pool = sample_pool();
        let artifact = sign(&kp, 7, &pool);

        let update = load_signed_pool(&artifact, public_key(&kp), 0).expect("load");
        assert_eq!(update.version, 7);
        assert_eq!(update.resolvers, pool); // postcard round-trip, incl. SocketAddr
    }

    #[test]
    fn rejects_rollback_tamper_and_wrong_key() {
        let kp = keypair();
        let pool = sample_pool();
        let artifact = sign(&kp, 5, &pool);

        // anti-rollback: a floor above the artifact's version rejects it (re-installing the *same*
        // version is allowed, so floor 6 rejects a v5 pool; floor 5 would accept it).
        assert!(matches!(
            load_signed_pool(&artifact, public_key(&kp), 6),
            Err(SignedPoolError::Verify(VerifyError::Rollback { .. }))
        ));
        assert!(load_signed_pool(&artifact, public_key(&kp), 5).is_ok()); // same version = idempotent

        // tamper: flip a payload byte → signature fails.
        let mut tampered = artifact.clone();
        let i = tampered.len() - SIG_LEN - 1;
        tampered[i] ^= 0xff;
        assert!(matches!(
            load_signed_pool(&tampered, public_key(&kp), 0),
            Err(SignedPoolError::Verify(VerifyError::BadSignature))
        ));

        // wrong key.
        let attacker = keypair();
        assert!(matches!(
            load_signed_pool(&artifact, public_key(&attacker), 0),
            Err(SignedPoolError::Verify(VerifyError::BadSignature))
        ));
    }
}
