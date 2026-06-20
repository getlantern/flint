//! Ed25519 verification of signed bootstrap blobs (config / strategy updates).
//!
//! Foundation crate for flint. Homes the signed-blob verifier being extracted from spark's
//! `core::transport::wasm::ModuleVerifier` — see `docs/extraction-plan.md` step 1. flint's bootstrap
//! channels carry only Ed25519-signed payloads, so a consumer needs integrity + authenticity of a
//! small blob, not tunnel confidentiality.
#![forbid(unsafe_code)]

// TODO(extraction step 1): move `ModuleVerifier` here from spark `core::transport::wasm`.
