//! The composable `BootstrapDial` engine.
//!
//! A bootstrap TLS connection is data, not code: a `BootstrapStrategy` =
//! `(endpoint, transport, engine, ch_profile, sni_tactic, wire_plan)` that this engine *executes*
//! over `flint-tls` + `flint-shaping`, verifying signed updates with `flint-verify`. Capability
//! gating keeps the boring Chrome-JA4 and rustls real-ECH compositions as two competing strategies
//! the success signal chooses between. See `docs/design.md` §4.

// TODO(extraction step 4): build the engine over flint-tls / flint-shaping / flint-verify.
