# flint

**Censorship-resistant bootstrap dialing + resilient DNS, as reusable Rust crates.**

Flint strikes the spark. Before a circumvention tool can build a tunnel it has to make a *first hop*
under hostile conditions — resolve a name whose answer the censor is poisoning, then reach a config /
API host whose IP the censor is blocking. Flint is that first hop, factored out of any one tool so
several can share it.

Its kernel is a **composable `BootstrapDial` engine**: a bootstrap TLS connection expressed as a
*stack of independent, swappable tactics* —
`endpoint × transport × TLS-engine + ClientHello-profile × SNI/ECH × wire-shaping`. Its first
consumer is a **resilient DoH resolver** (diverse pool, race → validate → cache) that returns
un-poisoned DNS in censored regions. Domain fronting, a signed cloud-blob "dead-drop" fetch, and
proxyless dialing are later consumers of the same engine.

See [`docs/design.md`](docs/design.md) for the full design, and
[`docs/extraction-plan.md`](docs/extraction-plan.md) for how this is being assembled.

## Layout

| Crate | What it owns |
|---|---|
| `flint-verify` | Ed25519 verification of signed bootstrap blobs (config / strategy updates). |
| `flint-shaping` | Wire-shaping primitives: `tcp_split` (TCP-segment) + `record_fragment` (TLS-record). |
| `flint-tls` | Chrome-mimicry TLS: the boring Chrome-ClientHello connector, the gambit CH genome, JA4. |
| `flint-dial` | The composable `BootstrapDial` engine — executes a strategy `(endpoint, transport, engine, ch_profile, sni_tactic, wire_plan)`. |
| `flint-dns` | The resilient DoH resolver + a minimal A/AAAA DNS codec (first `BootstrapDial` consumer). |

## Relationship to spark

These crates began as modules inside [`getlantern/spark`](https://github.com/getlantern/spark)'s
`core` crate (`anytls::tls`, `gambit`, `shaping`, `ja4`, `wasm::ModuleVerifier`). They are being
**extracted here so the dependency points the other way**: flint owns the primitives, and spark — and
other tools — depend back on flint. The extraction is sequenced to keep spark green at every step; see
[`docs/extraction-plan.md`](docs/extraction-plan.md).

## Status

**Phase 1 complete** — all five crates are implemented and tested (the [extraction
plan](docs/extraction-plan.md) tracks the phases). `flint-dns` resolves a real name by racing the DoH
pool over composable bootstrap dials. Pure-Rust, `rustls`+`ring` baseline; the boring Chrome-mimicry
engine is feature-gated so the default build stays rustls-only, and a weekly CI job keeps it tracking
Chrome (`.github/workflows/update-mimicry.yml`, gated on the JA4 anchor).

Per-network caching of the winning dial, CDN-edge pool entries, and Ed25519-signed pool updates are
all in. The rustls baseline TLS engine is **deferred by design** — boring is the mimicry default and
is used as much as possible, so rustls is only worth adding for real ECH (boring greases only) or a
no-cmake fallback (design §11). Next: flipping the repo public and pointing spark at it (Phases 2–3).
Binary-size-conscious (mirrors spark's locked stack).

## License

MIT for now; this repo will dual-license **MIT OR Apache-2.0** before it goes public.
