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

Scaffold. The crates are stubs; primitives land one bounded, keep-green chunk at a time per the
extraction plan. Pure-Rust, `rustls`+`ring` baseline; the boring Chrome-mimicry engine is
feature-gated so the default build stays rustls-only. Binary-size-conscious (mirrors spark's locked
stack).

## License

MIT for now; this repo will dual-license **MIT OR Apache-2.0** before it goes public.
