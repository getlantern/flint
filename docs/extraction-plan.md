# flint — extraction plan

Flint's foundation crates are being extracted from spark's `core` crate. The dependency direction is
flipping: today spark's bootstrap design *reuses* `core::transport::{anytls::tls, gambit, ja4,
shaping, wasm}`; after extraction **flint owns these and spark depends back on flint**.

Hard rule (inherited from spark's `CLAUDE.md`): **one bounded chunk per session, spark stays green**
(`cargo build` / `cargo test` / `cargo clippy -- -D warnings`) at every boundary. Each step is its own
pair of PRs: land the crate in flint, then a spark PR that swaps the in-tree module for the flint
dependency and deletes the old code.

## Target dependency graph

```
flint-verify     flint-shaping        flint-tls
      \               |               /  (boring feature-gated)
       \              |              /
        \             v             /
         +------>  flint-dial  <---+        (the BootstrapDial engine)
                      |
                      v
                  flint-dns                 (resilient DoH resolver + codec)
```

## Sequence (innermost / smallest first)

1. **`flint-verify`** — move `core::transport::wasm::ModuleVerifier` (Ed25519). Smallest, no deps.
   Spark swap: `wasm` verifier → `flint_verify`. Gate: spark green; verifier unit tests pass in flint.
2. **`flint-shaping`** — move `core::transport::shaping` (`WirePlan`, `SegmentShapingStream` =
   `tcp_split`). Then **add `record_fragment`** (the new Layer-B TLS-record-fragmentation shim the
   design specs but spark never built). Spark swap: `shaping` → `flint_shaping`.
3. **`flint-tls`** — move the Chrome-mimicry stack: `anytls::tls::configure` + `anytls::profile::Profile`
   (the boring Chrome-137 connector), `gambit` (`ClientHello` / `Records` genome), `ja4`. Boring is
   **feature-gated** (`boring`), default build rustls-only — mirrors spark's `anytls` feature. The
   spark swap touches `anytls` *and* `samizdat` (both consume the connector); the most careful step.
4. **`flint-dial`** — *new code*: the composable engine that executes a `BootstrapStrategy` tuple over
   flint-tls + flint-shaping, with capability gating (boring Chrome-JA4 vs rustls real-ECH).
5. **`flint-dns`** — *new code*: the resilient DoH resolver (race → validate → per-network cache) + a
   minimal A/AAAA query/response codec; consumes flint-dial. (See `design.md` §6 and §10 build order.)

Steps 1–3 are *moves* (keep spark green by swapping deps); 4–5 are *new* (flint-only until spark wires
the resolver into its bootstrap path).

## Consuming from spark

While iterating, spark depends on flint by git (or `path` for a local checkout):

```toml
# spark/core/Cargo.toml (during extraction)
flint-verify  = { git = "https://github.com/getlantern/flint" }
flint-shaping = { git = "https://github.com/getlantern/flint" }
flint-tls     = { git = "https://github.com/getlantern/flint", features = ["boring"] }
```

Per the user's global Go-dep rule's spirit (pin + tidy together): pin each flint dep to a commit and
update spark's `Cargo.lock` in the same commit as the swap.
