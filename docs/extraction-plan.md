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
3. **`flint-tls`** ✅ — moved the Chrome-mimicry stack: the boring Chrome-137 connector (`connector`,
   ex `anytls::tls`), `Profile` (the boring executor mapping), the `gambit` genome, `ja4`, and the
   `anchor` JA4 drift test. Boring is **feature-gated** (`boring`, with `pq-experimental` +
   `cert-compression`), default build rustls-only. The JA4 anchor reproduces spark's exact
   `t13d1516h2_8daaf6152771_d8a2da3f94cd`. Auto-update of the mimicry libs is wired in CI
   (`.github/workflows/update-mimicry.yml`): a weekly bump gated on build + the JA4 anchor. The spark
   swap (Phase 3) touches `config`, `discovery`, `wasm`, `anytls`, *and* `samizdat` (all consume
   `gambit`/`profile`/`ja4`/the connector); the most careful swap.
4. **`flint-dial`** — *new code*: the composable engine that executes a `BootstrapStrategy` tuple over
   flint-tls + flint-shaping, with capability gating (boring Chrome-JA4 vs rustls real-ECH).
5. **`flint-dns`** — *new code*: the resilient DoH resolver (race → validate → per-network cache) + a
   minimal A/AAAA query/response codec; consumes flint-dial. (See `design.md` §6 and §10 build order.)

Steps 1–3 are *moves* (the eventual spark swap replaces the in-tree module with a flint dep); 4–5 are
*new* (flint-only until spark wires the resolver into its bootstrap path).

## Sequencing (flint starts private)

Because flint is **private at first**, spark cannot cleanly `git`-depend on it from CI without a
deploy key / token, and committing a `path` dep into spark would break a standalone `spark` clone. So
the extraction runs in two phases instead of interleaved flint-PR/spark-PR pairs:

1. **Phase 1 — build flint out while private.** Land each crate (steps 1–5) in flint with its own
   tests. spark is **untouched and stays green** the whole time; flint just *duplicates* the relevant
   code until the swap. (`flint-verify` ✅, `flint-shaping` ✅, `flint-tls` ✅ — steps 1–3 done.)
2. **Phase 2 — flip flint public**, dual-license MIT/Apache-2.0.
3. **Phase 3 — spark swaps.** Per-crate PRs that point spark at the public flint by git, delete the
   in-tree copy, and keep spark green (`cargo build` / `test` / `clippy -- -D warnings`).

(If we instead want spark consuming flint *before* the flip, the alternatives are a git dep + a CI
secret for the private repo, or a local-only `path` dep that is never committed to spark's main branch.)

## Consuming from spark (Phase 3)

```toml
# spark/core/Cargo.toml — flint deps gated behind the matching feature, so the base build is unchanged
[dependencies]
flint-verify  = { git = "https://github.com/getlantern/flint", rev = "…", optional = true }
flint-shaping = { git = "https://github.com/getlantern/flint", rev = "…" }
flint-tls     = { git = "https://github.com/getlantern/flint", rev = "…", optional = true }

[features]
wasm-transport = ["dep:flint-verify", …]   # flint-verify only needed where the signed loader is
anytls         = ["dep:flint-tls", …]       # the boring Chrome-CH engine
```

Per the user's global Go-dep rule's spirit (pin + tidy together): pin each flint dep to a commit and
update spark's `Cargo.lock` in the same commit as the swap.
