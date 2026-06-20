# flint — design: resilient DoH over a composable `BootstrapDial`

- **Status:** Proposed — 2026-06-20. Research-grounded (kindling, the Outline SDK smart-dialer, the
  circumvention corpus). This is **flint's** bootstrap layer (reaching API/config hosts on startup
  under censorship), reusable across tools; it establishes the composable dialing engine the rest of
  the bootstrap layer builds on. spark is the first consumer.
- **Scope:** A censorship-resistant **DNS resolution** layer that returns un-poisoned answers in
  censored regions, built on two things: (a) a **composable TLS-dialing strategy engine**
  (`BootstrapDial`, `flint-dial`) over flint's own gambit / shaping / boring machinery, and (b) a
  **resilient DoH resolver** (`flint-dns`; diverse pool, race → validate → cache) as its first
  consumer.
- **Builds on (now homed in flint — see `extraction-plan.md`):** the opening-gambit genome
  (`flint-tls`: gambit + `profile::for_boring`), the boring2 Chrome-mimicry TLS connector and JA4
  (`flint-tls`, ex `anytls::tls::configure`), wire shaping (`flint-shaping`), and Ed25519 verification
  (`flint-verify`, ex `wasm::ModuleVerifier`). These began as modules in spark's `core` crate (ADR
  0001, ADR 0006, the samizdat work); flint owns them and spark depends back.

---

## 1. Goal & scope

Spark currently loads config from a file/flags only — it has **no way to reach Lantern's
infrastructure on startup to fetch initial proxy configs**, and the very first hop of doing so is
DNS, which is the censor's cheapest and most common block (poisoned answers). This layer makes DNS
resolution survive that.

**In scope (v1):**
- A `BootstrapDial` engine: a bootstrap TLS connection expressed as a **composition** of swappable
  tactics (engine + ClientHello profile + SNI/ECH + wire shaping + endpoint/transport).
- A **resilient DoH resolver**: a diverse, signed-updatable resolver pool; a smart-dialer that races
  compositions, takes the first **validated** answer, and caches the winner per network; answer
  validation (poison rejection).
- Reuse of the boring2 Chrome ClientHello as the **default for DNS-over-TLS**, plus composable
  `tcp_split` (existing) and `record_fragment` (**new**) shaping.
- DoH/443 first; DoT/853 as a second transport (port diversity).

**Out of scope (this doc), explicitly:**
- The other bootstrap config-fetch transports — **domain fronting, the S3/cloud-blob "dead-drop"
  fetch, and proxyless dialing** — all consume the *same* `BootstrapDial` engine; DNS is just its
  first consumer. They get their own design once the engine lands.
- DNS-over-QUIC (DoQ/853-udp) — adds a QUIC dependency; deferred.
- A full DNS *tunnel* (dnstt-style over DoH) as a last-resort low-bandwidth channel — deferred; it's
  a heavier, separate carrier, not part of the resolver fast path.

## 2. Background & threat model

DNS poisoning/injection is the dominant first-layer block: Iran returns injected `10.10.34.x` for
>90% of censored-domain queries (`2025-aryapour-stealth-blackout`), and the GFW injects forged
A/AAAA (and, since 2026, SVCB/type-65) records.

**The reframe that makes this tractable:** DoH is **encrypted transport**, so a censor *cannot
poison a DoH answer* — it can only **block the connection**. That collapses "get uncensored DNS"
into "reach *any one* DoH resolver," which is the same proxyless/fronting problem spark already
reasons about. (Caveat: DoH *traffic* is itself classifiable — ~85% AUC in
`2026-lian-decompose-understand-fuse` — which is exactly why the DoH connection must be dialed with a
**browser-identical ClientHello**; see §7.)

**A second caveat that shapes the design:** censors also block on the *presence of encryption
metadata*, not just the payload. The GFW has dropped/reset TLS handshakes carrying **Encrypted SNI
since 2020** (`2020-gfw-esni-blocking`), and ECH — the standardized successor — is just as visible
(an `encrypted_client_hello` extension in an otherwise-cleartext ClientHello), so a censor can apply
the same presence-based rule to it. **Hostname-hiding via ECH is therefore not assumable in the
hardest regions.** It is one tactic among many, never a dependency: the resolver must still be
reachable with a *non-ECH* composition (CDN-edge IP + an innocuous real SNI + record/segment
fragmentation), which the dialer races alongside the ECH variant so it degrades gracefully where ECH
presence is blocked. This demotes ECH from "the answer" to "additive where it's permitted"
throughout (see §6, §7).

## 3. Prior art

**kindling** (Lantern, Go) is the canonical bootstrap library ("ideal for accessing configuration
files during the bootstrapping phase"). It races redundant transports behind one HTTP client. Its
DNS resilience comes from the **Outline SDK smart-dialer**, configured by `smart_dialer_config.yml`,
which is exactly the model here — a pool of DoH resolvers × TLS evasion strategies, raced:

```yaml
dns:
  - system: {}                                                  # works where uncensored
  - https: {name: cloudflare-dns.com, address: cloudflare.net}  # DoH via a high-collateral CDN edge
  - https: {name: doh.dns.sb, address: cloudflare.net:443}      # 3rd-party DoH, also via the CDN edge
  - https: {name: "8.8.4.4"}        # raw-IP DoH (Google) — works because the cert carries IP SANs
  - https: {name: "1.0.0.1"}        #            (Cloudflare)
  - https: {name: "223.5.5.5"}      #            (AliDNS)   + IPv6 variants of each
tls:
  - ""                              # direct
  - split:1 / split:2,20*5 / split:200|disorder:1   # TCP ClientHello splitting (+ zero-TTL disorder)
  - tlsfrag:1                       # TLS record fragmentation
```

Three DoH addressing forms are visible and all carry over: **raw-IP** (no bootstrap-DNS
chicken-and-egg; works because Google/Cloudflare/Quad9 put IP SANs in their certs),
**DoH-via-high-collateral-CDN-edge** (reach the resolver through a CDN range that's collateral-
expensive to block — the strongest), and **hostname**. spark's resilient DoH = this, but with
spark's boring Chrome CH as the default TLS engine and spark's `shaping/` primitives as the
fragmentation tactics — i.e. the Outline smart-dialer *re-expressed as an ADR-0006 gambit search*.

## 4. The composable `BootstrapDial` engine

A bootstrap TLS connection is **not one fixed thing** — it is a **stack of independent, swappable
layers**, each already a spark module. This is ADR 0006's gambit genome, generalized from "the
AnyTLS handshake" to "any bootstrap dial."

```
endpoint      ── raw-IP | CDN-edge-fronted | hostname                 (resolver/host pool)
   ×
transport     ── DoH/443 | DoT/853 | (DoQ/853-udp later)
   ×
TLS engine    ── boring2 Chrome-137 profile   ← default for DNS-over-TLS (§7)
                 | rustls (baseline)
   ×
SNI tactic    ── real SNI | fronting SNI | ECH (hide it — additive, may itself be blocked; §2/§7)
   ×
wire shaping  ── none | tcp_split | record_fragment | (+ inter-segment delay / disorder)   (§5)
```

| Layer | flint crate (ex-spark module) |
|---|---|
| TLS engine + Chrome CH | `flint-tls` — `configure(&Profile)` (boring2 Chrome-137 connector, JA4 == real Chrome; ex `anytls::tls`) |
| CH knobs / genome | `flint-tls` — gambit `{ClientHello, Records}` + `Profile::for_boring` (capability-gated) |
| `tcp_split` shaping | `flint-shaping` — `{WirePlan, SegmentShapingStream}` (Layer C — already built; ex `shaping`) |
| `record_fragment` shaping | `flint-shaping` — **new** record-reframing shim (Layer B — §5) |
| ECH | rustls ECH (real) / boring2 ECH-grease (capability-gated per engine) |
| signed pool/strategy updates | `flint-verify` — Ed25519 (ex `wasm::ModuleVerifier`) |

**A `BootstrapStrategy` is data, not code** — a tuple `(endpoint, transport, engine, ch_profile,
sni_tactic, wire_plan)` that the engine *executes*. The dialer is handed a *set* of strategies.

**Capability gating (the engine split).** Real ECH lives in rustls; exact Chrome-JA4 lives in
boring2 (which today does ECH-*grease*, not real ECH). You can't trivially have both in one
ClientHello, so a strategy **picks an engine**, and a `for_boring`-style capability check decides
which knobs are realizable. The dialer treats "rustls + real-ECH + generic-CH" and "boring +
Chrome-JA4 + grease-ECH" as **two competing compositions** and lets the success signal choose — it
does not try to merge them.

## 5. Wire-shaping primitives: `tcp_split` (have) + `record_fragment` (new)

These are two *distinct* levers (ADR 0006 Layer C vs Layer B). spark has only the first today.

| | `tcp_split` (Layer C, exists) | **`record_fragment` (Layer B, new)** |
|---|---|---|
| What's split | the **byte stream** across TCP segments; the ClientHello stays one TLS record | the **ClientHello**, re-emitted as *multiple TLS records* (each with its own `16 03 01 <len>` header) |
| Defeats | DPI matching SNI within one packet | DPI that inspects only the first TLS record / doesn't reassemble handshake messages across records |
| Survives censor **TCP reassembly** | ❌ (reassembled back) | ✅ (it's above TCP — fragmentation is in the record structure) |
| spark today | `SegmentShapingStream` | — |

**`record_fragment` implementation:** a small, pure-Rust **record-reframing shim** — sibling to
`SegmentShapingStream` in `shaping/`, sitting between the TLS engine and the socket. On the first
write it parses the outgoing ClientHello record (`type=0x16`, `legacy_version`, u16 length) and
**re-emits its payload as N records** (`16 03 01 <len_i>` + chunk), cut to straddle the SNI
extension, leaving the inner handshake-message bytes untouched (the peer concatenates record payloads
per RFC 8446 §5.1). Everything after the CH passes through. **Engine-agnostic** — neither boring2 nor
rustls fragments the CH across records natively, so the shim is the right approach *and* it composes
under either engine. Compat caveat: a few middleboxes mishandle a fragmented CH — handled by the
fact that the smart-dialer only keeps a tactic that *raises* the success rate.

Both shaping tactics are orthogonal and composable (`none` / `tcp_split` / `record_fragment` /
both, + delay/disorder), under either TLS engine. Building `record_fragment` also closes a real gap:
ADR 0006 specced Layer B but only Layer C was ever built.

## 6. The resilient DoH resolver (first `BootstrapDial` consumer)

**Resolver pool** — entries of `(provider, transport, endpoint{raw-ip | cdn-edge-front | hostname},
strategy hints)`, **baked-in and Ed25519-signed-updatable** (the bootstrap config can ship a fresh
list without a client release). Curated for **diversity across providers AND ASNs AND jurisdictions
AND transports**, not raw IP count — blocking `1.1.1.1`/`8.8.8.8` is one cheap censor rule, so the
pool's value is the *spread*. The **spearhead is DoH reached over a high-collateral CDN/cloud edge**
(blocking that edge range is collateral-expensive — the durable property); ECH is layered on top
*where it's permitted* but is never required (§2). Three addressing forms compose with each provider:
**raw-IP** (no bootstrap-DNS chicken-and-egg; works wherever the cert carries IP SANs),
**CDN-edge-front** (reach the resolver through a collateral-expensive range), and **hostname**.

**Provider survey (diverse pool — v1 candidates).** Beyond the usual Cloudflare/Google/OpenDNS, the
pool deliberately spreads across operators, hosting ASNs, and *legal jurisdictions* — a censor that
pressures or IP-blocks one operator shouldn't reach the others:

| Provider | DoH endpoint (raw IPs) | Hosting / ASN | Jurisdiction | Filtering / poisoning | Role |
|---|---|---|---|---|---|
| Cloudflare | `cloudflare-dns.com` (1.1.1.1 / 1.0.0.1) | Cloudflare anycast (AS13335) | US | none | **CDN-edge spearhead**; `mozilla.cloudflare-dns.com` alias; IP-SAN cert (raw-IP works) |
| Google | `dns.google` (8.8.8.8 / 8.8.4.4) | Google anycast (AS15169) | US | none | high-collateral edge; IP-SAN cert |
| Quad9 | `dns.quad9.net` (9.9.9.9, 149.112.112.112; **9.9.9.10** = no-block) | anycast via PCH + SWITCH & partners | **Switzerland** (Quad9 Foundation, Swiss law) | malware/phishing block on `.9` only | **jurisdiction diversity**; DNSSEC; IP-SAN cert — see note |
| Mullvad | `dns.mullvad.net` (194.242.2.2) | Mullvad infra | **Sweden**, no-log | none (base endpoint) | privacy/jurisdiction diversity |
| DNS0.eu | `dns0.eu` (193.110.81.0) | anycast | **EU non-profit** | optional (use base) | EU jurisdiction diversity |
| AdGuard | `dns.adguard-dns.com` (94.140.14.140) | own + partial Cloudflare | Cyprus | ad/tracker variants — use **unfiltered** endpoint | diversity |
| NextDNS | `dns.nextdns.io` | anycast (own + edge) | US / config | config-driven | diversity |
| dns.sb | `doh.dns.sb` (+ **frontable via `cloudflare.net` edge**, per kindling) | xTom anycast | — | none | CDN-edge-frontable diversity |
| OpenDNS | `doh.opendns.com` (208.67.222.222) | Cisco anycast (AS36692) | US | optional category filtering | diversity |
| AliDNS *(public)* | `dns.alidns.com` (223.5.5.5 / 223.6.6.6) | Alibaba **China** (AS37963/AS45102, Hangzhou) | **China** | **⚠ policy-bound — censors/poisons sensitive names** | **untrusted** — see note |
| *self-hosted* | our DoH on an **Alibaba Cloud overseas** IP (e.g. us-east-1 Virginia, ap-southeast-1 Singapore) | Alibaba Cloud international ASN | outside CN policy | honest (we operate it) | **collateral-freedom play** — see note |

*(v4 **and** v6 addresses for each; the signed update can add/retire entries between releases.)*

**Quad9 note.** A strong addition precisely because its differentiator is *jurisdictional*, not
technical: the Quad9 Foundation relocated to Zürich in 2021 and is entirely subject to Swiss privacy
law — no US/CN legal compulsion to log or tamper. It is anycast (so widely reachable), publishes IP
SANs (raw-IP DoH works with no bootstrap DNS), and does DNSSEC. One caveat for *our* use: the primary
`9.9.9.9` does malware/phishing **threat-blocking**, which could `NXDOMAIN` a config host that landed
on a blocklist; for bootstrap, prefer **`9.9.9.10`** (no blocking, also `dns10.quad9.net`). Its IPs
are well-known and thus cheaply IP-blockable, so pair Quad9 with the CDN-edge/fragmentation tactics
rather than relying on the raw IP alone.

**Alicloud note (answering "is there a non-poisoning AliDNS, maybe a US one?").** Two distinct things,
and only one is usable:
- **Public AliDNS (`223.5.5.5` / `dns.alidns.com`, incl. the HTTPDNS-DoH product) is the wrong tool.**
  It is operated *inside China* on Alibaba's Chinese ASNs and is legally bound to Chinese DNS policy,
  so it returns censored/forged answers for sensitive names. There is **no separate "honest US AliDNS"
  public endpoint** — the HTTPDNS DoH product routes back to the same `alidns.com` policy backend.
  Keep it in the pool only for *operational diversity on our own non-sensitive config hostnames*, and
  even then treat it as **untrusted** and run every answer through the validation layer (below). Never
  trust it for an arbitrary name.
- **The real Alicloud play is collateral freedom at the *infrastructure* layer: run our own DoH on an
  Alibaba Cloud *overseas* region** (us-east-1 Virginia, us-west-1 Silicon Valley, ap-southeast-1
  Singapore, eu-central-1 Frankfurt). Such a node (a) sits outside CN DNS-policy jurisdiction so it
  resolves honestly, and (b) lives in an Alibaba-Cloud-international range that carries legitimate
  Chinese-company cross-border commerce — a range the GFW is economically reluctant to wholesale-block.
  The collateral is real but *narrower* than a global CDN anycast edge (the GFW can selectively block
  individual Alicloud-international prefixes), so this is a valuable diversity/jurisdiction entry, not a
  replacement for the CDN-edge spearhead. (Same template applies to a self-hosted DoH on Tencent
  Cloud International, AWS, GCP, etc.)

**Smart-dialer** — race/stagger (resolver × strategy) compositions (happy-eyeballs), take the first
that returns a **validated** answer, and **cache the winning composition per network** (keyed on a
network fingerprint — gateway MAC / resolver identity / SSID) so steady-state resolution is one shot.
DNS success-rate is the selection signal — which means this plugs into the ADR-0006 discovery loop
later (the winning genome per ASN/region is shippable, signed, as data).

**Answer validation** — DoH prevents in-stream poisoning, but a blocked/hostile resolver can still
return garbage, so: reject bogon/blocklist answers (Iran's `10.10.34.x`; `127.0.0.1`/private ranges
for public names), optional DNSSEC, optional cross-resolver agreement. A failed validation drops to
the next composition.

**DNS codec** — lean toward a **hand-rolled minimal A/AAAA query/response codec** (a query is ~30
bytes; bootstrap only needs A/AAAA of a few hostnames) to protect the binary budget, vs pulling
`hickory-proto` (pure-Rust, handles DoH/DoT/DoQ + full wire format, but sizable). Open question §11.

## 7. Why boring Chrome-CH is the default for DNS-over-TLS

Browsers do DoH with *their own* ClientHello, so a generic (rustls) TLS stack doing DoH is **itself a
fingerprint**, and DoH traffic is already classifiable (`2026-lian-decompose-understand-fuse`).
Dialing DoH with spark's boring2 Chrome-137 profile makes the DoH connection's JA3/JA4
**indistinguishable from a browser's own DoH** to the same resolver — so the connection blends with
ordinary browser HTTPS to that CDN/resolver. Hence: **boring Chrome-CH is the default engine for any
DNS-over-TLS dial**, with `record_fragment`/`tcp_split` layered when they raise success. (The rustls
engine remains as a baseline/ECH-capable alternative the dialer can also try.)

**ECH is additive, not load-bearing.** Real Chrome *does* offer ECH where the network permits it, so
where ECH works, the boring/rustls ECH composition blends best. But because some censors block on the
*presence* of ECH (the GFW's ESNI precedent, §2), every resolver must also be reachable **without**
ECH — a Chrome-CH dial to a **CDN-edge IP with an innocuous real SNI** (a high-collateral hostname
served by the same edge), plus `record_fragment`/`tcp_split` to defeat SNI-based DPI. The smart-dialer
**treats ECH-on and ECH-off as two competing compositions** and lets the success signal pick; and
because an ECH-present handshake that gets reset looks like a generic failure, the dialer learns "ECH
is blocked on this network" simply by ECH-off compositions winning — no special detector required,
though it may also explicitly down-rank ECH-present strategies once they fail repeatedly on a network.

## 8. Dependencies & locked-stack fit

- **Baseline (rustls + ring):** DoH/DoT over rustls, the hand-rolled DNS codec, raw-IP + hostname
  dialing, and **real ECH** (rustls) all live here — no new heavy deps.
- **boring (`anytls` feature):** the Chrome-CH engine reuses `anytls::tls::configure`; boring
  strategies are gated behind that feature (the base build stays rustls-only).
- **Reused:** `shaping/` (`tcp_split`), `gambit`/`profile` (CH knobs + capability gating), Ed25519
  (`wasm::ModuleVerifier`) for signed pool updates. New code is small: `record_fragment` shim,
  resolver pool, smart-dialer, DNS codec.
- **Deferred (add deps only if needed):** DoQ (quinn), a dnstt-style DNS tunnel. Small binary
  preserved for the v1 path.

## 9. Cross-cutting payoff

`BootstrapDial` is not DNS-only: **every bootstrap TLS connection** — domain fronting, the
S3/cloud-blob fetch, proxyless — dials TLS and wants the same stack (boring Chrome CH + shaping + ECH
+ endpoint/SNI tactic). Build the engine once; DNS is its first consumer; the other channels become
thin strategy sets over the same engine. And because the bootstrap payloads are **Ed25519-signed**,
the channels need only *integrity+authenticity of a small blob*, not tunnel confidentiality — which
keeps every channel simple.

## 10. Build order (one bounded chunk per session; green at each boundary)

1. **DNS codec + DoH-over-rustls to a raw-IP resolver**, with answer validation. Pure baseline, no
   boring. Gate: resolve a known name through `1.0.0.1`/`8.8.4.4`, reject an injected bogon.
2. **Resolver pool + smart-dialer** (race → first-validated → per-network cache).
3. **boring Chrome-CH engine option** (reuse `anytls::tls::configure`) — DNS-over-TLS as Chrome.
4. **`record_fragment` shim** (Layer B) + compose with `tcp_split`; selection by success rate.
5. **CDN-edge-fronted DoH pool entries** (the spearhead — works without ECH), **then ECH (rustls) as
   an additive composition** the dialer races against the non-ECH variant.
6. **Signed pool/strategy updates** (Ed25519) + **DoT/853**.
- **Live gate:** against a DNS-poisoning testbed (a local injector that races a forged answer) and,
  ideally, a censored-style network.

## 11. Open questions / risks

- **ECH may be blocked outright** (presence-based, like the GFW's ESNI block — §2). Mitigation is
  built in: ECH-off compositions (CDN-edge IP + innocuous SNI + fragmentation) are first-class pool
  members, so the dialer degrades gracefully. Open: whether to add an *explicit* ECH-block signal per
  network vs. relying purely on the success-rate race to down-rank ECH there.
- **ECH config retrieval** is itself a chicken-and-egg: the ECHConfigList is normally fetched via DNS
  (HTTPS/SVCB RR) or HTTPS — bootstrap it via the working (non-ECH) DoH path, or bake/sign-update it.
- **Engine capability split** (boring Chrome-JA4 vs rustls real-ECH) — accept two competing
  compositions rather than trying to unify; revisit if boring gains real ECH.
- **Network-fingerprint key** for the per-network cache — define it (gateway/resolver/SSID) and its
  invalidation.
- **Codec choice** — hand-rolled minimal vs `hickory-proto` (binary budget vs convenience/DoT/DoQ).
- **Discovery-loop tie-in** — DNS success-rate as an ADR-0006 fitness signal; how the signed
  strategy-update list relates to the broader bootstrap config and the server-side P5 loop.
- **`record_fragment` interop** — confirm no widely-deployed resolver/middlebox rejects a
  record-fragmented CH (probe; the success-gated dialer tolerates it either way).

## 12. References

kindling (`getlantern/kindling`, `smart_dialer_config.yml`); Outline SDK smart-dialer
(`Jigsaw-Code/outline-sdk/x/smart`); corpus: `2025-aryapour-stealth-blackout` (Iran DNS poisoning /
DoH bypass), `2026-lian-decompose-understand-fuse` (DoH traffic detectability),
`2025-alaraj-iran-refraction` (Iran IP-layer attacks), `2020-gfw-esni-blocking` (GFW blocks ESNI by
presence — the ECH-block precedent); ADR 0001 (boring mimicry), ADR 0006 (gambit genome / shaping);
RFC 8446 §5.1 (handshake-message record fragmentation); Quad9 (Swiss Quad9 Foundation); Alibaba Cloud
HTTPDNS DoH (`alibabacloud.com/help/en/dns/httpdns-dns-over-https-doh`).
