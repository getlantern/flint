//! JA4 TLS-client fingerprinting (ADR 0006 anchor / drift control).
//!
//! Computes the [FoxIO JA4](https://github.com/FoxIO-LLC/ja4) fingerprint of a raw TLS ClientHello
//! record. JA4 is the right fingerprint for an *anchor drift check* precisely because it is
//! **GREASE-stripped and extension-sorted** — so it is invariant to the per-connection GREASE +
//! extension permutation our boring profile emits, yet sensitive to a real change in the cipher
//! list, curves, extensions, sigalgs, or ALPN. Pin the JA4 our profile emits and a silent drift
//! (a dep bump, a profile edit) flips it; matching a real Chrome's JA4 proves the mimicry (ADR 0006
//! §4 "anchor template + drift control").
//!
//! `ja4` = `JA4_a _ JA4_b _ JA4_c`:
//! - `JA4_a` — `t`(TCP) + 2-char TLS version + `d`/`i`(SNI?) + 2-digit cipher count + 2-digit
//!   extension count + first/last char of the first ALPN value (all GREASE-excluded counts).
//! - `JA4_b` — first 12 hex of SHA-256 over the GREASE-stripped, hex-sorted cipher list.
//! - `JA4_c` — first 12 hex of SHA-256 over the GREASE-stripped, hex-sorted extension list (with
//!   SNI `0000` and ALPN `0010` removed — they're already in `JA4_a`), then `_`, then the signature
//!   algorithms **in order** (not sorted).
//!
//! Pure byte parsing; not a TLS implementation. A truncated/non-ClientHello buffer yields `None`.

use ring::digest;

/// The fields of a ClientHello that determine its JA4 fingerprint. Lists are kept **raw** (GREASE
/// included, in wire order); [`ja4`] applies GREASE filtering and sorting per the spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHelloSummary {
    /// `legacy_version` from the ClientHello body (the JA4 version when no `supported_versions`).
    pub legacy_version: u16,
    /// The `legacy_session_id` (0–32 bytes), as carried on the wire. Not part of the JA4 itself, but
    /// surfaced so a `session_id`-injection test can assert the bytes the connector stamped.
    pub legacy_session_id: Vec<u8>,
    /// The `supported_versions` (0x002b) list, if present (JA4 uses its highest non-GREASE value).
    pub supported_versions: Option<Vec<u16>>,
    /// Whether the `server_name` (0x0000) extension is present.
    pub sni: bool,
    /// Cipher suites, in wire order.
    pub ciphers: Vec<u16>,
    /// Extension types, in wire order.
    pub extensions: Vec<u16>,
    /// The first protocol of the ALPN (0x0010) extension, if any.
    pub alpn_first: Option<Vec<u8>>,
    /// The `signature_algorithms` (0x000d) list, in wire order.
    pub sigalgs: Vec<u16>,
}

/// `true` for a GREASE-reserved 16-bit value (RFC 8701: both bytes equal and of the form `0x?a`).
pub(crate) fn is_grease(v: u16) -> bool {
    let hi = (v >> 8) as u8;
    let lo = (v & 0xff) as u8;
    hi == lo && (lo & 0x0f) == 0x0a
}

/// Compute the JA4 fingerprint of an already-parsed ClientHello.
pub fn ja4(s: &ClientHelloSummary) -> String {
    format!("{}_{}_{}", ja4_a(s), ja4_b(s), ja4_c(s))
}

/// Parse a raw TLS ClientHello **record** and compute its JA4, or `None` if it isn't one.
pub fn ja4_of_record(record: &[u8]) -> Option<String> {
    parse_client_hello(record).map(|s| ja4(&s))
}

fn ja4_a(s: &ClientHelloSummary) -> String {
    let version = version_code(resolve_version(s));
    let sni = if s.sni { 'd' } else { 'i' };
    let n_ciphers = s.ciphers.iter().filter(|c| !is_grease(**c)).count().min(99);
    // The extension *count* includes SNI and ALPN (only GREASE is excluded).
    let n_exts = s
        .extensions
        .iter()
        .filter(|e| !is_grease(**e))
        .count()
        .min(99);
    format!(
        "t{version}{sni}{n_ciphers:02}{n_exts:02}{}",
        alpn_code(&s.alpn_first)
    )
}

fn ja4_b(s: &ClientHelloSummary) -> String {
    let mut ciphers: Vec<u16> = s
        .ciphers
        .iter()
        .copied()
        .filter(|c| !is_grease(*c))
        .collect();
    if ciphers.is_empty() {
        return "000000000000".to_string();
    }
    ciphers.sort_unstable();
    hash12(&hex_csv(&ciphers))
}

fn ja4_c(s: &ClientHelloSummary) -> String {
    // The hashed extension list excludes GREASE *and* SNI (0x0000) + ALPN (0x0010) — both are
    // already represented in JA4_a, so omitting them keeps JA4_c stable across SNI/ALPN changes.
    let mut exts: Vec<u16> = s
        .extensions
        .iter()
        .copied()
        .filter(|e| !is_grease(*e) && *e != 0x0000 && *e != 0x0010)
        .collect();
    if exts.is_empty() {
        return "000000000000".to_string();
    }
    exts.sort_unstable();
    // Signature algorithms are appended in wire order (not sorted), GREASE excluded.
    let sigalgs: Vec<u16> = s
        .sigalgs
        .iter()
        .copied()
        .filter(|a| !is_grease(*a))
        .collect();
    let input = if sigalgs.is_empty() {
        hex_csv(&exts)
    } else {
        format!("{}_{}", hex_csv(&exts), hex_csv(&sigalgs))
    };
    hash12(&input)
}

/// The JA4 TLS version: the highest non-GREASE `supported_versions` entry, else `legacy_version`.
fn resolve_version(s: &ClientHelloSummary) -> u16 {
    s.supported_versions
        .as_ref()
        .and_then(|v| v.iter().copied().filter(|x| !is_grease(*x)).max())
        .unwrap_or(s.legacy_version)
}

fn version_code(v: u16) -> &'static str {
    match v {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        _ => "00",
    }
}

/// The 2-char ALPN code: first+last alphanumeric char of the first ALPN value, else `"00"`, else the
/// first/last char of the value's hex if either end byte isn't ASCII-alphanumeric (per the spec).
fn alpn_code(alpn: &Option<Vec<u8>>) -> String {
    let v = match alpn {
        Some(v) if !v.is_empty() => v,
        _ => return "00".to_string(),
    };
    let first = v[0];
    let last = v[v.len() - 1];
    if first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric() {
        format!("{}{}", first as char, last as char)
    } else {
        let hex = hex_bytes(v);
        let b = hex.as_bytes();
        format!("{}{}", b[0] as char, b[b.len() - 1] as char)
    }
}

/// Lowercase, comma-separated 4-hex encoding of a value list (`1301,c02b,...`).
fn hex_csv(values: &[u16]) -> String {
    values
        .iter()
        .map(|v| format!("{v:04x}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// Lowercase hex of a byte slice.
fn hex_bytes(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// First 12 lowercase-hex chars of the SHA-256 of `input`.
fn hash12(input: &str) -> String {
    let d = digest::digest(&digest::SHA256, input.as_bytes());
    hex_bytes(d.as_ref()).chars().take(12).collect()
}

/// Parse a raw TLS ClientHello record into the fields JA4 needs. `None` on any truncation or if the
/// buffer isn't a handshake/ClientHello record. Walks the structure with bounds checks; not a parser
/// of every field (only what JA4 consumes).
pub fn parse_client_hello(record: &[u8]) -> Option<ClientHelloSummary> {
    let mut c = Cursor::new(record);
    // TLS record header: content_type(1)=22, legacy_version(2), length(2).
    if c.u8()? != 22 {
        return None;
    }
    c.skip(2)?;
    c.skip(2)?; // record length
                // Handshake header: msg_type(1)=1 (ClientHello), length(3).
    if c.u8()? != 1 {
        return None;
    }
    c.skip(3)?;
    // Body: legacy_version(2), random(32), session_id(len(1)+bytes).
    let legacy_version = c.u16()?;
    c.skip(32)?;
    let sid = c.u8()? as usize;
    let legacy_session_id = c.take(sid)?.to_vec();
    // cipher_suites: len(2) then len/2 u16s.
    let cs_len = c.u16()? as usize;
    if cs_len % 2 != 0 {
        return None;
    }
    let mut ciphers = Vec::with_capacity(cs_len / 2);
    for _ in 0..cs_len / 2 {
        ciphers.push(c.u16()?);
    }
    // compression_methods: len(1) + bytes.
    let comp = c.u8()? as usize;
    c.skip(comp)?;

    let mut summary = ClientHelloSummary {
        legacy_version,
        legacy_session_id,
        supported_versions: None,
        sni: false,
        ciphers,
        extensions: Vec::new(),
        alpn_first: None,
        sigalgs: Vec::new(),
    };

    // extensions: total len(2), then a sequence of {type(2), len(2), data(len)}. Require the full
    // declared block to be present (a truncated record → `None`) and parse strictly within it.
    let ext_total = c.u16()? as usize;
    let ext_bytes = c.take(ext_total)?;
    let mut c = Cursor::new(ext_bytes);
    while let Some(ext_type) = c.u16() {
        let ext_len = c.u16()? as usize;
        let data = c.take(ext_len)?;
        summary.extensions.push(ext_type);
        match ext_type {
            0x0000 => summary.sni = true,
            0x0010 => summary.alpn_first = parse_alpn_first(data),
            0x000d => summary.sigalgs = parse_u16_list_u16len(data).unwrap_or_default(),
            0x002b => summary.supported_versions = parse_u16_list_u8len(data),
            _ => {}
        }
    }
    Some(summary)
}

/// ALPN extension body: ProtocolNameList len(2), then `{len(1), bytes}` entries — return the first.
fn parse_alpn_first(data: &[u8]) -> Option<Vec<u8>> {
    let mut c = Cursor::new(data);
    let _list_len = c.u16()?;
    let n = c.u8()? as usize;
    Some(c.take(n)?.to_vec())
}

/// A `len(2)`-prefixed list of u16s (e.g. `signature_algorithms`).
fn parse_u16_list_u16len(data: &[u8]) -> Option<Vec<u16>> {
    let mut c = Cursor::new(data);
    let len = c.u16()? as usize;
    read_u16s(&mut c, len)
}

/// A `len(1)`-prefixed list of u16s (e.g. `supported_versions`).
fn parse_u16_list_u8len(data: &[u8]) -> Option<Vec<u16>> {
    let mut c = Cursor::new(data);
    let len = c.u8()? as usize;
    read_u16s(&mut c, len)
}

fn read_u16s(c: &mut Cursor<'_>, byte_len: usize) -> Option<Vec<u16>> {
    if byte_len % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(byte_len / 2);
    for _ in 0..byte_len / 2 {
        out.push(c.u16()?);
    }
    Some(out)
}

/// A bounds-checked big-endian reader; every accessor returns `None` past the end.
struct Cursor<'a> {
    buf: &'a [u8],
    i: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, i: 0 }
    }
    fn u8(&mut self) -> Option<u8> {
        let v = *self.buf.get(self.i)?;
        self.i += 1;
        Some(v)
    }
    fn u16(&mut self) -> Option<u16> {
        let hi = *self.buf.get(self.i)? as u16;
        let lo = *self.buf.get(self.i + 1)? as u16;
        self.i += 2;
        Some((hi << 8) | lo)
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        let end = self.i.checked_add(n)?;
        if end > self.buf.len() {
            return None;
        }
        self.i = end;
        Some(())
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.i.checked_add(n)?;
        let s = self.buf.get(self.i..end)?;
        self.i = end;
        Some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Assemble a ClientHello record from a cipher list + ordered `(ext_type, body)` extensions.
    fn build_ch(legacy_version: u16, ciphers: &[u16], exts: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut ext_blob = Vec::new();
        for (ty, body) in exts {
            ext_blob.extend_from_slice(&ty.to_be_bytes());
            ext_blob.extend_from_slice(&(body.len() as u16).to_be_bytes());
            ext_blob.extend_from_slice(body);
        }
        let mut body = legacy_version.to_be_bytes().to_vec();
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id len
        body.extend_from_slice(&((ciphers.len() * 2) as u16).to_be_bytes());
        for cs in ciphers {
            body.extend_from_slice(&cs.to_be_bytes());
        }
        body.push(1); // compression len
        body.push(0); // null compression
        body.extend_from_slice(&(ext_blob.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext_blob);

        let mut hs = vec![1u8];
        let blen = body.len();
        hs.extend_from_slice(&[(blen >> 16) as u8, (blen >> 8) as u8, blen as u8]);
        hs.extend_from_slice(&body);

        let mut rec = vec![22u8, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    fn u16s_be(values: &[u16]) -> Vec<u8> {
        values.iter().flat_map(|v| v.to_be_bytes()).collect()
    }

    /// The worked example from the JA4 spec, reproduced byte-for-byte:
    /// `t13d1516h2_8daaf6152771_e5627efa2ab1`.
    #[test]
    fn matches_the_spec_example() {
        // 15 ciphers, original order (JA4_ro from the spec).
        let ciphers = [
            0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
            0x009c, 0x009d, 0x002f, 0x0035,
        ];
        // sigalgs (000d body), in order.
        let sigalgs = [
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ];
        let mut sigalgs_body = ((sigalgs.len() * 2) as u16).to_be_bytes().to_vec();
        sigalgs_body.extend_from_slice(&u16s_be(&sigalgs));
        // ALPN (0010 body): ProtocolNameList { "h2" }.
        let alpn_body = vec![0x00, 0x03, 0x02, b'h', b'2'];
        // supported_versions (002b body): highest = 0x0304 (TLS 1.3).
        let sv_body = vec![0x02, 0x03, 0x04];

        // 16 extensions, original order (JA4_ro), with real bodies where JA4 reads them.
        let body_for = |ty: u16| -> Vec<u8> {
            match ty {
                0x0010 => alpn_body.clone(),
                0x000d => sigalgs_body.clone(),
                0x002b => sv_body.clone(),
                _ => Vec::new(),
            }
        };
        let ext_types = [
            0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012,
            0x002b, 0xff01, 0x000b, 0x000a, 0x0015,
        ];
        let exts: Vec<(u16, Vec<u8>)> = ext_types.iter().map(|&t| (t, body_for(t))).collect();

        let record = build_ch(0x0303, &ciphers, &exts);
        assert_eq!(
            ja4_of_record(&record).as_deref(),
            Some("t13d1516h2_8daaf6152771_e5627efa2ab1"),
        );
    }

    #[test]
    fn grease_is_ignored_in_counts_and_hashes() {
        // Same as the spec example but with a GREASE cipher (0x0a0a) and GREASE extension (0x1a1a)
        // prepended — JA4 must be identical (GREASE stripped).
        let ciphers = [
            0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
            0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
        ];
        let sigalgs = [
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ];
        let mut sigalgs_body = ((sigalgs.len() * 2) as u16).to_be_bytes().to_vec();
        sigalgs_body.extend_from_slice(&u16s_be(&sigalgs));
        let body_for = |ty: u16| -> Vec<u8> {
            match ty {
                0x0010 => vec![0x00, 0x03, 0x02, b'h', b'2'],
                0x000d => sigalgs_body.clone(),
                0x002b => vec![0x02, 0x03, 0x04],
                _ => Vec::new(),
            }
        };
        let ext_types = [
            0x1a1a, 0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023,
            0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015,
        ];
        let exts: Vec<(u16, Vec<u8>)> = ext_types.iter().map(|&t| (t, body_for(t))).collect();
        let record = build_ch(0x0303, &ciphers, &exts);
        assert_eq!(
            ja4_of_record(&record).as_deref(),
            Some("t13d1516h2_8daaf6152771_e5627efa2ab1"),
            "GREASE values must not change the JA4",
        );
    }

    #[test]
    fn rejects_non_clienthello_and_truncations() {
        assert_eq!(ja4_of_record(b""), None);
        assert_eq!(ja4_of_record(&[22, 3, 1, 0, 5, 2, 0, 0, 0]), None);
        let ch = build_ch(0x0303, &[0x1301], &[(0x002b, vec![0x02, 0x03, 0x04])]);
        for n in 0..ch.len() {
            assert_eq!(ja4_of_record(&ch[..n]), None, "prefix len {n}");
        }
    }
}
