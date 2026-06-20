//! Minimal SNI locator for the handshake shapers (ADR 0006 Phase 1).
//!
//! Finds the byte range of the SNI host inside a raw TLS ClientHello record, so a shaper can fragment
//! the hostname across TCP segments (Layer C) or TLS records (Layer B). Bounds-checked and **total**:
//! any truncation or non-match returns `None`, so a malformed or absent SNI never breaks a connection
//! (the shaper just doesn't split). This is not a TLS parser — it walks only the fields needed to
//! reach `server_name`.

/// Locate the SNI host bytes in a raw TLS ClientHello record. Returns the `(offset, len)` of the host
/// name within `buf`, or `None` if `buf` is not a ClientHello carrying a `server_name` host extension
/// (or is truncated before it).
pub fn sni_host_range(buf: &[u8]) -> Option<(usize, usize)> {
    let mut c = Cursor::new(buf);
    // TLS record header: content_type(1) = 22 (handshake), legacy_version(2), length(2).
    if c.u8()? != 22 {
        return None;
    }
    c.skip(2)?;
    let _record_len = c.u16()?;
    // Handshake header: msg_type(1) = 1 (ClientHello), length(3).
    if c.u8()? != 1 {
        return None;
    }
    c.skip(3)?;
    // ClientHello body: legacy_version(2) + random(32).
    c.skip(2 + 32)?;
    // session_id: len(1) + bytes.
    let session_id = c.u8()? as usize;
    c.skip(session_id)?;
    // cipher_suites: len(2) + bytes.
    let cipher_suites = c.u16()? as usize;
    c.skip(cipher_suites)?;
    // compression_methods: len(1) + bytes.
    let compression = c.u8()? as usize;
    c.skip(compression)?;
    // extensions: total len(2), then a sequence of {type(2), len(2), data}.
    let _extensions_len = c.u16()?;
    while let Some(ext_type) = c.u16() {
        let ext_len = c.u16()? as usize;
        if ext_type != 0 {
            c.skip(ext_len)?;
            continue;
        }
        // server_name extension: ServerNameList len(2), then {name_type(1)=0, host len(2), host}.
        let _list_len = c.u16()?;
        if c.u8()? != 0 {
            return None; // not a host_name entry
        }
        let host_len = c.u16()? as usize;
        let off = c.pos();
        // The host bytes must actually be present in `buf`.
        if off.checked_add(host_len)? > buf.len() {
            return None;
        }
        return Some((off, host_len));
    }
    None
}

/// A bounds-checked big-endian byte reader over a borrowed buffer. Every accessor returns `None` past
/// the end, so the parser short-circuits cleanly on truncation.
struct Cursor<'a> {
    buf: &'a [u8],
    i: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, i: 0 }
    }

    fn pos(&self) -> usize {
        self.i
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
}

/// Test fixtures shared with the shaper modules' tests.
#[cfg(test)]
pub(crate) mod tests_support {
    /// Build a minimal but well-formed TLS ClientHello record carrying `host` as the SNI.
    pub fn clienthello_with_sni(host: &[u8]) -> Vec<u8> {
        // server_name extension body: ServerNameList { entry { name_type=0, host_len(2), host } }.
        let mut sni_entry = vec![0u8]; // name_type = host_name
        sni_entry.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni_entry.extend_from_slice(host);
        let mut sni_list = (sni_entry.len() as u16).to_be_bytes().to_vec();
        sni_list.extend_from_slice(&sni_entry);
        let mut ext = 0u16.to_be_bytes().to_vec(); // ext type 0 = server_name
        ext.extend_from_slice(&(sni_list.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni_list);

        // ClientHello body.
        let mut body = vec![0x03, 0x03]; // legacy_version TLS 1.2
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id len
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites len
        body.extend_from_slice(&[0x13, 0x01]); // one suite
        body.push(1); // compression len
        body.push(0); // null compression
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes()); // extensions total len
        body.extend_from_slice(&ext);

        // Handshake header: type(1)=1, length(3).
        let mut hs = vec![1u8];
        let blen = body.len();
        hs.extend_from_slice(&[(blen >> 16) as u8, (blen >> 8) as u8, blen as u8]);
        hs.extend_from_slice(&body);

        // Record header: type(1)=22, version(2), length(2).
        let mut rec = vec![22u8, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }
}

#[cfg(test)]
mod tests {
    use super::sni_host_range;
    use super::tests_support::clienthello_with_sni;

    #[test]
    fn finds_the_sni_host() {
        let host = b"example.com";
        let ch = clienthello_with_sni(host);
        let (off, len) = sni_host_range(&ch).expect("should locate SNI");
        assert_eq!(len, host.len());
        assert_eq!(&ch[off..off + len], host);
    }

    #[test]
    fn rejects_non_clienthello_and_truncations() {
        assert_eq!(sni_host_range(b""), None);
        assert_eq!(sni_host_range(&[22, 3, 1, 0, 5, 2, 0, 0, 0]), None); // wrong handshake type
        let ch = clienthello_with_sni(b"example.com");
        for n in 0..ch.len() {
            // Every strict prefix is either not-yet-at-SNI or truncated → None.
            assert_eq!(sni_host_range(&ch[..n]), None, "prefix len {n}");
        }
    }
}
