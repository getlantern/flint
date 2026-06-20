//! A minimal DNS wire codec — just enough to ask for A/AAAA records and read the answers.
//!
//! Bootstrap only needs to resolve a few hostnames, so this hand-rolls the ~30-byte query and a
//! bounds-checked answer parser rather than pulling a full DNS library (binary-budget; design §6/§11).
//! Not a general DNS implementation: it builds a standard recursive A/AAAA query and extracts A/AAAA
//! RDATA from the answer section, ignoring everything else.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// QTYPE for an IPv4 address record.
pub const TYPE_A: u16 = 1;
/// QTYPE for an IPv6 address record.
pub const TYPE_AAAA: u16 = 28;

/// Errors building or parsing DNS messages.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DnsError {
    /// A label exceeds 63 bytes or the name is otherwise unencodable.
    #[error("DNS name is not encodable")]
    BadName,
    /// The message ended before a field it declared.
    #[error("DNS message is truncated or malformed")]
    Truncated,
    /// The message is a query, not a response (QR bit clear).
    #[error("not a DNS response")]
    NotAResponse,
    /// The server returned a non-zero RCODE (e.g. 3 = NXDOMAIN, 2 = SERVFAIL).
    #[error("DNS server returned RCODE {0}")]
    Rcode(u8),
}

/// Build a standard recursive query for `name`/`qtype` (class IN). The transaction ID is `0`, as
/// recommended for DoH (RFC 8484 §4.1 — improves cache friendliness since DoH has its own framing).
pub fn build_query(name: &str, qtype: u16) -> Result<Vec<u8>, DnsError> {
    let mut q = Vec::with_capacity(name.len() + 18);
    q.extend_from_slice(&[0x00, 0x00]); // ID = 0
    q.extend_from_slice(&[0x01, 0x00]); // flags: RD (recursion desired)
    q.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    q.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // AN/NS/AR counts = 0
    encode_name(name, &mut q)?;
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN
    Ok(q)
}

/// Encode a domain name as length-prefixed labels terminated by a zero byte.
fn encode_name(name: &str, out: &mut Vec<u8>) -> Result<(), DnsError> {
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() {
            continue; // tolerate a stray empty label (e.g. a leading/trailing dot)
        }
        if label.len() > 63 {
            return Err(DnsError::BadName);
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0); // root
    Ok(())
}

/// Parse a DNS response, returning the A/AAAA addresses in its answer section. Errors on a truncated
/// message, a query (not a response), or a non-zero RCODE. An empty answer list is *not* an error here
/// (the validation layer decides what an empty/poisoned answer means).
pub fn parse_response(buf: &[u8]) -> Result<Vec<IpAddr>, DnsError> {
    if buf.len() < 12 {
        return Err(DnsError::Truncated);
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if flags & 0x8000 == 0 {
        return Err(DnsError::NotAResponse);
    }
    let rcode = (flags & 0x000f) as u8;
    if rcode != 0 {
        return Err(DnsError::Rcode(rcode));
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    let mut pos = 12;
    // Skip the question section: each is a name followed by QTYPE(2) + QCLASS(2).
    for _ in 0..qdcount {
        pos = skip_name(buf, pos)?;
        pos = pos.checked_add(4).ok_or(DnsError::Truncated)?;
        if pos > buf.len() {
            return Err(DnsError::Truncated);
        }
    }

    let mut out = Vec::new();
    for _ in 0..ancount {
        pos = skip_name(buf, pos)?;
        // TYPE(2) CLASS(2) TTL(4) RDLENGTH(2) = 10 bytes of fixed RR header.
        if pos + 10 > buf.len() {
            return Err(DnsError::Truncated);
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let rdlen = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > buf.len() {
            return Err(DnsError::Truncated);
        }
        let rdata = &buf[pos..pos + rdlen];
        pos += rdlen;
        match (rtype, rdlen) {
            (TYPE_A, 4) => out.push(IpAddr::V4(Ipv4Addr::new(
                rdata[0], rdata[1], rdata[2], rdata[3],
            ))),
            (TYPE_AAAA, 16) => {
                let mut b = [0u8; 16];
                b.copy_from_slice(rdata);
                out.push(IpAddr::V6(Ipv6Addr::from(b)));
            }
            _ => {} // CNAME, SOA, etc. — ignored
        }
    }
    Ok(out)
}

/// Advance past a DNS name starting at `pos`, returning the position just after it. Handles label
/// sequences and a compression pointer (which terminates the name in 2 bytes); does not follow the
/// pointer (we never need the name's value, only to skip it).
fn skip_name(buf: &[u8], mut pos: usize) -> Result<usize, DnsError> {
    loop {
        let len = *buf.get(pos).ok_or(DnsError::Truncated)?;
        if len & 0xc0 == 0xc0 {
            // Compression pointer: 2 bytes total, name ends here.
            if pos + 2 > buf.len() {
                return Err(DnsError::Truncated);
            }
            return Ok(pos + 2);
        }
        if len == 0 {
            return Ok(pos + 1);
        }
        pos = pos
            .checked_add(1 + len as usize)
            .ok_or(DnsError::Truncated)?;
        if pos > buf.len() {
            return Err(DnsError::Truncated);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a response for one question + the given answer RRs `(type, rdata)`, with a compression
    /// pointer (0xC00C) for each answer's NAME (the common real-world encoding).
    fn build_response(name: &str, qtype: u16, rcode: u8, answers: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&[0x00, 0x00]); // ID
        m.extend_from_slice(&(0x8000u16 | rcode as u16).to_be_bytes()); // QR=1 + rcode
        m.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
        m.extend_from_slice(&(answers.len() as u16).to_be_bytes()); // ANCOUNT
        m.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // NS/AR
        encode_name(name, &mut m).unwrap();
        m.extend_from_slice(&qtype.to_be_bytes());
        m.extend_from_slice(&[0x00, 0x01]); // QCLASS
        for (rtype, rdata) in answers {
            m.extend_from_slice(&[0xc0, 0x0c]); // NAME → pointer to the question name
            m.extend_from_slice(&rtype.to_be_bytes());
            m.extend_from_slice(&[0x00, 0x01]); // CLASS IN
            m.extend_from_slice(&[0x00, 0x00, 0x01, 0x2c]); // TTL 300
            m.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            m.extend_from_slice(rdata);
        }
        m
    }

    #[test]
    fn query_has_the_expected_shape() {
        let q = build_query("example.com", TYPE_A).unwrap();
        assert_eq!(&q[0..2], &[0, 0]); // ID
        assert_eq!(&q[2..4], &[0x01, 0x00]); // RD
        assert_eq!(&q[4..6], &[0, 1]); // QDCOUNT
                                       // name: 7 example 3 com 0, then qtype + qclass
        assert_eq!(&q[12..13], &[7]);
        assert_eq!(&q[q.len() - 4..], &[0x00, TYPE_A as u8, 0x00, 0x01]);
    }

    #[test]
    fn parses_a_and_aaaa_answers() {
        let v4 = vec![1, 1, 1, 1];
        let v6 = vec![
            0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11,
        ];
        let resp = build_response("one.one", TYPE_A, 0, &[(TYPE_A, v4), (TYPE_AAAA, v6)]);
        let ips = parse_response(&resp).unwrap();
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0], "1.1.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(ips[1], "2606:4700::1111".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn rejects_nxdomain_and_query_and_truncation() {
        let nx = build_response("nope.example", TYPE_A, 3, &[]);
        assert_eq!(parse_response(&nx), Err(DnsError::Rcode(3)));

        let mut q = build_response("x.example", TYPE_A, 0, &[]);
        q[2] &= 0x7f; // clear QR → looks like a query
        assert_eq!(parse_response(&q), Err(DnsError::NotAResponse));

        assert_eq!(parse_response(&[0u8; 4]), Err(DnsError::Truncated));
    }

    #[test]
    fn ignores_non_address_records() {
        // A CNAME (type 5) answer alongside an A record — only the A is returned.
        let resp = build_response(
            "www.example",
            TYPE_A,
            0,
            &[(5, vec![0xc0, 0x0c]), (TYPE_A, vec![93, 184, 216, 34])],
        );
        let ips = parse_response(&resp).unwrap();
        assert_eq!(ips, vec!["93.184.216.34".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn rejects_an_overlong_label() {
        let long = "a".repeat(64);
        assert_eq!(build_query(&long, TYPE_A), Err(DnsError::BadName));
    }
}
