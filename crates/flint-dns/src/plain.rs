//! The non-DoH query transports: length-prefixed DNS over a byte stream, and plaintext DNS over UDP.
//!
//! Three of the four non-DoH [`Kind`](crate::pool::Kind)s land here:
//!
//! - [`Kind::Dot`](crate::pool::Kind::Dot) — [`query_stream`] over a TLS stream from
//!   [`flint_dial::dial`], so it composes with opening-handshake [`WirePlan`](flint_dial::WirePlan)
//!   shaping exactly like DoH does.
//! - [`Kind::Tcp`](crate::pool::Kind::Tcp) — [`query_stream`] over a bare TCP socket. Same framing as
//!   DoT (RFC 1035 §4.2.2); the only difference is the absence of TLS.
//! - [`Kind::Udp`](crate::pool::Kind::Udp) — [`query_udp`], a single datagram exchange.
//!
//! **Plaintext transports are attacker-writable.** A censor can inject a forged answer without ever
//! seeing the query (the GFW does exactly this), so callers on these paths must use a random
//! transaction ID and verify it on the way back
//! ([`codec::parse_response_with_id`](crate::codec::parse_response_with_id)). UDP additionally
//! `connect`s its socket so the kernel drops datagrams from any source other than the resolver, and
//! binds an ephemeral port for source-port entropy. That is the standard off-path-injection bar; it is
//! *not* protection against an on-path censor, which is why these kinds stay out of
//! [`default_pool`](crate::pool::default_pool).

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;

/// The largest DNS response we will read. Bootstrap only asks for A/AAAA records, whose answers are
/// far smaller; this caps what a hostile resolver can make us allocate off a 2-byte length field.
const MAX_RESPONSE: usize = 8 * 1024;

/// Send `query` and read one response over a byte stream, using DNS's stream framing: a 2-byte
/// big-endian length prefix before each message (RFC 1035 §4.2.2).
///
/// Shared by DoT (stream = TLS) and plaintext TCP (stream = raw socket) — the framing is identical, so
/// those transports differ only in how the stream was obtained.
pub async fn query_stream<S>(mut stream: S, query: &[u8]) -> io::Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let len = u16::try_from(query.len()).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "DNS query exceeds 65535 bytes")
    })?;

    // One write for prefix+message: servers accept a split, but a single segment avoids handing a DPI
    // box a gratuitously distinctive two-packet pattern for a ~30-byte query.
    let mut framed = Vec::with_capacity(2 + query.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(query);
    stream.write_all(&framed).await?;
    stream.flush().await?;

    let mut prefix = [0u8; 2];
    stream.read_exact(&mut prefix).await?;
    let want = usize::from(u16::from_be_bytes(prefix));
    if want == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS response length prefix was zero",
        ));
    }
    if want > MAX_RESPONSE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS response length prefix exceeds the response cap",
        ));
    }
    let mut response = vec![0u8; want];
    stream.read_exact(&mut response).await?;
    Ok(response)
}

/// Send `query` to `target` over UDP and read one response.
///
/// Binds an ephemeral local port (source-port entropy) and `connect`s to `target`, so the kernel
/// discards datagrams from any other source — an off-path injector must then also guess the port. The
/// caller still must verify the transaction ID; see the module docs.
///
/// No retry and no timeout: a single attempt keeps this cancel-safe and leaves both policies to the
/// caller, which already bounds each attempt and races resolvers.
pub async fn query_udp(target: SocketAddr, query: &[u8]) -> io::Result<Vec<u8>> {
    // Bind in the target's address family — a v4-bound socket cannot reach a v6 resolver.
    let bind = if target.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(target).await?;
    socket.send(query).await?;

    let mut buf = vec![0u8; MAX_RESPONSE];
    // `recv` on a connected socket only yields datagrams from `target`; the kernel drops anything else
    // before it reaches us.
    let n = socket.recv(&mut buf).await?;
    buf.truncate(n);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Frame `msg` the way a DNS stream server would reply.
    fn framed(msg: &[u8]) -> Vec<u8> {
        let mut out = (msg.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(msg);
        out
    }

    #[tokio::test]
    async fn stream_round_trip_uses_length_prefix_framing() {
        let (client, mut server) = tokio::io::duplex(1024);
        let expected = b"\xab\xcd response bytes".to_vec();
        let reply = expected.clone();
        let server_task = tokio::spawn(async move {
            // Read the client's length-prefixed query back out, then answer.
            let mut prefix = [0u8; 2];
            server.read_exact(&mut prefix).await.unwrap();
            let n = usize::from(u16::from_be_bytes(prefix));
            let mut q = vec![0u8; n];
            server.read_exact(&mut q).await.unwrap();
            server.write_all(&framed(&reply)).await.unwrap();
            server.flush().await.unwrap();
            q
        });

        let got = query_stream(client, b"query").await.unwrap();
        assert_eq!(got, expected);
        assert_eq!(server_task.await.unwrap(), b"query".to_vec());
    }

    #[tokio::test]
    async fn stream_rejects_an_oversized_length_prefix() {
        let (client, mut server) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            let mut prefix = [0u8; 2];
            let _ = server.read_exact(&mut prefix).await;
            let mut q = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
            let _ = server.read_exact(&mut q).await;
            // Claim a response far larger than the cap; we must refuse rather than allocate it.
            let _ = server.write_all(&u16::MAX.to_be_bytes()).await;
            let _ = server.flush().await;
        });

        let err = query_stream(client, b"query").await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn stream_rejects_a_zero_length_prefix() {
        let (client, mut server) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            let mut prefix = [0u8; 2];
            let _ = server.read_exact(&mut prefix).await;
            let mut q = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
            let _ = server.read_exact(&mut q).await;
            let _ = server.write_all(&0u16.to_be_bytes()).await;
            let _ = server.flush().await;
        });

        let err = query_stream(client, b"query").await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn udp_round_trip_against_a_local_server() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, from) = server.recv_from(&mut buf).await.unwrap();
            // Echo the query back with the QR bit set, so it looks like a response.
            let mut reply = buf[..n].to_vec();
            reply[2] |= 0x80;
            server.send_to(&reply, from).await.unwrap();
        });

        let query =
            crate::codec::build_query_with_id("example.com", crate::TYPE_A, 0x1234).unwrap();
        let response = query_udp(addr, &query).await.unwrap();
        assert_eq!(&response[..2], &0x1234u16.to_be_bytes());
    }

    #[tokio::test]
    async fn udp_ignores_datagrams_from_another_source() {
        // A connected UDP socket must drop an off-path injection from a different address, so the real
        // resolver's later answer is the one we read. This is the off-path-forgery defense.
        let resolver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let resolver_addr = resolver.local_addr().unwrap();
        let injector = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, from) = resolver.recv_from(&mut buf).await.unwrap();
            // The injector fires first, from the wrong source address.
            let mut forged = buf[..n].to_vec();
            forged[2] |= 0x80;
            forged[0] = 0xff;
            forged[1] = 0xff;
            injector.send_to(&forged, from).await.unwrap();
            // Then the genuine answer arrives from the connected peer.
            let mut real = buf[..n].to_vec();
            real[2] |= 0x80;
            resolver.send_to(&real, from).await.unwrap();
        });

        let query =
            crate::codec::build_query_with_id("example.com", crate::TYPE_A, 0x4321).unwrap();
        let response = query_udp(resolver_addr, &query).await.unwrap();
        // We got the resolver's ID, not the injector's 0xffff.
        assert_eq!(&response[..2], &0x4321u16.to_be_bytes());
    }
}
