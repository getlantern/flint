//! Minimal SOCKS5 client `CONNECT`, run over a [`crate::MeekPollConn`].
//!
//! The deployed meek-server relays each session to a SOCKS5 upstream (microsocks),
//! so reaching an arbitrary target through meek means doing a no-auth SOCKS5
//! handshake + `CONNECT` over the tunnel, after which the stream carries the
//! target connection. Ported from lantern-box `protocol/meek/outbound.go`
//! (`socks5ConnectSequenced`): strictly sequenced (send, await reply, then next)
//! with `read_exact` framing — a byte-wise reader desyncs over the polling Conn.

use std::io;
use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Where to CONNECT through the proxy.
#[derive(Debug, Clone)]
pub enum Target {
    Ip(SocketAddr),
    /// Domain name + port — sent as SOCKS5 ATYP=0x03 so the proxy resolves it.
    Domain(String, u16),
}

impl From<SocketAddr> for Target {
    fn from(a: SocketAddr) -> Self {
        Target::Ip(a)
    }
}

/// Perform a no-auth SOCKS5 `CONNECT` to `target` over `stream`. On success the
/// stream is positioned to carry the tunneled connection.
pub async fn connect<S>(stream: &mut S, target: &Target) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Method select: VER=5, NMETHODS=1, NO_AUTH(0x00).
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut sel = [0u8; 2];
    stream.read_exact(&mut sel).await?;
    if sel[0] != 0x05 {
        return Err(io::Error::other(format!(
            "socks5: bad version 0x{:02x} in method-select reply",
            sel[0]
        )));
    }
    if sel[1] != 0x00 {
        return Err(io::Error::other(format!(
            "socks5: server rejected no-auth (method 0x{:02x})",
            sel[1]
        )));
    }

    // CONNECT request: VER, CMD=CONNECT(0x01), RSV=0, ATYP, ADDR, PORT.
    let mut req = vec![0x05, 0x01, 0x00];
    match target {
        Target::Ip(SocketAddr::V4(a)) => {
            req.push(0x01);
            req.extend_from_slice(&a.ip().octets());
            req.extend_from_slice(&a.port().to_be_bytes());
        }
        Target::Ip(SocketAddr::V6(a)) => {
            req.push(0x04);
            req.extend_from_slice(&a.ip().octets());
            req.extend_from_slice(&a.port().to_be_bytes());
        }
        Target::Domain(host, port) => {
            let bytes = host.as_bytes();
            if bytes.len() > 255 {
                return Err(io::Error::other("socks5: domain name too long"));
            }
            req.push(0x03);
            req.push(bytes.len() as u8);
            req.extend_from_slice(bytes);
            req.extend_from_slice(&port.to_be_bytes());
        }
    }
    stream.write_all(&req).await?;

    // Reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT. Read the fixed head, then
    // the address whose length depends on ATYP, then the 2-byte port.
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(io::Error::other(format!(
            "socks5: bad version 0x{:02x} in connect reply",
            head[0]
        )));
    }
    if head[1] != 0x00 {
        return Err(io::Error::other(format!(
            "socks5: CONNECT failed (reply code 0x{:02x})",
            head[1]
        )));
    }
    let addr_len = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut l = [0u8; 1];
            stream.read_exact(&mut l).await?;
            l[0] as usize
        }
        other => {
            return Err(io::Error::other(format!(
                "socks5: unknown ATYP 0x{other:02x} in connect reply"
            )))
        }
    };
    let mut rest = vec![0u8; addr_len + 2]; // bound addr + port
    stream.read_exact(&mut rest).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal SOCKS5 server: accept no-auth, accept a CONNECT, reply success,
    /// then echo. Runs over one end of a duplex.
    async fn mock_socks5(mut io: tokio::io::DuplexStream) {
        let mut greeting = [0u8; 3];
        io.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [0x05, 0x01, 0x00]);
        io.write_all(&[0x05, 0x00]).await.unwrap();

        let mut head = [0u8; 4];
        io.read_exact(&mut head).await.unwrap();
        assert_eq!(head[0], 0x05);
        assert_eq!(head[1], 0x01); // CONNECT
        let addr_len = match head[3] {
            0x01 => 4,
            0x04 => 16,
            0x03 => {
                let mut l = [0u8; 1];
                io.read_exact(&mut l).await.unwrap();
                l[0] as usize
            }
            _ => panic!("bad atyp"),
        };
        let mut rest = vec![0u8; addr_len + 2];
        io.read_exact(&mut rest).await.unwrap();
        // Success reply, bound addr 0.0.0.0:0.
        io.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        // Echo whatever follows.
        let mut buf = [0u8; 1024];
        loop {
            match io.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if io.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn socks5_connect_ip_then_tunnels() {
        let (mut client, server) = tokio::io::duplex(4096);
        tokio::spawn(mock_socks5(server));
        connect(
            &mut client,
            &Target::Ip("93.184.216.34:80".parse().unwrap()),
        )
        .await
        .expect("connect");
        client.write_all(b"GET /").await.unwrap();
        let mut out = [0u8; 5];
        client.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"GET /");
    }

    #[tokio::test]
    async fn socks5_connect_domain() {
        let (mut client, server) = tokio::io::duplex(4096);
        tokio::spawn(mock_socks5(server));
        connect(&mut client, &Target::Domain("example.com".into(), 80))
            .await
            .expect("connect domain");
    }
}
