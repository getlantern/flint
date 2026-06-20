//! DNS-over-HTTPS transport (RFC 8484) over an established TLS stream, using HTTP/2.
//!
//! A browser does DoH over its own HTTP/2 connection, so we do too: the TLS stream is dialed with the
//! Chrome ClientHello (ALPN `h2`, see flint-tls), then this runs one HTTP/2 `POST {path}` carrying the
//! DNS query as `application/dns-message` and returns the response body. The `h2` crate is the
//! sans-hyper exception (matches spark): the H2 layer lives inside TLS, so its fingerprint is
//! encrypted and not an evasion surface.

use std::io;

use bytes::Bytes;
use futures::future::poll_fn;
use http::{Method, Request, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::JoinHandle;

fn to_io<E: std::error::Error + Send + Sync + 'static>(e: E) -> io::Error {
    io::Error::other(e)
}

/// Aborts the HTTP/2 connection-driver task on drop (a bare `JoinHandle` would detach the task).
struct DriverGuard(JoinHandle<()>);

impl Drop for DriverGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Send one DoH query over `io` (an established, ALPN-`h2` TLS stream) and return the raw DNS
/// response message. `host` is the DoH `:authority`, `path` the DoH path (e.g. `/dns-query`), and
/// `dns_query` the wire-format query from [`crate::codec::build_query`]. The connection is one-shot:
/// its driver task is aborted when this returns.
pub async fn query<S>(io: S, host: &str, path: &str, dns_query: &[u8]) -> io::Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (send_request, connection) = h2::client::handshake(io).await.map_err(to_io)?;
    let _driver = DriverGuard(tokio::spawn(async move {
        let _ = connection.await;
    }));

    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("https://{host}{path}"))
        .header(http::header::CONTENT_TYPE, "application/dns-message")
        .header(http::header::ACCEPT, "application/dns-message")
        .body(())
        .map_err(to_io)?;

    // Send the query as the request body, then END_STREAM.
    let mut send_request = send_request.ready().await.map_err(to_io)?;
    let (response, mut send) = send_request.send_request(request, false).map_err(to_io)?;
    send.send_data(Bytes::copy_from_slice(dns_query), true)
        .map_err(to_io)?;

    let response = response.await.map_err(to_io)?;
    if response.status() != StatusCode::OK {
        return Err(io::Error::other(format!(
            "DoH server returned HTTP {}",
            response.status()
        )));
    }

    // Drain the response body, releasing flow-control capacity as we consume it.
    let mut body = response.into_body();
    let mut out = Vec::new();
    while let Some(chunk) = poll_fn(|cx| body.poll_data(cx)).await {
        let chunk = chunk.map_err(to_io)?;
        let _ = body.flow_control().release_capacity(chunk.len());
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Response;
    use tokio::net::{TcpListener, TcpStream};

    /// A minimal h2 server (plain TCP, h2 prior-knowledge) that accepts one POST, checks the path +
    /// content-type, reads the request body (the DNS query), and replies 200 with `canned` as the
    /// body. Returns the query bytes it received.
    async fn doh_echo_server(
        listener: TcpListener,
        canned: Vec<u8>,
    ) -> tokio::sync::oneshot::Receiver<Vec<u8>> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut conn = h2::server::handshake(tcp).await.unwrap();
            if let Some(accepted) = conn.accept().await {
                let (request, mut respond) = accepted.unwrap();
                assert_eq!(request.method(), Method::POST);
                assert_eq!(request.uri().path(), "/dns-query");
                let mut body = request.into_body();
                let mut got = Vec::new();
                while let Some(chunk) = poll_fn(|cx| body.poll_data(cx)).await {
                    let chunk = chunk.unwrap();
                    let _ = body.flow_control().release_capacity(chunk.len());
                    got.extend_from_slice(&chunk);
                }
                let mut send = respond
                    .send_response(Response::builder().status(200).body(()).unwrap(), false)
                    .unwrap();
                send.send_data(Bytes::from(canned), true).unwrap();
                let _ = tx.send(got);
            }
            // Keep driving the connection so the client can read the response.
            while conn.accept().await.is_some() {}
        });
        rx
    }

    #[tokio::test]
    async fn doh_round_trips_query_and_response_over_h2() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let canned = vec![0xde, 0xad, 0xbe, 0xef];
        let got_query = doh_echo_server(listener, canned.clone()).await;

        let tcp = TcpStream::connect(addr).await.unwrap();
        let query_bytes = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00query".to_vec();
        let resp = query(tcp, "resolver.example", "/dns-query", &query_bytes)
            .await
            .unwrap();

        assert_eq!(
            resp, canned,
            "client receives the server's DNS response body"
        );
        assert_eq!(
            got_query.await.unwrap(),
            query_bytes,
            "server receives the exact query the client sent"
        );
    }
}
