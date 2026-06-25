//! meek-v1 **polling** client (Psiphon/Lantern wire format), ported from
//! lantern-box `protocol/meek` (PR #282). This is deliberately distinct from the
//! h2 bidirectional [`crate::MeekStream`]: the deployed Lantern meek-server does
//! NOT keep a long-lived stream open — it answers discrete `POST`s, each keyed by
//! `X-Session-Id` and carrying a monotonic `X-Meek-Seq` the server dedupes
//! (replaying the buffered response for a repeated seq). That makes a lost
//! request or lost response safe to retry without duplicating or dropping bytes.
//!
//! A [`MeekPollConn`] is an `AsyncRead + AsyncWrite` byte stream. Internally it is
//! one half of an in-memory `tokio::io::duplex` pipe; a background poll task owns
//! the other half plus the HTTP backend over a fronted TLS connection, batching
//! the app's outbound bytes into each `POST` body and writing each response body
//! back to the app. The transport is meant to run over a verified, domain-fronted
//! Chrome TLS stream (see [`crate::FrontedTlsDialer::connect_fronted`]); the CDN
//! terminates TLS and re-originates the request, so this carries no end-to-end
//! auth — cert verification only guards against a third party impersonating the
//! edge.

use std::io;
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request};
use ring::rand::SecureRandom;
use tokio::io::{
    duplex, split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf,
};
use tokio::task::JoinHandle;

use std::pin::Pin;
use std::task::{Context, Poll};

/// Per-poll body cap (matches lantern-box `defaultMaxBodyBytes`). Throughput is
/// bytes-per-poll ÷ RTT; 256 KiB keeps a stream moving without making a single
/// retried poll expensive to replay.
pub const DEFAULT_MAX_BODY_BYTES: usize = 256 * 1024;
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(100);
const DEFAULT_MAX_POLL_RETRIES: u32 = 4;
const RETRY_BASE_BACKOFF: Duration = Duration::from_millis(250);
const DEFAULT_SESSION_ID_LEN: usize = 16;
/// Per-poll request timeout. A lost/stalled response must not block forever, or
/// the retry path never runs; an elapsed request becomes a retryable error.
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// In-memory pipe buffer between the app and the poll task (per direction).
const PIPE_BUF: usize = 1 << 20; // 1 MiB

const HEADER_SESSION_ID: &str = "x-session-id";
const HEADER_SEQ: &str = "x-meek-seq";
const HEADER_MAX_BODY: &str = "x-meek-max-body";

/// Which HTTP version to speak to the front. Prefer letting the caller
/// auto-select from the negotiated ALPN via [`crate::open_meek_poll_auto`] +
/// [`crate::dial_fronts_alpn`] (the boring Chrome dial offers `h2,http/1.1` and
/// the edge picks — e.g. the deployed Akamai meek endpoint negotiates h1). This
/// enum is for the cases that force a version explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MeekHttpVersion {
    H1,
    #[default]
    H2,
}

/// Runtime configuration for a [`MeekPollConn`]. Mirrors lantern-box `meek.Config`.
#[derive(Debug, Clone)]
pub struct MeekPollConfig {
    /// Request path on the meek endpoint (e.g. `/`).
    pub path: String,
    /// Inner `Host` / `:authority` the front routes to (the fronted host).
    pub inner_host: String,
    pub http_version: MeekHttpVersion,
    pub poll_interval: Duration,
    pub max_body_bytes: usize,
    pub max_poll_retries: u32,
    pub session_id_len: usize,
    /// Per-poll request timeout; an elapsed request is a retryable error so a
    /// stalled response can't block the session forever.
    pub request_timeout: Duration,
}

impl MeekPollConfig {
    pub fn new(inner_host: impl Into<String>) -> Self {
        Self {
            path: "/".into(),
            inner_host: inner_host.into(),
            http_version: MeekHttpVersion::default(),
            poll_interval: DEFAULT_POLL_INTERVAL,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            max_poll_retries: DEFAULT_MAX_POLL_RETRIES,
            session_id_len: DEFAULT_SESSION_ID_LEN,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
        }
    }

    fn normalized(mut self) -> Self {
        if self.path.is_empty() {
            self.path = "/".into();
        } else if !self.path.starts_with('/') {
            self.path = format!("/{}", self.path);
        }
        if self.poll_interval.is_zero() {
            self.poll_interval = DEFAULT_POLL_INTERVAL;
        }
        if self.max_body_bytes == 0 {
            self.max_body_bytes = DEFAULT_MAX_BODY_BYTES;
        }
        if self.session_id_len == 0 {
            self.session_id_len = DEFAULT_SESSION_ID_LEN;
        }
        if self.request_timeout.is_zero() {
            self.request_timeout = DEFAULT_REQUEST_TIMEOUT;
        }
        self
    }
}

/// A meek polling connection: an `AsyncRead + AsyncWrite` tunnel carried over a
/// fronted HTTPS endpoint. Drop it (or shut down both halves) to end the session;
/// the poll task stops once the app side is gone.
pub struct MeekPollConn {
    inner: DuplexStream,
    task: JoinHandle<()>,
}

impl Drop for MeekPollConn {
    fn drop(&mut self) {
        // Stop the poll task rather than detaching it: if it's parked in an HTTP
        // roundtrip, the task (and the fronted connection it holds) must not
        // outlive the conn.
        self.task.abort();
    }
}

impl MeekPollConn {
    /// Establish a meek polling session over an already-connected, fronted TLS
    /// `stream`. `cfg.inner_host` is the host the front routes to. The HTTP
    /// version must match what the front negotiated (see [`MeekHttpVersion`]).
    pub fn connect<S>(stream: S, cfg: MeekPollConfig) -> io::Result<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let cfg = cfg.normalized();
        // The h1 backend writes the request line + headers by hand. inner_host
        // must be a bare authority (host[:port]) — reject CR/LF/control, space,
        // non-ASCII, and authority-breaking chars (`/?#@\`) that would split the
        // request or produce an invalid Host. The path may contain `/?#`, so it
        // only gets the control/space/non-ASCII check.
        if invalid_inner_host(&cfg.inner_host) || has_invalid_host_char(&cfg.path) {
            return Err(io::Error::other(
                "meek: inner_host/path contains invalid characters",
            ));
        }
        let session_id = random_session_id(cfg.session_id_len)?;
        let (app_side, task_side) = duplex(PIPE_BUF);
        let task = tokio::spawn(async move {
            if let Err(err) = poll_task(stream, task_side, cfg, session_id).await {
                tracing::debug!(error = %err, "meek poll task ended");
            }
        });
        Ok(Self {
            inner: app_side,
            task,
        })
    }
}

impl AsyncRead for MeekPollConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for MeekPollConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// The poll loop. Reads outbound bytes from the app (`task_side`), batches up to
/// `max_body_bytes` into each `POST`, writes the response body back to the app,
/// and advances the seq. A timed-out read (no outbound bytes within
/// `poll_interval`) sends an empty poll-only request, so downstream data keeps
/// flowing even when the app is quiet. Ends when the app drops the conn.
async fn poll_task<S>(
    stream: S,
    task_side: DuplexStream,
    cfg: MeekPollConfig,
    session_id: String,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut from_app, mut to_app) = split(task_side);
    let mut backend = Backend::connect(stream, &cfg).await?;
    let mut seq: u64 = 0;
    let mut app_write_open = true;
    let mut read_buf = vec![0u8; cfg.max_body_bytes];

    loop {
        // Gather an outbound chunk: wake immediately on a write, or after the
        // poll interval send an empty (poll-only) request.
        let body: Bytes = if app_write_open {
            match tokio::time::timeout(cfg.poll_interval, from_app.read(&mut read_buf)).await {
                Ok(Ok(0)) => {
                    // App closed its write half; keep polling (empty) to drain
                    // downstream until the app drops the read half too.
                    app_write_open = false;
                    Bytes::new()
                }
                Ok(Ok(n)) => Bytes::copy_from_slice(&read_buf[..n]),
                Ok(Err(_)) => return Ok(()), // app gone
                Err(_) => Bytes::new(),      // interval elapsed: poll-only
            }
        } else {
            tokio::time::sleep(cfg.poll_interval).await;
            Bytes::new()
        };

        // POST with retry. The same seq + body is resent on each attempt; the
        // server dedupes on seq, so a lost request/response can't dup or drop.
        let resp = roundtrip_with_retry(&mut backend, &cfg, &session_id, seq, body).await?;
        if !resp.is_empty() && to_app.write_all(&resp).await.is_err() {
            return Ok(()); // app dropped the read half
        }
        seq += 1;
    }
}

async fn roundtrip_with_retry(
    backend: &mut Backend,
    cfg: &MeekPollConfig,
    session_id: &str,
    seq: u64,
    body: Bytes,
) -> io::Result<Vec<u8>> {
    let mut attempt: u32 = 0;
    loop {
        if attempt > 0 {
            tokio::time::sleep(RETRY_BASE_BACKOFF * attempt).await;
        }
        // Bound each poll: a stalled response must not block forever, or the retry
        // path never runs. An elapsed request is a retryable error.
        let outcome = match tokio::time::timeout(
            cfg.request_timeout,
            backend.roundtrip(cfg, session_id, seq, body.clone()),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "meek: poll request timed out",
            )),
        };
        match outcome {
            Ok(resp) => return Ok(resp),
            Err(err) => {
                // Retry only when it's safe to re-send on the same connection: h2
                // opens a fresh multiplexed stream and the server dedupes the seq,
                // so a lost request/response replays with no gap or duplication
                // (see the retry-integrity tests). h1 has a single keep-alive
                // connection that a failed/timed-out request leaves desynced, so a
                // failure there ends the session and the caller re-dials a fresh
                // front. (`reconnect` was a no-op and is gone.)
                if attempt >= cfg.max_poll_retries || !backend.can_retry_in_place() {
                    return Err(io::Error::other(format!(
                        "meek: poll failed (attempt {}): {err}",
                        attempt + 1
                    )));
                }
                attempt += 1;
            }
        }
    }
}

/// The HTTP backend over the fronted TLS stream. Holds the connection so polls
/// reuse it. h2 multiplexes a fresh stream per poll; h1 reuses one keep-alive
/// connection sequentially.
enum Backend {
    H2(h2_backend::H2Backend),
    H1(h1_backend::H1Backend),
}

impl Backend {
    async fn connect<S>(stream: S, cfg: &MeekPollConfig) -> io::Result<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        match cfg.http_version {
            MeekHttpVersion::H2 => Ok(Backend::H2(h2_backend::H2Backend::connect(stream).await?)),
            MeekHttpVersion::H1 => Ok(Backend::H1(h1_backend::H1Backend::connect(stream))),
        }
    }

    /// Whether a failed roundtrip can be safely retried on this same backend.
    /// True for h2 (a fresh multiplexed stream + server seq-dedupe makes a re-send
    /// idempotent); false for h1 (a single keep-alive connection that a
    /// failed/timed-out request leaves desynced — the session must end instead).
    fn can_retry_in_place(&self) -> bool {
        matches!(self, Backend::H2(_))
    }

    async fn roundtrip(
        &mut self,
        cfg: &MeekPollConfig,
        session_id: &str,
        seq: u64,
        body: Bytes,
    ) -> io::Result<Vec<u8>> {
        match self {
            Backend::H2(b) => b.roundtrip(cfg, session_id, seq, body).await,
            Backend::H1(b) => b.roundtrip(cfg, session_id, seq, body).await,
        }
    }
}

/// Type-erased fronted TLS stream for the h1 backend (which must keep the stream
/// to read responses, unlike h2 which hands it to the h2 connection task).
trait ReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + ?Sized> ReadWrite for T {}

mod h1_backend {
    use super::{ReadWrite, HEADER_MAX_BODY, HEADER_SEQ, HEADER_SESSION_ID};
    use crate::MeekPollConfig;
    use bytes::Bytes;
    use std::io;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    /// HTTP/1.1 meek backend: one keep-alive connection, one sequential
    /// POST/response per poll. Minimal by design — meek requests are a fixed set
    /// of headers + an octet-stream body, and responses are Content-Length or
    /// chunked.
    pub struct H1Backend {
        stream: BufReader<Box<dyn ReadWrite>>,
    }

    impl H1Backend {
        pub fn connect<S>(stream: S) -> Self
        where
            S: ReadWrite + 'static,
        {
            Self {
                stream: BufReader::new(Box::new(stream) as Box<dyn ReadWrite>),
            }
        }

        pub async fn roundtrip(
            &mut self,
            cfg: &MeekPollConfig,
            session_id: &str,
            seq: u64,
            body: Bytes,
        ) -> io::Result<Vec<u8>> {
            // Request line + headers + body. Keep-alive so the next poll reuses
            // this connection.
            let head = format!(
                "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/octet-stream\r\n\
                 {HEADER_SESSION_ID}: {}\r\n{HEADER_SEQ}: {}\r\n{HEADER_MAX_BODY}: {}\r\n\
                 Content-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                cfg.path,
                cfg.inner_host,
                session_id,
                seq,
                cfg.max_body_bytes,
                body.len(),
            );
            self.stream.write_all(head.as_bytes()).await?;
            if !body.is_empty() {
                self.stream.write_all(&body).await?;
            }
            self.stream.flush().await?;

            // Status line: "HTTP/1.1 200 OK".
            let mut line = String::new();
            if self.stream.read_line(&mut line).await? == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "meek: h1 eof"));
            }
            let status = line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse::<u16>().ok())
                .ok_or_else(|| io::Error::other(format!("meek: bad h1 status line {line:?}")))?;

            // Headers until the blank line.
            let mut content_length: Option<usize> = None;
            let mut chunked = false;
            loop {
                let mut h = String::new();
                if self.stream.read_line(&mut h).await? == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "meek: h1 eof in headers",
                    ));
                }
                let t = h.trim_end();
                if t.is_empty() {
                    break;
                }
                let lower = t.to_ascii_lowercase();
                if let Some(v) = lower.strip_prefix("content-length:") {
                    content_length = v.trim().parse().ok();
                } else if lower.starts_with("transfer-encoding:") && lower.contains("chunked") {
                    chunked = true;
                }
            }
            if status != 200 {
                return Err(io::Error::other(format!("meek: status {status}")));
            }

            // Body: Content-Length or chunked. The whole body MUST be consumed so
            // the next poll's response stays framed on this keep-alive connection.
            if chunked {
                self.read_chunked(cfg.max_body_bytes).await
            } else {
                // A keep-alive response with neither Content-Length nor chunked
                // has no frame boundary — reject rather than desync the next read.
                let n = content_length.ok_or_else(|| {
                    io::Error::other("meek: h1 response missing Content-Length on keep-alive")
                })?;
                // The server caps responses at the advertised max-body, so an
                // over-cap body is a protocol violation; error rather than leave
                // unread bytes that would desync the next response.
                if n > cfg.max_body_bytes {
                    return Err(io::Error::other(format!(
                        "meek: h1 response body {n} exceeds max_body_bytes {}",
                        cfg.max_body_bytes
                    )));
                }
                let mut buf = vec![0u8; n];
                self.stream.read_exact(&mut buf).await?;
                Ok(buf)
            }
        }

        async fn read_chunked(&mut self, cap: usize) -> io::Result<Vec<u8>> {
            let mut out = Vec::new();
            loop {
                let mut size_line = String::new();
                if self.stream.read_line(&mut size_line).await? == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "meek: h1 eof in chunk size",
                    ));
                }
                // The chunk size is the hex token before any `;chunk-extension`.
                let token = size_line.split(';').next().unwrap_or("").trim();
                let size = usize::from_str_radix(token, 16)
                    .map_err(|_| io::Error::other(format!("meek: bad chunk size {size_line:?}")))?;
                if size == 0 {
                    // Drain trailer lines through the terminating blank line so the
                    // connection stays framed for the next response.
                    loop {
                        let mut trailer = String::new();
                        if self.stream.read_line(&mut trailer).await? == 0 {
                            break;
                        }
                        if trailer.trim_end_matches(['\r', '\n']).is_empty() {
                            break;
                        }
                    }
                    break;
                }
                // The chunk size is attacker-controlled; cap the allocation. The
                // server caps responses at the advertised max-body, so a single
                // chunk larger than that is a protocol violation, not a huge body.
                if size > cap {
                    return Err(io::Error::other(format!(
                        "meek: chunk size {size} exceeds max_body_bytes {cap}"
                    )));
                }
                let mut chunk = vec![0u8; size];
                self.stream.read_exact(&mut chunk).await?;
                let mut crlf = [0u8; 2]; // consume + validate the chunk's trailing CRLF
                self.stream.read_exact(&mut crlf).await?;
                if &crlf != b"\r\n" {
                    return Err(io::Error::other("meek: malformed chunk terminator"));
                }
                // The server caps responses at the advertised max-body, so a total
                // exceeding it is a protocol violation. Error (matching the
                // non-chunked + h2 paths) rather than silently truncating and
                // advancing the seq past data the app never received.
                if out.len() + chunk.len() > cap {
                    return Err(io::Error::other(
                        "meek: chunked response exceeds max_body_bytes",
                    ));
                }
                out.extend_from_slice(&chunk);
            }
            Ok(out)
        }
    }
}

mod h2_backend {
    use super::*;
    use h2::client::SendRequest;

    const MAX_H2_WRITE_CHUNK: usize = 16 * 1024;

    pub struct H2Backend {
        send_request: SendRequest<Bytes>,
        driver: tokio::task::JoinHandle<()>,
    }

    impl Drop for H2Backend {
        fn drop(&mut self) {
            // Tear down the connection driver with the backend, or it (and the TLS
            // stream it holds) leaks after the conn is dropped/aborted.
            self.driver.abort();
        }
    }

    impl H2Backend {
        pub async fn connect<S>(stream: S) -> io::Result<Self>
        where
            S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        {
            let (send_request, connection) = h2::client::handshake(stream).await.map_err(to_io)?;
            // Drive the h2 connection; it must be polled for requests to make
            // progress. Held + aborted on Drop so it can't outlive the backend.
            let driver = tokio::spawn(async move {
                let _ = connection.await;
            });
            Ok(Self {
                send_request,
                driver,
            })
        }

        pub async fn roundtrip(
            &mut self,
            cfg: &MeekPollConfig,
            session_id: &str,
            seq: u64,
            body: Bytes,
        ) -> io::Result<Vec<u8>> {
            let uri = format!("https://{}{}", cfg.inner_host, cfg.path);
            let request = Request::builder()
                .method(Method::POST)
                .uri(uri)
                .header(http::header::HOST, cfg.inner_host.as_str())
                .header(http::header::CONTENT_TYPE, "application/octet-stream")
                .header(HEADER_SESSION_ID, session_id)
                .header(HEADER_SEQ, seq.to_string())
                .header(HEADER_MAX_BODY, cfg.max_body_bytes.to_string())
                .body(())
                .map_err(to_io)?;

            let send_request = self.send_request.clone();
            let mut send_request = send_request.ready().await.map_err(to_io)?;
            let end_stream = body.is_empty();
            let (response, mut send) = send_request
                .send_request(request, end_stream)
                .map_err(to_io)?;

            // Send the body honoring h2 flow control (a single send_data can
            // exceed the stream window).
            let mut remaining = body;
            while !remaining.is_empty() {
                send.reserve_capacity(remaining.len().min(MAX_H2_WRITE_CHUNK));
                let granted = std::future::poll_fn(|cx| send.poll_capacity(cx))
                    .await
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::BrokenPipe, "meek: h2 send stream closed")
                    })?
                    .map_err(to_io)?;
                let chunk = remaining.split_to(granted.min(remaining.len()));
                send.send_data(chunk, remaining.is_empty()).map_err(to_io)?;
            }

            let response = response.await.map_err(to_io)?;
            let status = response.status();
            if status != http::StatusCode::OK {
                return Err(io::Error::other(format!("meek: status {status}")));
            }
            let mut out = Vec::new();
            let mut recv = response.into_body();
            while let Some(chunk) = recv.data().await {
                let chunk = chunk.map_err(to_io)?;
                recv.flow_control()
                    .release_capacity(chunk.len())
                    .map_err(to_io)?;
                // The server caps responses at the advertised max-body; an over-cap
                // body is a protocol violation. Error rather than silently truncate
                // and advance the seq past data the app never received.
                if out.len() + chunk.len() > cfg.max_body_bytes {
                    return Err(io::Error::other("meek: h2 response exceeds max_body_bytes"));
                }
                out.extend_from_slice(&chunk);
            }
            Ok(out)
        }
    }

    fn to_io(err: impl std::fmt::Display) -> io::Error {
        io::Error::other(err.to_string())
    }
}

/// Dials a domain-fronted meek **polling** session: races the configured fronts
/// (Akamai/CloudFront/Aliyun) to a working verified-TLS edge, then runs the meek
/// polling protocol over it to the inner host. This is the type a transport (e.g.
/// spark's `fronted-meek`) instantiates.
///
/// Build it from a fronted [`crate::Config`] (server-delivered or embedded seed)
/// or, for the config-less self-bootstrap, from scanner-discovered fronts via
/// [`crate::scanner`] → [`crate::Config`].
pub struct FrontedMeekPollDialer<R> {
    dialer: crate::FrontedTlsDialer<R>,
    /// The inner meek endpoint host the front routes to (e.g.
    /// `meek.dsa.akamai.getiantem.org`).
    inner_host: String,
    /// Template meek config; `inner_host` is filled per-connection from the
    /// winning front's `fronted_host`.
    meek: MeekPollConfig,
}

impl<R> FrontedMeekPollDialer<R> {
    pub fn new(dialer: crate::FrontedTlsDialer<R>, inner_host: impl Into<String>) -> Self {
        let inner_host = inner_host.into();
        let meek = MeekPollConfig::new(inner_host.clone());
        Self {
            dialer,
            inner_host,
            meek,
        }
    }

    pub fn with_meek_config(mut self, meek: MeekPollConfig) -> Self {
        self.meek = meek;
        self
    }

    pub fn inner_host(&self) -> &str {
        &self.inner_host
    }
}

impl<R: crate::FrontResolver> FrontedMeekPollDialer<R> {
    /// Dial a working front and open a meek polling session over it.
    pub async fn connect(&self) -> io::Result<MeekPollConn> {
        let conn = self
            .dialer
            .connect_fronted(&self.inner_host)
            .await
            .map_err(io::Error::other)?;
        self.open_meek(conn)
    }

    /// Open meek over an already-dialed fronted connection. Factored out so the
    /// full glue path is testable without a real TLS dial.
    pub fn open_meek<S>(&self, conn: crate::FrontedConnection<S>) -> io::Result<MeekPollConn>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        open_meek_poll(conn, self.meek.clone())
    }
}

/// Open a meek polling session over an already-dialed fronted connection,
/// addressing the meek POSTs to the host the winning front routes to. Lets a
/// caller that races its own fronts (e.g. a scanner-driven transport that caches
/// the winning edge) reuse the meek layer without going through
/// [`FrontedMeekPollDialer`].
pub fn open_meek_poll<S>(
    conn: crate::FrontedConnection<S>,
    mut meek: MeekPollConfig,
) -> io::Result<MeekPollConn>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    meek.inner_host = conn.fronted_host().to_owned();
    MeekPollConn::connect(conn.stream, meek)
}

/// Like [`open_meek_poll`], but **auto-selects the HTTP version from the ALPN** the
/// front negotiated: h2 if the edge picked `h2`, else h1. Pair with
/// [`crate::dial_fronts_alpn`] so the meek client speaks whatever the CDN chose,
/// instead of a fixed guess. Any `meek.http_version` is overridden.
pub fn open_meek_poll_auto(
    conn: crate::FrontedConnection<flint_dial::AlpnStream>,
    mut meek: MeekPollConfig,
) -> io::Result<MeekPollConn> {
    meek.http_version = if conn.stream.alpn() == Some(b"h2".as_slice()) {
        MeekHttpVersion::H2
    } else {
        MeekHttpVersion::H1
    };
    open_meek_poll(conn, meek)
}

/// True if `s` contains an ASCII control char (incl. CR/LF) — these can split a
/// hand-built HTTP/1.1 request or inject headers, so the meek host/path reject them.
fn has_invalid_host_char(s: &str) -> bool {
    // Anything outside printable non-space ASCII (control incl. CR/LF, SPACE/DEL,
    // and non-ASCII) would break the hand-built h1 request line / Host header.
    s.bytes().any(|b| b <= 0x20 || b >= 0x7f)
}

/// inner_host must be a bare authority (`host[:port]`) — additionally reject the
/// authority-breaking characters that don't belong in a Host header / request
/// target (`/ ? # @ \`).
fn invalid_inner_host(s: &str) -> bool {
    s.is_empty()
        || has_invalid_host_char(s)
        || s.bytes()
            .any(|b| matches!(b, b'/' | b'?' | b'#' | b'@' | b'\\'))
}

fn random_session_id(len: usize) -> io::Result<String> {
    let mut raw = vec![0u8; len];
    ring::rand::SystemRandom::new()
        .fill(&mut raw)
        .map_err(|_| io::Error::other("meek: session id rng failed"))?;
    let mut s = String::with_capacity(len * 2);
    for b in raw {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// In-process h2 meek echo-server with the deployed server's seq semantics:
    /// each POST's body is echoed in its response; a repeated `X-Meek-Seq`
    /// (a retried poll) replays the buffered response instead of re-echoing.
    /// `drop_seqs` simulates a lost-after-processed response: the listed seqs are
    /// processed (state advances) but the response is dropped (stream reset), so
    /// the client must retry and rely on the replay.
    async fn run_echo_server(io: DuplexStream, drop_seqs: Vec<u64>) {
        use std::sync::{Arc, Mutex};
        let mut conn = h2::server::handshake(io).await.expect("server handshake");
        let last: Arc<Mutex<HashMap<String, (u64, Bytes)>>> = Arc::new(Mutex::new(HashMap::new()));
        let drop_seqs = Arc::new(drop_seqs);
        // Each request is handled on its own task so the accept loop keeps
        // driving the h2 connection (h2 requires the connection be polled while
        // a request's body/response is in flight — handling inline deadlocks).
        while let Some(accepted) = conn.accept().await {
            let (req, mut respond) = match accepted {
                Ok(v) => v,
                Err(_) => break,
            };
            let last = last.clone();
            let drop_seqs = drop_seqs.clone();
            tokio::spawn(async move {
                let sid = req
                    .headers()
                    .get("x-session-id")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_owned();
                let seq: u64 = req
                    .headers()
                    .get("x-meek-seq")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                let mut body = req.into_body();
                let mut buf = Vec::new();
                while let Some(chunk) = body.data().await {
                    let chunk = chunk.expect("server read body");
                    let _ = body.flow_control().release_capacity(chunk.len());
                    buf.extend_from_slice(&chunk);
                }
                let (resp_body, is_replay): (Bytes, bool) = {
                    let mut map = last.lock().unwrap();
                    match map.get(&sid) {
                        Some((lseq, lresp)) if *lseq == seq => (lresp.clone(), true), // replay
                        _ => {
                            let resp = Bytes::from(buf); // echo fresh
                            map.insert(sid.clone(), (seq, resp.clone()));
                            (resp, false)
                        }
                    }
                };
                // Model a response lost ONCE: drop only the first (fresh) delivery
                // of a dropped seq; the retry is a replay and goes through, so the
                // client recovers. State was already stored above.
                if !is_replay && drop_seqs.contains(&seq) {
                    respond.send_reset(h2::Reason::INTERNAL_ERROR);
                    return;
                }
                let response = http::Response::builder().status(200).body(()).unwrap();
                let mut send = respond
                    .send_response(response, resp_body.is_empty())
                    .expect("send_response");
                if !resp_body.is_empty() {
                    send.send_data(resp_body, true).expect("send_data");
                }
            });
        }
    }

    fn cfg() -> MeekPollConfig {
        let mut c = MeekPollConfig::new("meek.test");
        c.poll_interval = Duration::from_millis(10);
        c
    }

    fn dummy_front(host: &str) -> crate::Front {
        crate::Front {
            provider: "test".into(),
            domain: host.into(),
            endpoint: crate::FrontEndpoint::Ip("127.0.0.1:443".parse().unwrap()),
            sni: String::new(),
            fronted_host: host.into(),
            verification: flint_dial::CertVerification::Roots {
                roots_pem: std::sync::Arc::from([] as [String; 0]),
                hostname: host.into(),
            },
        }
    }

    #[tokio::test]
    async fn glue_dialer_opens_meek_over_a_fronted_connection() {
        // The full glue path: FrontedConnection (the verified-TLS stream a front
        // dial yields) -> FrontedMeekPollDialer::open_meek -> MeekPollConn, echoed
        // end-to-end. The "TLS stream" here is a duplex whose far end runs the h2
        // meek echo server.
        let host = "meek.test";
        let (client_io, server_io) = duplex(64 * 1024);
        tokio::spawn(run_echo_server(server_io, vec![]));

        let conn = crate::FrontedConnection {
            stream: client_io,
            front: dummy_front(host),
            addr: "127.0.0.1:443".parse().unwrap(),
            candidate_index: 0,
        };
        // A dialer whose pool is irrelevant here (we drive open_meek directly).
        let dialer = crate::FrontedTlsDialer::new(
            &crate::Config::default(),
            "",
            crate::SystemResolver::new(),
        );
        let mut meek_cfg = cfg();
        meek_cfg.inner_host = "placeholder".into(); // open_meek must override from the front
        let glue = FrontedMeekPollDialer::new(dialer, host).with_meek_config(meek_cfg);

        let mut meek = glue.open_meek(conn).expect("open meek");
        meek.write_all(b"via glue").await.expect("write");
        let mut out = [0u8; 8];
        meek.read_exact(&mut out).await.expect("read");
        assert_eq!(&out, b"via glue");
    }

    /// In-process HTTP/1.1 keep-alive meek echo server: read each POST's
    /// Content-Length body and echo it back with a Content-Length response. meek
    /// polls are sequential, so a single-threaded loop suffices.
    async fn run_h1_echo_server(io: DuplexStream) {
        use tokio::io::AsyncBufReadExt;
        let mut stream = tokio::io::BufReader::new(io);
        loop {
            let mut line = String::new();
            if stream.read_line(&mut line).await.unwrap_or(0) == 0 {
                break; // client closed
            }
            let mut content_length = 0usize;
            loop {
                let mut h = String::new();
                if stream.read_line(&mut h).await.unwrap_or(0) == 0 {
                    return;
                }
                let t = h.trim_end();
                if t.is_empty() {
                    break;
                }
                if let Some(v) = t.to_ascii_lowercase().strip_prefix("content-length:") {
                    content_length = v.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0u8; content_length];
            if stream.read_exact(&mut body).await.is_err() {
                break;
            }
            let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
            if stream.write_all(head.as_bytes()).await.is_err() {
                break;
            }
            if !body.is_empty() && stream.write_all(&body).await.is_err() {
                break;
            }
            let _ = stream.flush().await;
        }
    }

    #[tokio::test]
    async fn h1_echo_roundtrip() {
        let (client_io, server_io) = duplex(64 * 1024);
        tokio::spawn(run_h1_echo_server(server_io));
        let mut c = cfg();
        c.http_version = MeekHttpVersion::H1;
        let mut conn = MeekPollConn::connect(client_io, c).expect("connect");
        conn.write_all(b"hello h1 meek").await.expect("write");
        let mut out = [0u8; 13];
        conn.read_exact(&mut out).await.expect("read");
        assert_eq!(&out, b"hello h1 meek");
    }

    #[tokio::test]
    async fn echo_roundtrip_small() {
        let (client_io, server_io) = duplex(64 * 1024);
        tokio::spawn(run_echo_server(server_io, vec![]));
        let mut conn = MeekPollConn::connect(client_io, cfg()).expect("connect");

        conn.write_all(b"hello meek").await.expect("write");
        let mut out = [0u8; 10];
        conn.read_exact(&mut out).await.expect("read");
        assert_eq!(&out, b"hello meek");
    }

    #[tokio::test]
    async fn echo_roundtrip_multi_poll() {
        // Payload larger than one poll body cap → multiple polls reassemble.
        let (client_io, server_io) = duplex(1 << 20);
        tokio::spawn(run_echo_server(server_io, vec![]));
        let mut c = cfg();
        c.max_body_bytes = 16 * 1024; // force several polls
        let mut conn = MeekPollConn::connect(client_io, c).expect("connect");

        let payload: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let writer = payload.clone();
        let wh = tokio::spawn(async move {
            conn.write_all(&writer).await.expect("write");
            let mut got = vec![0u8; writer.len()];
            conn.read_exact(&mut got).await.expect("read");
            got
        });
        let got = wh.await.expect("task");
        assert_eq!(got, payload, "multi-poll payload corrupted");
    }

    #[tokio::test]
    async fn retry_replays_dropped_response_without_loss() {
        // Drop the response for seq 0 and seq 2: the server processed them, so a
        // correct client retries the same seq and the server replays — no gap, no
        // duplication in the echoed stream.
        let (client_io, server_io) = duplex(1 << 20);
        tokio::spawn(run_echo_server(server_io, vec![0, 2]));
        let mut c = cfg();
        c.max_body_bytes = 4 * 1024;
        let mut conn = MeekPollConn::connect(client_io, c).expect("connect");

        let payload: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
        let writer = payload.clone();
        let wh = tokio::spawn(async move {
            conn.write_all(&writer).await.expect("write");
            let mut got = vec![0u8; writer.len()];
            conn.read_exact(&mut got).await.expect("read");
            got
        });
        let got = tokio::time::timeout(Duration::from_secs(10), wh)
            .await
            .expect("did not hang")
            .expect("task");
        assert_eq!(got, payload, "retry caused gap/dup under dropped response");
    }
}
