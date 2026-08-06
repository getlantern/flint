//! Connection-based transport traits and racing for a Rust Kindling-style bootstrap layer.
//!
//! Kindling's Rust shape is intentionally connection-first: each transport opens an
//! `AsyncRead + AsyncWrite` byte stream, and protocol adapters such as HTTP can be layered above it.
#![forbid(unsafe_code)]

use std::io;
use std::time::Duration;

use async_trait::async_trait;
use futures::stream::{FuturesUnordered, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};

pub trait Connection: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + ?Sized> Connection for T {}

pub type BoxedConnection = Box<dyn Connection + 'static>;

#[async_trait]
pub trait ConnectionTransport {
    type Stream: Connection + 'static;

    fn name(&self) -> &str;

    async fn connect(&self, host: &str) -> io::Result<Self::Stream>;

    /// Like [`connect`](Self::connect), but also reports what the transport learned while
    /// establishing the connection — see [`ConnectionInfo`].
    ///
    /// Override this on any transport that knows something the HTTP layer above it needs: the ALPN
    /// its TLS negotiated, or the authority a request over this connection must be addressed to.
    ///
    /// The default reports nothing, which is the honest answer for a transport that has nothing to
    /// add. It is **not** a set of defaults to act on: an absent field means "this transport cannot
    /// say", so the consumer falls back to what it already knows, rather than treating the absence as
    /// evidence about the wire.
    ///
    /// Why this lives on the transport rather than the stream: [`Connection`] is blanket-implemented
    /// for every `AsyncRead + AsyncWrite`, so it cannot be specialized per stream type, and
    /// [`BoxedConnection`] erases the concrete type before a consumer could downcast to something like
    /// `flint_dial::AlpnStream`. The transport is the last layer that still knows.
    async fn connect_info(&self, host: &str) -> io::Result<(Self::Stream, ConnectionInfo)>
    where
        Self: Sync,
    {
        Ok((self.connect(host).await?, ConnectionInfo::default()))
    }
}

/// What a transport learned while connecting, beyond the byte stream itself.
///
/// These are facts the transport holds and the protocol layered above it needs, which the trait
/// boundary would otherwise destroy. Grouped rather than returned as a widening tuple so that adding
/// the next one is a new field instead of another signature change at every implementor.
///
/// Every field is optional and `None` means **"this transport cannot say"**, never a default worth
/// acting on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnectionInfo {
    /// The ALPN protocol the peer negotiated (e.g. `b"h2"`, `b"http/1.1"`), so a consumer picks its
    /// HTTP version from what actually happened rather than from what usually happens.
    ///
    /// One state, not two: it covers both "this transport does not report ALPN" and "the peer
    /// selected none". A transport forwarding `flint_dial::AlpnStream::alpn` cannot separate them, so
    /// a contract claiming to would be one no implementation honours.
    pub alpn: Option<Vec<u8>>,

    /// The host a request over this connection must be addressed to (`:authority` / `Host`), when
    /// that differs from the host the caller asked for.
    ///
    /// Domain fronting is the case that needs this: the connection is made to a CDN edge, and the
    /// request has to name the front's *inner* host for the edge to re-originate it — a different
    /// name per provider. A consumer that addresses the host it asked for reaches the right edge and
    /// gets the wrong routing, which looks like the CDN being blocked rather than a bug.
    pub authority: Option<String>,
}

impl ConnectionInfo {
    /// Whether the peer negotiated HTTP/2.
    ///
    /// Deliberately false for an unreported ALPN: nothing has said the peer speaks h2, and writing
    /// HTTP/2 preface bytes at an HTTP/1.1 peer does not fail like a protocol error — the response
    /// never terminates, surfacing as a hang or a "no header terminator" parse failure much later.
    /// Guessing in this direction is the expensive one.
    pub fn is_h2(&self) -> bool {
        self.alpn.as_deref() == Some(b"h2")
    }

    /// The authority to address, falling back to `asked_for` when the transport has no opinion.
    pub fn authority<'a>(&'a self, asked_for: &'a str) -> &'a str {
        self.authority.as_deref().unwrap_or(asked_for)
    }
}

#[async_trait]
pub trait BoxedConnectionTransport: Send + Sync {
    fn name(&self) -> &str;

    /// Connect and report what the transport learned — see [`ConnectionTransport::connect_info`].
    async fn connect_boxed(&self, host: &str) -> io::Result<(BoxedConnection, ConnectionInfo)>;
}

#[async_trait]
impl<T> BoxedConnectionTransport for T
where
    T: ConnectionTransport + Send + Sync,
{
    fn name(&self) -> &str {
        ConnectionTransport::name(self)
    }

    async fn connect_boxed(&self, host: &str) -> io::Result<(BoxedConnection, ConnectionInfo)> {
        let (stream, info) = self.connect_info(host).await?;
        Ok((Box::new(stream), info))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RaceOptions {
    pub window: usize,
    pub attempt_timeout: Option<Duration>,
}

impl Default for RaceOptions {
    fn default() -> Self {
        Self {
            window: 4,
            attempt_timeout: Some(Duration::from_secs(15)),
        }
    }
}

pub struct TransportConnection {
    pub stream: BoxedConnection,
    pub transport: String,
    pub index: usize,
    /// What the **winning** transport learned while connecting — see [`ConnectionInfo`]. Belongs to
    /// the member that won, not to the list, which is the point of carrying it here.
    pub info: ConnectionInfo,
}

impl TransportConnection {
    /// Whether the winner negotiated HTTP/2. See [`ConnectionInfo::is_h2`].
    pub fn is_h2(&self) -> bool {
        self.info.is_h2()
    }

    /// The authority to address a request over this connection to, falling back to `asked_for`.
    /// See [`ConnectionInfo::authority`].
    pub fn authority<'a>(&'a self, asked_for: &'a str) -> &'a str {
        self.info.authority(asked_for)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RaceError {
    #[error("no connection transports configured for `{host}`")]
    Empty { host: String },
    #[error("all {tried} connection transports failed for `{host}`: {errors}")]
    AllFailed {
        host: String,
        tried: usize,
        errors: String,
    },
}

pub async fn race_boxed(
    host: &str,
    transports: &[Box<dyn BoxedConnectionTransport>],
    options: RaceOptions,
) -> Result<TransportConnection, RaceError> {
    if transports.is_empty() {
        return Err(RaceError::Empty {
            host: host.to_owned(),
        });
    }

    let window = options.window.max(1);
    let mut set = FuturesUnordered::new();
    let mut next = 0;
    let mut errors = Vec::new();

    loop {
        while next < transports.len() && set.len() < window {
            let i = next;
            next += 1;
            let transport = &transports[i];
            let name = transport.name().to_owned();
            let fut = transport.connect_boxed(host);
            let timeout = options.attempt_timeout;
            set.push(async move {
                let result = match timeout {
                    Some(timeout) => match tokio::time::timeout(timeout, fut).await {
                        Ok(result) => result,
                        Err(_) => Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "connection transport attempt timed out",
                        )),
                    },
                    None => fut.await,
                };
                (i, name, result)
            });
        }

        match set.next().await {
            Some((index, transport, Ok((stream, info)))) => {
                return Ok(TransportConnection {
                    stream,
                    transport,
                    index,
                    info,
                });
            }
            Some((_index, transport, Err(err))) => {
                errors.push(format!("{transport}: {err}"));
            }
            None => {
                return Err(RaceError::AllFailed {
                    host: host.to_owned(),
                    tried: transports.len(),
                    errors: join_errors(errors),
                });
            }
        }
    }
}

fn join_errors(errors: Vec<String>) -> String {
    if errors.is_empty() {
        return "no attempts completed".into();
    }
    errors.join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct MemoryTransport {
        name: &'static str,
        fail: bool,
    }

    #[async_trait]
    impl ConnectionTransport for MemoryTransport {
        type Stream = tokio::io::DuplexStream;

        fn name(&self) -> &str {
            self.name
        }

        async fn connect(&self, _host: &str) -> io::Result<Self::Stream> {
            if self.fail {
                return Err(io::Error::other("not today"));
            }
            let (client, mut server) = tokio::io::duplex(256);
            tokio::spawn(async move {
                let mut buf = [0; 4];
                server.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"ping");
                server.write_all(b"pong").await.unwrap();
            });
            Ok(client)
        }
    }

    /// A transport that knows what its TLS negotiated and says so.
    struct AlpnTransport(&'static [u8]);

    #[async_trait]
    impl ConnectionTransport for AlpnTransport {
        type Stream = tokio::io::DuplexStream;

        fn name(&self) -> &str {
            "alpn"
        }

        async fn connect(&self, _host: &str) -> io::Result<Self::Stream> {
            Ok(tokio::io::duplex(8).0)
        }

        async fn connect_info(&self, host: &str) -> io::Result<(Self::Stream, ConnectionInfo)> {
            Ok((
                self.connect(host).await?,
                ConnectionInfo {
                    alpn: Some(self.0.to_vec()),
                    ..Default::default()
                },
            ))
        }
    }

    /// The compatibility claim behind the provided method: a transport written before `connect_info`
    /// existed still compiles and simply reports nothing.
    #[tokio::test]
    async fn a_transport_that_does_not_override_reports_no_alpn() {
        let transports: Vec<Box<dyn BoxedConnectionTransport>> = vec![Box::new(MemoryTransport {
            name: "memory",
            fail: false,
        })];
        let conn = race_boxed("api.example.com", &transports, RaceOptions::default())
            .await
            .expect("connects");
        assert_eq!(conn.info, ConnectionInfo::default());
        assert!(!conn.is_h2(), "an unknown ALPN must not read as h2");
    }

    #[tokio::test]
    async fn the_winners_alpn_reaches_the_caller() {
        let transports: Vec<Box<dyn BoxedConnectionTransport>> =
            vec![Box::new(AlpnTransport(b"h2"))];
        let conn = race_boxed("api.example.com", &transports, RaceOptions::default())
            .await
            .expect("connects");
        assert_eq!(conn.info.alpn.as_deref(), Some(&b"h2"[..]));
        assert!(conn.is_h2());
    }

    /// A transport that routes by a name the caller does not know must be able to say so, and the
    /// caller must get its own host back when the transport has no opinion. Domain fronting is the
    /// case: the request has to name the front's inner host, not the origin that was asked for.
    #[tokio::test]
    async fn the_authority_overrides_the_asked_for_host_only_when_reported() {
        struct Fronted;

        #[async_trait]
        impl ConnectionTransport for Fronted {
            type Stream = tokio::io::DuplexStream;

            fn name(&self) -> &str {
                "fronted"
            }

            async fn connect(&self, _host: &str) -> io::Result<Self::Stream> {
                Ok(tokio::io::duplex(8).0)
            }

            async fn connect_info(&self, host: &str) -> io::Result<(Self::Stream, ConnectionInfo)> {
                Ok((
                    self.connect(host).await?,
                    ConnectionInfo {
                        authority: Some("api.dsa.example.net".into()),
                        ..Default::default()
                    },
                ))
            }
        }

        let fronted: Vec<Box<dyn BoxedConnectionTransport>> = vec![Box::new(Fronted)];
        let conn = race_boxed("api.example.com", &fronted, RaceOptions::default())
            .await
            .expect("connects");
        assert_eq!(conn.authority("api.example.com"), "api.dsa.example.net");

        // A transport with no opinion must not rewrite the caller's host.
        let plain: Vec<Box<dyn BoxedConnectionTransport>> = vec![Box::new(MemoryTransport {
            name: "memory",
            fail: false,
        })];
        let conn = race_boxed("api.example.com", &plain, RaceOptions::default())
            .await
            .expect("connects");
        assert_eq!(conn.authority("api.example.com"), "api.example.com");
    }

    /// The ALPN must belong to the transport that actually won, not to whichever was listed first —
    /// that is the entire point of carrying it on the connection rather than assuming per transport.
    #[tokio::test]
    async fn the_alpn_follows_the_winner_not_the_order() {
        let transports: Vec<Box<dyn BoxedConnectionTransport>> = vec![
            Box::new(MemoryTransport {
                name: "blocked",
                fail: true,
            }),
            Box::new(AlpnTransport(b"http/1.1")),
        ];
        let conn = race_boxed(
            "api.example.com",
            &transports,
            RaceOptions {
                window: 1,
                attempt_timeout: None,
            },
        )
        .await
        .expect("second transport wins");
        assert_eq!(conn.transport, "alpn");
        assert_eq!(conn.info.alpn.as_deref(), Some(&b"http/1.1"[..]));
        assert!(!conn.is_h2());
    }

    #[tokio::test]
    async fn races_boxed_transports_and_returns_first_connection() {
        let transports: Vec<Box<dyn BoxedConnectionTransport>> = vec![
            Box::new(MemoryTransport {
                name: "blocked",
                fail: true,
            }),
            Box::new(MemoryTransport {
                name: "memory",
                fail: false,
            }),
        ];

        let mut conn = race_boxed(
            "api.example.com",
            &transports,
            RaceOptions {
                window: 1,
                attempt_timeout: None,
            },
        )
        .await
        .unwrap();

        assert_eq!(conn.index, 1);
        assert_eq!(conn.transport, "memory");
        conn.stream.write_all(b"ping").await.unwrap();
        let mut out = [0; 4];
        conn.stream.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"pong");
    }

    #[tokio::test]
    async fn empty_transport_set_is_an_error() {
        let err = match race_boxed("api.example.com", &[], RaceOptions::default()).await {
            Ok(_) => panic!("expected an empty transport error"),
            Err(err) => err,
        };
        assert!(matches!(err, RaceError::Empty { ref host } if host == "api.example.com"));
    }
}
