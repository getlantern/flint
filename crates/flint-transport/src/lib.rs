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

    /// Like [`connect`](Self::connect), but also reports the ALPN protocol the peer negotiated
    /// (e.g. `b"h2"`, `b"http/1.1"`), so a consumer layering HTTP over the returned stream can pick
    /// its version from what actually happened rather than from what usually happens.
    ///
    /// Override this on any transport whose TLS offers ALPN. The default reports `None`, which means
    /// only *"this transport cannot say"* — never *"nothing was negotiated"*. A consumer should read
    /// `None` as "fall back to the version you were built to speak", not as "assume HTTP/1.1".
    ///
    /// Why this lives on the transport rather than the stream: [`Connection`] is blanket-implemented
    /// for every `AsyncRead + AsyncWrite`, so it cannot be specialized to expose ALPN per stream
    /// type, and [`BoxedConnection`] erases the concrete type before a consumer could downcast to
    /// something like `flint_dial::AlpnStream`. The transport is the last layer that still knows.
    async fn connect_alpn(&self, host: &str) -> io::Result<(Self::Stream, Option<Vec<u8>>)>
    where
        Self: Sync,
    {
        Ok((self.connect(host).await?, None))
    }
}

#[async_trait]
pub trait BoxedConnectionTransport: Send + Sync {
    fn name(&self) -> &str;

    /// Connect and report the negotiated ALPN — see [`ConnectionTransport::connect_alpn`].
    async fn connect_boxed(&self, host: &str) -> io::Result<(BoxedConnection, Option<Vec<u8>>)>;
}

#[async_trait]
impl<T> BoxedConnectionTransport for T
where
    T: ConnectionTransport + Send + Sync,
{
    fn name(&self) -> &str {
        ConnectionTransport::name(self)
    }

    async fn connect_boxed(&self, host: &str) -> io::Result<(BoxedConnection, Option<Vec<u8>>)> {
        let (stream, alpn) = self.connect_alpn(host).await?;
        Ok((Box::new(stream), alpn))
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
    /// The ALPN protocol the winning transport negotiated, when it can say — see
    /// [`ConnectionTransport::connect_alpn`]. `None` means unreported, not "none negotiated".
    pub alpn: Option<Vec<u8>>,
}

impl TransportConnection {
    /// Whether the winner negotiated HTTP/2.
    ///
    /// Deliberately false for `None`: a transport that cannot report its ALPN has not told you it
    /// speaks h2, and writing HTTP/2 preface bytes at an HTTP/1.1 peer fails in a way that does not
    /// look like a protocol error — the response never terminates, so it surfaces as a hang or a
    /// "no header terminator" parse failure much later.
    pub fn is_h2(&self) -> bool {
        self.alpn.as_deref() == Some(b"h2")
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
            Some((index, transport, Ok((stream, alpn)))) => {
                return Ok(TransportConnection {
                    stream,
                    transport,
                    index,
                    alpn,
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

        async fn connect_alpn(&self, host: &str) -> io::Result<(Self::Stream, Option<Vec<u8>>)> {
            Ok((self.connect(host).await?, Some(self.0.to_vec())))
        }
    }

    /// The compatibility claim behind the provided method: a transport written before `connect_alpn`
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
        assert_eq!(conn.alpn, None);
        assert!(!conn.is_h2(), "unreported ALPN must not read as h2");
    }

    #[tokio::test]
    async fn the_winners_alpn_reaches_the_caller() {
        let transports: Vec<Box<dyn BoxedConnectionTransport>> =
            vec![Box::new(AlpnTransport(b"h2"))];
        let conn = race_boxed("api.example.com", &transports, RaceOptions::default())
            .await
            .expect("connects");
        assert_eq!(conn.alpn.as_deref(), Some(&b"h2"[..]));
        assert!(conn.is_h2());
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
        assert_eq!(conn.alpn.as_deref(), Some(&b"http/1.1"[..]));
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
