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
}

#[async_trait]
pub trait BoxedConnectionTransport: Send + Sync {
    fn name(&self) -> &str;

    async fn connect_boxed(&self, host: &str) -> io::Result<BoxedConnection>;
}

#[async_trait]
impl<T> BoxedConnectionTransport for T
where
    T: ConnectionTransport + Send + Sync,
{
    fn name(&self) -> &str {
        ConnectionTransport::name(self)
    }

    async fn connect_boxed(&self, host: &str) -> io::Result<BoxedConnection> {
        Ok(Box::new(self.connect(host).await?))
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
            Some((index, transport, Ok(stream))) => {
                return Ok(TransportConnection {
                    stream,
                    transport,
                    index,
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
