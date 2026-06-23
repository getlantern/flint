//! Connection-first Rust Kindling orchestration.
//!
//! This crate deliberately races byte-stream transports instead of HTTP clients. HTTP, config fetches,
//! or other bootstrap protocols can be layered above the returned connection.
#![forbid(unsafe_code)]

pub use flint_transport::{
    BoxedConnection, BoxedConnectionTransport, Connection, ConnectionTransport, RaceError,
    RaceOptions, TransportConnection,
};

pub use flint_fronted::{FlintDnsResolver, FrontResolver, FrontedMeekDialer, FrontedTlsDialer};

pub struct Kindling {
    transports: Vec<Box<dyn BoxedConnectionTransport>>,
    race_options: RaceOptions,
}

impl Kindling {
    pub fn new() -> Self {
        Self {
            transports: Vec::new(),
            race_options: RaceOptions::default(),
        }
    }

    pub fn with_race_options(mut self, options: RaceOptions) -> Self {
        self.race_options = options;
        self
    }

    pub fn with_transport<T>(mut self, transport: T) -> Self
    where
        T: BoxedConnectionTransport + 'static,
    {
        self.transports.push(Box::new(transport));
        self
    }

    pub fn with_fronted_meek<R>(self, dialer: FrontedMeekDialer<R>) -> Self
    where
        R: FrontResolver + 'static,
    {
        self.with_transport(dialer)
    }

    pub fn with_fronted_tls<R>(self, dialer: FrontedTlsDialer<R>) -> Self
    where
        R: FrontResolver + 'static,
    {
        self.with_transport(dialer)
    }

    pub fn with_fronted_tls_yaml(
        self,
        yaml: &[u8],
        country_code: &str,
        network: impl Into<String>,
    ) -> Result<Self, flint_fronted::Error> {
        Ok(
            self.with_fronted_tls(FrontedTlsDialer::from_yaml_config_with_default_dns(
                yaml,
                country_code,
                network,
            )?),
        )
    }

    pub fn with_fronted_tls_gzipped(
        self,
        gzipped_yaml: &[u8],
        country_code: &str,
        network: impl Into<String>,
    ) -> Result<Self, flint_fronted::Error> {
        Ok(
            self.with_fronted_tls(FrontedTlsDialer::from_gzipped_config_with_default_dns(
                gzipped_yaml,
                country_code,
                network,
            )?),
        )
    }

    pub fn with_fronted_meek_yaml(
        self,
        yaml: &[u8],
        country_code: &str,
        network: impl Into<String>,
    ) -> Result<Self, flint_fronted::Error> {
        Ok(
            self.with_fronted_meek(FrontedMeekDialer::from_yaml_config_with_default_dns(
                yaml,
                country_code,
                network,
            )?),
        )
    }

    pub fn with_fronted_meek_gzipped(
        self,
        gzipped_yaml: &[u8],
        country_code: &str,
        network: impl Into<String>,
    ) -> Result<Self, flint_fronted::Error> {
        Ok(
            self.with_fronted_meek(FrontedMeekDialer::from_gzipped_config_with_default_dns(
                gzipped_yaml,
                country_code,
                network,
            )?),
        )
    }

    pub fn push_transport<T>(&mut self, transport: T)
    where
        T: BoxedConnectionTransport + 'static,
    {
        self.transports.push(Box::new(transport));
    }

    pub fn push_fronted_meek<R>(&mut self, dialer: FrontedMeekDialer<R>)
    where
        R: FrontResolver + 'static,
    {
        self.push_transport(dialer);
    }

    pub fn push_fronted_tls<R>(&mut self, dialer: FrontedTlsDialer<R>)
    where
        R: FrontResolver + 'static,
    {
        self.push_transport(dialer);
    }

    pub fn transport_count(&self) -> usize {
        self.transports.len()
    }

    pub async fn connect(&self, host: &str) -> Result<TransportConnection, RaceError> {
        flint_transport::race_boxed(host, &self.transports, self.race_options.clone()).await
    }
}

impl Default for Kindling {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io;
    use std::io::Write;
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
                return Err(io::Error::other("blocked"));
            }
            let (client, mut server) = tokio::io::duplex(256);
            tokio::spawn(async move {
                let mut buf = [0; 5];
                server.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"hello");
                server.write_all(b"world").await.unwrap();
            });
            Ok(client)
        }
    }

    fn fronted_yaml() -> &'static [u8] {
        br#"
providers:
  akamai:
    hostaliases:
      api.example.com: api.dsa.example.net
    masquerades:
      - domain: edge.example.net
        ipaddress: "203.0.113.10"
"#
    }

    fn gzipped_fronted_yaml() -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(fronted_yaml()).unwrap();
        encoder.finish().unwrap()
    }

    #[tokio::test]
    async fn kindling_races_registered_connection_transports() {
        let kindling = Kindling::new()
            .with_race_options(RaceOptions {
                window: 1,
                attempt_timeout: None,
            })
            .with_transport(MemoryTransport {
                name: "blocked",
                fail: true,
            })
            .with_transport(MemoryTransport {
                name: "memory",
                fail: false,
            });

        assert_eq!(kindling.transport_count(), 2);

        let mut conn = kindling.connect("api.example.com").await.unwrap();
        assert_eq!(conn.index, 1);
        assert_eq!(conn.transport, "memory");

        conn.stream.write_all(b"hello").await.unwrap();
        let mut out = [0; 5];
        conn.stream.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"world");
    }

    #[tokio::test]
    async fn kindling_errors_without_transports() {
        let err = match Kindling::new().connect("api.example.com").await {
            Ok(_) => panic!("expected empty transport error"),
            Err(err) => err,
        };
        assert!(matches!(err, RaceError::Empty { ref host } if host == "api.example.com"));
    }

    #[test]
    fn kindling_registers_fronted_meek_from_yaml_with_default_dns() {
        let kindling = Kindling::new()
            .with_fronted_meek_yaml(fronted_yaml(), "", "wifi")
            .unwrap();

        assert_eq!(kindling.transport_count(), 1);
    }

    #[test]
    fn kindling_registers_fronted_tls_from_yaml_with_default_dns() {
        let kindling = Kindling::new()
            .with_fronted_tls_yaml(fronted_yaml(), "", "wifi")
            .unwrap();

        assert_eq!(kindling.transport_count(), 1);
    }

    #[test]
    fn kindling_registers_fronted_meek_from_gzipped_config_with_default_dns() {
        let kindling = Kindling::new()
            .with_fronted_meek_gzipped(&gzipped_fronted_yaml(), "", "wifi")
            .unwrap();

        assert_eq!(kindling.transport_count(), 1);
    }

    #[test]
    fn kindling_registers_fronted_tls_from_gzipped_config_with_default_dns() {
        let kindling = Kindling::new()
            .with_fronted_tls_gzipped(&gzipped_fronted_yaml(), "", "wifi")
            .unwrap();

        assert_eq!(kindling.transport_count(), 1);
    }
}
