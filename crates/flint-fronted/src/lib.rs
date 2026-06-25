//! Connection-first domain-fronting primitives for Lantern `fronted.yaml.gz` configs.
//!
//! This crate is the fronting consumer of Flint's lower layers: it parses the Lantern fronted config,
//! expands country-specific SNI choices, resolves host-based fronts through `flint-dns`, and
//! materializes `flint-dial::BootstrapStrategy` values. A higher-level transport can then run its
//! own CONNECT/Upgrade/meek-style stream establishment over the returned TLS stream.
//!
//! Fronted TLS strategies always verify the CDN/front certificate: `trustedcas` becomes the trust
//! roots (empty means system roots), and `verifyhostname` selects the certificate hostname
//! independently from SNI. Meek is deliberately standalone CDN-compatible framing over that verified
//! Chrome TLS stream: do not layer samizdat, anytls, or any other end-to-end TLS/auth transport inside
//! it. The CDN terminates TLS and re-originates the HTTP/2 request, so REALITY-style
//! `legacy_session_id` authentication cannot be domain-fronted; the CDN sees meek plaintext, while
//! certificate verification protects only against a third-party MITM impersonating the edge.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::future::Future;
use std::io::{self, Read};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use bytes::{Buf, Bytes};
use flint_dial::{BootstrapStrategy, BoxedTlsStream, CertVerification};
use flint_dns::{ResolverCache, TYPE_A, TYPE_AAAA};
use flint_shaping::WirePlan;
pub use flint_transport::{
    race_boxed, BoxedConnection, BoxedConnectionTransport, Connection, ConnectionTransport,
    RaceError, RaceOptions, TransportConnection,
};
use http::{Method, Request, StatusCode};
use ring::digest;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::task::JoinHandle;

const MAX_H2_WRITE_CHUNK: usize = 16 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("fronted config gzip decode failed: {0}")]
    Gzip(#[from] io::Error),
    #[error("fronted config yaml parse failed: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("unknown provider `{0}`")]
    UnknownProvider(String),
    #[error("no fronting provider maps `{host}`")]
    NoFrontingProvider { host: String },
    #[error("front `{front}` resolved to no usable A/AAAA records")]
    EmptyResolution { front: String },
    #[error("resolving front `{front}` failed: {source}")]
    Resolve {
        front: String,
        #[source]
        source: io::Error,
    },
    #[error("no usable fronts for `{host}`")]
    NoUsableFronts { host: String },
    #[error("all {tried} front dials failed: {errors}")]
    DialFailed { tried: usize, errors: String },
    #[error("opening fronted stream for `{fronted_host}` failed: {source}")]
    StreamOpen {
        fronted_host: String,
        #[source]
        source: io::Error,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    #[serde(default, rename = "trustedcas")]
    pub trusted_cas: Vec<CA>,
    #[serde(default)]
    pub providers: BTreeMap<String, Provider>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CA {
    #[serde(default, rename = "commonname")]
    pub common_name: String,
    #[serde(default)]
    pub cert: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provider {
    #[serde(default, rename = "hostaliases")]
    pub host_aliases: BTreeMap<String, String>,
    #[serde(default, rename = "passthroughpatterns", alias = "passthrupatterns")]
    pub passthrough_patterns: Vec<String>,
    #[serde(default, rename = "testurl")]
    pub test_url: String,
    #[serde(default)]
    pub masquerades: Vec<Masquerade>,
    #[serde(default, rename = "verifyhostname")]
    pub verify_hostname: Option<String>,
    #[serde(default, rename = "frontingsnis")]
    pub fronting_snis: BTreeMap<String, SNIConfig>,
}

impl Provider {
    pub fn lookup(&self, host: &str) -> Option<String> {
        let host = strip_port(host);
        let host = host.to_ascii_lowercase();
        if let Some(alias) = self.host_aliases.get(&host) {
            return Some(alias.clone());
        }
        self.passthrough_patterns.iter().find_map(|pattern| {
            if let Some(suffix) = pattern.strip_prefix("*.") {
                host.strip_suffix(suffix)
                    .is_some_and(|prefix| prefix.ends_with('.'))
                    .then_some(host.clone())
            } else {
                (pattern == &host).then_some(host.clone())
            }
        })
    }

    pub fn expanded(&self, country_code: &str) -> Self {
        // The "default" SNI bucket applies even when no country code is set: the production client
        // passes none, and gating "default" behind a non-empty country code would leave a provider
        // whose only bucket is "default" (e.g. the aliyun provider) permanently inert. An unknown
        // non-empty country code also falls back to "default". Matches domainfront::ExpandedProvider.
        let sni_cfg = self
            .fronting_snis
            .get(country_code)
            .or_else(|| self.fronting_snis.get("default"));
        Provider {
            host_aliases: self
                .host_aliases
                .iter()
                .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
                .collect(),
            passthrough_patterns: self
                .passthrough_patterns
                .iter()
                .map(|p| p.to_ascii_lowercase())
                .collect(),
            test_url: self.test_url.clone(),
            masquerades: self
                .masquerades
                .iter()
                .map(|m| {
                    let mut out = m.clone();
                    // A generated (arbitrary) SNI takes precedence; otherwise keep any SNI baked
                    // into the masquerade by the config (empty stays empty → SNI omitted on the
                    // wire). Matches domainfront::ExpandedProvider.
                    let generated = generate_sni(sni_cfg, &m.ip_address);
                    if !generated.is_empty() {
                        out.sni = generated;
                    }
                    if empty_opt(out.verify_hostname.as_deref()) {
                        out.verify_hostname = self.verify_hostname.clone();
                    }
                    out
                })
                .collect(),
            verify_hostname: self.verify_hostname.clone(),
            fronting_snis: self.fronting_snis.clone(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SNIConfig {
    #[serde(default, rename = "usearbitrarysnis")]
    pub use_arbitrary_snis: bool,
    #[serde(default, rename = "arbitrarysnis")]
    pub arbitrary_snis: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Masquerade {
    #[serde(default)]
    pub domain: String,
    #[serde(default, rename = "ipaddress")]
    pub ip_address: String,
    #[serde(default)]
    pub sni: String,
    #[serde(default, rename = "verifyhostname")]
    pub verify_hostname: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrontEndpoint {
    Ip(SocketAddr),
    Host { name: String, port: u16 },
}

impl FrontEndpoint {
    pub fn from_masquerade(m: &Masquerade) -> Option<Self> {
        parse_endpoint(&m.ip_address).or_else(|| parse_endpoint(&m.domain))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Front {
    pub provider: String,
    pub domain: String,
    pub endpoint: FrontEndpoint,
    pub sni: String,
    pub fronted_host: String,
    pub verification: CertVerification,
}

impl Front {
    pub fn strategies(&self, addrs: &[SocketAddr], wire: WirePlan) -> Vec<BootstrapStrategy> {
        addrs
            .iter()
            .copied()
            .map(|addr| {
                BootstrapStrategy::boring_chrome(addr, self.sni.clone())
                    .with_wire(wire.clone())
                    .with_verification(self.verification.clone())
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializedFront {
    pub front: Front,
    pub addrs: Vec<SocketAddr>,
}

impl MaterializedFront {
    pub fn strategies(&self, wire: WirePlan) -> Vec<BootstrapStrategy> {
        self.front.strategies(&self.addrs, wire)
    }
}

#[derive(Debug, Clone)]
pub struct DialOptions {
    pub wire: WirePlan,
    pub window: usize,
    pub attempt_timeout: Option<Duration>,
}

impl Default for DialOptions {
    fn default() -> Self {
        Self {
            wire: WirePlan::default(),
            window: 8,
            attempt_timeout: Some(Duration::from_secs(10)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FrontedConnection<T = BoxedTlsStream> {
    pub stream: T,
    pub front: Front,
    pub addr: SocketAddr,
    pub candidate_index: usize,
}

impl<T> FrontedConnection<T> {
    pub fn fronted_host(&self) -> &str {
        &self.front.fronted_host
    }

    pub async fn open_meek_stream(
        self,
        options: MeekOptions,
    ) -> Result<FrontedConnection<MeekStream>, Error>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        open_meek_stream(self, options).await
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeekOptions {
    pub path: String,
    pub method: Method,
    pub success_status: StatusCode,
}

impl Default for MeekOptions {
    fn default() -> Self {
        Self {
            path: "/".into(),
            method: Method::POST,
            success_status: StatusCode::OK,
        }
    }
}

pub struct MeekStream {
    recv: h2::RecvStream,
    send: h2::SendStream<Bytes>,
    read_buf: Option<Bytes>,
    write_closed: bool,
    driver_state: DriverState,
    _driver: DriverGuard,
}

#[derive(Debug, Clone)]
pub struct FrontedTlsDialer<R> {
    pool: FrontPool,
    resolver: R,
    dial_options: DialOptions,
}

impl<R> FrontedTlsDialer<R> {
    pub fn new(config: &Config, country_code: &str, resolver: R) -> Self {
        Self {
            pool: FrontPool::new(config, country_code),
            resolver,
            dial_options: DialOptions::default(),
        }
    }

    pub fn from_yaml_config(yaml: &[u8], country_code: &str, resolver: R) -> Result<Self, Error> {
        let config = parse_config_yaml(yaml)?;
        Ok(Self::new(&config, country_code, resolver))
    }

    pub fn from_gzipped_config(
        gzipped_yaml: &[u8],
        country_code: &str,
        resolver: R,
    ) -> Result<Self, Error> {
        let config = parse_config(gzipped_yaml)?;
        Ok(Self::new(&config, country_code, resolver))
    }

    pub fn from_pool(pool: FrontPool, resolver: R) -> Self {
        Self {
            pool,
            resolver,
            dial_options: DialOptions::default(),
        }
    }

    pub fn with_dial_options(mut self, options: DialOptions) -> Self {
        self.dial_options = options;
        self
    }

    pub fn front_pool(&self) -> &FrontPool {
        &self.pool
    }

    pub fn resolver(&self) -> &R {
        &self.resolver
    }
}

impl FrontedTlsDialer<FlintDnsResolver> {
    pub fn with_default_dns(
        config: &Config,
        country_code: &str,
        network: impl Into<String>,
    ) -> Self {
        Self::new(
            config,
            country_code,
            FlintDnsResolver::default_pool(network),
        )
    }

    pub fn from_yaml_config_with_default_dns(
        yaml: &[u8],
        country_code: &str,
        network: impl Into<String>,
    ) -> Result<Self, Error> {
        let config = parse_config_yaml(yaml)?;
        Ok(Self::with_default_dns(&config, country_code, network))
    }

    pub fn from_gzipped_config_with_default_dns(
        gzipped_yaml: &[u8],
        country_code: &str,
        network: impl Into<String>,
    ) -> Result<Self, Error> {
        let config = parse_config(gzipped_yaml)?;
        Ok(Self::with_default_dns(&config, country_code, network))
    }
}

impl<R: FrontResolver> FrontedTlsDialer<R> {
    pub async fn connect_fronted(&self, host: &str) -> Result<FrontedConnection, Error> {
        self.pool
            .dial(host, &self.resolver, self.dial_options.clone())
            .await
    }

    pub async fn connect_fronted_with<F, Fut, T>(
        &self,
        host: &str,
        dial_one: F,
    ) -> Result<FrontedConnection<T>, Error>
    where
        F: FnMut(BootstrapStrategy) -> Fut,
        Fut: Future<Output = io::Result<T>>,
    {
        self.pool
            .dial_with(host, &self.resolver, self.dial_options.clone(), dial_one)
            .await
    }
}

#[async_trait]
impl<R> ConnectionTransport for FrontedTlsDialer<R>
where
    R: FrontResolver,
{
    type Stream = BoxedTlsStream;

    fn name(&self) -> &str {
        "fronted-tls"
    }

    async fn connect(&self, host: &str) -> io::Result<Self::Stream> {
        self.connect_fronted(host)
            .await
            .map(|conn| conn.stream)
            .map_err(io::Error::other)
    }
}

#[derive(Debug, Clone)]
pub struct FrontedMeekDialer<R> {
    pool: FrontPool,
    resolver: R,
    dial_options: DialOptions,
    meek_options: MeekOptions,
}

impl<R> FrontedMeekDialer<R> {
    pub fn new(config: &Config, country_code: &str, resolver: R) -> Self {
        Self {
            pool: FrontPool::new(config, country_code),
            resolver,
            dial_options: DialOptions::default(),
            meek_options: MeekOptions::default(),
        }
    }

    pub fn from_yaml_config(yaml: &[u8], country_code: &str, resolver: R) -> Result<Self, Error> {
        let config = parse_config_yaml(yaml)?;
        Ok(Self::new(&config, country_code, resolver))
    }

    pub fn from_gzipped_config(
        gzipped_yaml: &[u8],
        country_code: &str,
        resolver: R,
    ) -> Result<Self, Error> {
        let config = parse_config(gzipped_yaml)?;
        Ok(Self::new(&config, country_code, resolver))
    }

    pub fn from_pool(pool: FrontPool, resolver: R) -> Self {
        Self {
            pool,
            resolver,
            dial_options: DialOptions::default(),
            meek_options: MeekOptions::default(),
        }
    }

    pub fn with_dial_options(mut self, options: DialOptions) -> Self {
        self.dial_options = options;
        self
    }

    pub fn with_meek_options(mut self, options: MeekOptions) -> Self {
        self.meek_options = options;
        self
    }

    pub fn front_pool(&self) -> &FrontPool {
        &self.pool
    }

    pub fn resolver(&self) -> &R {
        &self.resolver
    }
}

impl FrontedMeekDialer<FlintDnsResolver> {
    pub fn with_default_dns(
        config: &Config,
        country_code: &str,
        network: impl Into<String>,
    ) -> Self {
        Self::new(
            config,
            country_code,
            FlintDnsResolver::default_pool(network),
        )
    }

    pub fn from_yaml_config_with_default_dns(
        yaml: &[u8],
        country_code: &str,
        network: impl Into<String>,
    ) -> Result<Self, Error> {
        let config = parse_config_yaml(yaml)?;
        Ok(Self::with_default_dns(&config, country_code, network))
    }

    pub fn from_gzipped_config_with_default_dns(
        gzipped_yaml: &[u8],
        country_code: &str,
        network: impl Into<String>,
    ) -> Result<Self, Error> {
        let config = parse_config(gzipped_yaml)?;
        Ok(Self::with_default_dns(&config, country_code, network))
    }
}

impl<R: FrontResolver> FrontedMeekDialer<R> {
    pub async fn connect_fronted(
        &self,
        host: &str,
    ) -> Result<FrontedConnection<MeekStream>, Error> {
        let conn = self
            .pool
            .dial(host, &self.resolver, self.dial_options.clone())
            .await?;
        conn.open_meek_stream(self.meek_options.clone()).await
    }

    pub async fn connect_fronted_with<F, Fut, T>(
        &self,
        host: &str,
        dial_one: F,
    ) -> Result<FrontedConnection<MeekStream>, Error>
    where
        F: FnMut(BootstrapStrategy) -> Fut,
        Fut: Future<Output = io::Result<T>>,
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let conn = self
            .pool
            .dial_with(host, &self.resolver, self.dial_options.clone(), dial_one)
            .await?;
        conn.open_meek_stream(self.meek_options.clone()).await
    }
}

#[async_trait]
impl<R> ConnectionTransport for FrontedMeekDialer<R>
where
    R: FrontResolver,
{
    type Stream = MeekStream;

    fn name(&self) -> &str {
        "fronted-meek"
    }

    async fn connect(&self, host: &str) -> io::Result<Self::Stream> {
        self.connect_fronted(host)
            .await
            .map(|conn| conn.stream)
            .map_err(io::Error::other)
    }
}

/// A non-fronted HTTP/2 request-stream transport: the unfronted sibling of [`FrontedMeekDialer`].
///
/// It resolves the origin host through a [`FrontResolver`], dials it directly with a Chrome TLS
/// ClientHello (real SNI = the host, certificate verified against the host), opens one h2
/// `{method} {path}` request to the origin, and exposes the request/response bodies as a
/// [`MeekStream`]. Because it yields the same stream type and shape as [`FrontedMeekDialer`], a
/// connection race (e.g. `flint-kindling`) can pit a direct origin dial against fronted transports
/// with every transport presenting a uniform byte stream — the direct dial wins on an open network,
/// the fronted transports win where it is blocked.
///
/// Trust defaults to the system roots; [`with_trusted_roots`](Self::with_trusted_roots) pins a
/// specific root set (e.g. to match a fronted config's `trustedcas`, or for tests).
#[derive(Debug, Clone)]
pub struct DirectH2Dialer<R> {
    resolver: R,
    port: u16,
    dial_options: DialOptions,
    meek_options: MeekOptions,
    trusted_roots: Arc<[String]>,
}

impl<R> DirectH2Dialer<R> {
    /// Build a dialer over `resolver` (used to resolve the origin host to A/AAAA records). Defaults to
    /// port 443, default [`DialOptions`], default [`MeekOptions`] (`POST /`, expecting `200`), and
    /// system-root certificate verification.
    pub fn new(resolver: R) -> Self {
        Self {
            resolver,
            port: 443,
            dial_options: DialOptions::default(),
            meek_options: MeekOptions::default(),
            trusted_roots: Arc::from(Vec::<String>::new()),
        }
    }

    /// Override the origin port (default 443).
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Override the dial options (wire plan, race window, per-attempt timeout).
    pub fn with_dial_options(mut self, options: DialOptions) -> Self {
        self.dial_options = options;
        self
    }

    /// Override the request framing (method, path, expected success status).
    pub fn with_meek_options(mut self, options: MeekOptions) -> Self {
        self.meek_options = options;
        self
    }

    /// Pin the certificate trust roots (PEM). Empty (the default) means the system roots.
    pub fn with_trusted_roots(mut self, roots: Vec<String>) -> Self {
        self.trusted_roots = roots.into();
        self
    }

    /// Borrow the resolver.
    pub fn resolver(&self) -> &R {
        &self.resolver
    }
}

impl DirectH2Dialer<FlintDnsResolver> {
    /// Build a dialer that resolves the origin host through the default un-poisoned DoH pool on
    /// `network` (mirrors [`FrontedMeekDialer::with_default_dns`]).
    pub fn with_default_dns(network: impl Into<String>) -> Self {
        Self::new(FlintDnsResolver::default_pool(network))
    }
}

impl<R: FrontResolver> DirectH2Dialer<R> {
    /// Resolve `host`, dial it directly (racing the resolved addresses), and open an h2 request-stream
    /// to `host` at the configured path. The TLS certificate is verified against `host`.
    pub async fn connect_direct(&self, host: &str) -> Result<MeekStream, Error> {
        self.connect_direct_with(
            host,
            |strategy| async move { flint_dial::dial(&strategy).await },
        )
        .await
    }

    /// [`connect_direct`](Self::connect_direct) with an injectable per-strategy dial step (the seam
    /// tests use to substitute a local server for the real network dial).
    pub async fn connect_direct_with<F, Fut, T>(
        &self,
        host: &str,
        mut dial_one: F,
    ) -> Result<MeekStream, Error>
    where
        F: FnMut(BootstrapStrategy) -> Fut,
        Fut: Future<Output = io::Result<T>>,
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let host = strip_port(host).to_ascii_lowercase();
        let ips = self
            .resolver
            .resolve(&host)
            .await
            .map_err(|source| Error::Resolve {
                front: host.clone(),
                source,
            })?;
        if ips.is_empty() {
            return Err(Error::EmptyResolution { front: host });
        }
        let verification = CertVerification::Roots {
            roots_pem: self.trusted_roots.clone(),
            hostname: host.clone(),
        };
        let strategies: Vec<BootstrapStrategy> = ips
            .into_iter()
            .map(|ip| {
                BootstrapStrategy::boring_chrome(SocketAddr::new(ip, self.port), host.clone())
                    .with_wire(self.dial_options.wire.clone())
                    .with_verification(verification.clone())
            })
            .collect();
        let timeout = self.dial_options.attempt_timeout;
        let tls = match flint_dial::race_windowed(strategies.len(), self.dial_options.window, |i| {
            let strategy = strategies[i].clone();
            let fut = dial_one(strategy);
            async move {
                match timeout {
                    Some(timeout) => match tokio::time::timeout(timeout, fut).await {
                        Ok(result) => result,
                        Err(_) => Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "direct dial attempt timed out",
                        )),
                    },
                    None => fut.await,
                }
            }
        })
        .await
        {
            Ok((_, stream)) => stream,
            Err(errors) => {
                return Err(Error::DialFailed {
                    tried: strategies.len(),
                    errors: join_errors(errors),
                })
            }
        };
        h2_request_stream(tls, &host, self.meek_options.clone())
            .await
            .map_err(|source| Error::StreamOpen {
                fronted_host: host,
                source,
            })
    }
}

#[async_trait]
impl<R> ConnectionTransport for DirectH2Dialer<R>
where
    R: FrontResolver,
{
    type Stream = MeekStream;

    fn name(&self) -> &str {
        "direct-h2"
    }

    async fn connect(&self, host: &str) -> io::Result<Self::Stream> {
        self.connect_direct(host).await.map_err(io::Error::other)
    }
}

impl AsyncRead for MeekStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if dst.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if self.read_buf.is_some() {
                let empty;
                let n;
                {
                    let buf = self.read_buf.as_mut().expect("read_buf checked above");
                    n = buf.remaining().min(dst.remaining());
                    dst.put_slice(&buf[..n]);
                    buf.advance(n);
                    empty = !buf.has_remaining();
                }
                self.recv
                    .flow_control()
                    .release_capacity(n)
                    .map_err(to_io)?;
                if empty {
                    self.read_buf = None;
                }
                return Poll::Ready(Ok(()));
            }

            match futures::ready!(self.recv.poll_data(cx)) {
                Some(Ok(chunk)) => {
                    if chunk.is_empty() {
                        continue;
                    }
                    self.read_buf = Some(chunk);
                }
                Some(Err(e)) => return Poll::Ready(Err(to_io(e))),
                None => {
                    if let Some(err) = self.driver_state.error() {
                        return Poll::Ready(Err(io::Error::new(io::ErrorKind::UnexpectedEof, err)));
                    }
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl AsyncWrite for MeekStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(err) = self.driver_state.error() {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, err)));
        }
        if self.write_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "fronted stream write side is closed",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.send.capacity() == 0 {
            self.send
                .reserve_capacity(buf.len().min(MAX_H2_WRITE_CHUNK));
            match futures::ready!(self.send.poll_capacity(cx)) {
                Some(Ok(_)) => {}
                Some(Err(e)) => return Poll::Ready(Err(to_io(e))),
                None => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "fronted stream write side is closed",
                    )));
                }
            }
        }
        let n = buf.len().min(self.send.capacity()).min(MAX_H2_WRITE_CHUNK);
        if n == 0 {
            return Poll::Pending;
        }
        self.send
            .send_data(Bytes::copy_from_slice(&buf[..n]), false)
            .map_err(to_io)?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(err) = self.driver_state.error() {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, err)));
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(err) = self.driver_state.error() {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, err)));
        }
        if !self.write_closed {
            self.send.send_data(Bytes::new(), true).map_err(to_io)?;
            self.write_closed = true;
        }
        Poll::Ready(Ok(()))
    }
}

#[derive(Clone)]
struct DriverState(Arc<Mutex<Option<String>>>);

impl DriverState {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(None)))
    }

    fn set_error(&self, error: String) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = Some(error);
    }

    fn error(&self) -> Option<String> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

struct DriverGuard(JoinHandle<()>);

impl Drop for DriverGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub async fn open_meek_stream<S>(
    conn: FrontedConnection<S>,
    options: MeekOptions,
) -> Result<FrontedConnection<MeekStream>, Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let FrontedConnection {
        stream,
        front,
        addr,
        candidate_index,
    } = conn;
    let fronted_host = front.fronted_host.clone();
    let stream = h2_request_stream(stream, &fronted_host, options)
        .await
        .map_err(|source| Error::StreamOpen {
            fronted_host: fronted_host.clone(),
            source,
        })?;
    Ok(FrontedConnection {
        stream,
        front,
        addr,
        candidate_index,
    })
}

async fn h2_request_stream<S>(
    io: S,
    authority: &str,
    options: MeekOptions,
) -> io::Result<MeekStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (send_request, connection) = h2::client::handshake(io).await.map_err(to_io)?;
    let driver_state = DriverState::new();
    let driver_error = driver_state.clone();
    let authority = authority.to_owned();
    let driver_authority = authority.clone();
    let driver = DriverGuard(tokio::spawn(async move {
        if let Err(e) = connection.await {
            let error = e.to_string();
            tracing::warn!(
                authority = %driver_authority,
                error = %error,
                "fronted h2 connection driver failed"
            );
            driver_error.set_error(error);
        }
    }));

    let request = Request::builder()
        .method(options.method)
        .uri(format!(
            "https://{authority}{}",
            normalize_path(&options.path)
        ))
        .header(http::header::HOST, authority)
        .body(())
        .map_err(to_io)?;

    let mut send_request = send_request.ready().await.map_err(to_io)?;
    let (response, send) = send_request.send_request(request, false).map_err(to_io)?;
    let response = response.await.map_err(to_io)?;
    let status = response.status();
    if status != options.success_status {
        return Err(io::Error::other(format!(
            "fronted stream returned HTTP {status}"
        )));
    }
    Ok(MeekStream {
        recv: response.into_body(),
        send,
        read_buf: None,
        write_closed: false,
        driver_state,
        _driver: driver,
    })
}

#[async_trait]
pub trait FrontResolver: Send + Sync {
    async fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>>;
}

pub struct FlintDnsResolver {
    pool: Vec<flint_dns::Resolver>,
    cache: ResolverCache,
    network: String,
}

impl FlintDnsResolver {
    pub fn new(pool: Vec<flint_dns::Resolver>, network: impl Into<String>) -> Self {
        Self {
            pool,
            cache: ResolverCache::new(),
            network: network.into(),
        }
    }

    pub fn default_pool(network: impl Into<String>) -> Self {
        Self::new(flint_dns::default_pool(), network)
    }
}

#[async_trait]
impl FrontResolver for FlintDnsResolver {
    async fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        let mut out = Vec::new();
        let mut errors = Vec::new();

        match flint_dns::resolve_cached(host, TYPE_A, &self.pool, &self.cache, &self.network).await
        {
            Ok(addrs) => out.extend(addrs),
            Err(e) => errors.push(e.to_string()),
        }
        match flint_dns::resolve_cached(host, TYPE_AAAA, &self.pool, &self.cache, &self.network)
            .await
        {
            Ok(addrs) => out.extend(addrs),
            Err(e) => errors.push(e.to_string()),
        }

        out.sort_unstable();
        out.dedup();
        if out.is_empty() && !errors.is_empty() {
            return Err(io::Error::other(errors.join("; ")));
        }
        Ok(out)
    }
}

#[derive(Debug, Clone)]
pub struct FrontPool {
    providers: BTreeMap<String, Provider>,
    trusted_roots: std::sync::Arc<[String]>,
}

impl FrontPool {
    pub fn new(config: &Config, country_code: &str) -> Self {
        let providers = config
            .providers
            .iter()
            .map(|(id, p)| (id.clone(), p.expanded(country_code)))
            .collect();
        let trusted_roots: std::sync::Arc<[String]> = config
            .trusted_cas
            .iter()
            .filter_map(|ca| non_empty_str(&ca.cert).map(ToOwned::to_owned))
            .collect();
        Self {
            providers,
            trusted_roots,
        }
    }

    pub fn fronts_for_host(&self, host: &str) -> Result<Vec<Front>, Error> {
        let mut fronts = Vec::new();
        let mut saw_provider = false;
        for (provider_id, provider) in &self.providers {
            let Some(fronted_host) = provider.lookup(host) else {
                continue;
            };
            saw_provider = true;
            for m in &provider.masquerades {
                let verify_hostname = verification_hostname(m, provider);
                if verify_hostname.is_empty() {
                    tracing::warn!(
                        provider = %provider_id,
                        fronted_host = %fronted_host,
                        "skipping fronted masquerade with no certificate verification hostname"
                    );
                    continue;
                }
                let Some(endpoint) = FrontEndpoint::from_masquerade(m) else {
                    tracing::warn!(
                        provider = %provider_id,
                        fronted_host = %fronted_host,
                        "skipping fronted masquerade with no domain or IP address"
                    );
                    continue;
                };
                fronts.push(Front {
                    provider: provider_id.clone(),
                    domain: m.domain.clone(),
                    endpoint,
                    sni: m.sni.clone(),
                    fronted_host: fronted_host.clone(),
                    verification: CertVerification::Roots {
                        roots_pem: self.trusted_roots.clone(),
                        hostname: verify_hostname.to_owned(),
                    },
                });
            }
        }
        if fronts.is_empty() && !saw_provider {
            return Err(Error::NoFrontingProvider {
                host: host.to_owned(),
            });
        }
        Ok(fronts)
    }

    pub async fn materialize<R: FrontResolver>(
        &self,
        host: &str,
        resolver: &R,
    ) -> Result<Vec<MaterializedFront>, Error> {
        let mut out = Vec::new();
        for front in self.fronts_for_host(host)? {
            let addrs = match &front.endpoint {
                FrontEndpoint::Ip(addr) => vec![*addr],
                FrontEndpoint::Host { name, port } => match resolver.resolve(name).await {
                    Ok(ips) => {
                        if ips.is_empty() {
                            tracing::warn!(front = %name, "skipping front with no A/AAAA records");
                            continue;
                        }
                        ips.into_iter()
                            .map(|ip| SocketAddr::new(ip, *port))
                            .collect()
                    }
                    Err(source) => {
                        tracing::warn!(
                            front = %name,
                            error = %source,
                            "skipping front after DNS resolution failed"
                        );
                        continue;
                    }
                },
            };
            let mut addrs = addrs;
            addrs.sort_unstable();
            addrs.dedup();
            out.push(MaterializedFront { front, addrs });
        }
        Ok(out)
    }

    pub async fn dial<R: FrontResolver>(
        &self,
        host: &str,
        resolver: &R,
        options: DialOptions,
    ) -> Result<FrontedConnection, Error> {
        self.dial_with(host, resolver, options, |strategy| async move {
            flint_dial::dial(&strategy).await
        })
        .await
    }

    pub async fn dial_with<R, F, Fut, T>(
        &self,
        host: &str,
        resolver: &R,
        options: DialOptions,
        dial_one: F,
    ) -> Result<FrontedConnection<T>, Error>
    where
        R: FrontResolver,
        F: FnMut(BootstrapStrategy) -> Fut,
        Fut: Future<Output = io::Result<T>>,
    {
        let fronts = self.materialize(host, resolver).await?;
        race_materialized_with(host, &fronts, options, dial_one).await
    }
}

pub async fn race_materialized_with<F, Fut, T>(
    host: &str,
    fronts: &[MaterializedFront],
    options: DialOptions,
    mut dial_one: F,
) -> Result<FrontedConnection<T>, Error>
where
    F: FnMut(BootstrapStrategy) -> Fut,
    Fut: Future<Output = io::Result<T>>,
{
    let candidates = candidates(fronts, options.wire);
    if candidates.is_empty() {
        return Err(Error::NoUsableFronts {
            host: host.to_owned(),
        });
    }

    let timeout = options.attempt_timeout;
    match flint_dial::race_windowed(candidates.len(), options.window, |i| {
        let strategy = candidates[i].strategy.clone();
        let fut = dial_one(strategy);
        async move {
            match timeout {
                Some(timeout) => match tokio::time::timeout(timeout, fut).await {
                    Ok(result) => result,
                    Err(_) => Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "front dial attempt timed out",
                    )),
                },
                None => fut.await,
            }
        }
    })
    .await
    {
        Ok((winner, stream)) => {
            let candidate = &candidates[winner];
            Ok(FrontedConnection {
                stream,
                front: candidate.front.clone(),
                addr: candidate.addr,
                candidate_index: winner,
            })
        }
        Err(errors) => Err(Error::DialFailed {
            tried: candidates.len(),
            errors: join_errors(errors),
        }),
    }
}

struct DialCandidate {
    front: Front,
    addr: SocketAddr,
    strategy: BootstrapStrategy,
}

fn candidates(fronts: &[MaterializedFront], wire: WirePlan) -> Vec<DialCandidate> {
    fronts
        .iter()
        .flat_map(|front| {
            front.addrs.iter().copied().map({
                let front = front.front.clone();
                let wire = wire.clone();
                move |addr| {
                    let strategy = BootstrapStrategy::boring_chrome(addr, front.sni.clone())
                        .with_wire(wire.clone())
                        .with_verification(front.verification.clone());
                    DialCandidate {
                        front: front.clone(),
                        addr,
                        strategy,
                    }
                }
            })
        })
        .collect()
}

fn join_errors(errors: Vec<io::Error>) -> String {
    if errors.is_empty() {
        return "no candidates".into();
    }
    errors
        .into_iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("; ")
}

fn normalize_path(path: &str) -> String {
    if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    }
}

fn to_io<E: std::error::Error + Send + Sync + 'static>(e: E) -> io::Error {
    io::Error::other(e)
}

pub fn parse_config(gzipped_yaml: &[u8]) -> Result<Config, Error> {
    let mut decoder = flate2::read::GzDecoder::new(gzipped_yaml);
    let mut yaml = Vec::new();
    decoder.read_to_end(&mut yaml)?;
    parse_config_yaml(&yaml)
}

pub fn parse_config_yaml(yaml: &[u8]) -> Result<Config, Error> {
    Ok(serde_yaml::from_slice(yaml)?)
}

pub fn generate_sni(config: Option<&SNIConfig>, ip_address: &str) -> String {
    let Some(config) = config else {
        return String::new();
    };
    if !config.use_arbitrary_snis || config.arbitrary_snis.is_empty() {
        return String::new();
    }
    let hash = digest::digest(&digest::SHA256, ip_address.as_bytes());
    let idx = hash.as_ref()[0] as usize % config.arbitrary_snis.len();
    config.arbitrary_snis[idx].clone()
}

fn verification_hostname<'a>(masquerade: &'a Masquerade, provider: &'a Provider) -> &'a str {
    non_empty(masquerade.verify_hostname.as_deref())
        .or_else(|| non_empty(provider.verify_hostname.as_deref()))
        .unwrap_or(&masquerade.domain)
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.and_then(non_empty_str)
}

fn non_empty_str(value: &str) -> Option<&str> {
    (!value.is_empty()).then_some(value)
}

fn empty_opt(value: Option<&str>) -> bool {
    non_empty(value).is_none()
}

fn strip_port(host: &str) -> &str {
    // Bracketed IPv6 (`[::1]` / `[::1]:443`): keep everything through the closing bracket.
    if host.starts_with('[') {
        return match host.find(']') {
            Some(end) => &host[..=end],
            None => host,
        };
    }
    // Unbracketed: only strip a trailing `:<port>` when there is exactly one colon, so an
    // unbracketed IPv6 literal (multiple colons, e.g. `2001:db8::1`) is left unchanged.
    match host.rsplit_once(':') {
        Some((h, port))
            if !h.contains(':') && !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) =>
        {
            h
        }
        _ => host,
    }
}

fn parse_endpoint(s: &str) -> Option<FrontEndpoint> {
    if s.is_empty() {
        return None;
    }
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Some(FrontEndpoint::Ip(addr));
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(FrontEndpoint::Ip(SocketAddr::new(ip, 443)));
    }
    if let Some((host, port)) = s.rsplit_once(':') {
        if !host.is_empty() {
            if let Ok(port) = port.parse::<u16>() {
                return Some(FrontEndpoint::Host {
                    name: host.to_owned(),
                    port,
                });
            }
        }
    }
    Some(FrontEndpoint::Host {
        name: s.to_owned(),
        port: 443,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "boring")]
    use boring2::{
        asn1::Asn1Time,
        bn::BigNum,
        hash::MessageDigest,
        nid::Nid,
        pkey::{PKey, Private},
        rsa::Rsa,
        ssl::{NameType, SslAcceptor, SslMethod},
        x509::{
            extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
            X509NameBuilder, X509,
        },
    };
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use http::Response;
    use std::io::Write;
    #[cfg(feature = "boring")]
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[cfg(feature = "boring")]
    static SERIAL: AtomicU32 = AtomicU32::new(1);

    #[cfg(feature = "boring")]
    struct TestCa {
        cert: X509,
        key: PKey<Private>,
        pem: String,
    }

    struct StaticResolver(Vec<IpAddr>);

    #[async_trait]
    impl FrontResolver for StaticResolver {
        async fn resolve(&self, _host: &str) -> io::Result<Vec<IpAddr>> {
            Ok(self.0.clone())
        }
    }

    struct FailingResolver;

    #[async_trait]
    impl FrontResolver for FailingResolver {
        async fn resolve(&self, _host: &str) -> io::Result<Vec<IpAddr>> {
            Err(io::Error::new(io::ErrorKind::NotFound, "no such host"))
        }
    }

    struct MemoryTransport;

    #[async_trait]
    impl ConnectionTransport for MemoryTransport {
        type Stream = tokio::io::DuplexStream;

        fn name(&self) -> &str {
            "memory"
        }

        async fn connect(&self, _host: &str) -> io::Result<Self::Stream> {
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

    #[cfg(feature = "boring")]
    fn test_ca() -> TestCa {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let name = x509_name("Test Root");
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        builder.set_pubkey(&key).unwrap();
        set_serial(&mut builder);
        builder
            .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        builder
            .append_extension(KeyUsage::new().key_cert_sign().crl_sign().build().unwrap())
            .unwrap();
        builder.sign(&key, MessageDigest::sha256()).unwrap();
        let cert = builder.build();
        let pem = String::from_utf8(cert.to_pem().unwrap()).unwrap();
        TestCa { cert, key, pem }
    }

    #[cfg(feature = "boring")]
    fn server_acceptor(ca: &TestCa, hostname: &str) -> SslAcceptor {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let name = x509_name(hostname);
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(ca.cert.subject_name()).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        builder.set_pubkey(&key).unwrap();
        set_serial(&mut builder);
        builder
            .append_extension(BasicConstraints::new().critical().build().unwrap())
            .unwrap();
        builder
            .append_extension(
                KeyUsage::new()
                    .digital_signature()
                    .key_encipherment()
                    .build()
                    .unwrap(),
            )
            .unwrap();
        builder
            .append_extension(ExtendedKeyUsage::new().server_auth().build().unwrap())
            .unwrap();
        let san = SubjectAlternativeName::new()
            .dns(hostname)
            .build(&builder.x509v3_context(Some(&ca.cert), None))
            .unwrap();
        builder.append_extension(san).unwrap();
        builder.sign(&ca.key, MessageDigest::sha256()).unwrap();
        let cert = builder.build();

        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        acceptor.set_private_key(&key).unwrap();
        acceptor.set_certificate(&cert).unwrap();
        acceptor.check_private_key().unwrap();
        acceptor.build()
    }

    #[cfg(feature = "boring")]
    fn x509_name(common_name: &str) -> boring2::x509::X509Name {
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_nid(Nid::COMMONNAME, common_name)
            .unwrap();
        name.build()
    }

    #[cfg(feature = "boring")]
    fn set_serial(builder: &mut boring2::x509::X509Builder) {
        let n = SERIAL.fetch_add(1, Ordering::Relaxed);
        let serial = BigNum::from_u32(n).unwrap().to_asn1_integer().unwrap();
        builder.set_serial_number(&serial).unwrap();
    }

    fn config_yaml() -> &'static [u8] {
        br#"
trustedcas:
  - commonname: "Test CA"
    cert: |
      -----BEGIN CERTIFICATE-----
      MIIB
      -----END CERTIFICATE-----
providers:
  akamai:
    hostaliases:
      api.example.com: api.dsa.example.net
    passthrupatterns:
      - "*.cloudfront.net"
    verifyhostname: verify.example.net
    frontingsnis:
      default:
        usearbitrarysnis: false
      br:
        usearbitrarysnis: true
        arbitrarysnis:
          - mercadopago.com
          - amazon.com.br
    masquerades:
      - domain: edge-one.example.net
        ipaddress: "203.0.113.10"
      - domain: edge-two.example.net
        ipaddress: "front-host.example.net"
"#
    }

    fn gzipped_config_yaml() -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(config_yaml()).unwrap();
        encoder.finish().unwrap()
    }

    #[cfg(feature = "boring")]
    fn verified_config(ca_pem: String, sni: &str) -> Config {
        Config {
            trusted_cas: vec![CA {
                common_name: "Test Root".into(),
                cert: ca_pem,
            }],
            providers: BTreeMap::from([(
                "akamai".into(),
                Provider {
                    host_aliases: BTreeMap::from([(
                        "api.example.com".into(),
                        "origin.example.net".into(),
                    )]),
                    fronting_snis: if sni.is_empty() {
                        BTreeMap::new()
                    } else {
                        BTreeMap::from([(
                            "default".into(),
                            SNIConfig {
                                use_arbitrary_snis: true,
                                arbitrary_snis: vec![sni.into()],
                            },
                        )])
                    },
                    masquerades: vec![Masquerade {
                        domain: "edge.test".into(),
                        ip_address: "203.0.113.10".into(),
                        sni: String::new(),
                        verify_hostname: None,
                    }],
                    ..Default::default()
                },
            )]),
        }
    }

    #[test]
    fn parses_lantern_yaml_keys() {
        let cfg = parse_config_yaml(config_yaml()).unwrap();
        assert_eq!(cfg.trusted_cas[0].common_name, "Test CA");
        let provider = cfg.providers.get("akamai").unwrap();
        assert_eq!(
            provider.host_aliases.get("api.example.com").unwrap(),
            "api.dsa.example.net"
        );
        assert!(provider.fronting_snis["br"].use_arbitrary_snis);
        assert_eq!(provider.masquerades.len(), 2);
    }

    #[test]
    fn parses_canonical_passthroughpatterns_key() {
        let cfg = parse_config_yaml(
            br#"
providers:
  cloudfront:
    passthroughpatterns:
      - "*.cloudfront.net"
"#,
        )
        .unwrap();
        let provider = cfg.providers.get("cloudfront").unwrap().expanded("");

        assert_eq!(
            provider.lookup("asset.cloudfront.net"),
            Some("asset.cloudfront.net".into())
        );
    }

    #[test]
    fn parses_legacy_passthrupatterns_key() {
        let cfg = parse_config_yaml(
            br#"
providers:
  cloudfront:
    passthrupatterns:
      - "*.cloudfront.net"
"#,
        )
        .unwrap();
        let provider = cfg.providers.get("cloudfront").unwrap().expanded("");

        assert_eq!(
            provider.lookup("asset.cloudfront.net"),
            Some("asset.cloudfront.net".into())
        );
    }

    #[test]
    #[ignore = "set FLINT_FRONTED_CONFIG_GZ to a Lantern fronted.yaml.gz path"]
    fn parses_real_lantern_fronted_config() {
        let path = std::env::var("FLINT_FRONTED_CONFIG_GZ")
            .expect("FLINT_FRONTED_CONFIG_GZ must point to fronted.yaml.gz");
        let config = parse_config(&std::fs::read(path).unwrap()).unwrap();
        let pool = FrontPool::new(&config, "cn");
        let fronts = pool.fronts_for_host("config.getiantem.org").unwrap();

        assert!(config.providers.contains_key("akamai"));
        assert!(config.providers.contains_key("cloudfront"));
        assert!(fronts.len() >= 1000);
        assert!(fronts.iter().any(|front| {
            matches!(front.endpoint, FrontEndpoint::Ip(_))
                && front.fronted_host.contains("config")
                && front.sni.is_empty()
        }));
    }

    #[tokio::test]
    async fn fronted_meek_dialer_builds_from_gzipped_config_with_a_custom_resolver() {
        let resolver = StaticResolver(vec!["198.51.100.20".parse().unwrap()]);
        let dialer =
            FrontedMeekDialer::from_gzipped_config(&gzipped_config_yaml(), "", resolver).unwrap();
        let fronts = dialer
            .front_pool()
            .materialize("api.example.com", dialer.resolver())
            .await
            .unwrap();

        assert_eq!(fronts.len(), 2);
        assert_eq!(fronts[0].addrs, vec!["203.0.113.10:443".parse().unwrap()]);
        assert_eq!(fronts[1].addrs, vec!["198.51.100.20:443".parse().unwrap()]);
    }

    #[test]
    fn fronted_meek_dialer_builds_from_yaml_with_default_flint_dns() {
        let dialer =
            FrontedMeekDialer::from_yaml_config_with_default_dns(config_yaml(), "", "wifi")
                .unwrap();
        let fronts = dialer
            .front_pool()
            .fronts_for_host("api.example.com")
            .unwrap();

        assert_eq!(fronts.len(), 2);
        assert_eq!(fronts[0].fronted_host, "api.dsa.example.net");
    }

    #[test]
    fn lookup_is_case_insensitive_and_supports_ports_and_passthroughs() {
        let cfg = parse_config_yaml(config_yaml()).unwrap();
        let provider = cfg.providers.get("akamai").unwrap().expanded("");
        assert_eq!(
            provider.lookup("API.Example.COM:443"),
            Some("api.dsa.example.net".into())
        );
        assert_eq!(
            provider.lookup("d123.cloudfront.net"),
            Some("d123.cloudfront.net".into())
        );
        assert_eq!(provider.lookup("unknown.example"), None);
    }

    #[test]
    fn country_expansion_matches_go_sni_rule() {
        let cfg = parse_config_yaml(config_yaml()).unwrap();
        let provider = cfg.providers.get("akamai").unwrap().expanded("br");
        let snis: Vec<_> = provider
            .masquerades
            .iter()
            .map(|m| m.sni.as_str())
            .collect();
        assert!(snis.iter().all(|s| !s.is_empty()));
        assert!(snis
            .iter()
            .all(|s| ["mercadopago.com", "amazon.com.br"].contains(s)));
        assert!(provider
            .masquerades
            .iter()
            .all(|m| m.verify_hostname.as_deref() == Some("verify.example.net")));
    }

    #[test]
    fn default_sni_bucket_applies_with_empty_country_code() {
        // The production client passes no country code, yet a provider whose only frontingsnis
        // bucket is "default" with usearbitrarysnis (the aliyun provider's shape) must still apply
        // its arbitrary-SNI strategy. Regression for the old `fronted` gate that left "default"
        // inert on an empty CC — which would have dialed aliyun edges with no img.alicdn.com SNI.
        let yaml = br#"
trustedcas: []
providers:
  aliyun:
    hostaliases:
      df.iantem.io: df.dcdn.getiantem.org
    frontingsnis:
      default:
        usearbitrarysnis: true
        arbitrarysnis:
          - img.alicdn.com
          - gw.alicdn.com
          - a.alicdn.com
    masquerades:
      - domain: img.alicdn.com
        ipaddress: "122.226.74.97"
        sni: ""
      - domain: img.alicdn.com
        ipaddress: "155.102.181.137"
        sni: ""
"#;
        let cfg = parse_config_yaml(yaml).unwrap();
        let provider = cfg.providers.get("aliyun").unwrap().expanded("");
        let snis: Vec<_> = provider
            .masquerades
            .iter()
            .map(|m| m.sni.as_str())
            .collect();
        assert!(
            snis.iter().all(|s| !s.is_empty()),
            "default bucket must apply with an empty country code"
        );
        assert!(snis
            .iter()
            .all(|s| ["img.alicdn.com", "gw.alicdn.com", "a.alicdn.com"].contains(s)));
    }

    #[test]
    fn baked_in_masquerade_sni_is_preserved_without_arbitrary_snis() {
        // A provider can pin a per-masquerade SNI without an arbitrary-SNI bucket; expansion must
        // not clobber it with an empty generated SNI (matches domainfront::ExpandedProvider).
        let yaml = br#"
trustedcas: []
providers:
  pinned:
    masquerades:
      - domain: front.example.net
        ipaddress: "203.0.113.5"
        sni: pinned.example.net
"#;
        let cfg = parse_config_yaml(yaml).unwrap();
        let provider = cfg.providers.get("pinned").unwrap().expanded("");
        assert_eq!(provider.masquerades[0].sni, "pinned.example.net");
    }

    #[tokio::test]
    async fn materializes_raw_ips_and_hostnames_with_a_resolver() {
        let cfg = parse_config_yaml(config_yaml()).unwrap();
        let pool = FrontPool::new(&cfg, "");
        let resolver = StaticResolver(vec![
            "198.51.100.20".parse().unwrap(),
            "2001:db8::20".parse().unwrap(),
        ]);
        let fronts = pool
            .materialize("api.example.com", &resolver)
            .await
            .unwrap();
        assert_eq!(fronts.len(), 2);
        assert_eq!(fronts[0].addrs, vec!["203.0.113.10:443".parse().unwrap()]);
        assert_eq!(
            fronts[1].addrs,
            vec![
                "198.51.100.20:443".parse().unwrap(),
                "[2001:db8::20]:443".parse().unwrap(),
            ]
        );
        assert_eq!(fronts[0].front.fronted_host, "api.dsa.example.net");
        assert_eq!(fronts[0].front.sni, "");
        assert_eq!(
            fronts[0].front.verification,
            CertVerification::Roots {
                roots_pem: std::sync::Arc::from([cfg.trusted_cas[0].cert.clone()]),
                hostname: "verify.example.net".into(),
            }
        );
    }

    #[test]
    fn front_verification_prefers_masquerade_then_provider_then_domain() {
        let cfg = parse_config_yaml(
            br#"
providers:
  akamai:
    hostaliases:
      api.example.com: api.dsa.example.net
    verifyhostname: provider.example.net
    masquerades:
      - domain: edge-one.example.net
        ipaddress: "203.0.113.10"
        verifyhostname: mask.example.net
      - domain: edge-two.example.net
        ipaddress: "203.0.113.11"
      - domain: edge-three.example.net
        ipaddress: "203.0.113.12"
        verifyhostname: ""
  cloudfront:
    hostaliases:
      api.example.com: api.dsa.example.net
    masquerades:
      - domain: edge-four.example.net
        ipaddress: "203.0.113.13"
"#,
        )
        .unwrap();
        let pool = FrontPool::new(&cfg, "");
        let fronts = pool.fronts_for_host("api.example.com").unwrap();

        let hosts: Vec<_> = fronts
            .iter()
            .filter_map(|front| match &front.verification {
                CertVerification::Roots { hostname, .. } => Some(hostname.as_str()),
                CertVerification::None => None,
            })
            .collect();
        assert_eq!(
            hosts,
            vec![
                "mask.example.net",
                "provider.example.net",
                "provider.example.net",
                "edge-four.example.net",
            ]
        );
    }

    #[tokio::test]
    async fn materialize_skips_unresolved_host_fronts_and_keeps_raw_ips() {
        let cfg = parse_config_yaml(config_yaml()).unwrap();
        let pool = FrontPool::new(&cfg, "");

        let fronts = pool
            .materialize("api.example.com", &FailingResolver)
            .await
            .unwrap();

        assert_eq!(fronts.len(), 1);
        assert_eq!(fronts[0].addrs, vec!["203.0.113.10:443".parse().unwrap()]);
        assert_eq!(fronts[0].front.domain, "edge-one.example.net");
    }

    #[tokio::test]
    async fn materialize_skips_empty_host_front_resolutions() {
        let cfg = parse_config_yaml(config_yaml()).unwrap();
        let pool = FrontPool::new(&cfg, "");

        let fronts = pool
            .materialize("api.example.com", &StaticResolver(vec![]))
            .await
            .unwrap();

        assert_eq!(fronts.len(), 1);
        assert_eq!(fronts[0].addrs, vec!["203.0.113.10:443".parse().unwrap()]);
    }

    #[test]
    fn fronts_for_host_keeps_ip_only_masquerade_with_verify_hostname() {
        // An IP-only masquerade (no domain) is still dialable and verifiable when a
        // provider/masquerade `verifyhostname` supplies the certificate identity — it must not be
        // dropped by the empty-domain guard.
        let cfg = parse_config_yaml(
            br#"
providers:
  akamai:
    hostaliases:
      api.example.com: api.dsa.example.net
    verifyhostname: provider.example.net
    masquerades:
      - domain: ""
        ipaddress: "203.0.113.10"
"#,
        )
        .unwrap();
        let pool = FrontPool::new(&cfg, "");

        let fronts = pool.fronts_for_host("api.example.com").unwrap();

        assert_eq!(fronts.len(), 1);
        assert_eq!(
            fronts[0].endpoint,
            FrontEndpoint::Ip("203.0.113.10:443".parse().unwrap())
        );
        assert!(matches!(
            &fronts[0].verification,
            CertVerification::Roots { hostname, .. } if hostname == "provider.example.net"
        ));
    }

    #[test]
    fn strip_port_handles_ports_and_ipv6() {
        assert_eq!(strip_port("api.example.com"), "api.example.com");
        assert_eq!(strip_port("api.example.com:443"), "api.example.com");
        // An unbracketed IPv6 literal must not have its last hextet mistaken for a port.
        assert_eq!(strip_port("2001:db8::1"), "2001:db8::1");
        assert_eq!(strip_port("[2001:db8::1]"), "[2001:db8::1]");
        assert_eq!(strip_port("[2001:db8::1]:443"), "[2001:db8::1]");
    }

    #[test]
    fn fronts_for_host_skips_malformed_masquerades() {
        let cfg = parse_config_yaml(
            br#"
providers:
  akamai:
    hostaliases:
      api.example.com: api.dsa.example.net
    masquerades:
      - domain: ""
        ipaddress: ""
"#,
        )
        .unwrap();
        let pool = FrontPool::new(&cfg, "");

        let fronts = pool.fronts_for_host("api.example.com").unwrap();

        assert!(fronts.is_empty());
    }

    #[tokio::test]
    async fn dial_with_races_candidates_and_returns_front_metadata() {
        let cfg = parse_config_yaml(config_yaml()).unwrap();
        let pool = FrontPool::new(&cfg, "");
        let resolver = StaticResolver(vec![
            "198.51.100.20".parse().unwrap(),
            "2001:db8::20".parse().unwrap(),
        ]);
        let conn = pool
            .dial_with(
                "api.example.com",
                &resolver,
                DialOptions {
                    window: 1,
                    attempt_timeout: None,
                    ..Default::default()
                },
                |strategy| async move {
                    if strategy.target == "203.0.113.10:443".parse().unwrap() {
                        Err(io::Error::other("raw front unavailable"))
                    } else {
                        Ok(strategy.target)
                    }
                },
            )
            .await
            .unwrap();

        assert_eq!(conn.stream, "198.51.100.20:443".parse().unwrap());
        assert_eq!(conn.addr, "198.51.100.20:443".parse().unwrap());
        assert_eq!(conn.candidate_index, 1);
        assert_eq!(conn.fronted_host(), "api.dsa.example.net");
        assert_eq!(conn.front.domain, "edge-two.example.net");
    }

    #[tokio::test]
    async fn fronted_tls_dialer_returns_plain_fronted_connection() {
        let cfg = parse_config_yaml(config_yaml()).unwrap();
        let resolver = StaticResolver(vec!["198.51.100.20".parse().unwrap()]);
        let dialer = FrontedTlsDialer::new(&cfg, "", resolver).with_dial_options(DialOptions {
            window: 1,
            attempt_timeout: None,
            ..Default::default()
        });

        fn assert_connection_transport<T: ConnectionTransport<Stream = BoxedTlsStream>>(_: &T) {}
        assert_connection_transport(&dialer);
        assert_eq!(ConnectionTransport::name(&dialer), "fronted-tls");

        let raw_front: SocketAddr = "203.0.113.10:443".parse().unwrap();
        let resolved_front: SocketAddr = "198.51.100.20:443".parse().unwrap();
        let conn = dialer
            .connect_fronted_with("api.example.com", |strategy| async move {
                if strategy.target == raw_front {
                    Err(io::Error::other("prescanned IP blocked"))
                } else {
                    Ok(strategy.target)
                }
            })
            .await
            .unwrap();

        assert_eq!(conn.stream, resolved_front);
        assert_eq!(conn.addr, resolved_front);
        assert_eq!(conn.front.domain, "edge-two.example.net");
        assert_eq!(conn.fronted_host(), "api.dsa.example.net");
    }

    #[cfg(feature = "boring")]
    #[tokio::test]
    async fn fronted_tls_verifies_front_certificate_with_empty_sni() {
        let ca = test_ca();
        let cfg = verified_config(ca.pem.clone(), "");
        let resolver = StaticResolver(vec![]);
        let dialer = FrontedTlsDialer::new(&cfg, "", resolver).with_dial_options(DialOptions {
            window: 1,
            attempt_timeout: None,
            ..Default::default()
        });
        let acceptor = std::sync::Arc::new(server_acceptor(&ca, "edge.test"));
        let (sni_tx, sni_rx) = tokio::sync::oneshot::channel();
        let sni_tx = std::sync::Arc::new(std::sync::Mutex::new(Some(sni_tx)));

        let conn = dialer
            .connect_fronted_with("api.example.com", move |strategy| {
                let acceptor = acceptor.clone();
                let sni_tx = sni_tx.lock().unwrap().take();
                async move {
                    let (client, server) = tokio::io::duplex(32 * 1024);
                    tokio::spawn(async move {
                        let mut tls = tokio_boring2::accept(&acceptor, server).await.unwrap();
                        let seen = tls
                            .ssl()
                            .servername(NameType::HOST_NAME)
                            .map(ToOwned::to_owned);
                        if let Some(tx) = sni_tx {
                            let _ = tx.send(seen);
                        }
                        tls.write_all(b"ok").await.unwrap();
                    });
                    flint_dial::dial_over(client, &strategy).await
                }
            })
            .await
            .unwrap();

        let mut stream = conn.stream;
        let mut out = [0; 2];
        stream.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"ok");
        assert_eq!(sni_rx.await.unwrap(), None);
    }

    #[cfg(feature = "boring")]
    #[tokio::test]
    async fn fronted_tls_rejects_front_certificate_signed_by_untrusted_root() {
        let trusted = test_ca();
        let untrusted = test_ca();
        let cfg = verified_config(trusted.pem.clone(), "");
        let resolver = StaticResolver(vec![]);
        let dialer = FrontedTlsDialer::new(&cfg, "", resolver).with_dial_options(DialOptions {
            window: 1,
            attempt_timeout: None,
            ..Default::default()
        });
        let acceptor = std::sync::Arc::new(server_acceptor(&untrusted, "edge.test"));

        let err = match dialer
            .connect_fronted_with("api.example.com", move |strategy| {
                let acceptor = acceptor.clone();
                async move {
                    let (client, server) = tokio::io::duplex(32 * 1024);
                    tokio::spawn(async move {
                        let _ = tokio_boring2::accept(&acceptor, server).await;
                    });
                    flint_dial::dial_over(client, &strategy).await
                }
            })
            .await
        {
            Ok(_) => panic!("expected certificate verification failure"),
            Err(err) => err,
        };

        assert!(matches!(err, Error::DialFailed { tried: 1, .. }));
    }

    #[cfg(feature = "boring")]
    #[tokio::test]
    async fn fronted_tls_rejects_front_certificate_with_mismatched_hostname() {
        let ca = test_ca();
        let cfg = verified_config(ca.pem.clone(), "");
        let resolver = StaticResolver(vec![]);
        let dialer = FrontedTlsDialer::new(&cfg, "", resolver).with_dial_options(DialOptions {
            window: 1,
            attempt_timeout: None,
            ..Default::default()
        });
        // Chains to the *trusted* CA, but the leaf is issued for the wrong name. The config verifies
        // against `edge.test` (the masquerade domain), so the hostname check must reject it — this
        // proves verify_hostname is enforced against the leaf, not only the chain.
        let acceptor = std::sync::Arc::new(server_acceptor(&ca, "wrong-host.test"));

        let err = match dialer
            .connect_fronted_with("api.example.com", move |strategy| {
                let acceptor = acceptor.clone();
                async move {
                    let (client, server) = tokio::io::duplex(32 * 1024);
                    tokio::spawn(async move {
                        let _ = tokio_boring2::accept(&acceptor, server).await;
                    });
                    flint_dial::dial_over(client, &strategy).await
                }
            })
            .await
        {
            Ok(_) => panic!("expected hostname verification failure"),
            Err(err) => err,
        };

        assert!(matches!(err, Error::DialFailed { tried: 1, .. }));
    }

    #[cfg(feature = "boring")]
    #[tokio::test]
    async fn fronted_meek_round_trips_over_verified_front() {
        let ca = test_ca();
        let cfg = verified_config(ca.pem.clone(), "cover.example");
        let resolver = StaticResolver(vec![]);
        let dialer = FrontedMeekDialer::new(&cfg, "us", resolver)
            .with_dial_options(DialOptions {
                window: 1,
                attempt_timeout: None,
                ..Default::default()
            })
            .with_meek_options(MeekOptions {
                path: "/kindling".into(),
                ..Default::default()
            });
        let acceptor = std::sync::Arc::new(server_acceptor(&ca, "edge.test"));
        let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
        let seen_tx = std::sync::Arc::new(std::sync::Mutex::new(Some(seen_tx)));

        let mut conn = dialer
            .connect_fronted_with("api.example.com", move |strategy| {
                let acceptor = acceptor.clone();
                let seen_tx = seen_tx.lock().unwrap().take();
                async move {
                    let (client, server) = tokio::io::duplex(128 * 1024);
                    tokio::spawn(async move {
                        let tls = tokio_boring2::accept(&acceptor, server).await.unwrap();
                        let seen = tls
                            .ssl()
                            .servername(NameType::HOST_NAME)
                            .map(ToOwned::to_owned);
                        if let Some(tx) = seen_tx {
                            let _ = tx.send(seen);
                        }
                        let mut h2 = h2::server::handshake(tls).await.unwrap();
                        let accepted = h2.accept().await.unwrap().unwrap();
                        tokio::spawn(async move {
                            let (request, mut respond) = accepted;
                            assert_eq!(request.method(), Method::POST);
                            assert_eq!(request.uri().path(), "/kindling");
                            assert_eq!(request.headers()[http::header::HOST], "origin.example.net");

                            let mut send = respond
                                .send_response(
                                    Response::builder().status(200).body(()).unwrap(),
                                    false,
                                )
                                .unwrap();
                            let mut body = request.into_body();
                            let chunk = body.data().await.unwrap().unwrap();
                            assert_eq!(&chunk[..], b"ping");
                            send.send_data(Bytes::from_static(b"pong"), true).unwrap();
                        });
                        while h2.accept().await.is_some() {}
                    });
                    flint_dial::dial_over(client, &strategy).await
                }
            })
            .await
            .unwrap();

        conn.stream.write_all(b"ping").await.unwrap();
        let mut out = [0; 4];
        conn.stream.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"pong");
        assert_eq!(seen_rx.await.unwrap(), Some("cover.example".into()));
    }

    #[test]
    fn direct_h2_dialer_builds_with_default_dns_and_names_itself() {
        let dialer = DirectH2Dialer::with_default_dns("wifi").with_meek_options(MeekOptions {
            path: "/api/v1/config-new".into(),
            ..Default::default()
        });
        assert_eq!(ConnectionTransport::name(&dialer), "direct-h2");
    }

    #[cfg(feature = "boring")]
    #[tokio::test]
    async fn direct_h2_dialer_round_trips_over_origin_with_real_sni() {
        // The unfronted sibling of the meek round-trip: dial the origin directly with the *real* SNI,
        // open an h2 POST to the origin host, and round-trip a body. The cert is verified against the
        // pinned test roots, so this exercises the full TLS + h2 request-stream path.
        let ca = test_ca();
        let resolver = StaticResolver(vec!["198.51.100.20".parse().unwrap()]);
        let dialer = DirectH2Dialer::new(resolver)
            .with_dial_options(DialOptions {
                window: 1,
                attempt_timeout: None,
                ..Default::default()
            })
            .with_meek_options(MeekOptions {
                path: "/api/v1/config-new".into(),
                ..Default::default()
            })
            .with_trusted_roots(vec![ca.pem.clone()]);
        let acceptor = std::sync::Arc::new(server_acceptor(&ca, "df.iantem.io"));
        let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
        let seen_tx = std::sync::Arc::new(std::sync::Mutex::new(Some(seen_tx)));

        let mut stream = dialer
            .connect_direct_with("df.iantem.io", move |strategy| {
                let acceptor = acceptor.clone();
                let seen_tx = seen_tx.lock().unwrap().take();
                async move {
                    let (client, server) = tokio::io::duplex(128 * 1024);
                    tokio::spawn(async move {
                        let tls = tokio_boring2::accept(&acceptor, server).await.unwrap();
                        let seen = tls
                            .ssl()
                            .servername(NameType::HOST_NAME)
                            .map(ToOwned::to_owned);
                        if let Some(tx) = seen_tx {
                            let _ = tx.send(seen);
                        }
                        let mut h2 = h2::server::handshake(tls).await.unwrap();
                        let accepted = h2.accept().await.unwrap().unwrap();
                        tokio::spawn(async move {
                            let (request, mut respond) = accepted;
                            assert_eq!(request.method(), Method::POST);
                            assert_eq!(request.uri().path(), "/api/v1/config-new");
                            assert_eq!(request.headers()[http::header::HOST], "df.iantem.io");
                            let mut send = respond
                                .send_response(
                                    Response::builder().status(200).body(()).unwrap(),
                                    false,
                                )
                                .unwrap();
                            let mut body = request.into_body();
                            let chunk = body.data().await.unwrap().unwrap();
                            assert_eq!(&chunk[..], b"ping");
                            send.send_data(Bytes::from_static(b"pong"), true).unwrap();
                        });
                        while h2.accept().await.is_some() {}
                    });
                    flint_dial::dial_over(client, &strategy).await
                }
            })
            .await
            .unwrap();

        stream.write_all(b"ping").await.unwrap();
        let mut out = [0; 4];
        stream.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"pong");
        // Direct dial presents the real origin SNI, not a decoy front.
        assert_eq!(seen_rx.await.unwrap(), Some("df.iantem.io".into()));
    }

    #[tokio::test]
    async fn dial_with_reports_empty_materialized_fronts() {
        let err = race_materialized_with::<_, _, ()>(
            "api.example.com",
            &[],
            DialOptions::default(),
            |_| async { Ok(()) },
        )
        .await
        .unwrap_err();

        assert!(matches!(
            err,
            Error::NoUsableFronts { ref host } if host == "api.example.com"
        ));
    }

    #[tokio::test]
    async fn open_meek_stream_uses_fronted_authority_and_exposes_bytes() {
        let (client, server) = tokio::io::duplex(4096);
        let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
        let server_seen = tokio::spawn(async move {
            let mut conn = h2::server::handshake(server).await.unwrap();
            let accepted = conn.accept().await.unwrap().unwrap();
            tokio::spawn(async move {
                let (request, mut respond) = accepted;
                assert_eq!(request.method(), Method::POST);
                assert_eq!(request.uri().path(), "/meek");
                assert_eq!(request.headers()[http::header::HOST], "origin.example.net");

                let mut send = respond
                    .send_response(Response::builder().status(200).body(()).unwrap(), false)
                    .unwrap();
                let mut body = request.into_body();
                let chunk = body.data().await.unwrap().unwrap();
                assert_eq!(&chunk[..], b"ping");
                let _ = body.data().await;
                send.send_data(Bytes::from_static(b"pong"), true).unwrap();
                let _ = seen_tx.send(());
            });
            while conn.accept().await.is_some() {}
        });

        let conn = FrontedConnection {
            stream: client,
            front: Front {
                provider: "akamai".into(),
                domain: "edge.example.net".into(),
                endpoint: FrontEndpoint::Ip("203.0.113.10:443".parse().unwrap()),
                sni: "cover.example".into(),
                fronted_host: "origin.example.net".into(),
                verification: CertVerification::None,
            },
            addr: "203.0.113.10:443".parse().unwrap(),
            candidate_index: 0,
        };
        let mut stream = conn
            .open_meek_stream(MeekOptions {
                path: "meek".into(),
                ..Default::default()
            })
            .await
            .unwrap();

        stream.stream.write_all(b"ping").await.unwrap();
        stream.stream.shutdown().await.unwrap();

        let mut out = [0; 4];
        stream.stream.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"pong");
        assert_eq!(stream.fronted_host(), "origin.example.net");
        seen_rx.await.unwrap();
        server_seen.abort();
    }

    #[tokio::test]
    async fn meek_stream_write_reports_only_capacity_accepted() {
        let (client, server) = tokio::io::duplex(131_072);
        let server_seen = tokio::spawn(async move {
            let mut conn = h2::server::handshake(server).await.unwrap();
            let accepted = conn.accept().await.unwrap().unwrap();
            tokio::spawn(async move {
                let (request, mut respond) = accepted;
                respond
                    .send_response(Response::builder().status(200).body(()).unwrap(), false)
                    .unwrap();
                let mut body = request.into_body();
                tokio::time::sleep(Duration::from_millis(100)).await;
                let _ = body.data().await;
            });
            while conn.accept().await.is_some() {}
        });

        let conn = FrontedConnection {
            stream: client,
            front: Front {
                provider: "akamai".into(),
                domain: "edge.example.net".into(),
                endpoint: FrontEndpoint::Ip("203.0.113.10:443".parse().unwrap()),
                sni: String::new(),
                fronted_host: "origin.example.net".into(),
                verification: CertVerification::None,
            },
            addr: "203.0.113.10:443".parse().unwrap(),
            candidate_index: 0,
        };
        let mut stream = conn.open_meek_stream(MeekOptions::default()).await.unwrap();
        let buf = vec![0u8; MAX_H2_WRITE_CHUNK * 2];

        let n = stream.stream.write(&buf).await.unwrap();

        assert_eq!(n, MAX_H2_WRITE_CHUNK);
        server_seen.abort();
    }

    #[tokio::test]
    async fn fronted_meek_dialer_returns_a_connection_over_resolved_host_fronts() {
        let cfg = parse_config_yaml(config_yaml()).unwrap();
        let resolver = StaticResolver(vec!["198.51.100.20".parse().unwrap()]);
        let dialer = FrontedMeekDialer::new(&cfg, "", resolver)
            .with_dial_options(DialOptions {
                window: 1,
                attempt_timeout: None,
                ..Default::default()
            })
            .with_meek_options(MeekOptions {
                path: "/kindling".into(),
                ..Default::default()
            });

        fn assert_connection_transport<T: ConnectionTransport<Stream = MeekStream>>(_: &T) {}
        assert_connection_transport(&dialer);
        assert_eq!(ConnectionTransport::name(&dialer), "fronted-meek");

        let raw_front: SocketAddr = "203.0.113.10:443".parse().unwrap();
        let resolved_front: SocketAddr = "198.51.100.20:443".parse().unwrap();
        let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
        let mut seen_tx = Some(seen_tx);

        let mut conn = dialer
            .connect_fronted_with("api.example.com", |strategy| {
                let serve = strategy.target != raw_front;
                let tx = serve.then(|| seen_tx.take().unwrap());
                async move {
                    if strategy.target == raw_front {
                        return Err(io::Error::other("prescanned IP blocked"));
                    }
                    assert_eq!(strategy.target, resolved_front);
                    let (client, server) = tokio::io::duplex(4096);
                    tokio::spawn(async move {
                        let mut conn = h2::server::handshake(server).await.unwrap();
                        let accepted = conn.accept().await.unwrap().unwrap();
                        tokio::spawn(async move {
                            let (request, mut respond) = accepted;
                            assert_eq!(request.uri().path(), "/kindling");
                            assert_eq!(
                                request.headers()[http::header::HOST],
                                "api.dsa.example.net"
                            );
                            let mut send = respond
                                .send_response(
                                    Response::builder().status(200).body(()).unwrap(),
                                    false,
                                )
                                .unwrap();
                            let mut body = request.into_body();
                            let chunk = body.data().await.unwrap().unwrap();
                            assert_eq!(&chunk[..], b"hello");
                            let _ = body.data().await;
                            send.send_data(Bytes::from_static(b"world"), true).unwrap();
                            let _ = tx.unwrap().send(());
                        });
                        while conn.accept().await.is_some() {}
                    });
                    Ok(client)
                }
            })
            .await
            .unwrap();

        assert_eq!(conn.addr, resolved_front);
        assert_eq!(conn.front.domain, "edge-two.example.net");
        assert_eq!(conn.fronted_host(), "api.dsa.example.net");
        conn.stream.write_all(b"hello").await.unwrap();
        conn.stream.shutdown().await.unwrap();
        let mut out = [0; 5];
        conn.stream.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"world");
        seen_rx.await.unwrap();
    }

    #[tokio::test]
    async fn boxed_connection_transport_erases_stream_type_for_kindling_registry() {
        let transports: Vec<Box<dyn BoxedConnectionTransport>> = vec![Box::new(MemoryTransport)];
        assert_eq!(transports[0].name(), "memory");

        let mut conn = transports[0]
            .connect_boxed("api.example.com")
            .await
            .unwrap();
        conn.write_all(b"ping").await.unwrap();
        let mut out = [0; 4];
        conn.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"pong");
    }

    #[test]
    fn generated_front_strategies_use_front_sni_and_ips() {
        let front = Front {
            provider: "p".into(),
            domain: "edge.example".into(),
            endpoint: FrontEndpoint::Ip("203.0.113.10:443".parse().unwrap()),
            sni: "cover.example".into(),
            fronted_host: "origin.cdn.example".into(),
            verification: CertVerification::None,
        };
        let strategies =
            front.strategies(&["203.0.113.10:443".parse().unwrap()], WirePlan::default());
        assert_eq!(strategies.len(), 1);
        assert_eq!(strategies[0].sni, "cover.example");
        assert_eq!(strategies[0].target, "203.0.113.10:443".parse().unwrap());
    }
}
