//! Connection-first domain-fronting primitives for Lantern `fronted.yaml.gz` configs.
//!
//! This crate is the fronting consumer of Flint's lower layers: it parses the Lantern fronted config,
//! expands country-specific SNI choices, resolves host-based fronts through `flint-dns`, and
//! materializes `flint-dial::BootstrapStrategy` values. A higher-level transport can then run its
//! own CONNECT/Upgrade/meek-style stream establishment over the returned TLS stream.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::future::Future;
use std::io::{self, Read};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use bytes::{Buf, Bytes};
use flint_dial::{BootstrapStrategy, BoxedTlsStream};
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

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("fronted config gzip decode failed: {0}")]
    Gzip(#[from] io::Error),
    #[error("fronted config yaml parse failed: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("unknown provider `{0}`")]
    UnknownProvider(String),
    #[error("provider `{provider}` has no fronting mapping for `{host}`")]
    NoHostMapping { provider: String, host: String },
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
                host.ends_with(&format!(".{suffix}"))
                    .then_some(host.clone())
            } else {
                (pattern == &host).then_some(host.clone())
            }
        })
    }

    pub fn expanded(&self, country_code: &str) -> Self {
        let sni_cfg = if country_code.is_empty() {
            None
        } else {
            self.fronting_snis
                .get(country_code)
                .or_else(|| self.fronting_snis.get("default"))
        };
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
                    out.sni = generate_sni(sni_cfg, &m.ip_address);
                    out.verify_hostname = self.verify_hostname.clone();
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
    pub fn from_masquerade(m: &Masquerade) -> Self {
        parse_endpoint(&m.ip_address)
            .or_else(|| parse_endpoint(&m.domain))
            .unwrap_or_else(|| FrontEndpoint::Host {
                name: m.domain.clone(),
                port: 443,
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Front {
    pub provider: String,
    pub domain: String,
    pub endpoint: FrontEndpoint,
    pub sni: String,
    pub fronted_host: String,
}

impl Front {
    pub fn strategies(&self, addrs: &[SocketAddr], wire: WirePlan) -> Vec<BootstrapStrategy> {
        addrs
            .iter()
            .copied()
            .map(|addr| {
                BootstrapStrategy::boring_chrome(addr, self.sni.clone()).with_wire(wire.clone())
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

impl AsyncRead for MeekStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if let Some(buf) = &mut self.read_buf {
                let n = buf.remaining().min(dst.remaining());
                dst.put_slice(&buf.copy_to_bytes(n));
                if !buf.has_remaining() {
                    self.read_buf = None;
                }
                return Poll::Ready(Ok(()));
            }

            match futures::ready!(self.recv.poll_data(cx)) {
                Some(Ok(chunk)) => {
                    let _ = self.recv.flow_control().release_capacity(chunk.len());
                    if chunk.is_empty() {
                        continue;
                    }
                    self.read_buf = Some(chunk);
                }
                Some(Err(e)) => return Poll::Ready(Err(to_io(e))),
                None => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl AsyncWrite for MeekStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "fronted stream write side is closed",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        self.send
            .send_data(Bytes::copy_from_slice(buf), false)
            .map_err(to_io)?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.write_closed {
            self.send.send_data(Bytes::new(), true).map_err(to_io)?;
            self.write_closed = true;
        }
        Poll::Ready(Ok(()))
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
    let driver = DriverGuard(tokio::spawn(async move {
        let _ = connection.await;
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
}

impl FrontPool {
    pub fn new(config: &Config, country_code: &str) -> Self {
        let providers = config
            .providers
            .iter()
            .map(|(id, p)| (id.clone(), p.expanded(country_code)))
            .collect();
        Self { providers }
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
                fronts.push(Front {
                    provider: provider_id.clone(),
                    domain: m.domain.clone(),
                    endpoint: FrontEndpoint::from_masquerade(m),
                    sni: m.sni.clone(),
                    fronted_host: fronted_host.clone(),
                });
            }
        }
        if fronts.is_empty() && !saw_provider {
            return Err(Error::NoHostMapping {
                provider: "*".into(),
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
                FrontEndpoint::Host { name, port } => {
                    let ips = resolver
                        .resolve(name)
                        .await
                        .map_err(|source| Error::Resolve {
                            front: name.clone(),
                            source,
                        })?;
                    if ips.is_empty() {
                        return Err(Error::EmptyResolution {
                            front: name.clone(),
                        });
                    }
                    ips.into_iter()
                        .map(|ip| SocketAddr::new(ip, *port))
                        .collect()
                }
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
                        .with_wire(wire.clone());
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

fn strip_port(host: &str) -> &str {
    host.rsplit_once(':')
        .filter(|(_, port)| !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()))
        .map(|(host, _)| host)
        .unwrap_or(host)
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
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use http::Response;
    use std::io::Write;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct StaticResolver(Vec<IpAddr>);

    #[async_trait]
    impl FrontResolver for StaticResolver {
        async fn resolve(&self, _host: &str) -> io::Result<Vec<IpAddr>> {
            Ok(self.0.clone())
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
        };
        let strategies =
            front.strategies(&["203.0.113.10:443".parse().unwrap()], WirePlan::default());
        assert_eq!(strategies.len(), 1);
        assert_eq!(strategies[0].sni, "cover.example");
        assert_eq!(strategies[0].target, "203.0.113.10:443".parse().unwrap());
    }
}
