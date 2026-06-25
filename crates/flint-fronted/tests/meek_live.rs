//! Live wire-compat test: dial a real Akamai edge (resolved via the system
//! resolver), run the meek polling client against the DEPLOYED meek-server
//! (lantern-box PR #282, fronted as `meek.dsa.akamai.getiantem.org`), then SOCKS5
//! CONNECT to example.com and fetch `/`. Proves the Rust client speaks the same
//! wire protocol as the production Go server.
//!
//! Ignored by default (needs network + the `boring` Chrome dial path). Run with:
//!   cargo test -p flint-fronted --features boring --test meek_live -- --ignored --nocapture

use std::collections::BTreeMap;
use std::time::Duration;

use flint_fronted::socks5::{self, Target};
use flint_fronted::{
    Config, FrontedMeekPollDialer, FrontedTlsDialer, MeekHttpVersion, MeekPollConfig, Provider,
    SystemResolver,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MEEK_HOST: &str = "meek.dsa.akamai.getiantem.org";
const AKAMAI_EDGE: &str = "a248.e.akamai.net";

fn meek_config() -> Config {
    // One akamai provider routing the meek host through Akamai edges. The edge is
    // given as a HOSTNAME so the SystemResolver returns geo-local, reachable IPs
    // (the @nima local-DNS trick). Empty SNI; cert verified against the edge host.
    let mut masq = flint_fronted::Masquerade::default();
    masq.domain = AKAMAI_EDGE.into();
    masq.ip_address = AKAMAI_EDGE.into();
    masq.sni = String::new();
    masq.verify_hostname = Some(AKAMAI_EDGE.into());

    let mut akamai = Provider::default();
    akamai
        .host_aliases
        .insert(MEEK_HOST.to_string(), MEEK_HOST.to_string());
    akamai.masquerades = vec![masq];
    akamai.verify_hostname = Some(AKAMAI_EDGE.into());

    let mut providers = BTreeMap::new();
    providers.insert("akamai".to_string(), akamai);
    Config {
        trusted_cas: Vec::new(),
        providers,
    }
}

#[tokio::test]
#[ignore = "network + boring; run explicitly with --features boring --ignored"]
async fn meek_live_through_akamai_to_example_com() {
    let dialer = FrontedTlsDialer::new(&meek_config(), "", SystemResolver::new());
    // The deployed meek path (Akamai → Caddy) terminates as HTTP/1.1.
    let mut meek = MeekPollConfig::new(MEEK_HOST);
    meek.http_version = MeekHttpVersion::H1;
    let glue = FrontedMeekPollDialer::new(dialer, MEEK_HOST).with_meek_config(meek);

    let mut conn = tokio::time::timeout(Duration::from_secs(30), glue.connect())
        .await
        .expect("fronted meek dial timed out")
        .expect("fronted meek dial failed");

    // The meek-server's upstream is microsocks (SOCKS5); CONNECT to example.com.
    socks5::connect(&mut conn, &Target::Domain("example.com".into(), 80))
        .await
        .expect("socks5 connect");

    conn.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .await
        .expect("write request");

    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, conn.read(&mut chunk)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => {
                buf.extend_from_slice(&chunk[..n]);
                let text = String::from_utf8_lossy(&buf);
                if text.contains("Example Domain") || buf.len() > 8192 {
                    break;
                }
            }
            Ok(Err(e)) => panic!("read error: {e}"),
        }
    }
    let text = String::from_utf8_lossy(&buf);
    assert!(
        text.contains("200") || text.contains("Example Domain"),
        "unexpected response (first 200B): {:?}",
        &text.chars().take(200).collect::<String>()
    );
}
