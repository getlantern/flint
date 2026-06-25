//! Live wire-compat test of the full self-bootstrapping auto path: scan Akamai
//! edges via the system resolver, race them (`dial_fronts_alpn`), auto-select the
//! HTTP version from the negotiated ALPN (`open_meek_poll_auto`), run the meek
//! polling client against the DEPLOYED meek-server (lantern-box PR #282, fronted
//! as `meek.dsa.akamai.getiantem.org`), then SOCKS5 CONNECT to example.com.
//!
//! Ignored by default (needs network + the `boring` Chrome dial path). Run with:
//!   cargo test -p flint-fronted --features boring --test meek_live -- --ignored --nocapture

use std::time::Duration;

use flint_fronted::scanner::{self, ScanTargets};
use flint_fronted::socks5::{self, Target};
use flint_fronted::{
    dial_fronts_alpn, open_meek_poll_auto, DialOptions, MaterializedFront, MeekPollConfig,
    SystemResolver,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MEEK_HOST: &str = "meek.dsa.akamai.getiantem.org";

#[tokio::test]
#[ignore = "network + boring; run explicitly with --features boring --ignored"]
async fn meek_live_auto_alpn_through_akamai_to_example_com() {
    // Vantage-point discovery: resolve Akamai edge hostnames via the system
    // resolver, build candidate fronts for the meek endpoint.
    let targets = ScanTargets::for_host(MEEK_HOST);
    let candidates = scanner::akamai_candidates(&SystemResolver::new(), &targets).await;
    assert!(
        !candidates.is_empty(),
        "no Akamai candidates resolved via the system resolver"
    );
    let fronts: Vec<MaterializedFront> = candidates
        .iter()
        .map(|c| MaterializedFront {
            front: c.to_front(),
            addrs: vec![c.addr],
        })
        .collect();

    // Race the fronts; the winner carries the negotiated ALPN.
    let conn = tokio::time::timeout(
        Duration::from_secs(30),
        dial_fronts_alpn(MEEK_HOST, &fronts, DialOptions::default()),
    )
    .await
    .expect("fronted dial timed out")
    .expect("fronted dial failed");
    eprintln!("negotiated ALPN: {:?}", conn.stream.alpn());

    // Auto-select h1/h2 from the ALPN and open the meek session.
    let mut meek = open_meek_poll_auto(conn, MeekPollConfig::new(MEEK_HOST)).expect("open meek");

    // The meek-server's upstream is microsocks (SOCKS5); CONNECT to example.com.
    socks5::connect(&mut meek, &Target::Domain("example.com".into(), 80))
        .await
        .expect("socks5 connect");
    meek.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
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
        match tokio::time::timeout(remaining, meek.read(&mut chunk)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => {
                buf.extend_from_slice(&chunk[..n]);
                if String::from_utf8_lossy(&buf).contains("Example Domain") || buf.len() > 8192 {
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
