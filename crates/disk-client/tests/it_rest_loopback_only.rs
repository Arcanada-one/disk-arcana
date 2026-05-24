//! DISK-0006 R7 — Tier 1 loopback bind enforcement for REST `:9444`.
//!
//! PRD-DISK-0001 §4.13 Network Exposure Baseline classifies the daemon's
//! local REST surface as **Tier 1 (loopback)** — bind MUST be on
//! `127.0.0.0/8`. The plan §Risks row "Status endpoint accidentally binds
//! 0.0.0.0" is the explicit mitigation this test enforces.
//!
//! Three asserted invariants:
//! - `assert_loopback_bind` rejects non-loopback addresses (`0.0.0.0`,
//!   external IPs); the daemon's `serve` constructor refuses to start.
//! - A real listener bound via `serve` reports `127.0.0.1` from
//!   `local_addr()` and is reachable on the local interface only.
//! - When the host's `lsof` binary is available, the listening port shows
//!   ONLY a `127.0.0.1` entry (no `*:9444` / `0.0.0.0:9444`).

#![cfg(unix)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use disk_client::rest_api::{assert_loopback_bind, serve, DaemonState, RestApiError};

async fn spawn_loopback() -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let (state, _manual_rx, _reload_rx) = DaemonState::new("test-node", "1.1");
    // Hold the receivers in a tokio task so they don't close-signal the
    // sender when this fixture returns to the test.
    tokio::spawn(async move {
        let _r1 = _manual_rx;
        let _r2 = _reload_rx;
        // Park until the runtime tears down.
        std::future::pending::<()>().await
    });
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let local = serve(state, bind, async move {
        let _ = shutdown_rx.await;
    })
    .await
    .expect("serve must accept loopback bind");
    (local, shutdown_tx)
}

#[tokio::test]
async fn rejects_zero_address_bind() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 9444);
    match assert_loopback_bind(addr) {
        Err(RestApiError::NonLoopbackBind(ip)) => assert_eq!(ip, IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        other => panic!("expected NonLoopbackBind, got {other:?}"),
    }
}

#[tokio::test]
async fn rejects_external_address_bind() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 9444);
    match assert_loopback_bind(addr) {
        Err(RestApiError::NonLoopbackBind(ip)) => {
            assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)))
        }
        other => panic!("expected NonLoopbackBind, got {other:?}"),
    }
}

#[tokio::test]
async fn serve_refuses_non_loopback_bind() {
    let (state, _m, _r) = DaemonState::new("test-node", "1.1");
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    let result = serve(state, bind, async {}).await;
    assert!(
        matches!(result, Err(RestApiError::NonLoopbackBind(_))),
        "serve must reject 0.0.0.0 bind; got {result:?}"
    );
}

#[tokio::test]
async fn loopback_bind_reports_127_0_0_1() {
    let (local, _shutdown) = spawn_loopback().await;
    assert_eq!(local.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert!(local.port() != 0, "ephemeral port must be resolved");
}

#[tokio::test]
async fn lsof_shows_only_loopback_listener() {
    // Skip silently if lsof is not on PATH (e.g. minimal CI images).
    let lsof_probe = std::process::Command::new("lsof").arg("-v").output();
    if lsof_probe.is_err() {
        eprintln!("lsof not available; skipping lsof loopback bind assertion");
        return;
    }

    let (local, _shutdown) = spawn_loopback().await;
    // Tiny wait so the OS surfaces the LISTEN state in lsof's snapshot.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let port = local.port();
    let out = std::process::Command::new("lsof")
        .args([
            "-nP",
            "-iTCP",
            "-sTCP:LISTEN",
            "-a",
            "-p",
            &std::process::id().to_string(),
        ])
        .output()
        .expect("invoke lsof");
    let stdout = String::from_utf8_lossy(&out.stdout);

    // Filter to the row for our port — lsof may report unrelated listeners
    // held by the same test process from earlier in the suite.
    let port_str = format!(":{port}");
    let matching: Vec<&str> = stdout
        .lines()
        .filter(|line| line.contains(&port_str))
        .collect();

    assert!(
        !matching.is_empty(),
        "lsof must report a listener on the bound port; stdout was:\n{stdout}"
    );

    for line in &matching {
        assert!(
            line.contains(&format!("127.0.0.1:{port}")),
            "lsof row must show only 127.0.0.1 binding for port {port}; got:\n{line}"
        );
        assert!(
            !line.contains(&format!("*:{port}")) && !line.contains(&format!("0.0.0.0:{port}")),
            "lsof row must NOT show a wildcard binding for port {port}; got:\n{line}"
        );
    }
}
