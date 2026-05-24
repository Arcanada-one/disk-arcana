//! DISK-0006 R7 — `POST /sync` + `POST /config/reload` signal semantics.
//!
//! The REST layer is a thin signaller: each POST enqueues one `()` on
//! an `mpsc::Sender` held by the daemon loop / config watcher. The test
//! drives both endpoints, asserts the HTTP envelope (`202` + `{queued:
//! true}`), and asserts the receiver actually observes the events.
//!
//! Also covers the back-pressure path: when the receiver is dropped the
//! channel returns `503` + `{queued: false}` — the surface MUST stay
//! responsive instead of blocking.

#![cfg(unix)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use disk_client::rest_api::{serve, AcceptedResponse, DaemonState};

async fn spawn() -> (
    SocketAddr,
    tokio::sync::mpsc::Receiver<()>,
    tokio::sync::mpsc::Receiver<()>,
    tokio::sync::oneshot::Sender<()>,
) {
    let (state, manual_rx, reload_rx) = DaemonState::new("test-node", "1.1");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let local = serve(
        state,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        async move {
            let _ = shutdown_rx.await;
        },
    )
    .await
    .expect("serve");
    (local, manual_rx, reload_rx, shutdown_tx)
}

#[tokio::test]
async fn post_sync_signals_manual_trigger() {
    let (local, mut manual_rx, _reload_rx, _shutdown) = spawn().await;

    let resp = reqwest::Client::new()
        .post(format!("http://{local}/sync"))
        .send()
        .await
        .expect("POST /sync");
    assert_eq!(resp.status(), reqwest::StatusCode::ACCEPTED);
    let body: AcceptedResponse = resp.json().await.unwrap();
    assert_eq!(body, AcceptedResponse { queued: true });

    let event = tokio::time::timeout(Duration::from_millis(500), manual_rx.recv())
        .await
        .expect("receiver must observe a manual-sync event within 500ms");
    assert_eq!(event, Some(()));
}

#[tokio::test]
async fn post_config_reload_signals_reload_trigger() {
    let (local, _manual_rx, mut reload_rx, _shutdown) = spawn().await;

    let resp = reqwest::Client::new()
        .post(format!("http://{local}/config/reload"))
        .send()
        .await
        .expect("POST /config/reload");
    assert_eq!(resp.status(), reqwest::StatusCode::ACCEPTED);
    let body: AcceptedResponse = resp.json().await.unwrap();
    assert!(body.queued);

    let event = tokio::time::timeout(Duration::from_millis(500), reload_rx.recv())
        .await
        .expect("receiver must observe a reload event within 500ms");
    assert_eq!(event, Some(()));
}

#[tokio::test]
async fn post_sync_returns_503_when_receiver_dropped() {
    let (state, manual_rx, _reload_rx) = DaemonState::new("test-node", "1.1");
    // Drop the manual_rx half so the channel is "closed" for the next send.
    drop(manual_rx);

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let local = serve(
        state,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        async move {
            let _ = shutdown_rx.await;
        },
    )
    .await
    .expect("serve");

    let resp = reqwest::Client::new()
        .post(format!("http://{local}/sync"))
        .send()
        .await
        .expect("POST /sync");
    assert_eq!(resp.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    let body: AcceptedResponse = resp.json().await.unwrap();
    assert!(!body.queued);
    let _ = shutdown_tx.send(());
}
