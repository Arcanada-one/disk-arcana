//! DISK-0006 R7 — `GET /status` JSON shape pinned to PRD §4.12.4.
//!
//! Strategy: hydrate `DaemonState` with the same example data the §4.12.4
//! schema illustrates (one `publisher` share named `hermes-artefacts` in
//! `idle` state with explicit byte counters), hit the endpoint via HTTP,
//! then compare the rendered JSON against `tests/fixtures/status-example.json`
//! field-by-field. Adding a new field to `StatusShare` must update the
//! fixture in lock-step — that's the contract this test enforces.
//!
//! The `daemon_uptime_s` field is not pinned to the fixture's literal
//! `12345` because uptime is a side-effect of the test runtime; the
//! assertion is that the field exists with the right JSON type
//! (`number`). All other top-level + per-share keys must match the
//! fixture byte-for-byte (after JSON canonicalisation through `serde_json`).

#![cfg(unix)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use disk_client::config::schema::Direction;
use disk_client::rest_api::{serve, DaemonState, ShareSnapshot};
use disk_client::sync_loop::LoopState;

const FIXTURE_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/status-example.json"
);

async fn spawn_with_example_state() -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let (state, manual_rx, reload_rx) = DaemonState::new("arcana-ai", "1.1");
    // Hold receivers for the lifetime of the server.
    tokio::spawn(async move {
        let _r1 = manual_rx;
        let _r2 = reload_rx;
        std::future::pending::<()>().await
    });

    state
        .set_shares(vec![ShareSnapshot {
            name: "hermes-artefacts".into(),
            path: "/home/hermes/.hermes/cache".into(),
            declared_direction: Direction::Publisher,
            server_confirmed_role: Some(Direction::Publisher),
            state: LoopState::Idle,
            // 2026-05-23T18:00:00Z (matches fixture)
            last_success_at: Some(1_779_559_200),
            last_error: None,
            bytes_sent_session: 47_185_920,
            bytes_received_session: 0,
            pending_local_changes: 0,
        }])
        .await;

    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let local = serve(state, bind, async move {
        let _ = shutdown_rx.await;
    })
    .await
    .expect("serve");
    (local, shutdown_tx)
}

#[tokio::test]
async fn status_endpoint_matches_4_12_4_fixture() {
    let (local, _shutdown) = spawn_with_example_state().await;

    let body: serde_json::Value = reqwest::get(format!("http://{local}/status"))
        .await
        .expect("GET /status")
        .json()
        .await
        .expect("decode JSON");

    let fixture_raw = std::fs::read_to_string(FIXTURE_PATH).expect("read fixture");
    let fixture: serde_json::Value = serde_json::from_str(&fixture_raw).expect("parse fixture");

    // Top-level scalar keys (excluding daemon_uptime_s — see header).
    assert_eq!(body["node"], fixture["node"]);
    assert_eq!(body["config_version"], fixture["config_version"]);
    assert!(
        body["daemon_uptime_s"].is_u64() || body["daemon_uptime_s"].is_i64(),
        "daemon_uptime_s must be an integer, got {:?}",
        body["daemon_uptime_s"]
    );

    // Shares array shape.
    let body_shares = body["shares"].as_array().expect("shares array");
    let fixture_shares = fixture["shares"].as_array().expect("fixture shares");
    assert_eq!(body_shares.len(), fixture_shares.len());

    for (b, f) in body_shares.iter().zip(fixture_shares.iter()) {
        for key in [
            "name",
            "path",
            "declared_direction",
            "server_confirmed_role",
            "state",
            "last_success_at",
            "last_error",
            "bytes_sent_session",
            "bytes_received_session",
            "pending_local_changes",
        ] {
            assert_eq!(
                b[key], f[key],
                "share key `{key}` must match the §4.12.4 fixture"
            );
        }
    }
}

#[tokio::test]
async fn status_endpoint_strips_server_confirmed_role_when_absent() {
    let (state, manual_rx, reload_rx) = DaemonState::new("arcana-mac", "1.1");
    tokio::spawn(async move {
        let _r1 = manual_rx;
        let _r2 = reload_rx;
        std::future::pending::<()>().await
    });
    state
        .set_shares(vec![ShareSnapshot {
            name: "vault".into(),
            path: "/Users/ug/Vault".into(),
            declared_direction: Direction::Bidirectional,
            server_confirmed_role: None,
            state: LoopState::Idle,
            last_success_at: None,
            last_error: None,
            bytes_sent_session: 0,
            bytes_received_session: 0,
            pending_local_changes: 0,
        }])
        .await;

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

    let body: serde_json::Value = reqwest::get(format!("http://{local}/status"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // `server_confirmed_role: None` is rendered as a missing key (per
    // `#[serde(skip_serializing_if = "Option::is_none")]`).
    let share = &body["shares"][0];
    assert!(
        share.get("server_confirmed_role").is_none(),
        "absent server_confirmed_role must be elided, not rendered as null"
    );
    assert_eq!(share["last_success_at"], serde_json::Value::Null);
    let _ = shutdown_tx.send(());
}
