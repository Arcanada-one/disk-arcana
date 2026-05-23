//! Integration test — Ops Bot HTTP delivery via wiremock.
//!
//! Step 19 P4b: spin up a wiremock server, enqueue an audit event via
//! the `Forwarder`, assert the mock receives exactly one POST /events.

use std::time::Duration;

use disk_server::audit::ops_bot::{delivery_loop, Forwarder, OpsEvent, CHANNEL_CAP};
use reqwest::Client;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn audit_event_delivered_to_ops_bot() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/events"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let client = Client::new();
    let url = format!("{}/events", server.uri());
    let key = "test-ops-key".to_string();

    let dropped = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let (tx, rx) = tokio::sync::mpsc::channel::<OpsEvent>(CHANNEL_CAP);
    let dropped_bg = std::sync::Arc::clone(&dropped);
    tokio::spawn(delivery_loop(client, url, key, rx, dropped_bg));

    let fwd = Forwarder {
        tx: Some(tx),
        dropped_count: dropped,
    };

    let event = disk_server::audit::AuditEvent::new(disk_server::audit::AuditKind::AclLoadOk)
        .with_payload(&serde_json::json!({ "message": "ops bot delivery test" }));
    fwd.enqueue(&event, 1_000_000);

    // Give the background task time to drain.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Wiremock verifies exactly 1 POST on drop.
    assert_eq!(fwd.dropped_count(), 0, "event must not be dropped");
}

#[tokio::test]
async fn noop_forwarder_does_not_panic() {
    let fwd = Forwarder::noop();
    let event = disk_server::audit::AuditEvent::new(disk_server::audit::AuditKind::ConfigReload);
    fwd.enqueue(&event, 0);
    assert_eq!(fwd.dropped_count(), 0);
}
