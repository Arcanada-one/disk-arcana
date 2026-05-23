//! Ops Bot HTTP forwarder for audit events.
//!
//! Every audit event written to SQLite is also enqueued to a bounded
//! `tokio::sync::mpsc::channel(1024)`. A background task drains the queue
//! and POSTs each event to `https://ops.arcanada.one/events` (verified live
//! at plan-time: `/health` → HTTP 200).
//!
//! ## Fail-soft behaviour
//!
//! - If `OPS_BOT_KEY` env var is unset → log once at startup + no-op.
//!   Does NOT crash the server. (Per feedback: `feedback_authenticated_emit_endpoints_fail_soft`.)
//! - If the channel is full → drop event + increment a counter.
//! - Background delivery: exponential backoff, max 3 attempts → then drop.
//!
//! ## Wire format
//!
//! ```http
//! POST /events
//! Authorization: Bearer <OPS_BOT_KEY>
//! Content-Type: application/json
//!
//! { "kind": "acl.role_mismatch", "ts_ms": 1234567890, "payload": {...} }
//! ```

use std::env;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use reqwest::Client;
use serde_json::Value;
use tokio::sync::mpsc;

use super::AuditEvent;

/// Channel capacity: 1024 events buffered in memory.
pub const CHANNEL_CAP: usize = 1024;

/// Maximum retry attempts per event.
const MAX_RETRIES: u32 = 3;

/// Base backoff duration (doubles on each retry).
const BASE_BACKOFF_MS: u64 = 200;

/// Default Ops Bot events endpoint.
const DEFAULT_OPS_BOT_URL: &str = "https://ops.arcanada.one/events";

// ---------------------------------------------------------------------------
// Wire DTO
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
pub struct OpsEvent {
    pub kind: &'static str,
    pub ts_ms: u64,
    pub payload: Value,
}

// ---------------------------------------------------------------------------
// Forwarder handle (cheap to clone)
// ---------------------------------------------------------------------------

/// A `Forwarder` wraps a channel sender. Clone it to share across threads.
/// When dropped, the channel closes and the background task exits gracefully.
#[derive(Debug, Clone)]
pub struct Forwarder {
    pub tx: Option<mpsc::Sender<OpsEvent>>,
    pub dropped_count: Arc<AtomicU64>,
}

impl Forwarder {
    /// Enqueue an audit event for delivery to Ops Bot.
    ///
    /// If the channel is full, the event is dropped and an internal counter
    /// is incremented. This is intentionally fire-and-forget.
    pub fn enqueue(&self, event: &AuditEvent, ts_ms: u64) {
        let Some(ref tx) = self.tx else { return };
        let ops_event = OpsEvent {
            kind: event.kind.as_str(),
            ts_ms,
            payload: event.payload.clone(),
        };
        // try_send is non-blocking; drop on full channel.
        if tx.try_send(ops_event).is_err() {
            let prev = self.dropped_count.fetch_add(1, Ordering::Relaxed);
            eprintln!(
                "[ops_bot] channel full — dropped event (total dropped: {})",
                prev + 1
            );
        }
    }

    /// Total events dropped due to full channel.
    pub fn dropped_count(&self) -> u64 {
        self.dropped_count.load(Ordering::Relaxed)
    }

    /// Create a no-op forwarder (used when OPS_BOT_KEY is unset).
    pub fn noop() -> Self {
        Self {
            tx: None,
            dropped_count: Arc::new(AtomicU64::new(0)),
        }
    }
}

// ---------------------------------------------------------------------------
// Background delivery task
// ---------------------------------------------------------------------------

/// Spawn the Ops Bot delivery background task.
///
/// Returns a `Forwarder` handle for enqueuing events, plus a `JoinHandle`
/// that runs until the sender is dropped.
///
/// If `OPS_BOT_KEY` env var is unset, returns a no-op `Forwarder` and logs
/// once to stderr. No background task is spawned.
pub fn spawn(http_client: Client, ops_bot_url: Option<String>) -> Forwarder {
    let key = match env::var("OPS_BOT_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => {
            eprintln!("[ops_bot] OPS_BOT_KEY not set — audit forwarding disabled");
            return Forwarder::noop();
        }
    };
    let url = ops_bot_url.unwrap_or_else(|| DEFAULT_OPS_BOT_URL.to_string());
    let dropped = Arc::new(AtomicU64::new(0));
    let (tx, rx) = mpsc::channel::<OpsEvent>(CHANNEL_CAP);

    let dropped_bg = Arc::clone(&dropped);
    tokio::spawn(delivery_loop(http_client, url, key, rx, dropped_bg));

    Forwarder {
        tx: Some(tx),
        dropped_count: dropped,
    }
}

pub async fn delivery_loop(
    client: Client,
    url: String,
    key: String,
    mut rx: mpsc::Receiver<OpsEvent>,
    dropped: Arc<AtomicU64>,
) {
    while let Some(event) = rx.recv().await {
        let mut success = false;
        let mut backoff_ms = BASE_BACKOFF_MS;

        for attempt in 1..=MAX_RETRIES {
            match post_event(&client, &url, &key, &event).await {
                Ok(()) => {
                    success = true;
                    break;
                }
                Err(e) => {
                    tracing::warn!(
                        "[ops_bot] delivery attempt {attempt}/{MAX_RETRIES} failed: {e}"
                    );
                    if attempt < MAX_RETRIES {
                        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                        backoff_ms *= 2;
                    }
                }
            }
        }

        if !success {
            let prev = dropped.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                "[ops_bot] permanently dropped event '{}' after {MAX_RETRIES} retries (total: {})",
                event.kind,
                prev + 1
            );
        }
    }
}

async fn post_event(client: &Client, url: &str, key: &str, event: &OpsEvent) -> anyhow::Result<()> {
    let resp = client.post(url).bearer_auth(key).json(event).send().await?;

    let status = resp.status().as_u16();
    if status >= 400 {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("ops_bot returned HTTP {status}: {body}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::audit::AuditEvent;

    fn make_http_client() -> Client {
        Client::new()
    }

    #[tokio::test]
    async fn noop_forwarder_drops_silently() {
        // Use the explicit noop constructor — no env var needed.
        let fwd = Forwarder::noop();
        let event = AuditEvent::new(crate::audit::AuditKind::AclLoadOk);
        fwd.enqueue(&event, 12345);
        assert_eq!(
            fwd.dropped_count(),
            0,
            "noop forwarder should not count drops"
        );
    }

    #[tokio::test]
    async fn enqueue_and_deliver_to_mock_server() {
        // Spin up a wiremock server.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/events"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let client = make_http_client();
        let url = format!("{}/events", server.uri());

        // Construct forwarder directly to bypass env-var gating.
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let (tx, rx) = tokio::sync::mpsc::channel::<OpsEvent>(CHANNEL_CAP);
        let dropped_bg = std::sync::Arc::clone(&dropped);
        tokio::spawn(delivery_loop(
            client,
            url,
            "test-ops-key".into(),
            rx,
            dropped_bg,
        ));
        let fwd = Forwarder {
            tx: Some(tx),
            dropped_count: dropped,
        };

        let event = AuditEvent::new(crate::audit::AuditKind::AclLoadOk)
            .with_payload(&json!({ "message": "test delivery" }));
        fwd.enqueue(&event, 999_999);

        // Wait for background task to drain.
        tokio::time::sleep(Duration::from_millis(400)).await;

        // Wiremock verifies the mock was satisfied (1 POST received) on drop.
    }
}
