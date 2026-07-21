//! Async outbound agent webhook delivery (DISK-0028 slice 2).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use disk_core::agents::webhook_sig::{
    compute_disk_webhook_signature, format_disk_signature_header,
};
use disk_core::meta_db::MetaDb;
use reqwest::Client;
use serde::Serialize;
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// Channel capacity for queued webhook deliveries.
pub const CHANNEL_CAP: usize = 512;

const MAX_RETRIES: u32 = 3;
const BASE_BACKOFF_MS: u64 = 200;

/// Job enqueued after an agent/sync event occurs.
#[derive(Debug, Clone)]
pub struct AgentWebhookJob {
    pub tenant_id: Option<String>,
    pub vault_id: String,
    pub event: String,
    pub payload: Value,
}

#[derive(Debug, Clone)]
pub struct AgentWebhookDispatcher {
    tx: Option<mpsc::Sender<AgentWebhookJob>>,
    dropped_count: Arc<AtomicU64>,
}

impl AgentWebhookDispatcher {
    pub fn noop() -> Self {
        Self {
            tx: None,
            dropped_count: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Fire-and-forget enqueue. Drops when the channel is full.
    pub fn enqueue(&self, job: AgentWebhookJob) {
        let Some(ref tx) = self.tx else {
            return;
        };
        if tx.try_send(job).is_err() {
            let prev = self.dropped_count.fetch_add(1, Ordering::Relaxed);
            warn!(
                dropped_total = prev + 1,
                "agent webhook channel full — event dropped"
            );
        }
    }

    pub fn dropped_count(&self) -> u64 {
        self.dropped_count.load(Ordering::Relaxed)
    }
}

/// Spawn the background delivery task.
pub fn spawn(client: Client, meta_db: MetaDb) -> AgentWebhookDispatcher {
    let dropped = Arc::new(AtomicU64::new(0));
    let (tx, rx) = mpsc::channel::<AgentWebhookJob>(CHANNEL_CAP);
    let dropped_bg = Arc::clone(&dropped);
    tokio::spawn(delivery_loop(client, meta_db, rx, dropped_bg));
    AgentWebhookDispatcher {
        tx: Some(tx),
        dropped_count: dropped,
    }
}

async fn delivery_loop(
    client: Client,
    meta_db: MetaDb,
    mut rx: mpsc::Receiver<AgentWebhookJob>,
    _dropped: Arc<AtomicU64>,
) {
    while let Some(job) = rx.recv().await {
        let tenant_key = job.tenant_id.as_deref();
        let targets = match meta_db
            .list_agent_webhooks_for_event(tenant_key, &job.vault_id, &job.event)
            .await
        {
            Ok(t) => t,
            Err(e) => {
                warn!(error = %e, event = %job.event, "agent webhook lookup failed");
                continue;
            }
        };

        for target in targets {
            deliver_one(&client, &job, &target).await;
        }
    }
}

async fn deliver_one(
    client: &Client,
    job: &AgentWebhookJob,
    target: &disk_core::meta_db::AgentWebhookDeliveryTarget,
) {
    let body = WebhookEnvelope {
        id: format!("evt_{}", uuid_simple()),
        event: &job.event,
        created_at: unix_now_secs(),
        vault_id: &job.vault_id,
        data: &job.payload,
    };
    let body_bytes = match serde_json::to_vec(&body) {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, webhook_id = %target.id, "agent webhook serialize failed");
            return;
        }
    };

    let timestamp = unix_now_secs();
    let v1 = compute_disk_webhook_signature(&target.signing_secret, timestamp, &body_bytes);
    let signature = format_disk_signature_header(timestamp, &v1);

    let mut success = false;
    let mut backoff_ms = BASE_BACKOFF_MS;
    for attempt in 1..=MAX_RETRIES {
        let response = client
            .post(&target.url)
            .header("Content-Type", "application/json")
            .header("X-Disk-Signature", &signature)
            .header("X-Disk-Event", &job.event)
            .header("X-Disk-Webhook-Id", &target.id)
            .body(body_bytes.clone())
            .timeout(Duration::from_secs(10))
            .send()
            .await;

        match response {
            Ok(resp) if resp.status().is_success() => {
                debug!(
                    webhook_id = %target.id,
                    event = %job.event,
                    status = %resp.status(),
                    "agent webhook delivered"
                );
                success = true;
                break;
            }
            Ok(resp) => {
                warn!(
                    webhook_id = %target.id,
                    attempt,
                    status = %resp.status(),
                    "agent webhook delivery non-success"
                );
            }
            Err(e) => {
                warn!(
                    webhook_id = %target.id,
                    attempt,
                    error = %e,
                    "agent webhook delivery error"
                );
            }
        }

        if attempt < MAX_RETRIES {
            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            backoff_ms = backoff_ms.saturating_mul(2);
        }
    }

    if !success {
        warn!(
            webhook_id = %target.id,
            event = %job.event,
            "agent webhook delivery exhausted retries"
        );
    }
}

#[derive(Serialize)]
struct WebhookEnvelope<'a> {
    id: String,
    event: &'a str,
    created_at: i64,
    vault_id: &'a str,
    data: &'a Value,
}

fn unix_now_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn uuid_simple() -> String {
    use rand::RngCore;
    let mut raw = [0u8; 16];
    rand::rng().fill_bytes(&mut raw);
    hex::encode(raw)
}

/// Build a standard payload for agent write success.
pub fn agent_write_ok_payload(
    path: &str,
    revision: u64,
    content_hash_hex: &str,
    size: u64,
    agent_id: &str,
) -> Value {
    json!({
        "path": path,
        "revision": revision,
        "content_hash_hex": content_hash_hex,
        "size": size,
        "agent_id": agent_id,
    })
}

/// Build a standard payload for revision conflicts.
pub fn agent_write_conflict_payload(
    path: &str,
    expected_revision: u64,
    current_revision: u64,
) -> Value {
    json!({
        "path": path,
        "expected_revision": expected_revision,
        "current_revision": current_revision,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Bytes;
    use axum::extract::State;
    use axum::http::HeaderMap;
    use axum::routing::post;
    use axum::Router;
    use disk_core::agents::webhook_sig::verify_disk_webhook_signature;
    use std::sync::{Arc, Mutex};
    use tempfile::tempdir;

    #[derive(Clone, Default)]
    struct Capture {
        body: Arc<Mutex<Option<Vec<u8>>>>,
        signature: Arc<Mutex<Option<String>>>,
        event: Arc<Mutex<Option<String>>>,
    }

    async fn capture_handler(
        State(capture): State<Capture>,
        headers: HeaderMap,
        body: Bytes,
    ) -> &'static str {
        *capture.body.lock().unwrap() = Some(body.to_vec());
        *capture.signature.lock().unwrap() = headers
            .get("x-disk-signature")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        *capture.event.lock().unwrap() = headers
            .get("x-disk-event")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        "ok"
    }

    #[tokio::test]
    async fn delivery_posts_signed_payload() {
        let dir = tempdir().unwrap();
        let meta_db = MetaDb::open(&dir.path().join("dispatch.sqlite"))
            .await
            .unwrap();

        let secret = "whsec_integration_test";
        let secret_hash = blake3::hash(secret.as_bytes()).into();
        meta_db
            .insert_agent_webhook(disk_core::meta_db::NewAgentWebhook {
                id: "awh_test",
                tenant_id: Some("corp"),
                vault_id: "default",
                url: "http://will-replace",
                secret_hash: &secret_hash,
                signing_secret: secret,
                events: &["agent.write_ok".into()],
                label: None,
            })
            .await
            .unwrap();

        let capture = Capture::default();
        let app = Router::new()
            .route("/hook", post(capture_handler))
            .with_state(capture.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        // Point webhook at local test server (https check is registration-only).
        sqlx::query("UPDATE agent_webhooks SET url = ?1 WHERE id = 'awh_test'")
            .bind(format!("http://{addr}/hook"))
            .execute(meta_db.pool())
            .await
            .unwrap();

        let client = Client::new();
        let dispatcher = spawn(client, meta_db);
        dispatcher.enqueue(AgentWebhookJob {
            tenant_id: Some("corp".into()),
            vault_id: "default".into(),
            event: "agent.write_ok".into(),
            payload: agent_write_ok_payload("a.md", 1, "abc", 3, "bot"),
        });

        tokio::time::sleep(Duration::from_millis(500)).await;

        let body = capture.body.lock().unwrap().clone().expect("body received");
        let sig = capture
            .signature
            .lock()
            .unwrap()
            .clone()
            .expect("signature header");
        assert_eq!(
            capture.event.lock().unwrap().as_deref(),
            Some("agent.write_ok")
        );
        verify_disk_webhook_signature(&sig, &body, secret, 300).unwrap();
    }
}
