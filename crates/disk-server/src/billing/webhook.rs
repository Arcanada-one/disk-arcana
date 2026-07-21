//! HTTP Stripe webhook handler.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use disk_core::billing::{parse_stripe_subscription_event, verify_stripe_webhook_signature};
use disk_core::meta_db::MetaDb;
use tracing::warn;

use super::mode::BillingMode;

/// Default replay window for Stripe webhook timestamps (seconds).
pub const DEFAULT_STRIPE_TOLERANCE_SECS: u64 = 300;

#[derive(Clone)]
pub struct WebhookState {
    pub mode: BillingMode,
    pub meta_db: MetaDb,
    /// When set, verify `Stripe-Signature` HMAC before parsing the body.
    pub webhook_secret: Option<String>,
    /// Max age of the `t=` timestamp (default 300s).
    pub signature_tolerance_secs: u64,
    /// Legacy dev escape hatch: require header presence without HMAC verify.
    pub require_signature_header: bool,
}

impl WebhookState {
    fn verify_request(&self, headers: &HeaderMap, body: &[u8]) -> Result<(), StatusCode> {
        let sig_header = headers
            .get("stripe-signature")
            .and_then(|v| v.to_str().ok());

        match (&self.webhook_secret, sig_header) {
            (Some(secret), Some(header)) => {
                verify_stripe_webhook_signature(header, body, secret, self.signature_tolerance_secs)
                    .map_err(|e| {
                        warn!(error = %e, "stripe webhook signature rejected");
                        StatusCode::BAD_REQUEST
                    })
            }
            (Some(_), None) => {
                warn!("stripe webhook missing Stripe-Signature header");
                Err(StatusCode::BAD_REQUEST)
            }
            (None, Some(_)) if !self.require_signature_header => Ok(()),
            (None, None) if !self.require_signature_header => Ok(()),
            (None, None) => {
                warn!("stripe webhook missing Stripe-Signature header");
                Err(StatusCode::BAD_REQUEST)
            }
            (None, Some(_)) => {
                warn!("stripe webhook signature present but DISK_STRIPE_WEBHOOK_SECRET unset");
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    }
}

pub async fn stripe_webhook(
    State(state): State<Arc<WebhookState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    if state.mode != BillingMode::Stripe {
        return (
            StatusCode::NOT_FOUND,
            r#"{"error":"billing webhooks disabled"}"#,
        );
    }

    if let Err(status) = state.verify_request(&headers, &body) {
        let msg = match status {
            StatusCode::INTERNAL_SERVER_ERROR => r#"{"error":"webhook secret not configured"}"#,
            _ => r#"{"error":"invalid signature"}"#,
        };
        return (status, msg);
    }

    let body_str = match std::str::from_utf8(&body) {
        Ok(s) => s,
        Err(_) => return (StatusCode::BAD_REQUEST, r#"{"error":"invalid utf-8"}"#),
    };

    let event = match parse_stripe_subscription_event(body_str) {
        Ok(ev) => ev,
        Err(e) => {
            warn!(error = %e, "stripe webhook parse failed");
            return (StatusCode::BAD_REQUEST, r#"{"error":"invalid payload"}"#);
        }
    };

    // Tenant from webhook metadata / Stripe customer mapping (slice 2+).
    if let Err(e) = state
        .meta_db
        .apply_stripe_subscription(
            None,
            &event.stripe_customer_id,
            &event.stripe_subscription_id,
            event.plan_tier,
        )
        .await
    {
        warn!(error = %e, "stripe webhook persist failed");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            r#"{"error":"persist failed"}"#,
        );
    }

    (StatusCode::OK, r#"{"received":true}"#)
}

#[cfg(test)]
mod tests {
    use super::*;
    use disk_core::billing::{compute_v1_signature, PlanTier};
    use disk_core::meta_db::MetaDb;
    use std::net::SocketAddr;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tempfile::tempdir;
    use tokio::net::TcpListener;

    const SECRET: &str = "whsec_test_secret";

    fn signed_request_body(payload: &str) -> (String, String) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let sig = compute_v1_signature(SECRET, ts, payload.as_bytes());
        let header = format!("t={ts},v1={sig}");
        (header, payload.to_string())
    }

    #[tokio::test]
    async fn webhook_updates_tier_with_valid_signature() {
        let payload = r#"{
            "type": "customer.subscription.updated",
            "data": {
                "object": {
                    "id": "sub_t",
                    "customer": "cus_t",
                    "status": "active",
                    "items": { "data": [{ "price": { "lookup_key": "disk_team" } }] }
                }
            }
        }"#;
        let (sig_header, body) = signed_request_body(payload);

        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("wh.sqlite")).await.unwrap();
        let state = Arc::new(WebhookState {
            mode: super::super::mode::BillingMode::Stripe,
            meta_db: db.clone(),
            webhook_secret: Some(SECRET.to_string()),
            signature_tolerance_secs: DEFAULT_STRIPE_TOLERANCE_SECS,
            require_signature_header: true,
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        drop(listener);

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            crate::health::serve(addr, Some(state), None, async move {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{addr}/billing/stripe/webhook"))
            .header("content-type", "application/json")
            .header("stripe-signature", sig_header)
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        let tier = db.get_plan_tier(None, PlanTier::Free).await.unwrap();
        assert_eq!(tier, PlanTier::Team);

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn webhook_rejects_invalid_signature() {
        let payload = r#"{"type":"customer.subscription.updated"}"#;
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("wh2.sqlite")).await.unwrap();
        let state = Arc::new(WebhookState {
            mode: super::super::mode::BillingMode::Stripe,
            meta_db: db,
            webhook_secret: Some(SECRET.to_string()),
            signature_tolerance_secs: DEFAULT_STRIPE_TOLERANCE_SECS,
            require_signature_header: true,
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        drop(listener);

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            crate::health::serve(addr, Some(state), None, async move {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{addr}/billing/stripe/webhook"))
            .header("stripe-signature", "t=1,v1=deadbeef")
            .body(payload)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400);

        let _ = shutdown_tx.send(());
    }
}
