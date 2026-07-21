//! HTTP Stripe webhook handler (structure-only stub).

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use disk_core::billing::parse_stripe_subscription_event;
use disk_core::meta_db::MetaDb;
use tracing::warn;

use super::mode::BillingMode;

#[derive(Clone)]
pub struct WebhookState {
    pub mode: BillingMode,
    pub meta_db: MetaDb,
    /// When set, require `Stripe-Signature` header (verification deferred to slice 2).
    pub require_signature_header: bool,
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

    if state.require_signature_header && !headers.contains_key("stripe-signature") {
        return (
            StatusCode::BAD_REQUEST,
            r#"{"error":"missing Stripe-Signature header"}"#,
        );
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

    // Single-tenant SaaS default until DISK-0017 wires tenant_id from metadata.
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
    use disk_core::billing::PlanTier;
    use disk_core::meta_db::MetaDb;
    use std::net::SocketAddr;
    use tempfile::tempdir;
    use tokio::net::TcpListener;

    const PAYLOAD: &str = r#"{
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

    #[tokio::test]
    async fn webhook_updates_tier() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("wh.sqlite")).await.unwrap();
        let state = Arc::new(WebhookState {
            mode: super::super::mode::BillingMode::Stripe,
            meta_db: db.clone(),
            require_signature_header: false,
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        drop(listener);

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            crate::health::serve(addr, Some(state), async move {
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
            .body(PAYLOAD)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        let tier = db.get_plan_tier(None, PlanTier::Free).await.unwrap();
        assert_eq!(tier, PlanTier::Team);

        let _ = shutdown_tx.send(());
    }
}
