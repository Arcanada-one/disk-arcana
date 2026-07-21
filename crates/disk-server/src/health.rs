//! Minimal HTTP health listener for external monitoring.
//!
//! Binds to `DISK_HEALTH_BIND_ADDR` (default `0.0.0.0:9446`) and exposes:
//! - `GET /health` — liveness probe
//! - `POST /billing/stripe/webhook` — DISK-0018 Stripe stub (when mode=stripe)
//! - `POST /auth/signup`, `POST /auth/login`, `GET /auth/me` — DISK-0016 (when auth=enforce)
//! - `GET /auth/oauth/start`, `GET /auth/oauth/callback` — DISK-0016 slice 2 (when oauth active)
//! - `GET /auth/verify-email`, `POST /auth/resend-verification` — DISK-0016 slice 3 (when email verify active)
//! - `POST /auth/refresh` — DISK-0016 slice 5 (when oauth=auth_arcana + jwt JWKS mode)
//! - `GET /dashboard/summary` — DISK-0019 (when auth=enforce)
//! - `POST /dashboard/conflicts/{id}/resolve` — DISK-0019 slice 2
//! - `GET /compliance/export` — DISK-0021 GDPR data export (when auth=enforce)
//! - `POST /compliance/delete-account` — DISK-0021 slice 2 right-to-erasure
//! - `GET /compliance/sub-processors` — DISK-0021 slice 3 public registry
//! - `GET /compliance/consents` — DISK-0021 slice 3 consent audit (when auth=enforce)
//! - `GET /versions` — DISK-0020 file version history (when auth=enforce)
//! - `POST /versions/restore` — DISK-0020 restore a historical revision
//! - `GET /snapshots` — DISK-0020 slice 4 vault snapshot list (when auth=enforce)
//! - `POST /snapshots` — DISK-0020 slice 4 create vault snapshot
//! - `GET /snapshots/:id` — DISK-0020 slice 4 snapshot detail
//! - `POST /snapshots/:id/restore` — DISK-0020 slice 4 restore vault to snapshot
//! - `GET /trash` — DISK-0024 list soft-deleted files (when auth=enforce)
//! - `POST /trash/restore` — DISK-0024 undelete a file from trash
//! - `POST /trash/delete` — DISK-0024 permanently delete one trashed file
//! - `POST /trash/empty` — DISK-0024 permanently empty vault recycle bin
//! - `POST /sharing/invites` — DISK-0022 create vault invite link
//! - `GET /sharing/invites` — DISK-0022 list pending invites
//! - `POST /sharing/invites/accept` — DISK-0022 accept invite token
//! - `GET /sharing/members` — DISK-0022 list vault collaborators
//! - `POST /sharing/members/remove` — DISK-0022 revoke collaborator access
//! - `GET /selective-sync` — DISK-0023 per-device folder include rules
//! - `PUT /selective-sync` — DISK-0023 replace per-device folder include rules
//! - `GET /onboarding` — DISK-0025 getting-started checklist state
//! - `PUT /onboarding` — DISK-0025 persist checklist dismiss across devices
//! - `GET /telemetry/config` — DISK-0026 PostHog public runtime config
//! - `GET /telemetry` — DISK-0026 per-user analytics opt-in preference
//! - `PUT /telemetry` — DISK-0026 update analytics opt-in + consent audit

use std::net::SocketAddr;
use std::sync::Arc;

use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};

use crate::accounts::routes::{login, me, signup, AuthHttpState};
use crate::accounts::{
    oauth_callback, oauth_start, refresh_token, resend_verification, verify_email,
};
use crate::billing::webhook::{stripe_webhook, WebhookState};
use crate::compliance::{delete_account, export_data, list_consents, sub_processors};
use crate::dashboard::{resolve_conflict, summary};
use crate::onboarding::{get_onboarding, put_onboarding};
use crate::telemetry::{get_telemetry, get_telemetry_config, put_telemetry};
use crate::selective_sync::{get_selective_sync, put_selective_sync};
use crate::sharing::{accept_invite, create_invite, list_invites, list_members, remove_member};
use crate::snapshots::{create_snapshot, get_snapshot, list_snapshots, restore_snapshot};
use crate::trash::{delete_trash, empty_trash, list_trash, restore_trash};
use crate::versions::{list_versions, restore_version};

/// Start the health HTTP server. Returns an error if the bind fails; otherwise
/// drives the server until the provided `shutdown` future resolves.
pub async fn serve(
    addr: SocketAddr,
    webhook: Option<Arc<WebhookState>>,
    auth: Option<Arc<AuthHttpState>>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let mut app = Router::new()
        .route("/health", get(health_handler))
        .route("/compliance/sub-processors", get(sub_processors))
        .route("/telemetry/config", get(get_telemetry_config));
    if let Some(state) = webhook {
        app = app.route(
            "/billing/stripe/webhook",
            post(stripe_webhook).with_state(state),
        );
    }
    if let Some(state) = auth {
        let mut auth_router = Router::new()
            .route("/auth/signup", post(signup))
            .route("/auth/login", post(login))
            .route("/auth/me", get(me));
        if state.oauth.mode.is_active() {
            auth_router = auth_router
                .route("/auth/oauth/start", get(oauth_start))
                .route("/auth/oauth/callback", get(oauth_callback));
        }
        if state.oauth.mode == crate::accounts::OAuthMode::AuthArcana
            && state.jwt.mode.allows_jwks_verify()
        {
            auth_router = auth_router.route("/auth/refresh", post(refresh_token));
        }
        if state.email_verify.mode.is_active() {
            auth_router = auth_router
                .route("/auth/verify-email", get(verify_email))
                .route("/auth/resend-verification", post(resend_verification));
        }
        auth_router = auth_router
            .route("/dashboard/summary", get(summary))
            .route("/dashboard/conflicts/:id/resolve", post(resolve_conflict))
            .route("/compliance/export", get(export_data))
            .route("/compliance/delete-account", post(delete_account))
            .route("/compliance/consents", get(list_consents))
            .route("/versions", get(list_versions))
            .route("/versions/restore", post(restore_version))
            .route("/snapshots", get(list_snapshots).post(create_snapshot))
            .route("/snapshots/:id", get(get_snapshot))
            .route("/snapshots/:id/restore", post(restore_snapshot))
            .route("/trash", get(list_trash))
            .route("/trash/restore", post(restore_trash))
            .route("/trash/delete", post(delete_trash))
            .route("/trash/empty", post(empty_trash))
            .route("/sharing/invites", get(list_invites).post(create_invite))
            .route("/sharing/invites/accept", post(accept_invite))
            .route("/sharing/members", get(list_members))
            .route("/sharing/members/remove", post(remove_member))
            .route(
                "/selective-sync",
                get(get_selective_sync).put(put_selective_sync),
            )
            .route("/onboarding", get(get_onboarding).put(put_onboarding))
            .route("/telemetry", get(get_telemetry).put(put_telemetry));
        crate::trash::scheduler::spawn_periodic_prune(state.clone());
        app = app.merge(auth_router.with_state(state));
    }

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| anyhow::anyhow!("health listener bind {addr}: {e}"))?;

    tracing::info!(addr = %addr, "health HTTP listener ready");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .map_err(|e| anyhow::anyhow!("health server error: {e}"))
}

async fn health_handler() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    /// Bind to an ephemeral port, start the health server, query /health, verify
    /// the response is 200 with the expected JSON shape.
    #[tokio::test]
    async fn health_endpoint_returns_200() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        drop(listener);

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            serve(addr, None, None, async move {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let url = format!("http://{addr}/health");
        let resp = reqwest::get(&url).await.expect("request failed");
        assert_eq!(resp.status(), 200, "expected HTTP 200");
        let body: serde_json::Value = resp.json().await.expect("json parse failed");
        assert_eq!(body["status"], "ok", "expected status=ok");
        assert!(
            body["version"].is_string(),
            "expected version string in response"
        );

        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn health_handler_returns_version() {
        let Json(body) = health_handler().await;
        assert_eq!(body["status"], "ok");
        let version = body["version"].as_str().expect("version must be a string");
        assert!(!version.is_empty(), "version must be non-empty");
    }
}
