//! HTTP handlers for `/telemetry` and `/telemetry/config` (DISK-0026 slice 1).

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use disk_core::meta_db::consent::{ANALYTICS_POLICY_VERSION, CONSENT_TYPE_ANALYTICS};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::accounts::routes::{resolve_user_from_access, verify_bearer, AuthHttpState};

use super::config::TelemetryRuntimeConfig;

#[derive(Debug, Serialize)]
pub struct TelemetryConfigResponse {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_key: Option<String>,
    pub api_host: String,
}

#[derive(Debug, Serialize)]
pub struct TelemetryPreferenceResponse {
    pub user_id: String,
    pub opt_in: bool,
    pub updated_at: Option<i64>,
    pub server_enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct PutTelemetryRequest {
    pub opt_in: bool,
}

pub async fn get_telemetry_config() -> Json<TelemetryConfigResponse> {
    Json(telemetry_config_payload())
}

fn telemetry_config_payload() -> TelemetryConfigResponse {
    let runtime = TelemetryRuntimeConfig::from_env();
    TelemetryConfigResponse {
        enabled: runtime.enabled,
        project_key: runtime.project_key,
        api_host: runtime.api_host,
    }
}

pub async fn get_telemetry(
    State(state): State<std::sync::Arc<AuthHttpState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    match get_telemetry_inner(&state, &headers).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err((code, msg)) => (code, Json(json!({ "error": msg }))).into_response(),
    }
}

async fn get_telemetry_inner(
    state: &AuthHttpState,
    headers: &HeaderMap,
) -> Result<TelemetryPreferenceResponse, (StatusCode, &'static str)> {
    let claims = verify_bearer(state, headers).await?;
    let user = resolve_user_from_access(state, &claims).await?;

    let row = state
        .meta_db
        .get_user_telemetry(&user.id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    let runtime = TelemetryRuntimeConfig::from_env();

    Ok(TelemetryPreferenceResponse {
        user_id: user.id,
        opt_in: row.opt_in,
        updated_at: if row.updated_at == 0 {
            None
        } else {
            Some(row.updated_at)
        },
        server_enabled: runtime.enabled,
    })
}

pub async fn put_telemetry(
    State(state): State<std::sync::Arc<AuthHttpState>>,
    headers: HeaderMap,
    Json(body): Json<PutTelemetryRequest>,
) -> impl IntoResponse {
    match put_telemetry_inner(&state, &headers, body).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err((code, msg)) => (code, Json(json!({ "error": msg }))).into_response(),
    }
}

async fn put_telemetry_inner(
    state: &AuthHttpState,
    headers: &HeaderMap,
    body: PutTelemetryRequest,
) -> Result<TelemetryPreferenceResponse, (StatusCode, &'static str)> {
    let claims = verify_bearer(state, headers).await?;
    let user = resolve_user_from_access(state, &claims).await?;

    if body.opt_in && !TelemetryRuntimeConfig::from_env().enabled {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "product analytics is not configured on this server",
        ));
    }

    let row = state
        .meta_db
        .upsert_user_telemetry_opt_in(&user.id, body.opt_in)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    state
        .meta_db
        .record_consent_event(
            &user.id,
            &user.tenant_id,
            CONSENT_TYPE_ANALYTICS,
            ANALYTICS_POLICY_VERSION,
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    let runtime = TelemetryRuntimeConfig::from_env();

    Ok(TelemetryPreferenceResponse {
        user_id: user.id,
        opt_in: row.opt_in,
        updated_at: Some(row.updated_at),
        server_enabled: runtime.enabled,
    })
}
