//! HTTP handlers for `/compliance/*` (DISK-0021).

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use disk_core::billing::PlanTier;
use disk_core::normalize_email;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::accounts::routes::{resolve_user_from_access, verify_bearer, AuthHttpState};

#[derive(Debug, Serialize)]
pub struct DataExportResponse {
    pub exported_at: i64,
    pub format_version: u32,
    pub user: ExportUser,
    pub tenant: ExportTenant,
}

#[derive(Debug, Serialize)]
pub struct ExportUser {
    pub user_id: String,
    pub email: String,
    pub tenant_id: String,
    pub email_verified: bool,
    pub oauth_provider: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Serialize)]
pub struct ExportTenant {
    pub tenant_id: String,
    pub plan_tier: String,
    pub vaults: Vec<ExportVault>,
    pub devices: Vec<ExportDevice>,
}

#[derive(Debug, Serialize)]
pub struct ExportVault {
    pub vault_id: String,
    pub created_at: i64,
}

#[derive(Debug, Serialize)]
pub struct ExportDevice {
    pub node_id: String,
    pub display_name: Option<String>,
    pub platform: Option<String>,
    pub registered_at: i64,
    pub last_seen: Option<i64>,
}

pub async fn export_data(
    State(state): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    match export_data_inner(&state, &headers).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err((code, msg)) => (code, Json(json!({ "error": msg }))).into_response(),
    }
}

async fn export_data_inner(
    state: &AuthHttpState,
    headers: &HeaderMap,
) -> Result<DataExportResponse, (StatusCode, &'static str)> {
    let claims = verify_bearer(state, headers).await?;
    let user = resolve_user_from_access(state, &claims).await?;
    let tenant_key = Some(user.tenant_id.as_str());

    let tier = state
        .meta_db
        .get_plan_tier(tenant_key, PlanTier::Free)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    let vault_rows = state
        .meta_db
        .list_tenant_vaults(tenant_key)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;
    let node_rows = state
        .meta_db
        .list_tenant_nodes(tenant_key)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    Ok(DataExportResponse {
        exported_at: unix_now(),
        format_version: 1,
        user: ExportUser {
            user_id: user.id.clone(),
            email: user.email.clone(),
            tenant_id: user.tenant_id.clone(),
            email_verified: user.email_verified,
            oauth_provider: user.oauth_provider.clone(),
            created_at: user.created_at,
            updated_at: user.updated_at,
        },
        tenant: ExportTenant {
            tenant_id: user.tenant_id,
            plan_tier: tier.as_str().to_owned(),
            vaults: vault_rows
                .into_iter()
                .map(|v| ExportVault {
                    vault_id: v.vault_id,
                    created_at: v.created_at,
                })
                .collect(),
            devices: node_rows
                .into_iter()
                .map(|n| ExportDevice {
                    node_id: n.node_id,
                    display_name: n.display_name,
                    platform: n.platform,
                    registered_at: n.registered_at,
                    last_seen: n.last_seen,
                })
                .collect(),
        },
    })
}

#[derive(Debug, Deserialize)]
pub struct DeleteAccountRequest {
    pub confirm_email: String,
}

#[derive(Debug, Serialize)]
pub struct DeleteAccountResponse {
    pub deleted: bool,
    pub user_id: String,
    pub tenant_purged: bool,
}

pub async fn delete_account(
    State(state): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    Json(body): Json<DeleteAccountRequest>,
) -> impl IntoResponse {
    match delete_account_inner(&state, &headers, body).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err((code, msg)) => (code, Json(json!({ "error": msg }))).into_response(),
    }
}

async fn delete_account_inner(
    state: &AuthHttpState,
    headers: &HeaderMap,
    body: DeleteAccountRequest,
) -> Result<DeleteAccountResponse, (StatusCode, &'static str)> {
    let claims = verify_bearer(state, headers).await?;
    let user = resolve_user_from_access(state, &claims).await?;

    let confirm = normalize_email(&body.confirm_email);
    if confirm != user.email {
        return Err((StatusCode::BAD_REQUEST, "confirm_email mismatch"));
    }

    let tenant_id = user.tenant_id.clone();
    let user_id = user.id.clone();

    state
        .meta_db
        .delete_consent_events_for_user(&user_id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    let removed = state
        .meta_db
        .delete_user_by_id(&user_id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;
    if !removed {
        return Err((StatusCode::NOT_FOUND, "user not found"));
    }

    let remaining = state
        .meta_db
        .count_users_for_tenant(&tenant_id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    let tenant_purged = if remaining == 0 {
        state
            .meta_db
            .purge_tenant_metadata(&tenant_id)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;
        true
    } else {
        false
    };

    Ok(DeleteAccountResponse {
        deleted: true,
        user_id,
        tenant_purged,
    })
}

#[derive(Debug, Serialize)]
pub struct SubProcessorEntry {
    pub name: &'static str,
    pub purpose: &'static str,
    pub location: &'static str,
    pub website: &'static str,
}

#[derive(Debug, Serialize)]
pub struct SubProcessorsResponse {
    pub updated_at: &'static str,
    pub processors: &'static [SubProcessorEntry],
}

pub async fn sub_processors() -> Json<SubProcessorsResponse> {
    Json(sub_processors_payload())
}

fn sub_processors_payload() -> SubProcessorsResponse {
    SubProcessorsResponse {
        updated_at: "2026-07-21",
        processors: &[
            SubProcessorEntry {
                name: "Hetzner Online GmbH",
                purpose: "Cloud infrastructure hosting",
                location: "Germany (EU/EEA)",
                website: "https://www.hetzner.com",
            },
            SubProcessorEntry {
                name: "Cloudflare, Inc.",
                purpose: "CDN, DNS, and DDoS protection",
                location: "United States (Standard Contractual Clauses)",
                website: "https://www.cloudflare.com",
            },
        ],
    }
}

#[derive(Debug, Serialize)]
pub struct ConsentEventResponse {
    pub consent_type: String,
    pub policy_version: String,
    pub recorded_at: i64,
}

#[derive(Debug, Serialize)]
pub struct ConsentsListResponse {
    pub events: Vec<ConsentEventResponse>,
}

pub async fn list_consents(
    State(state): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    match list_consents_inner(&state, &headers).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err((code, msg)) => (code, Json(json!({ "error": msg }))).into_response(),
    }
}

async fn list_consents_inner(
    state: &AuthHttpState,
    headers: &HeaderMap,
) -> Result<ConsentsListResponse, (StatusCode, &'static str)> {
    let claims = verify_bearer(state, headers).await?;
    let user = resolve_user_from_access(state, &claims).await?;

    let rows = state
        .meta_db
        .list_consent_events_for_user(&user.id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    Ok(ConsentsListResponse {
        events: rows
            .into_iter()
            .map(|r| ConsentEventResponse {
                consent_type: r.consent_type,
                policy_version: r.policy_version,
                recorded_at: r.recorded_at,
            })
            .collect(),
    })
}

fn unix_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod integration_tests {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use disk_core::meta_db::MetaDb;
    use serde_json::Value;
    use tempfile::tempdir;
    use tokio::net::TcpListener;

    use super::*;
    use crate::accounts::{
        EmailVerifyConfig, EmailVerifyMode, JwksCache, JwtConfig, JwtMode, OAuthConfig, OAuthMode,
    };
    use crate::health;

    const TEST_KEY: &str = "01234567890123456789012345678901";

    async fn with_compliance_server<F, Fut>(meta_db: MetaDb, exercise: F)
    where
        F: FnOnce(SocketAddr) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        drop(listener);

        let state = Arc::new(crate::accounts::routes::auth_http_state_for_tests(meta_db));

        let server = health::serve(addr, None, Some(state), std::future::pending::<()>());
        tokio::pin!(server);

        tokio::select! {
            result = &mut server => panic!("health server exited early: {result:?}"),
            () = async {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                exercise(addr).await;
            } => {}
        }
    }

    #[tokio::test]
    async fn compliance_export_requires_auth() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("export-auth.sqlite"))
            .await
            .unwrap();
        with_compliance_server(db, |addr| async move {
            let resp = reqwest::Client::new()
                .get(format!("http://{addr}/compliance/export"))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 401);
        })
        .await;
    }

    #[tokio::test]
    async fn compliance_export_round_trip() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("export-rt.sqlite"))
            .await
            .unwrap();
        let seed_db = db.clone();

        with_compliance_server(db, |addr| async move {
            let base = format!("http://{addr}");
            let client = reqwest::Client::new();

            let signup: Value = client
                .post(format!("{base}/auth/signup"))
                .json(&serde_json::json!({
                    "email": "export@example.com",
                    "password": "secure-pass",
                    "tenant_id": "export-corp"
                }))
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap()
                .json()
                .await
                .unwrap();
            let token = signup["access_token"].as_str().unwrap();

            let hash = [3u8; 32];
            seed_db
                .register_tenant_vault(Some("export-corp"), "wiki")
                .await
                .unwrap();
            seed_db
                .upsert_node_tenant("node-1", Some("export-corp"), &hash, "Laptop", "darwin")
                .await
                .unwrap();

            let export: Value = client
                .get(format!("{base}/compliance/export"))
                .bearer_auth(token)
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap()
                .json()
                .await
                .unwrap();

            assert_eq!(export["format_version"], 1);
            assert_eq!(export["user"]["email"], "export@example.com");
            assert_eq!(export["tenant"]["tenant_id"], "export-corp");
            assert_eq!(export["tenant"]["vaults"].as_array().unwrap().len(), 1);
            assert_eq!(export["tenant"]["devices"].as_array().unwrap().len(), 1);
            assert!(export["exported_at"].as_i64().unwrap() > 0);
            assert!(export["user"].get("password_hash").is_none());
        })
        .await;
    }

    #[tokio::test]
    async fn compliance_delete_account_requires_auth() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("delete-auth.sqlite"))
            .await
            .unwrap();
        with_compliance_server(db, |addr| async move {
            let resp = reqwest::Client::new()
                .post(format!("http://{addr}/compliance/delete-account"))
                .json(&serde_json::json!({ "confirm_email": "a@b.com" }))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 401);
        })
        .await;
    }

    #[tokio::test]
    async fn compliance_delete_account_round_trip() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("delete-rt.sqlite"))
            .await
            .unwrap();
        let seed_db = db.clone();

        with_compliance_server(db, |addr| async move {
            let base = format!("http://{addr}");
            let client = reqwest::Client::new();

            let signup: Value = client
                .post(format!("{base}/auth/signup"))
                .json(&serde_json::json!({
                    "email": "delete@example.com",
                    "password": "secure-pass",
                    "tenant_id": "delete-corp"
                }))
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap()
                .json()
                .await
                .unwrap();
            let token = signup["access_token"].as_str().unwrap();

            seed_db
                .register_tenant_vault(Some("delete-corp"), "wiki")
                .await
                .unwrap();

            let deleted: Value = client
                .post(format!("{base}/compliance/delete-account"))
                .bearer_auth(token)
                .json(&serde_json::json!({ "confirm_email": "delete@example.com" }))
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap()
                .json()
                .await
                .unwrap();

            assert_eq!(deleted["deleted"], true);
            assert_eq!(deleted["tenant_purged"], true);

            assert!(seed_db
                .get_user_by_email("delete@example.com")
                .await
                .unwrap()
                .is_none());
            assert!(seed_db
                .list_tenant_vaults(Some("delete-corp"))
                .await
                .unwrap()
                .is_empty());

            let me = client
                .get(format!("{base}/auth/me"))
                .bearer_auth(token)
                .send()
                .await
                .unwrap();
            assert_eq!(me.status(), 401);
        })
        .await;
    }

    #[tokio::test]
    async fn compliance_delete_account_rejects_email_mismatch() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("delete-mismatch.sqlite"))
            .await
            .unwrap();

        with_compliance_server(db, |addr| async move {
            let base = format!("http://{addr}");
            let client = reqwest::Client::new();

            let signup: Value = client
                .post(format!("{base}/auth/signup"))
                .json(&serde_json::json!({
                    "email": "keep@example.com",
                    "password": "secure-pass",
                    "tenant_id": "keep-corp"
                }))
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap()
                .json()
                .await
                .unwrap();
            let token = signup["access_token"].as_str().unwrap();

            let resp = client
                .post(format!("{base}/compliance/delete-account"))
                .bearer_auth(token)
                .json(&serde_json::json!({ "confirm_email": "wrong@example.com" }))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 400);
        })
        .await;
    }

    #[tokio::test]
    async fn compliance_sub_processors_is_public() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("subproc.sqlite"))
            .await
            .unwrap();
        with_compliance_server(db, |addr| async move {
            let body: Value = reqwest::Client::new()
                .get(format!("http://{addr}/compliance/sub-processors"))
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap()
                .json()
                .await
                .unwrap();
            assert!(body["processors"].as_array().unwrap().len() >= 2);
        })
        .await;
    }

    #[tokio::test]
    async fn compliance_consents_recorded_on_signup() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("consents.sqlite"))
            .await
            .unwrap();

        with_compliance_server(db, |addr| async move {
            let base = format!("http://{addr}");
            let client = reqwest::Client::new();

            let signup: Value = client
                .post(format!("{base}/auth/signup"))
                .json(&serde_json::json!({
                    "email": "consent@example.com",
                    "password": "secure-pass",
                    "tenant_id": "consent-corp"
                }))
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap()
                .json()
                .await
                .unwrap();
            let token = signup["access_token"].as_str().unwrap();

            let consents: Value = client
                .get(format!("{base}/compliance/consents"))
                .bearer_auth(token)
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap()
                .json()
                .await
                .unwrap();

            let events = consents["events"].as_array().unwrap();
            assert_eq!(events.len(), 2);
            assert_eq!(events[0]["consent_type"], "terms_of_service");
            assert_eq!(events[1]["consent_type"], "privacy_policy");
        })
        .await;
    }
}
