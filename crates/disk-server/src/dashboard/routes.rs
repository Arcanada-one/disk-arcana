//! HTTP handlers for `/dashboard/*` (DISK-0019).

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use disk_core::billing::PlanTier;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::accounts::routes::{resolve_user_from_access, verify_bearer, AuthHttpState};

#[derive(Debug, Serialize)]
pub struct DashboardSummary {
    pub user: DashboardUser,
    pub billing: DashboardBilling,
    pub vaults: Vec<DashboardVault>,
    pub devices: Vec<DashboardDevice>,
    pub conflicts: Vec<DashboardConflict>,
}

#[derive(Debug, Serialize)]
pub struct DashboardUser {
    pub user_id: String,
    pub email: String,
    pub tenant_id: String,
    pub email_verified: bool,
}

#[derive(Debug, Serialize)]
pub struct DashboardBilling {
    pub plan_tier: String,
    pub storage_bytes: u64,
    pub storage_limit_bytes: u64,
    pub nodes_count: u32,
    pub nodes_limit: u32,
    pub vaults_count: u32,
    pub vaults_limit: u32,
}

#[derive(Debug, Serialize)]
pub struct DashboardVault {
    pub vault_id: String,
    pub created_at: i64,
}

#[derive(Debug, Serialize)]
pub struct DashboardDevice {
    pub node_id: String,
    pub display_name: Option<String>,
    pub platform: Option<String>,
    pub registered_at: i64,
    pub last_seen: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct DashboardConflict {
    pub id: i64,
    pub vault_id: String,
    pub path: String,
    pub conflict_type: String,
    pub fork_path: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct ResolveConflictRequest {
    pub action: String,
}

#[derive(Debug, Serialize)]
pub struct ResolveConflictResponse {
    pub resolved: bool,
    pub id: i64,
    pub action: String,
}

pub async fn resolve_conflict(
    State(state): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(body): Json<ResolveConflictRequest>,
) -> impl IntoResponse {
    match resolve_conflict_inner(&state, &headers, id, body).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err((code, msg)) => (code, Json(json!({ "error": msg }))).into_response(),
    }
}

async fn resolve_conflict_inner(
    state: &AuthHttpState,
    headers: &HeaderMap,
    id: i64,
    body: ResolveConflictRequest,
) -> Result<ResolveConflictResponse, (StatusCode, &'static str)> {
    if !is_valid_resolve_action(&body.action) {
        return Err((StatusCode::BAD_REQUEST, "invalid action"));
    }

    let claims = verify_bearer(state, headers).await?;
    let user = resolve_user_from_access(state, &claims).await?;
    let tenant_key = Some(user.tenant_id.as_str());

    let conflict = state
        .meta_db
        .get_unresolved_conflict_for_tenant(tenant_key, id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?
        .ok_or((StatusCode::NOT_FOUND, "conflict not found"))?;

    state
        .meta_db
        .resolve_conflict(id, &body.action)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    Ok(ResolveConflictResponse {
        resolved: true,
        id: conflict.id.unwrap_or(id),
        action: body.action,
    })
}

fn is_valid_resolve_action(action: &str) -> bool {
    matches!(
        action,
        "fork-local" | "fork-remote" | "merge" | "keep-local" | "keep-remote"
    )
}

pub async fn summary(
    State(state): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    match summary_inner(&state, &headers).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err((code, msg)) => (code, Json(json!({ "error": msg }))).into_response(),
    }
}

async fn summary_inner(
    state: &AuthHttpState,
    headers: &HeaderMap,
) -> Result<DashboardSummary, (StatusCode, &'static str)> {
    let claims = verify_bearer(state, headers).await?;
    let user = resolve_user_from_access(state, &claims).await?;
    let tenant_key = Some(user.tenant_id.as_str());

    let tier = state
        .meta_db
        .get_plan_tier(tenant_key, PlanTier::Free)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;
    let limits = tier.limits();

    let storage_bytes = state
        .meta_db
        .sum_storage_bytes(tenant_key)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;
    let nodes_count = state
        .meta_db
        .count_tenant_nodes(tenant_key)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;
    let vaults_count = state
        .meta_db
        .count_tenant_vaults(tenant_key)
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
    let conflict_rows = state
        .meta_db
        .list_unresolved_conflicts_for_tenant(tenant_key)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    Ok(DashboardSummary {
        user: DashboardUser {
            user_id: user.id,
            email: user.email,
            tenant_id: user.tenant_id,
            email_verified: user.email_verified,
        },
        billing: DashboardBilling {
            plan_tier: tier.as_str().to_owned(),
            storage_bytes,
            storage_limit_bytes: limits.max_storage_bytes,
            nodes_count,
            nodes_limit: limits.max_nodes,
            vaults_count,
            vaults_limit: limits.max_vaults,
        },
        vaults: vault_rows
            .into_iter()
            .map(|v| DashboardVault {
                vault_id: v.vault_id,
                created_at: v.created_at,
            })
            .collect(),
        devices: node_rows
            .into_iter()
            .map(|n| DashboardDevice {
                node_id: n.node_id,
                display_name: n.display_name,
                platform: n.platform,
                registered_at: n.registered_at,
                last_seen: n.last_seen,
            })
            .collect(),
        conflicts: conflict_rows
            .into_iter()
            .filter_map(|c| {
                Some(DashboardConflict {
                    id: c.id?,
                    vault_id: c.vault_id,
                    path: c.path,
                    conflict_type: c.conflict_type,
                    fork_path: c.fork_path,
                    created_at: c.created_at,
                })
            })
            .collect(),
    })
}

#[cfg(test)]
mod integration_tests {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use disk_core::billing::PlanTier;
    use disk_core::meta_db::MetaDb;
    use disk_core::types::ConflictRecord;
    use serde_json::Value;
    use tempfile::tempdir;
    use tokio::net::TcpListener;

    use super::*;
    use crate::accounts::{
        EmailVerifyConfig, EmailVerifyMode, JwksCache, JwtConfig, JwtMode, OAuthConfig, OAuthMode,
    };
    use crate::health;

    const TEST_KEY: &str = "01234567890123456789012345678901";

    async fn with_dashboard_server<F, Fut>(meta_db: MetaDb, exercise: F)
    where
        F: FnOnce(SocketAddr) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        drop(listener);

        let state = Arc::new(AuthHttpState {
            meta_db,
            signing_key: TEST_KEY.as_bytes().to_vec(),
            jwt: JwtConfig {
                mode: JwtMode::Local,
                local_signing_key: TEST_KEY.as_bytes().to_vec(),
                token_ttl_secs: 3600,
                issuer: disk_core::DEFAULT_ISSUER.into(),
                jwks: Arc::new(JwksCache::new("http://127.0.0.1:9/jwks")),
            },
            oauth: OAuthConfig {
                mode: OAuthMode::Disabled,
                issuer: None,
                client_id: None,
                client_secret: None,
                redirect_uri: None,
                public_base_url: None,
            },
            email_verify: EmailVerifyConfig {
                mode: EmailVerifyMode::Disabled,
                public_base_url: None,
                token_ttl_secs: 86_400,
            },
        });

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
    async fn dashboard_summary_requires_auth() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("dash-auth.sqlite"))
            .await
            .unwrap();
        with_dashboard_server(db, |addr| async move {
            let resp = reqwest::Client::new()
                .get(format!("http://{addr}/dashboard/summary"))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 401);
        })
        .await;
    }

    #[tokio::test]
    async fn dashboard_summary_round_trip() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("dash-summary.sqlite"))
            .await
            .unwrap();
        let seed_db = db.clone();

        with_dashboard_server(db, |addr| async move {
            let base = format!("http://{addr}");
            let client = reqwest::Client::new();

            let signup: Value = client
                .post(format!("{base}/auth/signup"))
                .json(&serde_json::json!({
                    "email": "dash@example.com",
                    "password": "secure-pass",
                    "tenant_id": "dash-corp"
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
                .set_plan_tier(Some("dash-corp"), PlanTier::Pro)
                .await
                .unwrap();
            seed_db
                .register_tenant_vault(Some("dash-corp"), "wiki")
                .await
                .unwrap();
            let hash = [9u8; 32];
            seed_db
                .upsert_node_tenant("node-mac", Some("dash-corp"), &hash, "MacBook", "darwin")
                .await
                .unwrap();
            let conflict = ConflictRecord {
                id: None,
                vault_id: "wiki".into(),
                path: "notes/todo.md".into(),
                conflict_type: "Concurrent".into(),
                local_hash: None,
                remote_hash: None,
                base_hash: None,
                resolution: None,
                fork_path: Some("notes/todo.sync-conflict.md".into()),
                resolved: false,
                created_at: 1,
                resolved_at: None,
            };
            seed_db
                .create_conflict_scoped(Some("dash-corp"), &conflict)
                .await
                .unwrap();

            let summary: Value = client
                .get(format!("{base}/dashboard/summary"))
                .bearer_auth(token)
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap()
                .json()
                .await
                .unwrap();

            assert_eq!(summary["user"]["tenant_id"], "dash-corp");
            assert_eq!(summary["billing"]["plan_tier"], "pro");
            assert_eq!(summary["vaults"].as_array().unwrap().len(), 1);
            assert_eq!(summary["devices"].as_array().unwrap().len(), 1);
            assert_eq!(summary["conflicts"].as_array().unwrap().len(), 1);
        })
        .await;
    }

    #[tokio::test]
    async fn dashboard_resolve_conflict_round_trip() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("dash-resolve.sqlite"))
            .await
            .unwrap();
        let seed_db = db.clone();

        with_dashboard_server(db, |addr| async move {
            let base = format!("http://{addr}");
            let client = reqwest::Client::new();

            let signup: Value = client
                .post(format!("{base}/auth/signup"))
                .json(&serde_json::json!({
                    "email": "resolve@example.com",
                    "password": "secure-pass",
                    "tenant_id": "resolve-corp"
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

            let conflict = ConflictRecord {
                id: None,
                vault_id: "default".into(),
                path: "notes/a.md".into(),
                conflict_type: "Concurrent".into(),
                local_hash: None,
                remote_hash: None,
                base_hash: None,
                resolution: None,
                fork_path: None,
                resolved: false,
                created_at: 1,
                resolved_at: None,
            };
            let id = seed_db
                .create_conflict_scoped(Some("resolve-corp"), &conflict)
                .await
                .unwrap();

            let resolved: Value = client
                .post(format!("{base}/dashboard/conflicts/{id}/resolve"))
                .bearer_auth(token)
                .json(&serde_json::json!({ "action": "keep-local" }))
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(resolved["resolved"], true);

            let summary: Value = client
                .get(format!("{base}/dashboard/summary"))
                .bearer_auth(token)
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(summary["conflicts"].as_array().unwrap().len(), 0);
        })
        .await;
    }
}
