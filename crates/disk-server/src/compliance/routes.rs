//! HTTP handlers for `/compliance/*` (DISK-0021).

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use disk_core::billing::PlanTier;
use serde::Serialize;
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
}
