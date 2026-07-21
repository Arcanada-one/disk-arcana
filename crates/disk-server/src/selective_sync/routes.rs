//! HTTP handlers for `/selective-sync` (DISK-0023).

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::accounts::routes::{resolve_user_from_access, verify_bearer, AuthHttpState};
use crate::sharing::access::{require_read, require_write, resolve_vault_access};

#[derive(Debug, Deserialize)]
pub struct SelectiveSyncQuery {
    #[serde(default = "default_vault")]
    pub vault_id: String,
    pub node_id: String,
}

#[derive(Debug, Deserialize)]
pub struct PutSelectiveSyncRequest {
    #[serde(default = "default_vault")]
    pub vault_id: String,
    pub node_id: String,
    /// Folder prefixes to sync on this device. Empty = sync entire vault.
    #[serde(default)]
    pub includes: Vec<String>,
}

fn default_vault() -> String {
    "default".into()
}

#[derive(Debug, Serialize)]
pub struct SelectiveSyncResponse {
    pub vault_id: String,
    pub node_id: String,
    pub user_id: String,
    /// When true, no folder filter is active (full vault sync).
    pub sync_all: bool,
    pub includes: Vec<String>,
}

pub async fn get_selective_sync(
    State(state): State<std::sync::Arc<AuthHttpState>>,
    headers: HeaderMap,
    Query(query): Query<SelectiveSyncQuery>,
) -> impl IntoResponse {
    match get_selective_sync_inner(&state, &headers, query).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err((code, msg)) => (code, Json(json!({ "error": msg }))).into_response(),
    }
}

async fn get_selective_sync_inner(
    state: &AuthHttpState,
    headers: &HeaderMap,
    query: SelectiveSyncQuery,
) -> Result<SelectiveSyncResponse, (StatusCode, &'static str)> {
    if query.node_id.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "node_id required"));
    }

    let claims = verify_bearer(state, headers).await?;
    let user = resolve_user_from_access(state, &claims).await?;
    let access = resolve_vault_access(state, &user, &query.vault_id).await?;
    require_read(&access)?;

    let includes = state
        .meta_db
        .list_device_sync_includes(
            access.tenant_key(),
            &user.id,
            query.node_id.trim(),
            &query.vault_id,
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    Ok(SelectiveSyncResponse {
        vault_id: query.vault_id,
        node_id: query.node_id.trim().to_string(),
        user_id: user.id,
        sync_all: includes.is_empty(),
        includes,
    })
}

pub async fn put_selective_sync(
    State(state): State<std::sync::Arc<AuthHttpState>>,
    headers: HeaderMap,
    Json(body): Json<PutSelectiveSyncRequest>,
) -> impl IntoResponse {
    match put_selective_sync_inner(&state, &headers, body).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err((code, msg)) => (code, Json(json!({ "error": msg }))).into_response(),
    }
}

async fn put_selective_sync_inner(
    state: &AuthHttpState,
    headers: &HeaderMap,
    body: PutSelectiveSyncRequest,
) -> Result<SelectiveSyncResponse, (StatusCode, &'static str)> {
    if body.node_id.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "node_id required"));
    }

    let claims = verify_bearer(state, headers).await?;
    let user = resolve_user_from_access(state, &claims).await?;
    let access = resolve_vault_access(state, &user, &body.vault_id).await?;
    require_write(&access)?;

    let includes = state
        .meta_db
        .replace_device_sync_includes(
            access.tenant_key(),
            &user.id,
            body.node_id.trim(),
            &body.vault_id,
            &body.includes,
        )
        .await
        .map_err(|e| match e {
            disk_core::error::MetaDbError::Invalid(_) => {
                (StatusCode::BAD_REQUEST, "invalid include prefix")
            }
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "database error"),
        })?;

    Ok(SelectiveSyncResponse {
        vault_id: body.vault_id,
        node_id: body.node_id.trim().to_string(),
        user_id: user.id,
        sync_all: includes.is_empty(),
        includes,
    })
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::health;
    use disk_core::meta_db::MetaDb;
    use std::time::Duration;
    use tempfile::tempdir;

    async fn spawn_auth_server(meta_db: MetaDb) -> u16 {
        let bundle = crate::accounts::routes::auth_http_state_for_tests(meta_db);
        let state = std::sync::Arc::new(bundle);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        tokio::spawn(async move {
            health::serve(addr, None, Some(state), std::future::pending::<()>())
                .await
                .unwrap();
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        addr.port()
    }

    #[tokio::test]
    async fn selective_sync_get_put_round_trip() {
        let dir = tempdir().unwrap();
        let meta_db = MetaDb::open(&dir.path().join("selective-http.sqlite"))
            .await
            .unwrap();

        let email = disk_core::normalize_email("sel@corp.test");
        let hash_pw = disk_core::hash_password("long-password").unwrap();
        meta_db
            .create_user_account("usr_sel", &email, &hash_pw, "corp")
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO tenant_vaults (tenant_id, vault_id, created_at) VALUES ('corp', 'default', 1)",
        )
        .execute(meta_db.pool())
        .await
        .unwrap();

        let port = spawn_auth_server(meta_db).await;
        let client = reqwest::Client::new();

        let login: serde_json::Value = client
            .post(format!("http://127.0.0.1:{port}/auth/login"))
            .json(&serde_json::json!({ "email": email, "password": "long-password" }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let token = login["access_token"].as_str().unwrap();

        let get_empty: serde_json::Value = client
            .get(format!(
                "http://127.0.0.1:{port}/selective-sync?vault_id=default&node_id=macbook"
            ))
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(get_empty["sync_all"], true);
        assert!(get_empty["includes"].as_array().unwrap().is_empty());

        let put: serde_json::Value = client
            .put(format!("http://127.0.0.1:{port}/selective-sync"))
            .bearer_auth(token)
            .json(&serde_json::json!({
                "vault_id": "default",
                "node_id": "macbook",
                "includes": ["docs/", "photos"]
            }))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(put["sync_all"], false);
        let includes = put["includes"].as_array().unwrap();
        assert_eq!(includes.len(), 2);
        assert!(includes.iter().any(|v| v == "docs"));
        assert!(includes.iter().any(|v| v == "photos"));

        let get: serde_json::Value = client
            .get(format!(
                "http://127.0.0.1:{port}/selective-sync?vault_id=default&node_id=macbook"
            ))
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(get["includes"].as_array().unwrap().len(), 2);
    }
}
