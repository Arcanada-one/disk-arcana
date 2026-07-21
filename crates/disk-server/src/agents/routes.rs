//! HTTP handlers for `/agents/*` (DISK-0028 slice 1).

use std::path::Path;
use std::sync::Arc;

use axum::extract::Query;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use disk_core::billing::PlanTier;
use disk_core::meta_db::{FileVersionUpsert, NewAgentWebhook, RevisionBumpOutcome};
use disk_core::path_guard;
use disk_core::types::FileMeta;
use disk_core::vector_clock::VectorClock;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::accounts::routes::{resolve_user_from_access, verify_bearer, AuthHttpState};
use crate::sharing::access::{require_write, resolve_vault_access};

const ALLOWED_WEBHOOK_EVENTS: &[&str] = &[
    "sync.file_changed",
    "sync.file_deleted",
    "agent.write_ok",
    "agent.write_conflict",
];

#[derive(Debug, Deserialize)]
pub struct VaultScopedQuery {
    #[serde(default = "default_vault")]
    pub vault_id: String,
}

#[derive(Debug, Deserialize)]
pub struct RevisionQuery {
    pub path: String,
    #[serde(default = "default_vault")]
    pub vault_id: String,
}

#[derive(Debug, Deserialize)]
pub struct RegisterWebhookRequest {
    #[serde(default = "default_vault")]
    pub vault_id: String,
    pub url: String,
    pub events: Vec<String>,
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeleteWebhookRequest {
    pub webhook_id: String,
}

#[derive(Debug, Deserialize)]
pub struct AgentWriteRequest {
    #[serde(default = "default_vault")]
    pub vault_id: String,
    pub path: String,
    pub content_base64: String,
    #[serde(default)]
    pub if_match_revision: Option<u64>,
    #[serde(default)]
    pub agent_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct WebhookSummary {
    pub webhook_id: String,
    pub vault_id: String,
    pub url: String,
    pub events: Vec<String>,
    pub label: Option<String>,
    pub enabled: bool,
    pub created_at: i64,
}

#[derive(Debug, Serialize)]
pub struct WebhookListResponse {
    pub vault_id: String,
    pub webhooks: Vec<WebhookSummary>,
}

#[derive(Debug, Serialize)]
pub struct RegisterWebhookResponse {
    pub webhook_id: String,
    pub vault_id: String,
    pub url: String,
    pub events: Vec<String>,
    pub webhook_secret: String,
}

#[derive(Debug, Serialize)]
pub struct DeleteWebhookResponse {
    pub deleted: bool,
    pub webhook_id: String,
}

#[derive(Debug, Serialize)]
pub struct RevisionResponse {
    pub path: String,
    pub vault_id: String,
    pub revision: u64,
    pub exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash_hex: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AgentWriteResponse {
    pub path: String,
    pub vault_id: String,
    pub revision: u64,
    pub content_hash_hex: String,
    pub size: u64,
}

fn default_vault() -> String {
    "default".into()
}

fn normalize_rel_path(raw: &str) -> Result<String, &'static str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.contains("..") {
        return Err("invalid path");
    }
    Ok(trimmed.replace('\\', "/"))
}

fn new_webhook_id() -> String {
    let mut raw = [0u8; 8];
    rand::rng().fill_bytes(&mut raw);
    format!("awh_{}", hex::encode(raw))
}

fn issue_webhook_secret() -> ([u8; 32], String) {
    let mut raw = [0u8; 32];
    rand::rng().fill_bytes(&mut raw);
    let secret = format!("whsec_{}", hex::encode(raw));
    (raw, secret)
}

fn secret_hash(raw: &[u8; 32]) -> [u8; 32] {
    *blake3::hash(raw).as_bytes()
}

fn validate_events(events: &[String]) -> Result<(), &'static str> {
    if events.is_empty() {
        return Err("events required");
    }
    for event in events {
        if !ALLOWED_WEBHOOK_EVENTS.contains(&event.as_str()) {
            return Err("invalid event name");
        }
    }
    Ok(())
}

fn validate_webhook_url(url: &str) -> Result<(), &'static str> {
    if !url.starts_with("https://") {
        return Err("webhook url must use https");
    }
    if url.len() < 12 {
        return Err("invalid url");
    }
    Ok(())
}

async fn assert_vault_manager(
    state: &AuthHttpState,
    user: &disk_core::meta_db::UserAccount,
    vault_id: &str,
) -> Result<(), (StatusCode, &'static str)> {
    let access = resolve_vault_access(state, user, vault_id).await?;
    crate::sharing::access::require_manage(&access)
}

pub async fn list_webhooks(
    axum::extract::State(state): axum::extract::State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    Query(query): Query<VaultScopedQuery>,
) -> impl IntoResponse {
    match list_webhooks_inner(&state, &headers, query).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err((code, msg)) => (code, Json(json!({ "error": msg }))).into_response(),
    }
}

async fn list_webhooks_inner(
    state: &AuthHttpState,
    headers: &HeaderMap,
    query: VaultScopedQuery,
) -> Result<WebhookListResponse, (StatusCode, &'static str)> {
    let claims = verify_bearer(state, headers).await?;
    let user = resolve_user_from_access(state, &claims).await?;
    assert_vault_manager(state, &user, &query.vault_id).await?;

    let rows = state
        .meta_db
        .list_agent_webhooks(Some(user.tenant_id.as_str()), &query.vault_id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    Ok(WebhookListResponse {
        vault_id: query.vault_id.clone(),
        webhooks: rows
            .into_iter()
            .map(|row| WebhookSummary {
                webhook_id: row.id,
                vault_id: row.vault_id,
                url: row.url,
                events: row.events,
                label: row.label,
                enabled: row.enabled,
                created_at: row.created_at,
            })
            .collect(),
    })
}

pub async fn register_webhook(
    axum::extract::State(state): axum::extract::State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    Json(body): Json<RegisterWebhookRequest>,
) -> impl IntoResponse {
    match register_webhook_inner(&state, &headers, body).await {
        Ok(resp) => (StatusCode::CREATED, Json(resp)).into_response(),
        Err((code, msg)) => (code, Json(json!({ "error": msg }))).into_response(),
    }
}

async fn register_webhook_inner(
    state: &AuthHttpState,
    headers: &HeaderMap,
    body: RegisterWebhookRequest,
) -> Result<RegisterWebhookResponse, (StatusCode, &'static str)> {
    validate_webhook_url(&body.url).map_err(|msg| (StatusCode::BAD_REQUEST, msg))?;
    validate_events(&body.events).map_err(|msg| (StatusCode::BAD_REQUEST, msg))?;

    let claims = verify_bearer(state, headers).await?;
    let user = resolve_user_from_access(state, &claims).await?;
    assert_vault_manager(state, &user, &body.vault_id).await?;

    let (raw, secret) = issue_webhook_secret();
    let hash = secret_hash(&raw);
    let webhook_id = new_webhook_id();

    state
        .meta_db
        .insert_agent_webhook(NewAgentWebhook {
            id: &webhook_id,
            tenant_id: Some(user.tenant_id.as_str()),
            vault_id: &body.vault_id,
            url: &body.url,
            secret_hash: &hash,
            events: &body.events,
            label: body.label.as_deref(),
        })
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    Ok(RegisterWebhookResponse {
        webhook_id,
        vault_id: body.vault_id,
        url: body.url,
        events: body.events,
        webhook_secret: secret,
    })
}

pub async fn delete_webhook(
    axum::extract::State(state): axum::extract::State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    Json(body): Json<DeleteWebhookRequest>,
) -> impl IntoResponse {
    match delete_webhook_inner(&state, &headers, body).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err((code, msg)) => (code, Json(json!({ "error": msg }))).into_response(),
    }
}

async fn delete_webhook_inner(
    state: &AuthHttpState,
    headers: &HeaderMap,
    body: DeleteWebhookRequest,
) -> Result<DeleteWebhookResponse, (StatusCode, &'static str)> {
    let claims = verify_bearer(state, headers).await?;
    let user = resolve_user_from_access(state, &claims).await?;

    let deleted = state
        .meta_db
        .delete_agent_webhook(Some(user.tenant_id.as_str()), &body.webhook_id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    if !deleted {
        return Err((StatusCode::NOT_FOUND, "webhook not found"));
    }

    Ok(DeleteWebhookResponse {
        deleted: true,
        webhook_id: body.webhook_id,
    })
}

pub async fn get_revision(
    axum::extract::State(state): axum::extract::State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    Query(query): Query<RevisionQuery>,
) -> impl IntoResponse {
    match get_revision_inner(&state, &headers, query).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err((code, msg)) => (code, Json(json!({ "error": msg }))).into_response(),
    }
}

async fn get_revision_inner(
    state: &AuthHttpState,
    headers: &HeaderMap,
    query: RevisionQuery,
) -> Result<RevisionResponse, (StatusCode, &'static str)> {
    let path = normalize_rel_path(&query.path).map_err(|msg| (StatusCode::BAD_REQUEST, msg))?;

    let claims = verify_bearer(state, headers).await?;
    let user = resolve_user_from_access(state, &claims).await?;
    let access = resolve_vault_access(state, &user, &query.vault_id).await?;
    require_write(&access)?;
    let tenant_key = access.tenant_key();

    let db = state
        .tenant_router
        .tenant_data(tenant_key)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    let row = db
        .get_agent_write_revision(tenant_key, &query.vault_id, &path)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    Ok(RevisionResponse {
        path,
        vault_id: query.vault_id,
        revision: row.revision,
        exists: row.revision > 0,
        content_hash_hex: row.content_hash.map(hex::encode),
    })
}

pub async fn agent_write(
    axum::extract::State(state): axum::extract::State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    Json(body): Json<AgentWriteRequest>,
) -> impl IntoResponse {
    match agent_write_inner(&state, &headers, body).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err((code, msg)) => (code, Json(json!({ "error": msg }))).into_response(),
    }
}

async fn agent_write_inner(
    state: &AuthHttpState,
    headers: &HeaderMap,
    body: AgentWriteRequest,
) -> Result<AgentWriteResponse, (StatusCode, &'static str)> {
    let path = normalize_rel_path(&body.path).map_err(|msg| (StatusCode::BAD_REQUEST, msg))?;

    let bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        body.content_base64.trim(),
    )
    .map_err(|_| (StatusCode::BAD_REQUEST, "invalid content_base64"))?;

    let claims = verify_bearer(state, headers).await?;
    let user = resolve_user_from_access(state, &claims).await?;
    let access = resolve_vault_access(state, &user, &body.vault_id).await?;
    require_write(&access)?;
    let tenant_key = access.tenant_key();

    let db = state
        .tenant_router
        .tenant_data(tenant_key)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    let current = db
        .get_agent_write_revision(tenant_key, &body.vault_id, &path)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    let expected = body.if_match_revision.unwrap_or(0);
    if expected != current.revision {
        return Err((StatusCode::CONFLICT, "revision_conflict"));
    }

    let target = path_guard::validate(Path::new(&path), &state.sync_root)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid path"))?;

    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "write failed"))?;
    }

    if target.exists() {
        if let Ok(current_bytes) = std::fs::read(&target) {
            if let Ok(Some(current_meta)) =
                db.get_file_scoped(tenant_key, &body.vault_id, &path).await
            {
                let _ = state
                    .version_blobs
                    .put(&current_meta.content_hash, &current_bytes);
            }
        }
    }

    std::fs::write(&target, &bytes)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "write failed"))?;

    let content_hash = *blake3::hash(&bytes).as_bytes();
    let agent_label = body
        .agent_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or(user.id.as_str());

    let bump = db
        .bump_agent_write_revision(
            tenant_key,
            &body.vault_id,
            &path,
            expected,
            content_hash,
            agent_label,
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    let new_revision = match bump {
        RevisionBumpOutcome::Applied { new_revision } => new_revision,
        RevisionBumpOutcome::Conflict { .. } => {
            return Err((StatusCode::CONFLICT, "revision_conflict"));
        }
    };

    let tier = db
        .get_plan_tier(tenant_key, PlanTier::Free)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;
    let retention = tier.version_retention();

    let mtime_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0);

    let mut vc = VectorClock::new();
    vc.advance(agent_label);

    let meta = FileMeta {
        path: target
            .strip_prefix(&state.sync_root)
            .unwrap_or(&target)
            .to_path_buf(),
        content_hash,
        size: bytes.len() as u64,
        mtime_ns,
        inode: None,
        vector_clock: vc,
        deleted: false,
        deleted_at: None,
        node_id: agent_label.into(),
        encryption_nonce: None,
        version_id: None,
        parent_version_id: None,
    };

    let ctx = FileVersionUpsert {
        created_by: user.id.clone(),
        retention,
    };
    db.upsert_file_scoped_versioned(tenant_key, &body.vault_id, &meta, &ctx)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    let _ = state.version_blobs.put(&content_hash, &bytes);

    Ok(AgentWriteResponse {
        path,
        vault_id: body.vault_id,
        revision: new_revision,
        content_hash_hex: hex::encode(content_hash),
        size: bytes.len() as u64,
    })
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::health;
    use disk_core::meta_db::MetaDb;
    use std::time::Duration;
    use tempfile::tempdir;

    async fn seed_tenant_vault(db: &MetaDb, tenant: &str, vault: &str) {
        db.register_tenant_vault(Some(tenant), vault).await.unwrap();
    }

    async fn spawn_auth_server(meta_db: MetaDb, sync_root: std::path::PathBuf) -> u16 {
        let mut bundle = crate::accounts::routes::auth_http_state_for_tests(meta_db);
        bundle.sync_root = sync_root;
        let state = Arc::new(bundle);

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

    async fn login_token(port: u16, email: &str, password: &str) -> String {
        let client = reqwest::Client::new();
        let login: serde_json::Value = client
            .post(format!("http://127.0.0.1:{port}/auth/login"))
            .json(&serde_json::json!({ "email": email, "password": password }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        login["access_token"].as_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn agent_write_and_revision_conflict() {
        let dir = tempdir().unwrap();
        let sync_root = dir.path().join("sync");
        std::fs::create_dir_all(&sync_root).unwrap();
        let db = MetaDb::open(&dir.path().join("meta.sqlite")).await.unwrap();

        let email = disk_core::normalize_email("agent@corp.test");
        let hash_pw = disk_core::hash_password("long-password").unwrap();
        db.create_user_account("usr_agent", &email, &hash_pw, "corp")
            .await
            .unwrap();
        seed_tenant_vault(&db, "corp", "default").await;

        let port = spawn_auth_server(db, sync_root.clone()).await;
        let token = login_token(port, &email, "long-password").await;
        let client = reqwest::Client::new();

        let content =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"hello agent");

        let write1: serde_json::Value = client
            .post(format!("http://127.0.0.1:{port}/agents/write"))
            .bearer_auth(&token)
            .json(&serde_json::json!({
                "path": "notes/agent.md",
                "content_base64": content,
                "agent_id": "dreamer"
            }))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(write1["revision"], 1);
        assert!(sync_root.join("notes/agent.md").exists());

        let stale = client
            .post(format!("http://127.0.0.1:{port}/agents/write"))
            .bearer_auth(&token)
            .json(&serde_json::json!({
                "path": "notes/agent.md",
                "content_base64": content,
                "if_match_revision": 0
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(stale.status(), StatusCode::CONFLICT);

        let rev: serde_json::Value = client
            .get(format!(
                "http://127.0.0.1:{port}/agents/revision?path=notes/agent.md"
            ))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(rev["revision"], 1);
        assert_eq!(rev["exists"], true);
    }

    #[tokio::test]
    async fn webhook_register_list_delete() {
        let dir = tempdir().unwrap();
        let sync_root = dir.path().join("sync");
        std::fs::create_dir_all(&sync_root).unwrap();
        let db = MetaDb::open(&dir.path().join("meta2.sqlite"))
            .await
            .unwrap();

        let email = disk_core::normalize_email("owner@corp.test");
        let hash_pw = disk_core::hash_password("long-password").unwrap();
        db.create_user_account("usr_owner", &email, &hash_pw, "corp")
            .await
            .unwrap();
        seed_tenant_vault(&db, "corp", "default").await;

        let port = spawn_auth_server(db, sync_root).await;
        let token = login_token(port, &email, "long-password").await;
        let client = reqwest::Client::new();

        let created: serde_json::Value = client
            .post(format!("http://127.0.0.1:{port}/agents/webhooks"))
            .bearer_auth(&token)
            .json(&serde_json::json!({
                "url": "https://hooks.example/agent",
                "events": ["agent.write_ok"]
            }))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        let webhook_id = created["webhook_id"].as_str().unwrap();
        assert!(created["webhook_secret"]
            .as_str()
            .unwrap()
            .starts_with("whsec_"));

        let listed: serde_json::Value = client
            .get(format!(
                "http://127.0.0.1:{port}/agents/webhooks?vault_id=default"
            ))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(listed["webhooks"].as_array().unwrap().len(), 1);

        let deleted: serde_json::Value = client
            .delete(format!("http://127.0.0.1:{port}/agents/webhooks"))
            .bearer_auth(&token)
            .json(&serde_json::json!({ "webhook_id": webhook_id }))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(deleted["deleted"], true);
    }
}
