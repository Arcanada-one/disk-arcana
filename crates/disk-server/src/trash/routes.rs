//! HTTP handlers for `/trash/*` (DISK-0024).

use std::path::Path;

use axum::extract::Query;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use disk_core::billing::PlanTier;
use disk_core::meta_db::{FileVersionUpsert, TrashRow};
use disk_core::path_guard;
use disk_core::types::FileMeta;
use disk_core::vector_clock::VectorClock;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::accounts::routes::{resolve_user_from_access, verify_bearer, AuthHttpState};
use crate::sharing::access::{require_manage, require_read, require_write, resolve_vault_access};

#[derive(Debug, Deserialize)]
pub struct ListTrashQuery {
    #[serde(default = "default_vault")]
    pub vault_id: String,
    #[serde(default = "default_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
}

fn default_vault() -> String {
    "default".into()
}

fn default_limit() -> u32 {
    20
}

fn normalize_rel_path(raw: &str) -> Result<String, &'static str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.contains("..") {
        return Err("invalid path");
    }
    Ok(trimmed.replace('\\', "/"))
}

#[derive(Debug, Serialize)]
pub struct TrashListResponse {
    pub vault_id: String,
    pub plan_tier: String,
    pub retention: TrashRetentionInfo,
    pub pagination: TrashPagination,
    pub pruned_expired: u32,
    pub items: Vec<TrashEntry>,
}

#[derive(Debug, Serialize)]
pub struct TrashRetentionInfo {
    pub max_age_secs: i64,
    pub max_age_days: u32,
}

#[derive(Debug, Serialize)]
pub struct TrashPagination {
    pub limit: u32,
    pub offset: u32,
    pub total: u32,
    pub has_more: bool,
}

#[derive(Debug, Serialize)]
pub struct TrashEntry {
    pub path: String,
    pub content_hash_hex: String,
    pub size: u64,
    pub deleted_at: i64,
    pub version_id: Option<u64>,
    pub blob_available: bool,
    pub expires_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct RestoreTrashRequest {
    pub path: String,
    #[serde(default = "default_vault")]
    pub vault_id: String,
}

#[derive(Debug, Serialize)]
pub struct RestoreTrashResponse {
    pub restored: bool,
    pub path: String,
    pub vault_id: String,
    pub new_version_id: u64,
    pub content_hash_hex: String,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct DeleteTrashRequest {
    pub path: String,
    #[serde(default = "default_vault")]
    pub vault_id: String,
}

#[derive(Debug, Serialize)]
pub struct DeleteTrashResponse {
    pub deleted: bool,
    pub path: String,
    pub vault_id: String,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct EmptyTrashRequest {
    #[serde(default = "default_vault")]
    pub vault_id: String,
    /// Must be `true` to permanently delete all trashed files in the vault.
    pub confirm: bool,
}

#[derive(Debug, Serialize)]
pub struct EmptyTrashResponse {
    pub emptied: bool,
    pub vault_id: String,
    pub deleted_count: u32,
    pub message: String,
}

pub async fn list_trash(
    axum::extract::State(state): axum::extract::State<std::sync::Arc<AuthHttpState>>,
    headers: HeaderMap,
    Query(query): Query<ListTrashQuery>,
) -> impl IntoResponse {
    match list_trash_inner(&state, &headers, query).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err((code, msg)) => (code, Json(json!({ "error": msg }))).into_response(),
    }
}

async fn list_trash_inner(
    state: &AuthHttpState,
    headers: &HeaderMap,
    query: ListTrashQuery,
) -> Result<TrashListResponse, (StatusCode, &'static str)> {
    let claims = verify_bearer(state, headers).await?;
    let user = resolve_user_from_access(state, &claims).await?;
    let access = resolve_vault_access(state, &user, &query.vault_id).await?;
    require_read(&access)?;
    let tenant_key = access.tenant_key();

    let tier = state
        .meta_db
        .get_plan_tier(tenant_key, PlanTier::Free)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;
    let retention = tier.trash_retention();

    let db = state
        .tenant_router
        .tenant_data(tenant_key)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    let pruned_expired = db
        .prune_expired_trash(tenant_key, &query.vault_id, &retention)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    let limit = query.limit.clamp(1, 200);
    let offset = query.offset.min(10_000);

    let total = db
        .count_trash(tenant_key, &query.vault_id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    let rows = db
        .list_trash(tenant_key, &query.vault_id, limit, offset)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    let has_more = offset.saturating_add(limit) < total;
    let items = rows
        .iter()
        .map(|row| trash_entry(row, state, retention.max_age_secs))
        .collect();

    Ok(TrashListResponse {
        vault_id: query.vault_id,
        plan_tier: tier.as_str().to_string(),
        retention: TrashRetentionInfo {
            max_age_secs: retention.max_age_secs,
            max_age_days: (retention.max_age_secs / 86_400) as u32,
        },
        pagination: TrashPagination {
            limit,
            offset,
            total,
            has_more,
        },
        pruned_expired,
        items,
    })
}

fn trash_entry(row: &TrashRow, state: &AuthHttpState, max_age_secs: i64) -> TrashEntry {
    TrashEntry {
        path: row.path.clone(),
        content_hash_hex: hex::encode(row.content_hash),
        size: row.size,
        deleted_at: row.deleted_at,
        version_id: row.version_id,
        blob_available: state.version_blobs.contains(&row.content_hash),
        expires_at: row.deleted_at.saturating_add(max_age_secs),
    }
}

pub async fn restore_trash(
    axum::extract::State(state): axum::extract::State<std::sync::Arc<AuthHttpState>>,
    headers: HeaderMap,
    Json(body): Json<RestoreTrashRequest>,
) -> impl IntoResponse {
    match restore_trash_inner(&state, &headers, body).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err((code, msg)) => (code, Json(json!({ "error": msg }))).into_response(),
    }
}

async fn restore_trash_inner(
    state: &AuthHttpState,
    headers: &HeaderMap,
    body: RestoreTrashRequest,
) -> Result<RestoreTrashResponse, (StatusCode, &'static str)> {
    let path = normalize_rel_path(&body.path).map_err(|msg| (StatusCode::BAD_REQUEST, msg))?;

    let claims = verify_bearer(state, headers).await?;
    let user = resolve_user_from_access(state, &claims).await?;
    let access = resolve_vault_access(state, &user, &body.vault_id).await?;
    require_write(&access)?;
    let tenant_key = access.tenant_key();

    let tier = state
        .meta_db
        .get_plan_tier(tenant_key, PlanTier::Free)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;
    let version_retention = tier.version_retention();

    let db = state
        .tenant_router
        .tenant_data(tenant_key)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    let trashed = db
        .get_file_scoped(tenant_key, &body.vault_id, &path)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?
        .ok_or((StatusCode::NOT_FOUND, "path not found"))?;

    if !trashed.deleted {
        return Err((StatusCode::CONFLICT, "file is not in trash"));
    }

    let bytes = resolve_trash_blob(state, &db, tenant_key, &body.vault_id, &trashed)
        .await
        .ok_or((StatusCode::CONFLICT, "file blob not available"))?;

    let target = path_guard::validate(Path::new(&path), &state.sync_root)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid path"))?;

    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "write failed"))?;
    }

    std::fs::write(&target, &bytes)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "write failed"))?;

    let mtime_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0);

    let mut vc = VectorClock::new();
    vc.advance("trash-restore");

    let meta = FileMeta {
        path: target
            .strip_prefix(&state.sync_root)
            .unwrap_or(&target)
            .to_path_buf(),
        content_hash: trashed.content_hash,
        size: trashed.size,
        mtime_ns,
        inode: None,
        vector_clock: vc,
        deleted: false,
        deleted_at: None,
        node_id: "trash-restore".into(),
        encryption_nonce: trashed.encryption_nonce.clone(),
        version_id: None,
        parent_version_id: None,
    };

    let ctx = FileVersionUpsert {
        created_by: user.id.clone(),
        retention: version_retention,
    };
    let new_version_id = db
        .upsert_file_scoped_versioned(tenant_key, &body.vault_id, &meta, &ctx)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    let _ = state.version_blobs.put(&trashed.content_hash, &bytes);

    let message = format!("Restored {path} from trash as revision {new_version_id}");

    Ok(RestoreTrashResponse {
        restored: true,
        path,
        vault_id: body.vault_id,
        new_version_id,
        content_hash_hex: hex::encode(trashed.content_hash),
        message,
    })
}

async fn resolve_trash_blob(
    state: &AuthHttpState,
    db: &disk_core::MetaDb,
    tenant_key: Option<&str>,
    vault_id: &str,
    meta: &FileMeta,
) -> Option<Vec<u8>> {
    if let Some(bytes) = state.version_blobs.get(&meta.content_hash) {
        return Some(bytes);
    }

    if let Some(version_id) = meta.version_id {
        if let Ok(Some(version)) = db
            .get_file_version(
                tenant_key,
                vault_id,
                meta.path.to_str().unwrap_or(""),
                version_id,
            )
            .await
        {
            if let Some(bytes) = state.version_blobs.get(&version.content_hash) {
                return Some(bytes);
            }
        }
    }

    let rel = meta.path.to_str()?;
    let candidate = state.sync_root.join(rel);
    if let Ok(bytes) = std::fs::read(&candidate) {
        let hash = *blake3::hash(&bytes).as_bytes();
        if hash == meta.content_hash {
            return Some(bytes);
        }
    }

    None
}

pub async fn delete_trash(
    axum::extract::State(state): axum::extract::State<std::sync::Arc<AuthHttpState>>,
    headers: HeaderMap,
    Json(body): Json<DeleteTrashRequest>,
) -> impl IntoResponse {
    match delete_trash_inner(&state, &headers, body).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err((code, msg)) => (code, Json(json!({ "error": msg }))).into_response(),
    }
}

async fn delete_trash_inner(
    state: &AuthHttpState,
    headers: &HeaderMap,
    body: DeleteTrashRequest,
) -> Result<DeleteTrashResponse, (StatusCode, &'static str)> {
    let path = normalize_rel_path(&body.path).map_err(|msg| (StatusCode::BAD_REQUEST, msg))?;

    let claims = verify_bearer(state, headers).await?;
    let user = resolve_user_from_access(state, &claims).await?;
    let access = resolve_vault_access(state, &user, &body.vault_id).await?;
    require_manage(&access)?;
    let tenant_key = access.tenant_key();

    let db = state
        .tenant_router
        .tenant_data(tenant_key)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    let deleted = db
        .delete_trash_item(tenant_key, &body.vault_id, &path)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    if !deleted {
        return Err((StatusCode::NOT_FOUND, "path not in trash"));
    }

    Ok(DeleteTrashResponse {
        deleted: true,
        path: path.clone(),
        vault_id: body.vault_id,
        message: format!("Permanently deleted {path} from trash"),
    })
}

pub async fn empty_trash(
    axum::extract::State(state): axum::extract::State<std::sync::Arc<AuthHttpState>>,
    headers: HeaderMap,
    Json(body): Json<EmptyTrashRequest>,
) -> impl IntoResponse {
    match empty_trash_inner(&state, &headers, body).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err((code, msg)) => (code, Json(json!({ "error": msg }))).into_response(),
    }
}

async fn empty_trash_inner(
    state: &AuthHttpState,
    headers: &HeaderMap,
    body: EmptyTrashRequest,
) -> Result<EmptyTrashResponse, (StatusCode, &'static str)> {
    if !body.confirm {
        return Err((
            StatusCode::BAD_REQUEST,
            "confirm must be true to empty trash",
        ));
    }

    let claims = verify_bearer(state, headers).await?;
    let user = resolve_user_from_access(state, &claims).await?;
    let access = resolve_vault_access(state, &user, &body.vault_id).await?;
    require_manage(&access)?;
    let tenant_key = access.tenant_key();

    let db = state
        .tenant_router
        .tenant_data(tenant_key)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    let deleted_count = db
        .empty_trash(tenant_key, &body.vault_id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    Ok(EmptyTrashResponse {
        emptied: true,
        vault_id: body.vault_id.clone(),
        deleted_count,
        message: format!(
            "Permanently deleted {deleted_count} file(s) from vault {}",
            body.vault_id
        ),
    })
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::health;
    use disk_core::meta_db::MetaDb;
    use disk_core::types::FileMeta;
    use disk_core::vector_clock::VectorClock;
    use disk_core::ContentBlobStore;
    use std::path::PathBuf;
    use std::time::Duration;
    use tempfile::tempdir;

    async fn seed_tenant_vault(db: &MetaDb, tenant: &str, vault: &str) {
        sqlx::query(
            "INSERT INTO tenant_vaults (tenant_id, vault_id, created_at) VALUES (?1, ?2, 1)",
        )
        .bind(tenant)
        .bind(vault)
        .execute(db.pool())
        .await
        .unwrap();
    }

    async fn spawn_auth_server(
        meta_db: MetaDb,
        sync_root: std::path::PathBuf,
        blobs: ContentBlobStore,
    ) -> u16 {
        let mut bundle = crate::accounts::routes::auth_http_state_for_tests(meta_db);
        bundle.sync_root = sync_root;
        bundle.version_blobs = blobs;
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

    fn trashed(path: &str, hash_byte: u8) -> FileMeta {
        FileMeta {
            path: PathBuf::from(path),
            content_hash: [hash_byte; 32],
            size: 5,
            mtime_ns: 1,
            inode: None,
            vector_clock: VectorClock::new(),
            deleted: true,
            deleted_at: Some(1_700_000_000),
            node_id: "test".into(),
            encryption_nonce: None,
            version_id: Some(1),
            parent_version_id: None,
        }
    }

    #[tokio::test]
    async fn trash_list_restore_round_trip() {
        let dir = tempdir().unwrap();
        let sync_root = dir.path().join("sync");
        std::fs::create_dir_all(&sync_root).unwrap();
        let meta_db = MetaDb::open(&dir.path().join("meta.sqlite")).await.unwrap();

        let bytes = b"trash";
        let hash = *blake3::hash(bytes).as_bytes();
        let mut meta = trashed("notes/restore-me.md", hash[0]);
        meta.content_hash = hash;
        meta.size = bytes.len() as u64;
        meta.deleted_at = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0)
                - 60,
        );

        let blobs = ContentBlobStore::new(dir.path().join("version-blobs"));
        blobs.put(&hash, bytes).unwrap();

        meta_db
            .upsert_file_scoped(Some("corp"), "default", &meta)
            .await
            .unwrap();

        let email = disk_core::normalize_email("trash@example.com");
        let hash_pw = disk_core::hash_password("long-password").unwrap();
        meta_db
            .create_user_account("usr_trash", &email, &hash_pw, "corp")
            .await
            .unwrap();
        seed_tenant_vault(&meta_db, "corp", "default").await;

        let port = spawn_auth_server(meta_db, sync_root.clone(), blobs).await;
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

        let list: serde_json::Value = client
            .get(format!("http://127.0.0.1:{port}/trash?vault_id=default"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(list["items"].as_array().unwrap().len(), 1);
        assert_eq!(
            list["items"][0]["path"].as_str().unwrap(),
            "notes/restore-me.md"
        );
        assert!(list["items"][0]["blob_available"].as_bool().unwrap());

        let restore: serde_json::Value = client
            .post(format!("http://127.0.0.1:{port}/trash/restore"))
            .bearer_auth(token)
            .json(&json!({ "path": "notes/restore-me.md", "vault_id": "default" }))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(restore["restored"].as_bool(), Some(true));
        assert!(sync_root.join("notes/restore-me.md").exists());
    }
}
