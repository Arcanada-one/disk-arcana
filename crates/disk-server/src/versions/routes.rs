//! HTTP handlers for `/versions/*` (DISK-0020).

use std::path::Path;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use disk_core::billing::PlanTier;
use disk_core::meta_db::{FileVersionRow, FileVersionUpsert};
use disk_core::path_guard;
use disk_core::types::FileMeta;
use disk_core::vector_clock::VectorClock;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::accounts::routes::{resolve_user_from_access, verify_bearer, AuthHttpState};

#[derive(Debug, Deserialize)]
pub struct ListVersionsQuery {
    pub path: String,
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
pub struct VersionListResponse {
    pub path: String,
    pub vault_id: String,
    pub plan_tier: String,
    pub file_exists: bool,
    pub file_deleted: bool,
    pub current_version_id: Option<u64>,
    pub retention: RetentionInfo,
    pub pagination: VersionPagination,
    pub current: Option<VersionEntry>,
    pub versions: Vec<VersionEntry>,
}

#[derive(Debug, Serialize)]
pub struct VersionPagination {
    pub limit: u32,
    pub offset: u32,
    pub total_historical: u32,
    pub has_more: bool,
}

#[derive(Debug, Serialize)]
pub struct RetentionInfo {
    pub max_versions: u32,
    pub max_age_secs: i64,
    pub max_age_days: u32,
}

#[derive(Debug, Serialize)]
pub struct VersionEntry {
    pub version_id: u64,
    pub parent_version_id: u64,
    pub content_hash_hex: String,
    pub size: u64,
    pub mtime_ns: i64,
    pub created_at: i64,
    pub created_by: Option<String>,
    pub blob_available: bool,
    pub is_current: bool,
}

#[derive(Debug, Deserialize)]
pub struct RestoreVersionRequest {
    pub path: String,
    pub version_id: u64,
    #[serde(default = "default_vault")]
    pub vault_id: String,
}

#[derive(Debug, Serialize)]
pub struct RestoreVersionResponse {
    pub restored: bool,
    pub path: String,
    pub vault_id: String,
    pub version_id: u64,
    pub new_version_id: u64,
    pub content_hash_hex: String,
    pub message: String,
}

pub async fn list_versions(
    State(state): State<std::sync::Arc<AuthHttpState>>,
    headers: HeaderMap,
    Query(query): Query<ListVersionsQuery>,
) -> impl IntoResponse {
    match list_versions_inner(&state, &headers, query).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err((code, msg)) => (code, Json(json!({ "error": msg }))).into_response(),
    }
}

async fn list_versions_inner(
    state: &AuthHttpState,
    headers: &HeaderMap,
    query: ListVersionsQuery,
) -> Result<VersionListResponse, (StatusCode, &'static str)> {
    let path = normalize_rel_path(&query.path).map_err(|msg| (StatusCode::BAD_REQUEST, msg))?;

    let claims = verify_bearer(state, headers).await?;
    let user = resolve_user_from_access(state, &claims).await?;
    let tenant_key = Some(user.tenant_id.as_str());

    let tier = state
        .meta_db
        .get_plan_tier(tenant_key, PlanTier::Free)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;
    let retention = tier.version_retention();

    let db = state
        .tenant_router
        .tenant_data(tenant_key)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    let current = db
        .get_file_scoped(tenant_key, &query.vault_id, &path)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    let limit = query.limit.clamp(1, 200);
    let offset = query.offset.min(10_000);

    let total_historical = db
        .count_file_versions(tenant_key, &query.vault_id, &path)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    let rows = db
        .list_file_versions(tenant_key, &query.vault_id, &path, limit, offset)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    let current_entry = current
        .as_ref()
        .map(|meta| version_entry_from_meta(meta, state, true, None));

    let versions = rows
        .into_iter()
        .map(|row| version_entry_from_row(&row, state, false))
        .collect();

    let has_more = offset.saturating_add(limit) < total_historical;

    Ok(VersionListResponse {
        path,
        vault_id: query.vault_id,
        plan_tier: tier.as_str().into(),
        file_exists: current.is_some(),
        file_deleted: current.as_ref().is_some_and(|m| m.deleted),
        current_version_id: current.and_then(|m| m.version_id),
        retention: RetentionInfo {
            max_versions: retention.max_versions,
            max_age_secs: retention.max_age_secs,
            max_age_days: (retention.max_age_secs / 86_400).max(1) as u32,
        },
        pagination: VersionPagination {
            limit,
            offset,
            total_historical,
            has_more,
        },
        current: current_entry,
        versions,
    })
}

fn version_entry_from_row(
    row: &FileVersionRow,
    state: &AuthHttpState,
    is_current: bool,
) -> VersionEntry {
    VersionEntry {
        version_id: row.version_id,
        parent_version_id: row.parent_version_id,
        content_hash_hex: hex::encode(row.content_hash),
        size: row.size,
        mtime_ns: row.mtime_ns,
        created_at: row.created_at,
        created_by: row.created_by.clone(),
        blob_available: state.version_blobs.contains(&row.content_hash),
        is_current,
    }
}

fn version_entry_from_meta(
    meta: &FileMeta,
    state: &AuthHttpState,
    is_current: bool,
    created_by: Option<String>,
) -> VersionEntry {
    VersionEntry {
        version_id: meta.version_id.unwrap_or(1),
        parent_version_id: meta.parent_version_id.unwrap_or(0),
        content_hash_hex: hex::encode(meta.content_hash),
        size: meta.size,
        mtime_ns: meta.mtime_ns,
        created_at: meta.mtime_ns / 1_000_000_000,
        created_by,
        blob_available: state.version_blobs.contains(&meta.content_hash),
        is_current,
    }
}

pub async fn restore_version(
    State(state): State<std::sync::Arc<AuthHttpState>>,
    headers: HeaderMap,
    Json(body): Json<RestoreVersionRequest>,
) -> impl IntoResponse {
    match restore_version_inner(&state, &headers, body).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err((code, msg)) => (code, Json(json!({ "error": msg }))).into_response(),
    }
}

async fn restore_version_inner(
    state: &AuthHttpState,
    headers: &HeaderMap,
    body: RestoreVersionRequest,
) -> Result<RestoreVersionResponse, (StatusCode, &'static str)> {
    let path = normalize_rel_path(&body.path).map_err(|msg| (StatusCode::BAD_REQUEST, msg))?;
    if body.version_id == 0 {
        return Err((StatusCode::BAD_REQUEST, "invalid version_id"));
    }

    let claims = verify_bearer(state, headers).await?;
    let user = resolve_user_from_access(state, &claims).await?;
    let tenant_key = Some(user.tenant_id.as_str());

    let tier = state
        .meta_db
        .get_plan_tier(tenant_key, PlanTier::Free)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;
    let retention = tier.version_retention();

    let db = state
        .tenant_router
        .tenant_data(tenant_key)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    let live = db
        .get_file_scoped(tenant_key, &body.vault_id, &path)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    if let Some(ref meta) = live {
        if meta.version_id == Some(body.version_id) {
            return Err((StatusCode::CONFLICT, "version is already current"));
        }
    }

    let version = db
        .get_file_version(tenant_key, &body.vault_id, &path, body.version_id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?
        .ok_or((StatusCode::NOT_FOUND, "version not found"))?;

    let bytes = state
        .version_blobs
        .get(&version.content_hash)
        .ok_or((StatusCode::CONFLICT, "version blob not available"))?;

    if live
        .as_ref()
        .is_some_and(|m| !m.deleted && m.content_hash == version.content_hash)
    {
        return Err((StatusCode::CONFLICT, "file already matches this revision"));
    }

    let target = path_guard::validate(Path::new(&path), &state.sync_root)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid path"))?;

    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "write failed"))?;
    }

    if target.exists() {
        if let Ok(current_bytes) = std::fs::read(&target) {
            if let Ok(Some(current)) = db.get_file_scoped(tenant_key, &body.vault_id, &path).await {
                let _ = state
                    .version_blobs
                    .put(&current.content_hash, &current_bytes);
            }
        }
    }

    std::fs::write(&target, &bytes)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "write failed"))?;

    let mtime_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0);

    let mut vc = VectorClock::new();
    vc.advance("dashboard-restore");

    let meta = FileMeta {
        path: target
            .strip_prefix(&state.sync_root)
            .unwrap_or(&target)
            .to_path_buf(),
        content_hash: version.content_hash,
        size: version.size,
        mtime_ns,
        inode: None,
        vector_clock: vc,
        deleted: false,
        deleted_at: None,
        node_id: "dashboard-restore".into(),
        encryption_nonce: None,
        version_id: None,
        parent_version_id: None,
    };

    let ctx = FileVersionUpsert {
        created_by: user.id.clone(),
        retention,
    };
    let new_version_id = db
        .upsert_file_scoped_versioned(tenant_key, &body.vault_id, &meta, &ctx)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    let _ = state.version_blobs.put(&version.content_hash, &bytes);

    let message = format!(
        "Restored version {} as new revision {}",
        body.version_id, new_version_id
    );

    Ok(RestoreVersionResponse {
        restored: true,
        path,
        vault_id: body.vault_id,
        version_id: body.version_id,
        new_version_id,
        content_hash_hex: hex::encode(version.content_hash),
        message,
    })
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::health;
    use disk_core::meta_db::MetaDb;
    use disk_core::ContentBlobStore;
    use std::time::Duration;
    use tempfile::tempdir;

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

    #[tokio::test]
    async fn versions_list_and_restore_round_trip() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("meta.sqlite");
        let sync_root = dir.path().join("sync");
        std::fs::create_dir_all(&sync_root).unwrap();
        let blobs = ContentBlobStore::new(dir.path().join("version-blobs"));

        let db = MetaDb::open(&db_path).await.unwrap();
        let retention = PlanTier::Free.version_retention();
        let ctx = FileVersionUpsert {
            created_by: "server".into(),
            retention,
        };

        let v1_bytes = b"version-one";
        let v1_hash = *blake3::hash(v1_bytes).as_bytes();
        blobs.put(&v1_hash, v1_bytes).unwrap();
        std::fs::write(sync_root.join("notes.md"), v1_bytes).unwrap();

        let mut meta_v1 = FileMeta {
            path: "notes.md".into(),
            content_hash: v1_hash,
            size: v1_bytes.len() as u64,
            mtime_ns: 1,
            inode: None,
            vector_clock: VectorClock::new(),
            deleted: false,
            deleted_at: None,
            node_id: "server".into(),
            encryption_nonce: None,
            version_id: None,
            parent_version_id: None,
        };
        db.upsert_file_scoped_versioned(Some("corp"), "default", &meta_v1, &ctx)
            .await
            .unwrap();

        let v2_bytes = b"version-two-content";
        let v2_hash = *blake3::hash(v2_bytes).as_bytes();
        blobs.put(&v1_hash, v1_bytes).unwrap();
        std::fs::write(sync_root.join("notes.md"), v2_bytes).unwrap();
        meta_v1.content_hash = v2_hash;
        meta_v1.size = v2_bytes.len() as u64;
        db.upsert_file_scoped_versioned(Some("corp"), "default", &meta_v1, &ctx)
            .await
            .unwrap();

        let email = disk_core::normalize_email("ver@example.com");
        let hash = disk_core::hash_password("long-password").unwrap();
        db.create_user_account("usr_ver", &email, &hash, "corp")
            .await
            .unwrap();

        let port = spawn_auth_server(db, sync_root.clone(), blobs).await;

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
            .get(format!(
                "http://127.0.0.1:{port}/versions?path=notes.md&vault_id=default"
            ))
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(list["versions"].as_array().unwrap().len(), 1);
        assert!(list["versions"][0]["blob_available"].as_bool().unwrap());
        assert_eq!(list["pagination"]["total_historical"], 1);
        assert!(list["current"].is_object());
        assert_eq!(list["current"]["is_current"], true);
        assert_eq!(list["plan_tier"], "free");

        let restore: serde_json::Value = client
            .post(format!("http://127.0.0.1:{port}/versions/restore"))
            .bearer_auth(token)
            .json(&serde_json::json!({
                "path": "notes.md",
                "vault_id": "default",
                "version_id": 1
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(restore["restored"], true);
        assert!(restore["message"]
            .as_str()
            .unwrap()
            .contains("Restored version 1"));

        let on_disk = std::fs::read(sync_root.join("notes.md")).unwrap();
        assert_eq!(on_disk, v1_bytes);
    }

    #[tokio::test]
    async fn restore_rejects_current_version() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("meta.sqlite");
        let sync_root = dir.path().join("sync");
        std::fs::create_dir_all(&sync_root).unwrap();
        let blobs = ContentBlobStore::new(dir.path().join("version-blobs"));

        let db = MetaDb::open(&db_path).await.unwrap();
        let retention = PlanTier::Free.version_retention();
        let ctx = FileVersionUpsert {
            created_by: "server".into(),
            retention,
        };

        let bytes = b"only";
        let hash = *blake3::hash(bytes).as_bytes();
        blobs.put(&hash, bytes).unwrap();
        std::fs::write(sync_root.join("x.txt"), bytes).unwrap();

        let meta = FileMeta {
            path: "x.txt".into(),
            content_hash: hash,
            size: bytes.len() as u64,
            mtime_ns: 1,
            inode: None,
            vector_clock: VectorClock::new(),
            deleted: false,
            deleted_at: None,
            node_id: "server".into(),
            encryption_nonce: None,
            version_id: None,
            parent_version_id: None,
        };
        let vid = db
            .upsert_file_scoped_versioned(Some("corp"), "default", &meta, &ctx)
            .await
            .unwrap();

        let email = disk_core::normalize_email("cur@example.com");
        let pw = disk_core::hash_password("long-password").unwrap();
        db.create_user_account("usr_cur", &email, &pw, "corp")
            .await
            .unwrap();

        let port = spawn_auth_server(db, sync_root, blobs).await;
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

        let res = client
            .post(format!("http://127.0.0.1:{port}/versions/restore"))
            .bearer_auth(token)
            .json(&serde_json::json!({
                "path": "x.txt",
                "vault_id": "default",
                "version_id": vid
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 409);
    }
}
