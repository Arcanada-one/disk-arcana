//! HTTP handlers for `/snapshots/*` (DISK-0020 slice 4).

use std::path::Path;

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use disk_core::billing::PlanTier;
use disk_core::meta_db::{FileVersionUpsert, VaultSnapshotFileRow, VaultSnapshotRow};
use disk_core::path_guard;
use disk_core::types::FileMeta;
use disk_core::vector_clock::VectorClock;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::accounts::routes::{resolve_user_from_access, verify_bearer, AuthHttpState};

fn default_vault() -> String {
    "default".into()
}

fn default_limit() -> u32 {
    20
}

#[derive(Debug, Deserialize)]
pub struct ListSnapshotsQuery {
    #[serde(default = "default_vault")]
    pub vault_id: String,
    #[serde(default = "default_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
}

#[derive(Debug, Deserialize)]
pub struct GetSnapshotQuery {
    #[serde(default = "default_vault")]
    pub vault_id: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateSnapshotRequest {
    #[serde(default = "default_vault")]
    pub vault_id: String,
    pub label: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RestoreSnapshotRequest {
    #[serde(default = "default_vault")]
    pub vault_id: String,
}

#[derive(Debug, Serialize)]
pub struct SnapshotSummary {
    pub id: u64,
    pub vault_id: String,
    pub label: Option<String>,
    pub file_count: u32,
    pub bytes_total: u64,
    pub created_at: i64,
    pub created_by: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SnapshotFileEntry {
    pub path: String,
    pub version_id: u64,
    pub content_hash_hex: String,
    pub size: u64,
    pub deleted: bool,
    pub blob_available: bool,
}

#[derive(Debug, Serialize)]
pub struct SnapshotListResponse {
    pub vault_id: String,
    pub plan_tier: String,
    pub retention: SnapshotRetentionInfo,
    pub pagination: SnapshotPagination,
    pub snapshots: Vec<SnapshotSummary>,
}

#[derive(Debug, Serialize)]
pub struct SnapshotPagination {
    pub limit: u32,
    pub offset: u32,
    pub total: u32,
    pub has_more: bool,
}

#[derive(Debug, Serialize)]
pub struct SnapshotRetentionInfo {
    pub max_snapshots: u32,
    pub max_age_secs: i64,
    pub max_age_days: u32,
}

#[derive(Debug, Serialize)]
pub struct SnapshotDetailResponse {
    pub snapshot: SnapshotSummary,
    pub files: Vec<SnapshotFileEntry>,
}

#[derive(Debug, Serialize)]
pub struct CreateSnapshotResponse {
    pub created: bool,
    pub snapshot: SnapshotSummary,
}

#[derive(Debug, Serialize)]
pub struct RestoreSnapshotResponse {
    pub restored: bool,
    pub snapshot_id: u64,
    pub vault_id: String,
    pub files_restored: u32,
    pub files_skipped: u32,
    pub files_failed: u32,
    pub message: String,
}

fn summary_from_row(row: VaultSnapshotRow) -> SnapshotSummary {
    SnapshotSummary {
        id: row.id,
        vault_id: row.vault_id,
        label: row.label,
        file_count: row.file_count,
        bytes_total: row.bytes_total,
        created_at: row.created_at,
        created_by: row.created_by,
    }
}

fn file_entry(row: &VaultSnapshotFileRow, state: &AuthHttpState) -> SnapshotFileEntry {
    SnapshotFileEntry {
        path: row.path.clone(),
        version_id: row.version_id,
        content_hash_hex: hex::encode(row.content_hash),
        size: row.size,
        deleted: row.deleted,
        blob_available: state.version_blobs.contains(&row.content_hash),
    }
}

pub async fn create_snapshot(
    State(state): State<std::sync::Arc<AuthHttpState>>,
    headers: HeaderMap,
    Json(body): Json<CreateSnapshotRequest>,
) -> impl IntoResponse {
    match create_snapshot_inner(&state, &headers, body).await {
        Ok(resp) => (StatusCode::CREATED, Json(resp)).into_response(),
        Err((code, msg)) => (code, Json(json!({ "error": msg }))).into_response(),
    }
}

async fn create_snapshot_inner(
    state: &AuthHttpState,
    headers: &HeaderMap,
    body: CreateSnapshotRequest,
) -> Result<CreateSnapshotResponse, (StatusCode, &'static str)> {
    let claims = verify_bearer(state, headers).await?;
    let user = resolve_user_from_access(state, &claims).await?;
    let tenant_key = Some(user.tenant_id.as_str());

    let tier = state
        .meta_db
        .get_plan_tier(tenant_key, PlanTier::Free)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;
    let retention = tier.snapshot_retention();

    let db = state
        .tenant_router
        .tenant_data(tenant_key)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    let label = body
        .label
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let row = db
        .create_vault_snapshot(tenant_key, &body.vault_id, label, &user.id, &retention)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    Ok(CreateSnapshotResponse {
        created: true,
        snapshot: summary_from_row(row),
    })
}

pub async fn list_snapshots(
    State(state): State<std::sync::Arc<AuthHttpState>>,
    headers: HeaderMap,
    Query(query): Query<ListSnapshotsQuery>,
) -> impl IntoResponse {
    match list_snapshots_inner(&state, &headers, query).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err((code, msg)) => (code, Json(json!({ "error": msg }))).into_response(),
    }
}

async fn list_snapshots_inner(
    state: &AuthHttpState,
    headers: &HeaderMap,
    query: ListSnapshotsQuery,
) -> Result<SnapshotListResponse, (StatusCode, &'static str)> {
    let claims = verify_bearer(state, headers).await?;
    let user = resolve_user_from_access(state, &claims).await?;
    let tenant_key = Some(user.tenant_id.as_str());

    let tier = state
        .meta_db
        .get_plan_tier(tenant_key, PlanTier::Free)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;
    let retention = tier.snapshot_retention();

    let db = state
        .tenant_router
        .tenant_data(tenant_key)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    let limit = query.limit.clamp(1, 200);
    let offset = query.offset.min(10_000);
    let total = db
        .count_vault_snapshots(tenant_key, &query.vault_id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;
    let rows = db
        .list_vault_snapshots(tenant_key, &query.vault_id, limit, offset)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    Ok(SnapshotListResponse {
        vault_id: query.vault_id,
        plan_tier: tier.as_str().into(),
        retention: SnapshotRetentionInfo {
            max_snapshots: retention.max_snapshots,
            max_age_secs: retention.max_age_secs,
            max_age_days: (retention.max_age_secs / 86_400).max(1) as u32,
        },
        pagination: SnapshotPagination {
            limit,
            offset,
            total,
            has_more: offset.saturating_add(limit) < total,
        },
        snapshots: rows.into_iter().map(summary_from_row).collect(),
    })
}

pub async fn get_snapshot(
    State(state): State<std::sync::Arc<AuthHttpState>>,
    headers: HeaderMap,
    AxumPath(snapshot_id): AxumPath<u64>,
    Query(query): Query<GetSnapshotQuery>,
) -> impl IntoResponse {
    match get_snapshot_inner(&state, &headers, snapshot_id, query).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err((code, msg)) => (code, Json(json!({ "error": msg }))).into_response(),
    }
}

async fn get_snapshot_inner(
    state: &AuthHttpState,
    headers: &HeaderMap,
    snapshot_id: u64,
    query: GetSnapshotQuery,
) -> Result<SnapshotDetailResponse, (StatusCode, &'static str)> {
    let claims = verify_bearer(state, headers).await?;
    let user = resolve_user_from_access(state, &claims).await?;
    let tenant_key = Some(user.tenant_id.as_str());

    let db = state
        .tenant_router
        .tenant_data(tenant_key)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    let snap = db
        .get_vault_snapshot(tenant_key, &query.vault_id, snapshot_id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?
        .ok_or((StatusCode::NOT_FOUND, "snapshot not found"))?;

    let files = db
        .list_snapshot_files(tenant_key, &query.vault_id, snapshot_id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    Ok(SnapshotDetailResponse {
        snapshot: summary_from_row(snap),
        files: files.iter().map(|f| file_entry(f, state)).collect(),
    })
}

pub async fn restore_snapshot(
    State(state): State<std::sync::Arc<AuthHttpState>>,
    headers: HeaderMap,
    AxumPath(snapshot_id): AxumPath<u64>,
    Json(body): Json<RestoreSnapshotRequest>,
) -> impl IntoResponse {
    match restore_snapshot_inner(&state, &headers, snapshot_id, body).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err((code, msg)) => (code, Json(json!({ "error": msg }))).into_response(),
    }
}

async fn restore_snapshot_inner(
    state: &AuthHttpState,
    headers: &HeaderMap,
    snapshot_id: u64,
    body: RestoreSnapshotRequest,
) -> Result<RestoreSnapshotResponse, (StatusCode, &'static str)> {
    let claims = verify_bearer(state, headers).await?;
    let user = resolve_user_from_access(state, &claims).await?;
    let tenant_key = Some(user.tenant_id.as_str());

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

    let _snap = db
        .get_vault_snapshot(tenant_key, &body.vault_id, snapshot_id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?
        .ok_or((StatusCode::NOT_FOUND, "snapshot not found"))?;

    let files = db
        .list_snapshot_files(tenant_key, &body.vault_id, snapshot_id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    let mut restored = 0u32;
    let mut skipped = 0u32;
    let mut failed = 0u32;

    let ctx = FileVersionUpsert {
        created_by: user.id.clone(),
        retention: version_retention,
    };

    for entry in &files {
        if entry.deleted {
            skipped += 1;
            continue;
        }

        let path = entry.path.as_str();
        if path.is_empty() || path.contains("..") {
            failed += 1;
            continue;
        }

        let bytes = match resolve_blob(state, &db, tenant_key, &body.vault_id, entry).await {
            Some(b) => b,
            None => {
                failed += 1;
                continue;
            }
        };

        let target = match path_guard::validate(Path::new(path), &state.sync_root) {
            Ok(t) => t,
            Err(_) => {
                failed += 1;
                continue;
            }
        };

        if let Some(parent) = target.parent() {
            if std::fs::create_dir_all(parent).is_err() {
                failed += 1;
                continue;
            }
        }

        if target.exists() {
            if let Ok(current_bytes) = std::fs::read(&target) {
                if let Ok(Some(current)) =
                    db.get_file_scoped(tenant_key, &body.vault_id, path).await
                {
                    let _ = state
                        .version_blobs
                        .put(&current.content_hash, &current_bytes);
                }
            }
        }

        if std::fs::write(&target, &bytes).is_err() {
            failed += 1;
            continue;
        }

        let mtime_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);

        let mut vc = VectorClock::new();
        vc.advance("snapshot-restore");

        let meta = FileMeta {
            path: target
                .strip_prefix(&state.sync_root)
                .unwrap_or(&target)
                .to_path_buf(),
            content_hash: entry.content_hash,
            size: entry.size,
            mtime_ns,
            inode: None,
            vector_clock: vc,
            deleted: false,
            deleted_at: None,
            node_id: "snapshot-restore".into(),
            encryption_nonce: None,
            version_id: None,
            parent_version_id: None,
        };

        if db
            .upsert_file_scoped_versioned(tenant_key, &body.vault_id, &meta, &ctx)
            .await
            .is_err()
        {
            failed += 1;
            continue;
        }

        let _ = state.version_blobs.put(&entry.content_hash, &bytes);
        restored += 1;
    }

    let message = format!(
        "Restored snapshot {snapshot_id}: {restored} file(s), {skipped} skipped, {failed} failed"
    );

    Ok(RestoreSnapshotResponse {
        restored: true,
        snapshot_id,
        vault_id: body.vault_id,
        files_restored: restored,
        files_skipped: skipped,
        files_failed: failed,
        message,
    })
}

async fn resolve_blob(
    state: &AuthHttpState,
    db: &disk_core::MetaDb,
    tenant_key: Option<&str>,
    vault_id: &str,
    entry: &VaultSnapshotFileRow,
) -> Option<Vec<u8>> {
    if let Some(bytes) = state.version_blobs.get(&entry.content_hash) {
        return Some(bytes);
    }

    if entry.version_id > 0 {
        if let Ok(Some(version)) = db
            .get_file_version(tenant_key, vault_id, &entry.path, entry.version_id)
            .await
        {
            if let Some(bytes) = state.version_blobs.get(&version.content_hash) {
                return Some(bytes);
            }
        }
    }

    let candidate = state.sync_root.join(&entry.path);
    if let Ok(bytes) = std::fs::read(&candidate) {
        let hash = *blake3::hash(&bytes).as_bytes();
        if hash == entry.content_hash {
            return Some(bytes);
        }
    }

    None
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::health;
    use disk_core::meta_db::MetaDb;
    use disk_core::types::FileMeta;
    use disk_core::vector_clock::VectorClock;
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
    async fn snapshot_create_list_restore_round_trip() {
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

        let v1_bytes = b"snapshot-v1";
        let v1_hash = *blake3::hash(v1_bytes).as_bytes();
        blobs.put(&v1_hash, v1_bytes).unwrap();
        std::fs::write(sync_root.join("doc.md"), v1_bytes).unwrap();

        let meta = FileMeta {
            path: "doc.md".into(),
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
        db.upsert_file_scoped_versioned(Some("corp"), "default", &meta, &ctx)
            .await
            .unwrap();

        let email = disk_core::normalize_email("snap@example.com");
        let hash = disk_core::hash_password("long-password").unwrap();
        db.create_user_account("usr_snap", &email, &hash, "corp")
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

        let create: serde_json::Value = client
            .post(format!("http://127.0.0.1:{port}/snapshots"))
            .bearer_auth(token)
            .json(&serde_json::json!({ "vault_id": "default", "label": "at-v1" }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let snapshot_id = create["snapshot"]["id"].as_u64().unwrap();

        std::fs::write(sync_root.join("doc.md"), b"snapshot-v2-overwrite").unwrap();

        let list: serde_json::Value = client
            .get(format!(
                "http://127.0.0.1:{port}/snapshots?vault_id=default"
            ))
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(list["snapshots"].as_array().unwrap().len(), 1);

        let restore: serde_json::Value = client
            .post(format!(
                "http://127.0.0.1:{port}/snapshots/{snapshot_id}/restore"
            ))
            .bearer_auth(token)
            .json(&serde_json::json!({ "vault_id": "default" }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(restore["files_restored"], 1);

        let on_disk = std::fs::read(sync_root.join("doc.md")).unwrap();
        assert_eq!(on_disk, v1_bytes);
    }
}
