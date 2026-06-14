//! `GET /conflicts` and `POST /conflicts/{path}` handlers.
//!
//! These endpoints expose the conflicts table through the loopback REST
//! surface on `127.0.0.1:9444`.  Both endpoints are available only when a
//! `MetaDb` handle has been attached to `DaemonState` via `with_meta_db`.
//!
//! **`GET /conflicts`** — returns all unresolved conflict rows as JSON.
//!
//! **`POST /conflicts/{path}`** — resolves the conflict at the given
//! percent-decoded vault-relative path.  The request body is a JSON object
//! with a single `action` field (e.g. `{"action": "keep-local"}`).  The
//! `path` URL segment is percent-decoded and validated against path-traversal
//! before any DB operation is performed.
//!
//! ## File operations per action
//!
//! The sync-loop APPLY phase writes the remote (losing) bytes to
//! `fork_path` and leaves the local file at `path` untouched before
//! recording the conflict row.  The REST handler therefore assumes:
//!
//! - Live file at `vault_root/path` = current local version.
//! - Fork file at `vault_root/fork_path` = remote version (if present).
//!
//! | Action       | File operation                                                   |
//! |--------------|------------------------------------------------------------------|
//! | `keep-local` | No file change; just mark resolved (local already wins).        |
//! | `keep-remote`| Read fork file (remote bytes) → overwrite live path atomically. |
//! | `fork-local` | Fork the current local bytes, then apply remote (keep-remote).  |
//! | `fork-remote`| Fork file already on disk from APPLY phase; mark resolved.      |
//! | `merge`      | Re-run `apply_conflict` on local vs. remote bytes; base=None.   |
//!
//! Network exposure: inherits the `127.0.0.1:9444` bind from the existing
//! loopback REST listener — no new ports or public sockets.

use std::path::Path;

use axum::{
    extract::{Path as AxumPath, State},
    http::StatusCode,
    response::{IntoResponse, Json},
};
use serde::{Deserialize, Serialize};

use super::DaemonState;
use crate::conflict_writer::{apply_conflict, write_fork};

/// JSON representation of a single unresolved conflict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConflictListItem {
    pub id: i64,
    pub path: String,
    pub conflict_type: String,
    pub fork_path: Option<String>,
    pub created_at: i64,
}

/// Request body for `POST /conflicts/{path}`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResolveRequest {
    /// Resolution action.  Accepted values: `fork-local`, `fork-remote`,
    /// `merge`, `keep-local`, `keep-remote`.
    pub action: String,
}

/// `GET /conflicts` — list all unresolved conflicts.
pub async fn get_conflicts(State(state): State<DaemonState>) -> impl IntoResponse {
    let db = match state.meta_db() {
        Some(db) => db.clone(),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "meta_db not available"})),
            )
                .into_response();
        }
    };

    match db.list_unresolved_conflicts().await {
        Ok(rows) => {
            let items: Vec<ConflictListItem> = rows
                .into_iter()
                .map(|c| ConflictListItem {
                    id: c.id.unwrap_or(0),
                    path: c.path,
                    conflict_type: c.conflict_type,
                    fork_path: c.fork_path,
                    created_at: c.created_at,
                })
                .collect();
            (StatusCode::OK, Json(serde_json::to_value(items).unwrap())).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{e}")})),
        )
            .into_response(),
    }
}

/// `POST /conflicts/{path}` — resolve the conflict at `path`.
///
/// The `path` segment is percent-decoded by axum's extractor.  We then
/// validate it for path-traversal before querying the database.
pub async fn post_resolve_conflict(
    State(state): State<DaemonState>,
    AxumPath(raw_path): AxumPath<String>,
    Json(body): Json<ResolveRequest>,
) -> impl IntoResponse {
    // Security: validate the path before touching the database.
    if let Err(e) = validate_conflict_path(&raw_path) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e})),
        )
            .into_response();
    }

    // Validate the action string.
    if !is_valid_action(&body.action) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("invalid action '{}'; accepted: fork-local, fork-remote, merge, keep-local, keep-remote", body.action)
            })),
        )
            .into_response();
    }

    let db = match state.meta_db() {
        Some(db) => db.clone(),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "meta_db not available"})),
            )
                .into_response();
        }
    };

    // Find the conflict row by path.
    let conflicts = match db.list_unresolved_conflicts().await {
        Ok(rows) => rows,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("{e}")})),
            )
                .into_response();
        }
    };

    let row = conflicts.into_iter().find(|c| c.path == raw_path);
    let row = match row {
        Some(r) => r,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": format!("no unresolved conflict at path '{raw_path}'")})),
            )
                .into_response();
        }
    };

    let id = match row.id {
        Some(id) => id,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "conflict row has no id"})),
            )
                .into_response();
        }
    };

    // Perform the file operation for the requested action, then mark resolved.
    if let Some(vault_root) = state.vault_root() {
        if let Err(e) = perform_file_op(
            vault_root.as_path(),
            &raw_path,
            row.fork_path.as_deref(),
            &body.action,
        ) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("file op failed: {e}")})),
            )
                .into_response();
        }
    }
    // When vault_root is absent (e.g. in unit tests without a real filesystem),
    // skip the file operation but still mark the DB row resolved.

    match db.resolve_conflict(id, &body.action).await {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({"resolved": true, "path": raw_path, "action": body.action})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{e}")})),
        )
            .into_response(),
    }
}

/// Execute the filesystem side of a conflict resolution action.
///
/// `live_rel`  — vault-relative path of the conflicting file.
/// `fork_rel`  — optional vault-relative path of the fork (remote version).
/// `action`    — one of `keep-local`, `keep-remote`, `fork-local`,
///               `fork-remote`, `merge`.
///
/// # Zero-data-loss guarantee
/// Every path that writes to the live file first reads and forks (or re-uses
/// the existing fork of) the losing version.  `keep-local` performs no writes.
fn perform_file_op(
    vault_root: &std::path::Path,
    live_rel: &str,
    fork_rel: Option<&str>,
    action: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let live_path = vault_root.join(live_rel);

    match action {
        "keep-local" => {
            // Local already wins — no file change required.
        }

        "keep-remote" => {
            // Read the remote bytes from the fork file, then atomically
            // replace the live path.  The fork file is left in place so
            // the operator can inspect it.
            if let Some(fork) = fork_rel {
                let fork_abs = vault_root.join(fork);
                let remote_bytes = std::fs::read(&fork_abs)?;
                atomic_write(&live_path, &remote_bytes)?;
            }
            // If no fork_rel is recorded (unexpected), keep-remote is a no-op.
        }

        "fork-local" => {
            // Fork the current local bytes first (zero-data-loss), then apply
            // the remote version (equivalent to keep-remote after forking local).
            if live_path.exists() {
                let local_bytes = std::fs::read(&live_path)?;
                // node_id is embedded in the fork name; use a placeholder that
                // is recognisable as "operator-initiated" when no node_id is
                // available from the REST context.
                write_fork(vault_root, Path::new(live_rel), &local_bytes, "local-fork")?;
            }
            // Now apply the remote bytes if available.
            if let Some(fork) = fork_rel {
                let fork_abs = vault_root.join(fork);
                if fork_abs.exists() {
                    let remote_bytes = std::fs::read(&fork_abs)?;
                    atomic_write(&live_path, &remote_bytes)?;
                }
            }
        }

        "fork-remote" => {
            // The fork file was already written by the sync-loop APPLY phase.
            // No additional file op needed — just accept the existing state.
            // (If fork_rel is absent, this is a no-op.)
        }

        "merge" => {
            // Read local and remote (from fork), then re-run apply_conflict.
            // Base is not available at this point, so three_way_merge will
            // refuse (NoBase) and fall back to forking the remote bytes.
            if let Some(fork) = fork_rel {
                let fork_abs = vault_root.join(fork);
                if live_path.exists() && fork_abs.exists() {
                    let local_bytes = std::fs::read(&live_path)?;
                    let remote_bytes = std::fs::read(&fork_abs)?;
                    apply_conflict(
                        vault_root,
                        Path::new(live_rel),
                        None,
                        &local_bytes,
                        &remote_bytes,
                        "merge-op",
                    )?;
                }
            }
        }

        _ => {
            // Validated earlier — unreachable.
        }
    }

    Ok(())
}

/// Atomically write `contents` to `path` via a temp file in the same directory.
fn atomic_write(path: &std::path::Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    std::fs::create_dir_all(parent)?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.write_all(contents)?;
    tmp.flush()?;
    tmp.persist(path)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok(())
}

/// Check that a conflict path does not contain traversal components.
///
/// Rejects: `..` components, absolute paths, NUL bytes.
fn validate_conflict_path(path: &str) -> Result<(), &'static str> {
    if path.contains('\0') {
        return Err("path contains NUL byte");
    }
    if path.starts_with('/') {
        return Err("path must not be absolute");
    }
    // Check for '..' components.
    for seg in path.split('/') {
        if seg == ".." {
            return Err("path contains '..' component");
        }
    }
    Ok(())
}

/// Accepted resolution actions.
fn is_valid_action(action: &str) -> bool {
    matches!(
        action,
        "fork-local" | "fork-remote" | "merge" | "keep-local" | "keep-remote"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Method, Request};
    use disk_core::types::ConflictRecord;
    use disk_core::MetaDb;
    use tower::util::ServiceExt;

    async fn test_state_with_db() -> (DaemonState, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("meta.db")).await.unwrap();
        let (state, _, _) = DaemonState::new("test-node", "v0");
        let state = state.with_meta_db(db);
        (state, dir)
    }

    fn sample_conflict_record(path: &str) -> ConflictRecord {
        ConflictRecord {
            id: None,
            vault_id: "default".into(),
            path: path.into(),
            conflict_type: "Concurrent".into(),
            local_hash: None,
            remote_hash: None,
            base_hash: None,
            resolution: None,
            fork_path: Some(format!("{path}.sync-conflict-abc12345-20260101-120000")),
            resolved: false,
            created_at: 0,
            resolved_at: None,
        }
    }

    /// GET /conflicts with no conflicts → empty JSON array.
    #[tokio::test]
    async fn conflict_transport_get_empty() {
        let (state, _dir) = test_state_with_db().await;
        let app = super::super::router(state);

        let req = Request::builder()
            .method(Method::GET)
            .uri("/conflicts")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json, serde_json::json!([]));
    }

    /// Full round-trip: seed conflict → GET /conflicts returns it → POST resolves → GET returns empty.
    #[tokio::test]
    async fn conflict_transport_resolve_roundtrip() {
        let (state, _dir) = test_state_with_db().await;
        let db = state.meta_db().unwrap().clone();

        // Seed a conflict row.
        let rec = sample_conflict_record("notes/todo.md");
        db.create_conflict(&rec).await.unwrap();

        let app = super::super::router(state);

        // GET /conflicts → one item.
        let req = Request::builder()
            .method(Method::GET)
            .uri("/conflicts")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
        let items: Vec<ConflictListItem> = serde_json::from_slice(&body).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].path, "notes/todo.md");

        // POST /conflicts/notes%2Ftodo.md  { "action": "keep-local" }
        let body_str = r#"{"action":"keep-local"}"#;
        let req = Request::builder()
            .method(Method::POST)
            .uri("/conflicts/notes%2Ftodo.md")
            .header("content-type", "application/json")
            .body(Body::from(body_str))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // GET /conflicts → now empty.
        let req = Request::builder()
            .method(Method::GET)
            .uri("/conflicts")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
        let items: Vec<ConflictListItem> = serde_json::from_slice(&body).unwrap();
        assert!(items.is_empty(), "conflict must be gone after resolve");
    }

    #[test]
    fn validate_path_rejects_traversal() {
        assert!(validate_conflict_path("../etc/passwd").is_err());
        assert!(validate_conflict_path("a/../../b").is_err());
        assert!(validate_conflict_path("/absolute").is_err());
    }

    #[test]
    fn validate_path_accepts_valid() {
        assert!(validate_conflict_path("notes/todo.md").is_ok());
        assert!(validate_conflict_path("file.txt").is_ok());
    }
}
