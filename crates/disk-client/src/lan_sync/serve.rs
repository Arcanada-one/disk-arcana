//! LAN blob HTTP server — serve local vault bytes to enrolled peers (DISK-0027 slice 2).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use disk_core::validate_path;
use serde::Deserialize;
use tokio::net::TcpListener;
use tracing::{debug, warn};

use super::fetch::{HEADER_DISK_CONTENT_HASH, HEADER_DISK_NODE_ID, HEADER_DISK_TENANT};

#[derive(Debug, Clone)]
pub struct LanServeState {
    pub share_roots: HashMap<String, PathBuf>,
    pub tenant_id: Option<String>,
    pub self_node_id: String,
}

#[derive(Debug, Deserialize)]
struct BlobQuery {
    share: String,
    path: String,
}

/// Spawn the LAN data-plane HTTP listener. Fail-soft on bind errors.
pub fn spawn_lan_serve(
    bind_port: u16,
    state: LanServeState,
    shutdown: tokio::sync::oneshot::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = run_lan_serve(bind_port, state, shutdown).await {
            warn!(error = %e, "lan_sync: serve task exited");
        }
    })
}

async fn run_lan_serve(
    bind_port: u16,
    state: LanServeState,
    shutdown: tokio::sync::oneshot::Receiver<()>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = Router::new()
        .route("/lan/v1/blob", get(get_blob))
        .with_state(Arc::new(state));

    let addr = SocketAddr::from(([0, 0, 0, 0], bind_port));
    let listener = TcpListener::bind(addr).await?;
    debug!(%addr, "lan_sync: blob server listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = shutdown.await;
        })
        .await?;

    Ok(())
}

async fn get_blob(
    State(state): State<Arc<LanServeState>>,
    headers: HeaderMap,
    Query(query): Query<BlobQuery>,
) -> Response {
    if let Some(resp) = check_authorize(&state, &headers) {
        return resp;
    }

    let Some(root) = state.share_roots.get(&query.share) else {
        return (StatusCode::NOT_FOUND, "unknown share").into_response();
    };

    let rel = Path::new(&query.path);
    let canonical = match validate_path(rel, root) {
        Ok(p) => p,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid path").into_response(),
    };

    let bytes = match tokio::fs::read(&canonical).await {
        Ok(b) => b,
        Err(_) => return (StatusCode::NOT_FOUND, "file not found").into_response(),
    };

    let hash_hex = hex::encode(blake3::hash(&bytes).as_bytes());
    let mut resp = bytes.into_response();
    if let Ok(val) = hash_hex.parse() {
        resp.headers_mut().insert(HEADER_DISK_CONTENT_HASH, val);
    }
    resp
}

fn check_authorize(state: &LanServeState, headers: &HeaderMap) -> Option<Response> {
    let requester = headers
        .get(HEADER_DISK_NODE_ID)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if requester.is_empty() {
        return Some((StatusCode::UNAUTHORIZED, "missing x-disk-node-id").into_response());
    }
    if requester == state.self_node_id {
        return Some((StatusCode::FORBIDDEN, "self-fetch not allowed").into_response());
    }

    let req_tenant = headers
        .get(HEADER_DISK_TENANT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    match (
        state.tenant_id.as_deref().filter(|t| !t.is_empty()),
        (!req_tenant.is_empty()).then_some(req_tenant),
    ) {
        (Some(local), Some(remote)) if local == remote => None,
        (None, None) | (None, Some("")) => None,
        (Some(_), None) | (Some(_), Some("")) => {
            Some((StatusCode::FORBIDDEN, "tenant required").into_response())
        }
        _ => Some((StatusCode::FORBIDDEN, "tenant mismatch").into_response()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[tokio::test]
    async fn serve_blob_returns_bytes_and_hash() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("notes").join("a.md");
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, b"hello lan").unwrap();

        let mut roots = HashMap::new();
        roots.insert("vault".into(), dir.path().to_path_buf());
        let state = Arc::new(LanServeState {
            share_roots: roots,
            tenant_id: Some("corp".into()),
            self_node_id: "host-a".into(),
        });

        let app = Router::new()
            .route("/lan/v1/blob", get(get_blob))
            .with_state(state);

        let req = Request::builder()
            .uri("/lan/v1/blob?share=vault&path=notes/a.md")
            .header(HEADER_DISK_TENANT, "corp")
            .header(HEADER_DISK_NODE_ID, "host-b")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let hash_hdr = resp
            .headers()
            .get(HEADER_DISK_CONTENT_HASH)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(hash_hdr, hex::encode(blake3::hash(b"hello lan").as_bytes()));
    }

    #[tokio::test]
    async fn serve_rejects_tenant_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let mut roots = HashMap::new();
        roots.insert("vault".into(), dir.path().to_path_buf());
        let state = Arc::new(LanServeState {
            share_roots: roots,
            tenant_id: Some("corp".into()),
            self_node_id: "host-a".into(),
        });

        let app = Router::new()
            .route("/lan/v1/blob", get(get_blob))
            .with_state(state);

        let req = Request::builder()
            .uri("/lan/v1/blob?share=vault&path=x")
            .header(HEADER_DISK_TENANT, "other")
            .header(HEADER_DISK_NODE_ID, "host-b")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
