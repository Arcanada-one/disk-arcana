//! `GET /embeddings/status` — last post-sync sidecar sweep (DISK-0029 slice 2).

use axum::{extract::State, response::Json};
use serde::Serialize;

use crate::embeddings_sweep::EmbeddingsStatusSnapshot;

use super::DaemonState;

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct EmbeddingsStatusResponse {
    pub enabled: bool,
    pub shares: Vec<EmbeddingsStatusSnapshot>,
}

pub async fn get_embeddings_status(
    State(state): State<DaemonState>,
) -> Json<EmbeddingsStatusResponse> {
    let (enabled, shares) = state.embeddings_status().await;
    Json(EmbeddingsStatusResponse { enabled, shares })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_serializes_enabled_flag() {
        let body = EmbeddingsStatusResponse {
            enabled: true,
            shares: vec![EmbeddingsStatusSnapshot {
                share: "wiki".into(),
                enabled: true,
                fresh: 1,
                stale: 0,
                missing: 2,
                co_storage_files: 3,
                swept_at_unix: 42,
            }],
        };
        let json = serde_json::to_value(body).unwrap();
        assert_eq!(json["enabled"], true);
        assert_eq!(json["shares"][0]["share"], "wiki");
    }
}
