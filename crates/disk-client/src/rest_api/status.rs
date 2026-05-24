//! `GET /status` handler + JSON DTO.
//!
//! Schema is locked by PRD-DISK-0001 §4.12.4 (see [`plan §Status endpoint
//! contract`]). Fields are whitelisted — adding a new field is a public
//! surface change and must update the §4.12.4 fixture together with
//! `it_status_schema.rs`.

use axum::{extract::State, response::Json};
use serde::{Deserialize, Serialize};

use super::{direction_to_schema, format_iso8601, loop_state_to_schema, DaemonState};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct StatusResponse {
    pub node: String,
    pub daemon_uptime_s: u64,
    pub config_version: String,
    pub shares: Vec<StatusShare>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct StatusShare {
    pub name: String,
    pub path: String,
    pub declared_direction: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_confirmed_role: Option<String>,
    pub state: String,
    pub last_success_at: Option<String>,
    pub last_error: Option<String>,
    pub bytes_sent_session: u64,
    pub bytes_received_session: u64,
    pub pending_local_changes: u64,
}

pub async fn get_status(State(state): State<DaemonState>) -> Json<StatusResponse> {
    let shares = state.snapshot_shares().await;
    let rendered: Vec<StatusShare> = shares
        .into_iter()
        .map(|s| StatusShare {
            name: s.name,
            path: s.path,
            declared_direction: direction_to_schema(s.declared_direction).to_string(),
            server_confirmed_role: s
                .server_confirmed_role
                .map(|d| direction_to_schema(d).to_string()),
            state: loop_state_to_schema(s.state).to_string(),
            last_success_at: s.last_success_at.map(format_iso8601),
            last_error: s.last_error,
            bytes_sent_session: s.bytes_sent_session,
            bytes_received_session: s.bytes_received_session,
            pending_local_changes: s.pending_local_changes,
        })
        .collect();

    Json(StatusResponse {
        node: state.node_id().to_string(),
        daemon_uptime_s: state.daemon_uptime_secs(),
        config_version: state.config_version().await,
        shares: rendered,
    })
}
