//! `GET /lan/peers` — LAN discovery snapshot (DISK-0027 slice 1).

use axum::{extract::State, response::Json};
use serde::Serialize;

use crate::lan_sync::{LanPeer, PEER_TTL_SECS};

use super::DaemonState;

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct LanPeerResponse {
    pub node_id: String,
    pub host: String,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    pub last_seen_unix: i64,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct LanPeersResponse {
    pub enabled: bool,
    pub peers: Vec<LanPeerResponse>,
}

pub async fn get_lan_peers(State(state): State<DaemonState>) -> Json<LanPeersResponse> {
    let registry = state.lan_peers();
    if let Some(reg) = registry {
        let peers = reg.snapshot(PEER_TTL_SECS).await;
        Json(LanPeersResponse {
            enabled: reg.is_enabled(),
            peers: peers.into_iter().map(peer_to_response).collect(),
        })
    } else {
        Json(LanPeersResponse {
            enabled: false,
            peers: vec![],
        })
    }
}

fn peer_to_response(peer: LanPeer) -> LanPeerResponse {
    LanPeerResponse {
        node_id: peer.node_id,
        host: peer.host,
        port: peer.port,
        tenant_id: peer.tenant_id,
        last_seen_unix: peer.last_seen_unix,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_response_serializes_tenant() {
        let body = peer_to_response(LanPeer {
            node_id: "a".into(),
            host: "10.0.0.2".into(),
            port: 9447,
            tenant_id: Some("corp".into()),
            last_seen_unix: 1,
        });
        let json = serde_json::to_value(body).unwrap();
        assert_eq!(json["tenant_id"], "corp");
    }
}
