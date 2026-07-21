//! LAN-preferred delta fetch — try enrolled peers before cloud (DISK-0027 slice 2).

use std::sync::Arc;
use std::time::Duration;

use tracing::debug;

use super::registry::{LanPeer, LanPeerRegistry};

/// Default per-peer HTTP timeout for LAN blob fetch.
pub const LAN_FETCH_TIMEOUT: Duration = Duration::from_secs(3);

pub const HEADER_DISK_TENANT: &str = "x-disk-tenant";
pub const HEADER_DISK_NODE_ID: &str = "x-disk-node-id";
pub const HEADER_DISK_CONTENT_HASH: &str = "x-disk-content-hash";

/// Context wired into [`crate::sync_loop::RemoteSync`] when `[lan_sync]` is on.
#[derive(Debug, Clone)]
pub struct LanFetchContext {
    pub registry: Arc<LanPeerRegistry>,
    pub tenant_id: Option<String>,
    pub node_id: String,
}

impl LanFetchContext {
    pub fn new(
        registry: Arc<LanPeerRegistry>,
        tenant_id: Option<String>,
        node_id: impl Into<String>,
    ) -> Self {
        Self {
            registry,
            tenant_id,
            node_id: node_id.into(),
        }
    }
}

/// Return live peers that share the local tenant (enrolled fleet on the LAN).
pub fn eligible_peers(peers: &[LanPeer], local_tenant_id: Option<&str>) -> Vec<LanPeer> {
    let local = local_tenant_id.filter(|t| !t.is_empty());
    peers
        .iter()
        .filter(|p| {
            let peer_tenant = p.tenant_id.as_deref().filter(|t| !t.is_empty());
            match (local, peer_tenant) {
                (Some(a), Some(b)) => a == b,
                (None, None) => true,
                _ => false,
            }
        })
        .cloned()
        .collect()
}

/// Try each eligible peer in order; return bytes on first successful verified fetch.
pub async fn try_lan_fetch(
    ctx: &LanFetchContext,
    share: &str,
    path: &str,
    expected_hash: Option<&[u8; 32]>,
) -> Option<Vec<u8>> {
    if !ctx.registry.is_enabled() {
        return None;
    }

    let peers = ctx.registry.snapshot(super::PEER_TTL_SECS).await;
    let candidates = eligible_peers(&peers, ctx.tenant_id.as_deref());
    if candidates.is_empty() {
        return None;
    }

    let client = reqwest::Client::builder()
        .timeout(LAN_FETCH_TIMEOUT)
        .build()
        .ok()?;

    let tenant_hdr = ctx.tenant_id.as_deref().unwrap_or("");

    for peer in candidates {
        match fetch_blob_from_peer(
            &client,
            &peer,
            share,
            path,
            tenant_hdr,
            &ctx.node_id,
            expected_hash,
        )
        .await
        {
            Ok(bytes) => {
                debug!(
                    peer = %peer.node_id,
                    share,
                    path,
                    bytes = bytes.len(),
                    "lan_sync: fetch hit"
                );
                return Some(bytes);
            }
            Err(e) => {
                debug!(
                    peer = %peer.node_id,
                    share,
                    path,
                    error = %e,
                    "lan_sync: fetch miss; trying next peer"
                );
            }
        }
    }
    None
}

async fn fetch_blob_from_peer(
    client: &reqwest::Client,
    peer: &LanPeer,
    share: &str,
    path: &str,
    tenant_id: &str,
    requester_node_id: &str,
    expected_hash: Option<&[u8; 32]>,
) -> Result<Vec<u8>, FetchError> {
    let url = format!("http://{}:{}/lan/v1/blob", peer.host, peer.port);
    let resp = client
        .get(&url)
        .query(&[("share", share), ("path", path)])
        .header(HEADER_DISK_TENANT, tenant_id)
        .header(HEADER_DISK_NODE_ID, requester_node_id)
        .send()
        .await
        .map_err(|e| FetchError::Transport(e.to_string()))?;

    if !resp.status().is_success() {
        return Err(FetchError::Http(resp.status().as_u16()));
    }

    let hash_hdr = resp
        .headers()
        .get(HEADER_DISK_CONTENT_HASH)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| FetchError::Transport(e.to_string()))?
        .to_vec();

    let computed: [u8; 32] = *blake3::hash(&bytes).as_bytes();

    if let Some(expected) = expected_hash {
        if &computed != expected {
            return Err(FetchError::HashMismatch);
        }
    } else if let Some(hdr_str) = hash_hdr {
        if let Ok(decoded) = hex::decode(hdr_str.trim()) {
            if decoded.len() == 32 {
                let hdr_hash: [u8; 32] = decoded.try_into().unwrap();
                if hdr_hash != computed {
                    return Err(FetchError::HashMismatch);
                }
            }
        }
    }

    Ok(bytes)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchError {
    Transport(String),
    Http(u16),
    HashMismatch,
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::Transport(m) => write!(f, "transport: {m}"),
            FetchError::Http(c) => write!(f, "http {c}"),
            FetchError::HashMismatch => write!(f, "content hash mismatch"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lan_sync::unix_now;

    fn peer(id: &str, tenant: Option<&str>) -> LanPeer {
        LanPeer {
            node_id: id.into(),
            host: "10.0.0.2".into(),
            port: 9447,
            tenant_id: tenant.map(str::to_string),
            last_seen_unix: unix_now(),
        }
    }

    #[test]
    fn eligible_peers_requires_matching_tenant() {
        let peers = vec![
            peer("a", Some("corp")),
            peer("b", Some("other")),
            peer("c", None),
        ];
        let out = eligible_peers(&peers, Some("corp"));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].node_id, "a");
    }

    #[test]
    fn eligible_peers_both_absent_tenant_matches() {
        let peers = vec![peer("a", None), peer("b", Some("x"))];
        let out = eligible_peers(&peers, None);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].node_id, "a");
    }
}
