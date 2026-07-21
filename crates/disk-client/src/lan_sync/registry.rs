//! LAN peer registry — in-memory store updated by mDNS discovery (DISK-0027).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::RwLock;

/// A Disk Arcana client seen on the local network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanPeer {
    pub node_id: String,
    pub host: String,
    pub port: u16,
    pub tenant_id: Option<String>,
    pub last_seen_unix: i64,
}

/// Thread-safe peer table shared by the mDNS task and loopback REST API.
#[derive(Debug)]
pub struct LanPeerRegistry {
    enabled: AtomicBool,
    self_node_id: String,
    peers: RwLock<HashMap<String, LanPeer>>,
}

impl LanPeerRegistry {
    pub fn new(enabled: bool, self_node_id: impl Into<String>) -> Arc<Self> {
        Arc::new(Self {
            enabled: AtomicBool::new(enabled),
            self_node_id: self_node_id.into(),
            peers: RwLock::new(HashMap::new()),
        })
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn self_node_id(&self) -> &str {
        &self.self_node_id
    }

    pub async fn upsert(&self, peer: LanPeer) {
        if peer.node_id == self.self_node_id {
            return;
        }
        self.peers.write().await.insert(peer.node_id.clone(), peer);
    }

    pub async fn snapshot(&self, max_age_secs: i64) -> Vec<LanPeer> {
        let now = unix_now();
        let mut peers = self.peers.write().await;
        peers.retain(|_, p| now.saturating_sub(p.last_seen_unix) <= max_age_secs);
        let mut out: Vec<LanPeer> = peers.values().cloned().collect();
        out.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        out
    }

    pub async fn clear(&self) {
        self.peers.write().await.clear();
    }
}

pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn registry_ignores_self_and_prunes_stale() {
        let reg = LanPeerRegistry::new(true, "mac-a");
        reg.upsert(LanPeer {
            node_id: "mac-a".into(),
            host: "127.0.0.1".into(),
            port: 9447,
            tenant_id: None,
            last_seen_unix: unix_now(),
        })
        .await;
        reg.upsert(LanPeer {
            node_id: "mac-b".into(),
            host: "192.168.1.2".into(),
            port: 9447,
            tenant_id: Some("corp".into()),
            last_seen_unix: unix_now() - 10,
        })
        .await;
        reg.upsert(LanPeer {
            node_id: "mac-c".into(),
            host: "192.168.1.3".into(),
            port: 9447,
            tenant_id: None,
            last_seen_unix: unix_now() - 500,
        })
        .await;

        let live = reg.snapshot(120).await;
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].node_id, "mac-b");
    }
}
