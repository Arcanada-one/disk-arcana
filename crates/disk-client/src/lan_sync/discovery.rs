//! mDNS advertise + browse for LAN peer discovery (DISK-0027 slice 1).

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use tokio::sync::mpsc;
use tracing::{debug, warn};

use super::registry::{unix_now, LanPeer, LanPeerRegistry};

pub const SERVICE_TYPE: &str = "_disk-arcana._udp.local.";
pub const PEER_TTL_SECS: i64 = 120;

/// Spawn a background task that advertises this node and merges discovered peers.
///
/// Fail-soft: logs warnings and returns immediately when mDNS is unavailable.
pub fn spawn_lan_discovery(
    registry: Arc<LanPeerRegistry>,
    node_id: String,
    tenant_id: Option<String>,
    advertise_port: u16,
    grpc_port: u16,
    shutdown: tokio::sync::oneshot::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = run_lan_discovery(
            registry,
            node_id,
            tenant_id,
            advertise_port,
            grpc_port,
            shutdown,
        )
        .await
        {
            warn!(error = %e, "lan_sync: discovery task exited");
        }
    })
}

async fn run_lan_discovery(
    registry: Arc<LanPeerRegistry>,
    node_id: String,
    tenant_id: Option<String>,
    advertise_port: u16,
    grpc_port: u16,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !registry.is_enabled() {
        return Ok(());
    }

    let mdns = ServiceDaemon::new()?;
    let hostname = format!("{node_id}.local.");
    let grpc_port_str = grpc_port.to_string();
    let mut properties = vec![
        ("node_id", node_id.as_str()),
        ("grpc_port", grpc_port_str.as_str()),
    ];
    if let Some(tenant) = tenant_id.as_deref() {
        properties.push(("tenant_id", tenant));
    }

    let local_ip = local_ipv4().unwrap_or(Ipv4Addr::new(127, 0, 0, 1));
    let service_info = ServiceInfo::new(
        SERVICE_TYPE,
        &node_id,
        &hostname,
        IpAddr::V4(local_ip),
        advertise_port,
        &properties[..],
    )?;
    mdns.register(service_info)?;

    let receiver = mdns.browse(SERVICE_TYPE)?;
    let (peer_tx, mut peer_rx) = mpsc::channel::<LanPeer>(64);
    tokio::task::spawn_blocking(move || {
        while let Ok(event) = receiver.recv_timeout(Duration::from_secs(1)) {
            if let ServiceEvent::ServiceResolved(info) = event {
                if let Some(peer) = peer_from_service(&info) {
                    let _ = peer_tx.blocking_send(peer);
                }
            }
        }
    });

    debug!(
        node_id = %node_id,
        port = advertise_port,
        "lan_sync: mDNS advertise + browse started"
    );

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                let _ = mdns.shutdown();
                registry.clear().await;
                break;
            }
            peer = peer_rx.recv() => {
                if let Some(peer) = peer {
                    registry.upsert(peer).await;
                }
            }
        }
    }
    Ok(())
}

fn peer_from_service(info: &ServiceInfo) -> Option<LanPeer> {
    let props = info.get_properties();
    let node_id = props.get("node_id")?.val_str().to_string();
    let host = info
        .get_addresses()
        .iter()
        .find_map(|ip| match ip {
            IpAddr::V4(v4) if !v4.is_loopback() => Some(v4.to_string()),
            _ => None,
        })
        .or_else(|| info.get_hostname().strip_suffix('.').map(str::to_string))?;
    let port = info.get_port();
    let tenant_id = props
        .get("tenant_id")
        .map(|p| p.val_str().to_string())
        .filter(|s| !s.is_empty());
    Some(LanPeer {
        node_id,
        host,
        port,
        tenant_id,
        last_seen_unix: unix_now(),
    })
}

fn local_ipv4() -> Option<Ipv4Addr> {
    if_addrs::get_if_addrs()
        .ok()?
        .into_iter()
        .filter(|iface| !iface.is_loopback() && iface.addr.ip().is_ipv4())
        .find_map(|iface| match iface.addr.ip() {
            IpAddr::V4(v4) => Some(v4),
            _ => None,
        })
}

/// Parse the port from `host:port` server address.
pub fn parse_server_port(address: &str) -> u16 {
    address
        .rsplit(':')
        .next()
        .and_then(|p| p.parse().ok())
        .unwrap_or(9443)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_from_service_reads_txt() {
        let props = [
            ("node_id", "laptop-1"),
            ("grpc_port", "9443"),
            ("tenant_id", "corp"),
        ];
        let info = ServiceInfo::new(
            SERVICE_TYPE,
            "laptop-1",
            "laptop-1.local.",
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            9447,
            &props[..],
        )
        .unwrap();
        let peer = peer_from_service(&info).unwrap();
        assert_eq!(peer.node_id, "laptop-1");
        assert_eq!(peer.host, "192.168.1.10");
        assert_eq!(peer.tenant_id.as_deref(), Some("corp"));
    }

    #[test]
    fn parse_server_port_reads_trailing_port() {
        assert_eq!(parse_server_port("disk.example:9443"), 9443);
        assert_eq!(parse_server_port("65.108.236.39:9443"), 9443);
    }
}
