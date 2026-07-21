//! LAN sync — mDNS peer discovery (DISK-0027).

mod discovery;
mod registry;

pub use discovery::{parse_server_port, spawn_lan_discovery, PEER_TTL_SECS, SERVICE_TYPE};
pub use registry::{unix_now, LanPeer, LanPeerRegistry};
