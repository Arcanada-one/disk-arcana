//! LAN sync — mDNS discovery + LAN-preferred fetch (DISK-0027).

mod discovery;
mod fetch;
mod registry;
mod serve;

pub use discovery::{parse_server_port, spawn_lan_discovery, PEER_TTL_SECS, SERVICE_TYPE};
pub use fetch::{
    eligible_peers, try_lan_fetch, LanFetchContext, HEADER_DISK_CONTENT_HASH, HEADER_DISK_NODE_ID,
    HEADER_DISK_TENANT, LAN_FETCH_TIMEOUT,
};
pub use registry::{unix_now, LanPeer, LanPeerRegistry};
pub use serve::{spawn_lan_serve, LanServeState};
