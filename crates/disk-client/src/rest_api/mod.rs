//! DISK-0006 R7 — loopback REST surface on `127.0.0.1:9444`.
//!
//! Consumers: Obsidian plugin + `disk status` / `disk sync` / `disk config
//! reload` CLI subcommands on the **same host**. Tier 1 (loopback-only)
//! per the Network Exposure Baseline in PRD-DISK-0001 §4.13 — the bind
//! address is hard-coded to [`LOOPBACK_BIND_PREFIX`] (a `127.0.0.0/8`
//! check); attempts to construct with any other host return
//! [`RestApiError::NonLoopbackBind`] and the daemon refuses to start.
//!
//! Endpoint surface (plan §REST :9444):
//! - `GET /status`         — snapshot of daemon + shares (§4.12.4 schema)
//! - `POST /sync`          — one-shot trigger of the sync loop
//! - `POST /config/reload` — request hot reload of `disk.toml`
//!
//! The REST handler is intentionally a thin observer over a shared
//! [`DaemonState`] — it does not own the loop, does not own the watcher,
//! and does not own the config file. R7 ships the surface; R9 wires the
//! reload signal into the live `notify` watcher, R8 wires the manual
//! trigger into the running loop iteration scheduler.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{mpsc, RwLock};

use crate::config::schema::Direction;
use crate::sync_loop::LoopState;

pub mod status;
pub mod sync;

pub use status::{StatusResponse, StatusShare};

/// All bind addresses MUST match `127.0.0.0/8` (loopback). The daemon
/// is hard-pinned to this CIDR; remote consumers go through the Obsidian
/// plugin running on the same host or via Tailscale + a sidecar of the
/// operator's choice.
pub const LOOPBACK_BIND_PREFIX: [u8; 1] = [127u8];

/// Default port — `9444` per PRD §4.12.4.
pub const DEFAULT_PORT: u16 = 9444;

#[derive(Debug, Error)]
pub enum RestApiError {
    #[error("REST listener bind address {0} is not on the loopback interface (127.0.0.0/8)")]
    NonLoopbackBind(IpAddr),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Snapshot the REST layer surfaces in `GET /status` per share.
#[derive(Debug, Clone)]
pub struct ShareSnapshot {
    pub name: String,
    pub path: String,
    pub declared_direction: Direction,
    pub server_confirmed_role: Option<Direction>,
    pub state: LoopState,
    /// Unix seconds since epoch (UTC). Rendered as ISO-8601.
    pub last_success_at: Option<i64>,
    pub last_error: Option<String>,
    pub bytes_sent_session: u64,
    pub bytes_received_session: u64,
    pub pending_local_changes: u64,
}

/// Shared state the REST router reads. Cheaply cloneable (`Arc` inside).
#[derive(Clone)]
pub struct DaemonState {
    inner: Arc<DaemonStateInner>,
}

struct DaemonStateInner {
    node_id: String,
    config_version: RwLock<String>,
    started_at: Instant,
    shares: RwLock<Vec<ShareSnapshot>>,
    manual_sync_tx: mpsc::Sender<()>,
    reload_tx: mpsc::Sender<()>,
}

impl DaemonState {
    /// Build state + receivers. The caller owns the receiver ends and is
    /// expected to drive them from the daemon's loop scheduler / config
    /// watcher; in R7 they are observable signals only.
    pub fn new(
        node_id: impl Into<String>,
        config_version: impl Into<String>,
    ) -> (Self, mpsc::Receiver<()>, mpsc::Receiver<()>) {
        let (manual_tx, manual_rx) = mpsc::channel::<()>(8);
        let (reload_tx, reload_rx) = mpsc::channel::<()>(8);
        let inner = DaemonStateInner {
            node_id: node_id.into(),
            config_version: RwLock::new(config_version.into()),
            started_at: Instant::now(),
            shares: RwLock::new(Vec::new()),
            manual_sync_tx: manual_tx,
            reload_tx,
        };
        (
            Self {
                inner: Arc::new(inner),
            },
            manual_rx,
            reload_rx,
        )
    }

    pub fn node_id(&self) -> &str {
        &self.inner.node_id
    }

    pub fn daemon_uptime_secs(&self) -> u64 {
        self.inner.started_at.elapsed().as_secs()
    }

    pub async fn config_version(&self) -> String {
        self.inner.config_version.read().await.clone()
    }

    pub async fn set_config_version(&self, v: impl Into<String>) {
        *self.inner.config_version.write().await = v.into();
    }

    pub async fn set_shares(&self, shares: Vec<ShareSnapshot>) {
        *self.inner.shares.write().await = shares;
    }

    pub async fn snapshot_shares(&self) -> Vec<ShareSnapshot> {
        self.inner.shares.read().await.clone()
    }

    pub(crate) fn manual_sync_sender(&self) -> mpsc::Sender<()> {
        self.inner.manual_sync_tx.clone()
    }

    pub(crate) fn reload_sender(&self) -> mpsc::Sender<()> {
        self.inner.reload_tx.clone()
    }
}

/// Endpoint envelope returned by `POST /sync` and `POST /config/reload`.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AcceptedResponse {
    pub queued: bool,
}

/// Build the axum router. Pure function — useful for in-process testing
/// (no listener bind required).
pub fn router(state: DaemonState) -> Router {
    Router::new()
        .route("/status", get(status::get_status))
        .route("/sync", post(sync::post_sync))
        .route("/config/reload", post(sync::post_config_reload))
        .with_state(state)
}

/// Validate that `addr` lives on the loopback interface.
pub fn assert_loopback_bind(addr: SocketAddr) -> Result<(), RestApiError> {
    let ip = addr.ip();
    let ok = match ip {
        IpAddr::V4(v4) => v4.octets()[0] == LOOPBACK_BIND_PREFIX[0],
        IpAddr::V6(v6) => v6.is_loopback(),
    };
    if !ok {
        return Err(RestApiError::NonLoopbackBind(ip));
    }
    Ok(())
}

/// Bind a loopback listener and serve the router until `shutdown`
/// resolves. Returns the actual bound address so callers can recover
/// the OS-assigned port when `addr.port() == 0`.
///
/// Readiness guarantee: this function returns only after the spawned
/// accept task has been polled and has reached the point immediately
/// before the blocking `axum::serve` await.  Any caller that prints
/// a "listening on …" announcement after this call can be sure that
/// incoming connections will be accepted — the OS socket has been in
/// LISTEN state since the `TcpListener::bind` call above, and the
/// accept loop is now live.
pub async fn serve(
    state: DaemonState,
    addr: SocketAddr,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<SocketAddr, RestApiError> {
    assert_loopback_bind(addr)?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    let app = router(state);
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        // Signal readiness before entering the accept loop.  The OS
        // socket is already in LISTEN state (bind completed above), so
        // once this send completes the caller can safely announce the
        // address and expect connects to succeed.
        let _ = ready_tx.send(());
        // axum::serve's error type is documented as `std::convert::Infallible`
        // when feeding a TcpListener — the unwrap below cannot panic.
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown)
            .await
            .expect("axum::serve");
    });
    // Wait until the spawned task has been polled and has sent the
    // ready signal.  The recv() resolves as soon as the task runs its
    // first poll, which is sufficient to guarantee the accept loop is
    // entered on the very next poll of axum::serve.
    let _ = ready_rx.await;
    Ok(local)
}

/// Map a `LoopState` to the `state` string the §4.12.4 schema requires.
pub fn loop_state_to_schema(state: LoopState) -> &'static str {
    match state {
        LoopState::Idle => "idle",
        LoopState::Syncing => "syncing",
        LoopState::Backoff => "unknown_share",
        LoopState::AclMismatch => "acl_mismatch",
        LoopState::ServerUnreachable => "server_unreachable",
        LoopState::Error => "error",
    }
}

/// Map a `Direction` enum to its schema string ("publisher" / "send_only" / ...).
pub fn direction_to_schema(dir: Direction) -> &'static str {
    match dir {
        Direction::ReceiveOnly => "receive_only",
        Direction::SendOnly => "send_only",
        Direction::Bidirectional => "bidirectional",
        Direction::Publisher => "publisher",
    }
}

/// Helper: render a `unix_seconds` timestamp as RFC 3339 / ISO-8601 in
/// UTC (`2026-05-23T18:00:00Z`).
pub fn format_iso8601(unix_seconds: i64) -> String {
    let odt = time::OffsetDateTime::from_unix_timestamp(unix_seconds)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    odt.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

#[allow(dead_code)]
async fn handler_not_found() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, "endpoint not found")
}

#[allow(dead_code)]
async fn ping(State(_state): State<DaemonState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn loopback_v4_accepted() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
        assert!(assert_loopback_bind(addr).is_ok());
    }

    #[test]
    fn loopback_v4_127_x_accepted() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 1, 2, 3)), 0);
        assert!(assert_loopback_bind(addr).is_ok());
    }

    #[test]
    fn non_loopback_v4_rejected() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 9444);
        assert!(matches!(
            assert_loopback_bind(addr),
            Err(RestApiError::NonLoopbackBind(_))
        ));
    }

    #[test]
    fn external_v4_rejected() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)), 9444);
        assert!(matches!(
            assert_loopback_bind(addr),
            Err(RestApiError::NonLoopbackBind(_))
        ));
    }

    #[test]
    fn loopback_v6_accepted() {
        let addr: SocketAddr = "[::1]:0".parse().unwrap();
        assert!(assert_loopback_bind(addr).is_ok());
    }

    #[test]
    fn iso8601_format_round_trip() {
        // 1700000000 = 2023-11-14T22:13:20Z
        assert_eq!(format_iso8601(1_700_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn loop_state_mapping_is_total() {
        for &state in &[
            LoopState::Idle,
            LoopState::Syncing,
            LoopState::Backoff,
            LoopState::AclMismatch,
            LoopState::ServerUnreachable,
            LoopState::Error,
        ] {
            let s = loop_state_to_schema(state);
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn direction_mapping_is_total() {
        for &d in &[
            Direction::ReceiveOnly,
            Direction::SendOnly,
            Direction::Bidirectional,
            Direction::Publisher,
        ] {
            let s = direction_to_schema(d);
            assert!(!s.is_empty());
        }
    }
}
