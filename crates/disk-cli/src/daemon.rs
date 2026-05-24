//! `disk daemon` — foreground orchestrator (DISK-0006 R11).
//!
//! Plan §All Rounds R11: launchd plist + systemd unit + install scripts.
//! The plist + unit invoke `/usr/local/bin/disk daemon start --foreground`;
//! lifecycle is owned by `launchd` / `systemd` (Restart=on-failure +
//! KeepAlive). The R11 daemon ships a minimal but production-shaped
//! assembly:
//!
//! 1. Load `disk.toml` via `DiskConfig::load` (validates on parse).
//! 2. Build the R7 `DaemonState` from `[node].id` + `[[share]]` rows;
//!    populate `/status` with declared directions per share.
//! 3. Spawn the R9 `ConfigWatcher` and wire its `reload_rx` channel to
//!    `DaemonState::reload_sender()` so `POST :9444/config/reload` shares
//!    one apply path with on-disk edits.
//! 4. Bind the R7 REST listener on `127.0.0.1:9444` (Tier 1 loopback;
//!    overridable via `--status-bind 127.0.0.1:<port>` for IT).
//! 5. Install SIGTERM/SIGINT handlers BEFORE first log line so the
//!    grace-window race fix from R1 server bootstrap is honoured here too.
//!
//! Deferred (per plan §All Rounds + §Hot config reload):
//! - Per-share `SyncLoop::run_iteration` scheduler — R6 wired the transport
//!   adapter; R11 hosts the state machine surface but does NOT yet drive
//!   iterations. `DaemonState::manual_sync_sender` channel is observable
//!   via `POST /sync` but consumer wiring lands separately (R12 runbooks
//!   or future polish).
//! - Background mode (`disk daemon start` without `--foreground`) — owned
//!   by launchd / systemd. R11 refuses background flag with a clear hint.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use disk_client::config::{spawn_config_watcher, ConfigWatcher, Direction, DiskConfig};
use disk_client::rest_api::{serve, DaemonState, ShareSnapshot};
use disk_client::sync_loop::LoopState;

/// CLI arguments for `disk daemon start`.
#[derive(clap::Args, Debug)]
pub struct DaemonStartArgs {
    /// Path to `disk.toml`.
    #[arg(long, default_value = "/etc/disk-arcana/disk.toml")]
    pub config: PathBuf,

    /// Bind address for the loopback REST surface (PRD §4.13 Tier 1).
    /// Must live on `127.0.0.0/8` or IPv6 loopback; override only for
    /// integration tests (`127.0.0.1:0` picks an ephemeral port).
    #[arg(long, default_value = "127.0.0.1:9444")]
    pub status_bind: SocketAddr,

    /// Run in the foreground (the only mode R11 supports — launchd /
    /// systemd manages the background lifecycle).
    #[arg(long, default_value_t = false)]
    pub foreground: bool,
}

/// Entry point invoked from `main.rs`. Hosts the daemon for the lifetime
/// of the process.
pub async fn run_start(args: DaemonStartArgs) -> Result<()> {
    if !args.foreground {
        return Err(anyhow!(
            "background mode is not supported in this build — use launchd \
             (deploy/macos/com.arcanada.disk-arcana.plist) or systemd \
             (deploy/linux/disk-arcana.service), or pass --foreground"
        ));
    }

    let cfg = DiskConfig::load(&args.config)
        .with_context(|| format!("load {}", args.config.display()))?;
    let cfg = Arc::new(cfg);
    let node_id = cfg.node.id.clone();
    let config_version = "1.1"; // matches PRD-DISK-0001 schema version.

    let (state, _manual_sync_rx, reload_rx) = DaemonState::new(&node_id, config_version);
    state.set_shares(build_share_snapshots(&cfg)).await;

    let watcher = spawn_config_watcher(args.config.clone(), cfg.clone(), Some(reload_rx), None)
        .with_context(|| "spawn ConfigWatcher")?;

    // Install signal handlers BEFORE binding the REST listener — closes
    // the R1-vintage race window where SIGTERM arrives between «listening»
    // and the first poll of the shutdown future.
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let signal_task = tokio::spawn(wait_for_terminate_signal(shutdown_tx));

    let shutdown_fut = async move {
        let _ = shutdown_rx.await;
    };

    let local = serve(state, args.status_bind, shutdown_fut)
        .await
        .with_context(|| "bind REST listener")?;
    tracing::info!(addr = %local, "disk daemon listening on {local}");
    println!("disk daemon listening on {local}");

    let _ = signal_task.await;
    watcher.abort();
    tracing::info!("disk daemon shutdown complete");
    Ok(())
}

fn build_share_snapshots(cfg: &DiskConfig) -> Vec<ShareSnapshot> {
    cfg.shares
        .iter()
        .map(|s| ShareSnapshot {
            name: s.name.clone(),
            path: s.path.display().to_string(),
            declared_direction: s
                .effective_direction(cfg.node.default.intended_direction)
                .unwrap_or(Direction::Bidirectional),
            server_confirmed_role: None,
            state: LoopState::Idle,
            last_success_at: None,
            last_error: None,
            bytes_sent_session: 0,
            bytes_received_session: 0,
            pending_local_changes: 0,
        })
        .collect()
}

#[cfg(unix)]
async fn wait_for_terminate_signal(tx: tokio::sync::oneshot::Sender<()>) {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "failed to install SIGTERM handler");
            let _ = tx.send(());
            return;
        }
    };
    let mut sigint = match signal(SignalKind::interrupt()) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "failed to install SIGINT handler");
            let _ = tx.send(());
            return;
        }
    };
    tokio::select! {
        _ = sigterm.recv() => tracing::info!("SIGTERM received — shutting down"),
        _ = sigint.recv() => tracing::info!("SIGINT received — shutting down"),
    }
    let _ = tx.send(());
}

#[cfg(not(unix))]
async fn wait_for_terminate_signal(tx: tokio::sync::oneshot::Sender<()>) {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("Ctrl-C received — shutting down");
    let _ = tx.send(());
}

/// `KeepAlive` returned by [`ConfigWatcher`] held to avoid Clippy
/// «used-only-for-Drop» false positive. Tests that need to drop the
/// watcher early call `.abort()` explicitly via this re-export.
#[doc(hidden)]
pub type _DaemonConfigWatcher = ConfigWatcher;

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    const MINIMAL: &str = r#"
[node]
id = "arcana-ai"
[node.default]
intended_direction = "bidirectional"

[server]
address = "host:9443"
client_cert = "/etc/disk-arcana/client.crt"
client_key  = "/etc/disk-arcana/client.key"

[[share]]
name = "wiki"
path = "/data/wiki"
"#;

    #[test]
    fn build_share_snapshots_resolves_inherited_direction() {
        let cfg = DiskConfig::from_str(MINIMAL).unwrap();
        let snaps = build_share_snapshots(&cfg);
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0].name, "wiki");
        assert_eq!(snaps[0].declared_direction, Direction::Bidirectional);
        assert_eq!(snaps[0].path, "/data/wiki");
        assert_eq!(snaps[0].state, LoopState::Idle);
    }

    #[test]
    fn build_share_snapshots_handles_empty_shares() {
        let cfg_str = r#"
[node]
id = "x"
[node.default]
intended_direction = "receive_only"
[server]
address = "h:1"
client_cert = "/a"
client_key  = "/b"
"#;
        let cfg = DiskConfig::from_str(cfg_str).unwrap();
        let snaps = build_share_snapshots(&cfg);
        assert!(snaps.is_empty());
    }
}
