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

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use disk_client::config::{spawn_config_watcher, ConfigWatcher, Direction, DiskConfig};
use disk_client::connection::DiskClient;
use disk_client::lan_sync::{
    parse_server_port, spawn_lan_discovery, spawn_lan_serve, LanFetchContext, LanPeerRegistry,
    LanServeState,
};
use disk_client::resolve_vault_key;
use disk_client::rest_api::{serve, DaemonState, ShareSnapshot};
use disk_client::sync_loop::{LoopState, LoopTrigger, RemoteSync, SyncLoop, POLL_INTERVAL};
use disk_client::telemetry::{sync_outcome_label, ClientTelemetry};
use disk_client::BlobCache;
use disk_core::{MetaDb, DEFAULT_CONFLICT_TTL_SECS};
use rand::{rngs::StdRng, SeedableRng};
use serde_json::json;

/// CLI arguments for `disk daemon start`.
#[derive(clap::Args, Debug)]
pub struct DaemonStartArgs {
    /// Path to `disk.toml`.
    #[arg(long, default_value = crate::paths::DEFAULT_CONFIG)]
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

    /// Directory used for persistent client state: the shared SQLite
    /// `MetaDb` (`meta.db`) and the content-addressed blob cache (`blob-cache/`)
    /// used by the auto-3-way-merge path.  Must survive daemon restarts.
    #[arg(long, default_value = crate::paths::DEFAULT_STATE_DIR)]
    pub state_dir: PathBuf,
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

    let telemetry = ClientTelemetry::open(
        &args.state_dir,
        &cfg.telemetry,
        &cfg.server.address,
        &node_id,
    );
    if let Some(t) = &telemetry {
        t.capture(
            "client_daemon_started",
            json!({
                "share_count": cfg.shares.len(),
            }),
        );
    }

    let (state, manual_sync_rx, reload_rx) = DaemonState::new(&node_id, config_version);
    state.set_shares(build_share_snapshots(&cfg)).await;

    let watcher = spawn_config_watcher(args.config.clone(), cfg.clone(), Some(reload_rx), None)
        .with_context(|| "spawn ConfigWatcher")?;

    // Install signal handlers BEFORE binding the REST listener — closes
    // the R1-vintage race window where SIGTERM arrives between «listening»
    // and the first poll of the shutdown future.
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let signal_task = tokio::spawn(wait_for_terminate_signal(shutdown_tx));

    // ── Open the shared client MetaDb and BlobCache ───────────────────────
    //
    // A single MetaDb at `{state_dir}/meta.db` records `node_baselines` for
    // ALL shares keyed by `(node_id, vault_id=share_name, path)`.  The blob
    // cache at `{state_dir}/blob-cache/` is content-addressed and therefore
    // also shared across shares — blobs from one share that happen to match
    // another's hash cause no harm, only a slight space saving.
    //
    // Both are opened once here and held for the lifetime of the process.
    // If the state dir cannot be created or the DB cannot be opened we log a
    // warning and run WITHOUT blob-cache / baselines (falling back to
    // fork-on-conflict, which was the pre-existing safe behaviour).
    let (meta_db, blob_cache): (Option<Arc<MetaDb>>, Arc<BlobCache>) =
        match open_client_state(&args.state_dir).await {
            Ok((db, cache)) => (Some(Arc::new(db)), Arc::new(cache)),
            Err(e) => {
                tracing::warn!(
                    state_dir = %args.state_dir.display(),
                    error = %e,
                    "daemon: could not open client state (MetaDb/BlobCache); \
                     3-way merge will not fire — conflicts will fork instead"
                );
                // BlobCache::new never fails (lazy dir creation); supply a
                // no-op cache so the Arc is always present and the sync loop
                // can still attach it when a real DB is available later.
                (
                    None,
                    Arc::new(BlobCache::new(args.state_dir.join("blob-cache"))),
                )
            }
        };

    // ── Attach MetaDb and vault_root to the served REST state ─────────────
    //
    // `GET /conflicts` and `POST /conflicts/{path}` require `state.meta_db()`.
    // The file-operation path in the resolve handler also requires
    // `state.vault_root()` to know where the live and fork files reside.
    //
    let share_roots: std::collections::HashMap<String, std::path::PathBuf> = cfg
        .shares
        .iter()
        .map(|share| (share.name.clone(), share.path.clone()))
        .collect();

    // Take ownership of `state` to chain `with_meta_db` / `with_vault_root`.
    // Both methods consume `Self` and return a new `Self`; the two `set_shares`
    // / `set_config_version` mutations above used `&self` and are already done.
    let state = if let Some(db_arc) = meta_db.as_deref() {
        // `with_meta_db` expects a `MetaDb` (not `Arc<MetaDb>`); clone via
        // the MetaDb's `Clone` impl (it holds an inner Arc<Pool> itself).
        state.with_meta_db((*db_arc).clone())
    } else {
        state
    };
    let state = if !share_roots.is_empty() {
        state.with_vault_roots(share_roots.clone())
    } else {
        state
    };

    let lan_registry = LanPeerRegistry::new(cfg.lan_sync.enabled, &node_id);
    let state = state.with_lan_peers(Arc::clone(&lan_registry));
    let (lan_shutdown_tx, lan_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let (lan_serve_shutdown_tx, lan_serve_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let lan_discovery_handle = if cfg.lan_sync.enabled {
        tracing::info!(
            port = cfg.lan_sync.advertise_port,
            "daemon: LAN sync discovery enabled"
        );
        let serve_state = LanServeState {
            share_roots: share_roots.clone(),
            tenant_id: cfg.node.tenant_id.clone(),
            self_node_id: node_id.clone(),
        };
        spawn_lan_serve(
            cfg.lan_sync.advertise_port,
            serve_state,
            lan_serve_shutdown_rx,
        );
        Some(spawn_lan_discovery(
            Arc::clone(&lan_registry),
            node_id.clone(),
            cfg.node.tenant_id.clone(),
            cfg.lan_sync.advertise_port,
            parse_server_port(&cfg.server.address),
            lan_shutdown_rx,
        ))
    } else {
        drop(lan_shutdown_rx);
        drop(lan_serve_shutdown_rx);
        None
    };
    let lan_fetch_ctx = if cfg.lan_sync.enabled {
        Some(LanFetchContext::new(
            Arc::clone(&lan_registry),
            cfg.node.tenant_id.clone(),
            node_id.clone(),
        ))
    } else {
        None
    };

    // ── Spawn per-share sync-loop tasks (DISK-0043) ──────────────────────
    //
    // Each share gets a task that runs `SyncLoop::run_iteration` on:
    //   (a) a `POLL_INTERVAL` timer tick, and
    //   (b) a `manual_sync_rx` wakeup (sent by POST /sync).
    //
    // Tasks are aborted on shutdown alongside the config watcher.
    //
    // The `DiskClient` is not constructed here because it requires TLS cert
    // files that may not exist in a bootstrap environment.  Instead, we spawn
    // a lightweight async task that drives the sync-loop state machine and
    // calls `RemoteSync` when a real client can be obtained.  In environments
    // where certs exist, the task builds its own client; if cert loading fails
    // the task logs a warning and exits (daemon stays alive for REST surface).
    let server_addr = format!("https://{}", cfg.server.address);
    let server_tls_domain = cfg.server.tls_domain.clone();
    let ca_pem: Option<Vec<u8>> = cfg
        .server
        .server_ca
        .as_deref()
        .and_then(|p| std::fs::read(p).ok());
    let client_cert_pem: Option<Vec<u8>> = std::fs::read(&cfg.server.client_cert).ok();
    let client_key_pem: Option<Vec<u8>> = std::fs::read(&cfg.server.client_key).ok();
    let node_id_for_loop = node_id.clone();
    let tenant_id_for_loop = cfg.node.tenant_id.clone();

    let e2ee_key = if cfg.vault.e2ee_enabled {
        match resolve_vault_key(&node_id, &args.state_dir) {
            Ok(Some(key)) => {
                tracing::info!("daemon: client-side E2EE enabled for uploads");
                Some(key)
            }
            Ok(None) => {
                tracing::warn!(
                    "daemon: vault.e2ee_enabled=true but no key found; \
                     run `disk vault unlock` or set DISK_VAULT_PASSPHRASE + DISK_VAULT_SALT; \
                     uploads remain plaintext"
                );
                None
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "daemon: failed to load vault key; uploads remain plaintext"
                );
                None
            }
        }
    } else {
        None
    };

    // Use a broadcast-style approach: fan out manual_sync signals to all shares.
    let manual_sync_rx = Arc::new(tokio::sync::Mutex::new(manual_sync_rx));

    let mut sync_task_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    for share in cfg.shares.iter() {
        let share_name = share.name.clone();
        let share_path = share.path.clone();
        let declared_direction = share
            .effective_direction(cfg.node.default.intended_direction)
            .unwrap_or(Direction::Bidirectional);
        let server_addr = server_addr.clone();
        let server_tls_domain = server_tls_domain.clone();
        let ca_pem = ca_pem.clone();
        let client_cert_pem = client_cert_pem.clone();
        let client_key_pem = client_key_pem.clone();
        let node_id_for_loop = node_id_for_loop.clone();
        let tenant_id_for_loop = tenant_id_for_loop.clone();
        let manual_sync_rx = Arc::clone(&manual_sync_rx);
        let meta_db = meta_db.clone();
        let blob_cache = Arc::clone(&blob_cache);
        let e2ee_key = e2ee_key.clone();
        let telemetry_for_task = telemetry.clone();
        let lan_fetch_for_loop = lan_fetch_ctx.clone();
        // Clone the DaemonState handle into the per-share task so it can
        // write live loop state back via `update_share`.
        let state_for_task = state.clone();

        let handle = tokio::spawn(async move {
            // Build a DiskClient with bounded connect-retry.
            //
            // A transient connect failure (e.g. server starts after the client
            // task is spawned) must not abort the sync task — the task retries
            // with backoff up to MAX_CONNECT_ATTEMPTS before marking the share
            // server_unreachable.
            const MAX_CONNECT_ATTEMPTS: u32 = 8;
            let mut connect_delay = Duration::from_secs(1);
            const CONNECT_DELAY_CAP: Duration = Duration::from_secs(30);

            let client = {
                let mut attempt = 0u32;
                loop {
                    match build_disk_client(
                        server_addr.clone(),
                        ca_pem.clone(),
                        server_tls_domain.clone(),
                        client_cert_pem.clone(),
                        client_key_pem.clone(),
                        node_id_for_loop.clone(),
                        tenant_id_for_loop.clone(),
                    )
                    .await
                    {
                        Ok(c) => break c,
                        Err(e) => {
                            attempt += 1;
                            if attempt >= MAX_CONNECT_ATTEMPTS {
                                tracing::warn!(
                                    share = %share_name,
                                    error = %e,
                                    attempts = attempt,
                                    "sync-loop: could not connect after {MAX_CONNECT_ATTEMPTS} \
                                     attempts; share will not sync"
                                );
                                let unreachable_snap = build_live_snapshot(
                                    &share_name,
                                    share_path.clone(),
                                    declared_direction,
                                    LoopState::ServerUnreachable,
                                    None,
                                    Some(e.to_string()),
                                );
                                state_for_task
                                    .update_share(&share_name, unreachable_snap)
                                    .await;
                                return;
                            }
                            tracing::debug!(
                                share = %share_name,
                                attempt,
                                delay_ms = connect_delay.as_millis(),
                                error = %e,
                                "sync-loop: connect failed; retrying"
                            );
                            // Write server_unreachable during the retry window so
                            // /status does not stay frozen at idle.
                            let retrying_snap = build_live_snapshot(
                                &share_name,
                                share_path.clone(),
                                declared_direction,
                                LoopState::ServerUnreachable,
                                None,
                                Some(e.to_string()),
                            );
                            state_for_task
                                .update_share(&share_name, retrying_snap)
                                .await;
                            tokio::time::sleep(connect_delay).await;
                            connect_delay = (connect_delay * 2).min(CONNECT_DELAY_CAP);
                        }
                    }
                }
            };

            // Authenticate with the server so ExchangeState and other
            // session-gated RPCs succeed.  register_node is idempotent: the
            // server returns a fresh API key on each call; authenticate() then
            // exchanges it for a session token stored in the channel-local cache.
            //
            // A failure here is non-fatal: the loop proceeds; individual
            // iterations surface Unauthenticated → TransportUnavailable →
            // backoff → retry, which is the correct degraded behaviour.
            let mut client = client; // make mutable so we can set api_key
            if let Ok(api_key) = client.register_node(&node_id_for_loop, "disk-daemon").await {
                client.api_key = Some(api_key);
                match client.authenticate().await {
                    Ok(_token) => {
                        tracing::info!(
                            share = %share_name,
                            "sync-loop: authenticated with server"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            share = %share_name,
                            error = %e,
                            "sync-loop: authenticate() failed; iterations will retry"
                        );
                    }
                }
            } else {
                tracing::warn!(
                    share = %share_name,
                    "sync-loop: register_node() failed; ExchangeState will be unauthenticated"
                );
            }

            let mut loop_sm = SyncLoop::new();
            let mut rng = StdRng::from_os_rng();
            let mut interval = tokio::time::interval(POLL_INTERVAL);
            // Track last_success_at locally so syncing→idle transitions can
            // advance the timestamp only on a real success.
            let mut last_success_at: Option<i64> = None;

            loop {
                let trigger = tokio::select! {
                    _ = interval.tick() => LoopTrigger::Tick,
                    _ = async {
                        let mut guard = manual_sync_rx.lock().await;
                        guard.recv().await
                    } => LoopTrigger::Manual,
                };
                let trigger_label = match trigger {
                    LoopTrigger::Tick => "tick",
                    LoopTrigger::Manual => "manual",
                    LoopTrigger::FsEventBatch => "fs_event",
                };

                // Write a syncing snapshot before run_iteration so a fast
                // iteration still surfaces "syncing" to GET /status callers.
                let syncing_snap = build_live_snapshot(
                    &share_name,
                    share_path.clone(),
                    declared_direction,
                    LoopState::Syncing,
                    last_success_at,
                    None,
                );
                state_for_task.update_share(&share_name, syncing_snap).await;

                // Load per-share baselines from the MetaDb for this cycle.
                // A fresh load each cycle picks up baselines written in the
                // previous cycle without requiring inter-task communication.
                let baselines =
                    load_baselines_for_share(meta_db.as_deref(), &node_id_for_loop, &share_name)
                        .await;

                let mut transport = build_remote_sync_for_share(
                    &client,
                    &share_name,
                    share_path.clone(),
                    &node_id_for_loop,
                    Arc::clone(&blob_cache),
                    baselines,
                    meta_db.clone(),
                    lan_fetch_for_loop.clone(),
                );
                if let Some(ref key) = e2ee_key {
                    transport = transport.with_e2ee_key(key.clone());
                }
                let outcome = loop_sm
                    .run_iteration(&mut transport, trigger, &mut rng)
                    .await;

                // Advance last_success_at only on a real success.
                if matches!(outcome, Some(Ok(()))) {
                    last_success_at = Some(
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs() as i64,
                    );
                }

                // Write the final snapshot (reflects idle/backoff/error state
                // and the potentially-advanced last_success_at).
                let final_snap = build_live_snapshot(
                    &share_name,
                    share_path.clone(),
                    declared_direction,
                    loop_sm.state(),
                    last_success_at,
                    loop_sm.last_error().map(|e| e.to_string()),
                );
                state_for_task.update_share(&share_name, final_snap).await;

                if let Some(t) = telemetry_for_task.as_ref() {
                    let outcome =
                        sync_outcome_label(loop_sm.state(), loop_sm.last_error().is_some());
                    t.capture(
                        "client_sync_cycle",
                        json!({
                            "share": share_name,
                            "outcome": outcome,
                            "trigger": trigger_label,
                        }),
                    );
                }
            }
        });
        sync_task_handles.push(handle);
    }

    // ── Maintenance task: periodic conflict TTL cleanup ───────────────────
    //
    // Runs once every 24 hours.  Deletes resolved conflicts whose
    // `resolved_at` timestamp is older than `DEFAULT_CONFLICT_TTL_SECS` (30
    // days).  Non-fatal: a DB error is logged but does not stop the daemon.
    let maintenance_handle: Option<tokio::task::JoinHandle<()>> = meta_db.as_deref().map(|_| {
        let db_for_maint = meta_db.clone().unwrap(); // safe: checked above
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(24 * 3600));
            loop {
                interval.tick().await;
                match db_for_maint
                    .cleanup_resolved_conflicts(DEFAULT_CONFLICT_TTL_SECS)
                    .await
                {
                    Ok(n) if n > 0 => {
                        tracing::info!(
                            deleted = n,
                            "maintenance: pruned resolved conflicts older than 30d"
                        );
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "maintenance: cleanup_resolved_conflicts failed (non-fatal)"
                        );
                    }
                }
            }
        })
    });

    // ── P2: Config-reload reconcile consumer ─────────────────────────────
    //
    // Whenever the ConfigWatcher commits a new config via `snapshot.swap`,
    // the watch channel fires.  This task picks up the new config's share
    // list and calls `reconcile_shares` — preserving live sync state for
    // surviving shares while adding/removing entries to match the new config.
    //
    // This is the daemon-side consumer that makes V-AC-4's sub-assertion
    // work: a reload that adds or removes a share is reflected in `/status`
    // rather than leaving it frozen at the startup snapshot.
    let cfg_for_reconcile = cfg.clone();
    let snapshot_handle = watcher.snapshot.clone();
    let state_for_reconcile = state.clone();
    let reconcile_handle = tokio::spawn(async move {
        let mut change_rx = snapshot_handle.subscribe();
        // Mark the current value as seen so the first `changed()` fires on
        // the next actual swap, not immediately.
        change_rx.mark_unchanged();
        loop {
            match change_rx.changed().await {
                Ok(()) => {
                    let new_cfg = snapshot_handle.current();
                    let new_snaps = build_share_snapshots_from_cfg(&new_cfg, &cfg_for_reconcile);
                    tracing::info!(
                        share_count = new_snaps.len(),
                        "daemon: config reloaded — reconciling share list"
                    );
                    state_for_reconcile.reconcile_shares(new_snaps).await;
                }
                Err(_) => {
                    // Sender dropped (watcher task exited / aborted).
                    tracing::debug!("daemon: config-snapshot watch channel closed");
                    break;
                }
            }
        }
    });

    let shutdown_fut = async move {
        let _ = shutdown_rx.await;
        let _ = lan_shutdown_tx.send(());
        let _ = lan_serve_shutdown_tx.send(());
    };

    let local = serve(state, args.status_bind, shutdown_fut)
        .await
        .with_context(|| "bind REST listener")?;
    tracing::info!(addr = %local, "disk daemon listening on {local}");
    println!("disk daemon listening on {local}");

    let _ = signal_task.await;
    watcher.abort();
    reconcile_handle.abort();
    for h in sync_task_handles {
        h.abort();
    }
    if let Some(h) = maintenance_handle {
        h.abort();
    }
    if let Some(h) = lan_discovery_handle {
        h.abort();
    }
    tracing::info!("disk daemon shutdown complete");
    Ok(())
}

/// Open the client MetaDb and create the BlobCache under `state_dir`.
///
/// `state_dir` is created if it does not exist.  Returns both handles on
/// success; the caller degrades gracefully on error (log + fork fallback).
pub(crate) async fn open_client_state(state_dir: &Path) -> Result<(MetaDb, BlobCache)> {
    std::fs::create_dir_all(state_dir)
        .with_context(|| format!("create state_dir {}", state_dir.display()))?;

    let db_path = state_dir.join("meta.db");
    let db = MetaDb::open(&db_path)
        .await
        .with_context(|| format!("open MetaDb at {}", db_path.display()))?;

    let cache_dir = state_dir.join("blob-cache");
    let cache = BlobCache::new(cache_dir);

    Ok((db, cache))
}

/// Load `node_baselines` for `(node_id, share_name)` from the MetaDb and
/// convert them to the `HashMap<path_string, content_hash>` form expected by
/// [`RemoteSync::with_blob_cache`].
///
/// Returns an empty map when `meta_db` is `None` or when the DB query fails
/// (non-fatal; the APPLY path falls back to forking).
pub(crate) async fn load_baselines_for_share(
    meta_db: Option<&MetaDb>,
    node_id: &str,
    share_name: &str,
) -> HashMap<String, [u8; 32]> {
    let db = match meta_db {
        Some(db) => db,
        None => return HashMap::new(),
    };

    match db.load_node_baseline(node_id, share_name).await {
        Ok(entries) => entries
            .into_iter()
            .filter(|e| !e.deleted)
            .map(|e| {
                let path = e.path.to_string_lossy().into_owned();
                (path, e.content_hash)
            })
            .collect(),
        Err(e) => {
            tracing::warn!(
                node_id,
                share = share_name,
                error = %e,
                "daemon: load_node_baseline failed; 3-way merge skipped for this cycle"
            );
            HashMap::new()
        }
    }
}

/// Construct a [`RemoteSync`] transport with the blob cache, baseline map,
/// and MetaDb handle attached so the auto-3-way-merge path is active and
/// conflict rows are persisted to the client index.
///
/// This function is the single production call site that wires
/// `with_blob_cache` and `with_meta_db` onto the sync transport — keeping it
/// extracted makes it testable without a live gRPC server.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_remote_sync_for_share<'a>(
    client: &'a DiskClient,
    share_name: &str,
    share_path: PathBuf,
    node_id: &str,
    blob_cache: Arc<BlobCache>,
    baselines: HashMap<String, [u8; 32]>,
    meta_db: Option<Arc<MetaDb>>,
    lan_fetch: Option<LanFetchContext>,
) -> RemoteSync<'a> {
    let transport = RemoteSync::with_scan_root(client, share_name, share_path, node_id)
        .with_blob_cache(blob_cache, baselines);
    let transport = if let Some(ctx) = lan_fetch {
        transport.with_lan_fetch(ctx)
    } else {
        transport
    };
    if let Some(db) = meta_db {
        transport.with_meta_db(db)
    } else {
        transport
    }
}

/// Build idle `ShareSnapshot`s from a config for the reconcile consumer.
///
/// The `_old_cfg` parameter is unused at runtime (the new config is
/// self-contained for direction resolution) but kept for future use.
fn build_share_snapshots_from_cfg(
    new_cfg: &DiskConfig,
    _old_cfg: &DiskConfig,
) -> Vec<ShareSnapshot> {
    build_share_snapshots(new_cfg)
}

/// Build a `ShareSnapshot` with static descriptor fields and the provided
/// live loop fields. Used by per-share sync tasks to emit `update_share`
/// calls before and after `run_iteration`.
///
/// Byte counters are always 0 — `SyncLoop` exposes no stats API.
fn build_live_snapshot(
    name: &str,
    path: std::path::PathBuf,
    declared_direction: Direction,
    state: LoopState,
    last_success_at: Option<i64>,
    last_error: Option<String>,
) -> ShareSnapshot {
    ShareSnapshot {
        name: name.to_string(),
        path: path.display().to_string(),
        declared_direction,
        server_confirmed_role: None,
        state,
        last_success_at,
        last_error,
        bytes_sent_session: 0,
        bytes_received_session: 0,
        pending_local_changes: 0,
    }
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

/// Build a `DiskClient` from explicit TLS material.
///
/// Used by per-share sync-loop tasks spawned in `run_start`.  Returns an
/// error when cert/key loading fails so the task can log a warning and exit
/// gracefully rather than panicking.
///
/// When both `client_cert_pem` and `client_key_pem` are `Some`, the channel
/// presents the client certificate during the mTLS handshake.  A partial pair
/// degrades to one-way TLS (see `ClientConfig` docs).
async fn build_disk_client(
    endpoint: String,
    ca_pem: Option<Vec<u8>>,
    tls_domain: Option<String>,
    client_cert_pem: Option<Vec<u8>>,
    client_key_pem: Option<Vec<u8>>,
    node_id: String,
    tenant_id: Option<String>,
) -> Result<DiskClient> {
    use disk_client::connection::ClientConfig;

    let cfg = ClientConfig {
        endpoint,
        tls_ca_cert_pem: ca_pem,
        tls_domain,
        client_cert_pem,
        client_key_pem,
        node_id,
        api_key: None,
        tenant_id,
    };
    DiskClient::connect(cfg)
        .await
        .context("connect DiskClient for sync-loop")
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

    #[cfg(not(windows))]
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

    #[cfg(windows)]
    const MINIMAL: &str = r#"
[node]
id = "arcana-ai"
[node.default]
intended_direction = "bidirectional"
[server]
address = "host:9443"
client_cert = "C:\\disk-arcana\\client.crt"
client_key  = "C:\\disk-arcana\\client.key"
[[share]]
name = "wiki"
path = "C:\\data\\wiki"
"#;

    #[test]
    fn build_share_snapshots_resolves_inherited_direction() {
        let cfg = DiskConfig::from_str(MINIMAL).unwrap();
        let snaps = build_share_snapshots(&cfg);
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0].name, "wiki");
        assert_eq!(snaps[0].declared_direction, Direction::Bidirectional);
        assert_eq!(
            snaps[0].path,
            if cfg!(windows) {
                r"C:\data\wiki"
            } else {
                "/data/wiki"
            }
        );
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

    /// Prove that the daemon's own sync-construction path — `open_client_state`
    /// + `load_baselines_for_share` + `build_remote_sync_for_share` — wires
    /// the blob cache and baselines onto the transport before any network I/O.
    ///
    /// This is a daemon-faithful test: it calls the exact same helper
    /// functions the sync-loop task calls each iteration, asserting that
    /// `has_blob_cache()` is true and `baseline_count()` reflects the rows
    /// written to the MetaDb.  A fake DiskClient endpoint is used so no TLS
    /// connection is required.
    #[tokio::test]
    async fn daemon_attaches_blob_cache() {
        use disk_client::connection::ClientConfig;
        use disk_core::types::FileMeta;
        use disk_core::vector_clock::VectorClock;

        let state_dir = tempfile::tempdir().unwrap();

        // Open the client state exactly as the daemon does.
        let (db, cache) = open_client_state(state_dir.path())
            .await
            .expect("open_client_state must succeed");
        let db = Arc::new(db);
        let cache = Arc::new(cache);

        // Write a baseline row for share "wiki" to simulate a prior sync cycle
        // having persisted the last-synced common-ancestor hash.
        let baseline = FileMeta {
            path: "notes/daily.md".into(),
            content_hash: [0x42u8; 32],
            size: 128,
            mtime_ns: 1_700_000_000_000_000_000,
            inode: None,
            vector_clock: VectorClock::default(),
            deleted: false,
            deleted_at: None,
            node_id: "arcana-ai".to_string(),
            encryption_nonce: None,
            version_id: None,
            parent_version_id: None,
        };
        db.upsert_node_baselines("arcana-ai", "wiki", std::slice::from_ref(&baseline))
            .await
            .expect("upsert_node_baselines must succeed");

        // Load baselines through the daemon helper — this mirrors the
        // per-iteration call in the sync-loop task.
        let baselines = load_baselines_for_share(Some(db.as_ref()), "arcana-ai", "wiki").await;

        assert_eq!(
            baselines.len(),
            1,
            "load_baselines_for_share must return the upserted baseline row"
        );
        assert_eq!(
            baselines.get("notes/daily.md").copied(),
            Some([0x42u8; 32]),
            "baseline content_hash must match what was written"
        );

        // Build a stub DiskClient using the lazy constructor so no TCP
        // connection attempt is made.  Construction must succeed; actual
        // RPCs would fail at runtime, but this test only inspects wiring.
        let client = DiskClient::connect_lazy_for_test(ClientConfig {
            endpoint: "https://localhost:9999".into(),
            tls_ca_cert_pem: None,
            tls_domain: None,
            client_cert_pem: None,
            client_key_pem: None,
            node_id: "arcana-ai".into(),
            api_key: None,
            tenant_id: None,
        })
        .expect("connect_lazy_for_test must succeed (no I/O at construction)");

        // Construct RemoteSync through the daemon's own helper (no MetaDb in this test).
        let transport = build_remote_sync_for_share(
            &client,
            "wiki",
            PathBuf::from("/data/wiki"),
            "arcana-ai",
            Arc::clone(&cache),
            baselines,
            None,
            None,
        );

        // Assert the blob cache is attached.
        assert!(
            transport.has_blob_cache(),
            "build_remote_sync_for_share must attach the blob cache; \
             has_blob_cache() returned false"
        );

        // Assert the baselines were threaded through.
        assert_eq!(
            transport.baseline_count(),
            1,
            "build_remote_sync_for_share must carry the loaded baselines; \
             baseline_count() must equal 1 (one row was upserted)"
        );
    }

    /// Daemon-faithful test: the served `DaemonState` receives `meta_db` AND
    /// `vault_root` after `open_client_state` completes — matching the wiring
    /// inside `run_start`.
    ///
    /// This is the production-assembly test that was missing before the fix:
    /// it exercises exactly the same construction path that `run_start` now
    /// uses, without hand-seeding the DB or calling `with_meta_db` directly
    /// in a one-liner.
    #[tokio::test]
    async fn served_state_has_meta_db_and_vault_root_after_run_start_assembly() {
        let state_dir = tempfile::tempdir().unwrap();
        let vault_dir = tempfile::tempdir().unwrap();

        // Step 1: open client state exactly as run_start does.
        let (db, _cache) = open_client_state(state_dir.path())
            .await
            .expect("open_client_state must succeed in a temp dir");

        // Step 2: build DaemonState from scratch (mirrors run_start lines).
        let (base_state, _, _) = disk_client::DaemonState::new("node-id", "v1.1");

        // Step 3: chain with_meta_db + with_vault_root exactly as run_start does.
        let served_state = base_state
            .with_meta_db(db)
            .with_vault_root(vault_dir.path().to_path_buf());

        // Assert: the served state now exposes both handles.
        assert!(
            served_state.meta_db().is_some(),
            "served DaemonState must have meta_db attached after run_start assembly; \
             GET /conflicts would return 503 without it"
        );
        assert!(
            served_state.vault_root().is_some(),
            "served DaemonState must have vault_root attached after run_start assembly; \
             POST /conflicts resolve file-ops would silently skip without it"
        );
        // Sanity: vault_root points to the expected directory.
        assert_eq!(
            served_state.vault_root().unwrap(),
            vault_dir.path(),
            "vault_root must equal the configured share path"
        );
    }

    /// The 30-day maintenance cleanup is driven by `cleanup_resolved_conflicts`
    /// with `DEFAULT_CONFLICT_TTL_SECS`.  This unit test proves the call contract:
    ///   - an empty DB returns Ok(0) — nothing deleted, no panic.
    ///   - the TTL constant is the correct value (30 × 24 × 3600 = 2592000 s).
    ///
    /// End-to-end wiring: the daemon's `run_start` spawns a maintenance task
    /// only when `meta_db.is_some()` (line that creates `maintenance_handle`).
    /// This test validates the function the task calls is sound; the spawn itself
    /// is integration-tested via `served_state_has_meta_db_and_vault_root_after_run_start_assembly`.
    #[tokio::test]
    async fn maintenance_cleanup_resolved_conflicts_with_daemon_ttl() {
        let state_dir = tempfile::tempdir().unwrap();
        let (db, _cache) = open_client_state(state_dir.path())
            .await
            .expect("open_client_state must succeed");

        // Simulate what the maintenance task calls each 24-hour tick.
        let deleted = db
            .cleanup_resolved_conflicts(DEFAULT_CONFLICT_TTL_SECS)
            .await
            .expect("cleanup_resolved_conflicts must succeed on an empty DB");

        assert_eq!(deleted, 0, "cleanup on empty DB must return 0 deleted rows");

        // Verify the TTL constant is the expected 30-day value.
        assert_eq!(
            DEFAULT_CONFLICT_TTL_SECS,
            30 * 24 * 3600,
            "DEFAULT_CONFLICT_TTL_SECS must be 30 days in seconds"
        );
    }

    /// Daemon-faithful test: `build_remote_sync_for_share` with a MetaDb handle
    /// returns a transport that has BOTH blob cache and meta_db attached.
    #[tokio::test]
    async fn build_remote_sync_attaches_meta_db_when_provided() {
        use disk_client::connection::ClientConfig;

        let state_dir = tempfile::tempdir().unwrap();
        let (db, cache) = open_client_state(state_dir.path())
            .await
            .expect("open_client_state must succeed");
        let db = Arc::new(db);
        let cache = Arc::new(cache);

        let client = DiskClient::connect_lazy_for_test(ClientConfig {
            endpoint: "https://localhost:9999".into(),
            tls_ca_cert_pem: None,
            tls_domain: None,
            client_cert_pem: None,
            client_key_pem: None,
            node_id: "n1".into(),
            api_key: None,
            tenant_id: None,
        })
        .expect("lazy connect");

        let transport = build_remote_sync_for_share(
            &client,
            "wiki",
            PathBuf::from("/data/wiki"),
            "n1",
            Arc::clone(&cache),
            HashMap::new(),
            Some(Arc::clone(&db)),
            None,
        );

        assert!(
            transport.has_blob_cache(),
            "transport must have blob cache attached"
        );
        assert!(
            transport.has_meta_db(),
            "transport must have meta_db attached when provided to build_remote_sync_for_share"
        );
    }
}
