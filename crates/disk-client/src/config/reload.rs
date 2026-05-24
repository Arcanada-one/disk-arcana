//! Hot config reload (DISK-0006 R9).
//!
//! Plan §Hot config reload (verbatim):
//! 1. `validate(new_cfg)?` — same chain as startup.
//! 2. On ok: atomic swap `Arc<DiskConfig>` через `RwLock`; emit `config.reload`
//!    audit event (server-side via gRPC); shares получают reconcile-trigger.
//! 3. On err: log + surface в `/status.last_error`; previous active config
//!    продолжает работать. **Никакого daemon-restart**.
//!
//! The watcher binds [`FsWatcher`] from R5 on the **parent directory** of the
//! target file (notify on macOS / Linux is more reliable on directories than
//! single files because editors save via tmp + atomic rename — the file inode
//! is replaced, not modified). Events are filtered by `file_name()`.
//!
//! Two reload sources feed the same apply path:
//! - File change observed by the underlying `notify` backend → debounced by
//!   `debounce_window` (default 500 ms) to coalesce editor write bursts.
//! - Explicit signal on the optional `reload_rx` channel — R7
//!   `POST /config/reload` REST endpoint enqueues here. No debounce because
//!   the caller already debounced via REST.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use super::{validate, DiskConfig};
use crate::watcher::{FsWatcher, WatcherError, DEFAULT_DEBOUNCE_WINDOW};

/// Thread-safe handle to the currently active `disk.toml` snapshot.
///
/// `current()` clones the inner `Arc<DiskConfig>` — readers hold the lock
/// only long enough to bump the refcount. A concurrent swap installs a fresh
/// `Arc`; in-flight readers keep using the old one until they drop it.
#[derive(Clone)]
pub struct ConfigSnapshot {
    inner: Arc<RwLock<Arc<DiskConfig>>>,
}

impl ConfigSnapshot {
    pub fn new(initial: Arc<DiskConfig>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(initial)),
        }
    }

    /// Returns the currently active config snapshot. Always succeeds — the
    /// `Arc` is cloned out so callers don't hold the read lock.
    pub fn current(&self) -> Arc<DiskConfig> {
        self.inner
            .read()
            .expect("ConfigSnapshot lock poisoned")
            .clone()
    }

    /// Replace the active config. Old `Arc` references stay valid until
    /// their last holder drops.
    pub fn swap(&self, next: Arc<DiskConfig>) {
        *self.inner.write().expect("ConfigSnapshot lock poisoned") = next;
    }
}

/// Last reload failure, surfaced via `/status.last_error` per PRD §4.12.4.
///
/// Cleared on the next successful reload.
#[derive(Clone, Default)]
pub struct ReloadStatus {
    inner: Arc<RwLock<Option<String>>>,
}

impl ReloadStatus {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self) -> Option<String> {
        self.inner
            .read()
            .expect("ReloadStatus lock poisoned")
            .clone()
    }

    pub fn set(&self, msg: impl Into<String>) {
        *self.inner.write().expect("ReloadStatus lock poisoned") = Some(msg.into());
    }

    pub fn clear(&self) {
        *self.inner.write().expect("ReloadStatus lock poisoned") = None;
    }
}

/// Spawned watcher handle. Drop or `abort()` to stop the loop; the inner
/// `FsWatcher` is held by the task and tears down its notify thread on drop.
pub struct ConfigWatcher {
    pub snapshot: ConfigSnapshot,
    pub status: ReloadStatus,
    pub handle: JoinHandle<()>,
}

impl ConfigWatcher {
    /// Abort the watcher task. Useful in tests.
    pub fn abort(self) {
        self.handle.abort();
    }
}

/// Spawn a hot-reload watcher on `file_path`.
///
/// `file_path` MUST point at the `disk.toml` file (not its parent). The
/// watcher binds notify on the parent directory and filters events by
/// `file_name()`.
///
/// `initial` is the snapshot loaded at startup. The caller is responsible
/// for validating it before passing in.
///
/// `reload_rx` is the optional explicit-reload channel (typically wired to
/// R7's REST `POST /config/reload`). When `None`, only filesystem events
/// trigger reloads.
///
/// `debounce_window`: collapse rapid filesystem events within this window
/// into one reload attempt. Pass `None` for [`DEFAULT_DEBOUNCE_WINDOW`].
pub fn spawn_config_watcher(
    file_path: PathBuf,
    initial: Arc<DiskConfig>,
    reload_rx: Option<mpsc::Receiver<()>>,
    debounce_window: Option<Duration>,
) -> Result<ConfigWatcher, WatcherError> {
    let parent = file_path
        .parent()
        .ok_or_else(|| WatcherError::MissingShareRoot(file_path.clone()))?;
    let parent = parent.to_path_buf();
    let target_filename: OsString = file_path
        .file_name()
        .map(|s| s.to_os_string())
        .ok_or_else(|| WatcherError::MissingShareRoot(file_path.clone()))?;

    let fs = FsWatcher::watch(&parent)?;
    let snapshot = ConfigSnapshot::new(initial);
    let status = ReloadStatus::new();
    let window = debounce_window.unwrap_or(DEFAULT_DEBOUNCE_WINDOW);

    let snapshot_for_task = snapshot.clone();
    let status_for_task = status.clone();
    let path_for_task = file_path.clone();

    let handle = tokio::spawn(run_watcher_loop(
        fs,
        path_for_task,
        target_filename,
        snapshot_for_task,
        status_for_task,
        reload_rx,
        window,
    ));

    Ok(ConfigWatcher {
        snapshot,
        status,
        handle,
    })
}

async fn run_watcher_loop(
    mut fs: FsWatcher,
    file_path: PathBuf,
    target_filename: OsString,
    snapshot: ConfigSnapshot,
    status: ReloadStatus,
    mut reload_rx: Option<mpsc::Receiver<()>>,
    window: Duration,
) {
    let mut pending_until: Option<Instant> = None;

    loop {
        // Compute the sleep arm: either a real sleep until pending deadline
        // or a never-resolving future when nothing is pending. Recreated
        // every iteration so the deadline reflects the latest `pending_until`.
        let sleep_arm: Box<dyn std::future::Future<Output = ()> + Send + Unpin> =
            match pending_until {
                Some(t) => Box::new(Box::pin(tokio::time::sleep_until(t))),
                None => Box::new(Box::pin(std::future::pending::<()>())),
            };

        tokio::select! {
            biased;

            ev = fs.recv() => {
                match ev {
                    Some(e) if e.path().file_name() == Some(target_filename.as_os_str()) => {
                        pending_until = Some(Instant::now() + window);
                    }
                    Some(_) => continue,
                    None => break,
                }
            }

            _ = sleep_arm => {
                pending_until = None;
                apply_reload(&file_path, &snapshot, &status).await;
            }

            sig = recv_reload(&mut reload_rx) => {
                if sig.is_none() {
                    // reload_rx dropped → ignore further signals but keep
                    // serving fs events.
                    reload_rx = None;
                    continue;
                }
                apply_reload(&file_path, &snapshot, &status).await;
            }
        }
    }
}

async fn recv_reload(rx: &mut Option<mpsc::Receiver<()>>) -> Option<()> {
    match rx {
        Some(r) => r.recv().await,
        None => std::future::pending().await,
    }
}

async fn apply_reload(path: &Path, snapshot: &ConfigSnapshot, status: &ReloadStatus) {
    let raw = match tokio::fs::read_to_string(path).await {
        Ok(s) => s,
        Err(e) => {
            let msg = format!("config reload: read {} failed: {}", path.display(), e);
            tracing::warn!("{msg}");
            status.set(msg);
            return;
        }
    };
    let parsed: DiskConfig = match toml::from_str(&raw) {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("config reload: parse failed: {e}");
            tracing::warn!("{msg}");
            status.set(msg);
            return;
        }
    };
    if let Err(e) = validate(&parsed) {
        let msg = format!("config reload: validation failed: {e}");
        tracing::warn!("{msg}");
        status.set(msg);
        return;
    }
    snapshot.swap(Arc::new(parsed));
    status.clear();
    tracing::info!(path = %path.display(), "config reloaded");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    const MINIMAL: &str = r#"
[node]
id = "dev"
[node.default]
intended_direction = "receive_only"
[server]
address = "host:9443"
client_cert = "/etc/disk-arcana/client.crt"
client_key  = "/etc/disk-arcana/client.key"
"#;

    fn minimal_cfg() -> DiskConfig {
        DiskConfig::from_str(MINIMAL).unwrap()
    }

    #[test]
    fn snapshot_swap_replaces_inner_arc() {
        let snap = ConfigSnapshot::new(Arc::new(minimal_cfg()));
        let first = snap.current();
        assert_eq!(first.node.id, "dev");

        let mut updated = minimal_cfg();
        updated.node.id = "updated".into();
        snap.swap(Arc::new(updated));

        assert_eq!(snap.current().node.id, "updated");
        // First Arc still readable — defensive contract for in-flight readers.
        assert_eq!(first.node.id, "dev");
    }

    #[test]
    fn status_set_then_clear_round_trip() {
        let s = ReloadStatus::new();
        assert_eq!(s.get(), None);
        s.set("boom");
        assert_eq!(s.get().as_deref(), Some("boom"));
        s.clear();
        assert_eq!(s.get(), None);
    }

    #[test]
    fn status_overwrites_on_repeat_set() {
        let s = ReloadStatus::new();
        s.set("first");
        s.set("second");
        assert_eq!(s.get().as_deref(), Some("second"));
    }
}
