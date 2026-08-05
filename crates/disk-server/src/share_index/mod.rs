//! Local filesystem index for `DISK_SHARE_ROOTS` (POST-R13 follow-up).
//!
//! Hermes and other secondary share roots receive writes outside the gRPC
//! `delta_upload` path. A `notify` watcher keeps the server MetaDb aligned
//! with on-disk state so `exchange_state` can fan out local changes to mesh
//! clients without a manual `disk import-state` re-run.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use disk_core::meta_db::MetaDb;
use disk_core::scanner::hash_file;
use disk_core::types::FileMeta;
use disk_core::vector_clock::VectorClock;
use notify::event::RemoveKind;
use notify::{Config, PollWatcher, RecursiveMode, Watcher};
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

const DEBOUNCE_MS: u64 = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IndexEventKind {
    Upsert,
    Tombstone,
}

#[derive(Debug, Clone)]
struct IndexEvent {
    vault_id: String,
    abs_path: PathBuf,
    kind: IndexEventKind,
}

#[derive(Debug, Error)]
pub enum ShareIndexError {
    #[error("share root missing: {0}")]
    MissingRoot(PathBuf),
    #[error(
        "configured share roots are unavailable: {available} of {configured} resolved to directories"
    )]
    ConfiguredRootsUnavailable { configured: usize, available: usize },
    #[error("one or more share-index watchers failed to start: {0}")]
    WatcherStartup(String),
    #[error("notify: {0}")]
    Notify(#[from] notify::Error),
    #[error("metadb: {0}")]
    MetaDb(#[from] disk_core::error::MetaDbError),
    #[error("scanner: {0}")]
    Scanner(#[from] disk_core::error::ScannerError),
    #[error("io at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Handle for the background share-index watcher. Drop to abort.
pub struct ShareIndexHandle {
    task: JoinHandle<()>,
    stop: Arc<AtomicBool>,
    watcher_threads: Vec<std::thread::JoinHandle<()>>,
    saturation: Arc<AtomicBool>,
}

impl ShareIndexHandle {
    /// Request a full reconciliation of every configured share root.
    ///
    /// DISK-0071: a path whose row is `deleted=1` while its bytes are present on
    /// disk is never served to any client and reports no error anywhere. Such
    /// rows accumulate whenever tombstones are written for files that did not
    /// actually disappear, and putting the bytes back does not clear them —
    /// only a reconciliation does, because [`full_reconcile`] upserts every file
    /// it finds on disk and an upsert sets `deleted = false`.
    ///
    /// This is the supported way to revive them: it reuses the existing
    /// fail-closed reconciliation (any I/O or DB error aborts before the first
    /// mutation) instead of touching `files.deleted` by hand. Reconciliation
    /// starts on the index loop's next turn, within one poll interval.
    pub fn request_full_reconcile(&self) {
        self.saturation.store(true, Ordering::Release);
    }
}

impl Drop for ShareIndexHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.task.abort();
        for watcher_thread in &self.watcher_threads {
            watcher_thread.thread().unpark();
        }
        for watcher_thread in self.watcher_threads.drain(..) {
            let _ = watcher_thread.join();
        }
    }
}

/// Whether `sync_root` is left without a `share_index` watcher.
///
/// DISK-0070: `SyncService::root_for` serves any share missing from
/// `share_roots` out of `sync_root`, but the watcher only covers declared
/// roots. Such a share reads correctly and is never indexed, so clients pull
/// nothing while the server health endpoint and the client status both report
/// success. Callers use this to log the gap loudly at startup.
///
/// Returns `true` when no declared root points at `sync_root`.
pub fn sync_root_is_unwatched(share_roots: &HashMap<String, PathBuf>, sync_root: &Path) -> bool {
    !share_roots.values().any(|root| root == sync_root)
}

/// Spawn a debounced watcher over every configured share root. No-op when
/// `share_roots` is empty.
pub fn spawn_share_index_watcher(
    share_roots: HashMap<String, PathBuf>,
    meta_db: MetaDb,
    node_id: impl Into<String>,
) -> Result<Option<ShareIndexHandle>, ShareIndexError> {
    if share_roots.is_empty() {
        return Ok(None);
    }

    let node_id = node_id.into();
    let (tx, rx) = mpsc::channel::<IndexEvent>(256);
    let canonical_roots = canonicalize_roots(&share_roots);

    if canonical_roots.len() != share_roots.len() || share_roots.values().any(|root| !root.is_dir())
    {
        return Err(ShareIndexError::ConfiguredRootsUnavailable {
            configured: share_roots.len(),
            available: canonical_roots.len(),
        });
    }

    let stop = Arc::new(AtomicBool::new(false));
    let saturation = Arc::new(AtomicBool::new(false));
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let mut watcher_threads = Vec::with_capacity(share_roots.len());

    // Arm every backend with the canonical root used by the index loop.
    // Windows canonicalization may add a verbatim-path prefix; registering
    // and filtering against different path spellings can discard otherwise
    // valid notify events before they reach the index.
    for (vault_id, root) in &canonical_roots {
        watcher_threads.push(spawn_notify_thread(
            vault_id.clone(),
            root.clone(),
            tx.clone(),
            ready_tx.clone(),
            stop.clone(),
            saturation.clone(),
        ));
    }
    drop(ready_tx);

    let startup_deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut startup_failures = Vec::new();
    for _ in 0..share_roots.len() {
        let remaining = startup_deadline.saturating_duration_since(std::time::Instant::now());
        match ready_rx.recv_timeout(remaining) {
            Ok(WatcherStart {
                vault_id,
                result: Ok(backend),
            }) => tracing::info!(
                vault_id = %vault_id,
                backend = ?backend,
                "share_index watcher armed"
            ),
            Ok(WatcherStart {
                vault_id,
                result: Err(error),
            }) => {
                tracing::error!(
                    vault_id = %vault_id,
                    error = %error,
                    "share_index watcher failed to initialize"
                );
                startup_failures.push(format!("{vault_id}: {error}"));
            }
            Err(error) => {
                tracing::error!(
                    error = %error,
                    "share_index watcher startup acknowledgement failed"
                );
                startup_failures.push(error.to_string());
                break;
            }
        }
    }

    if !startup_failures.is_empty() {
        stop.store(true, Ordering::Release);
        for watcher_thread in &watcher_threads {
            watcher_thread.thread().unpark();
        }
        for watcher_thread in watcher_threads {
            let _ = watcher_thread.join();
        }
        return Err(ShareIndexError::WatcherStartup(startup_failures.join("; ")));
    }

    drop(tx);

    // The index loop owns one handle to the saturation flag; the returned
    // ShareIndexHandle keeps another so callers can request a reconciliation
    // (DISK-0071).
    let loop_saturation = saturation.clone();
    let task = tokio::spawn(async move {
        if let Err(e) = run_index_loop(rx, meta_db, node_id, canonical_roots, loop_saturation).await
        {
            tracing::error!(error = %e, "share_index loop exited");
        }
    });

    Ok(Some(ShareIndexHandle {
        task,
        stop,
        watcher_threads,
        saturation,
    }))
}

fn canonicalize_roots(share_roots: &HashMap<String, PathBuf>) -> HashMap<String, PathBuf> {
    share_roots
        .iter()
        .filter_map(|(vault_id, root)| {
            std::fs::canonicalize(root)
                .ok()
                .map(|c| (vault_id.clone(), c))
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WatcherBackend {
    Native,
    Poll,
}

type AnyWatcher = Box<dyn Watcher + Send>;

#[derive(Debug, Error)]
#[error("native watcher failed: {native}; poll watcher failed: {poll}")]
struct WatcherInitError {
    native: String,
    poll: String,
}

#[derive(Debug)]
struct ArmedWatcher<T> {
    backend: WatcherBackend,
    watcher: T,
    native_failure: Option<String>,
}

fn native_or_poll<T, Native, Poll>(
    native: Native,
    poll: Poll,
) -> Result<ArmedWatcher<T>, WatcherInitError>
where
    Native: FnOnce() -> notify::Result<T>,
    Poll: FnOnce() -> notify::Result<T>,
{
    match native() {
        Ok(watcher) => Ok(ArmedWatcher {
            backend: WatcherBackend::Native,
            watcher,
            native_failure: None,
        }),
        Err(native_error) => match poll() {
            Ok(watcher) => Ok(ArmedWatcher {
                backend: WatcherBackend::Poll,
                watcher,
                native_failure: Some(native_error.to_string()),
            }),
            Err(poll_error) => Err(WatcherInitError {
                native: native_error.to_string(),
                poll: poll_error.to_string(),
            }),
        },
    }
}

fn make_event_handler(
    tx: mpsc::Sender<IndexEvent>,
    vault_id: String,
    root: PathBuf,
    saturation: Arc<AtomicBool>,
) -> impl FnMut(notify::Result<notify::Event>) + Send + 'static {
    move |result| {
        if let Ok(event) = result {
            for translated in translate_notify_event(&event, &vault_id, &root) {
                if tx.try_send(translated).is_err() {
                    saturation.store(true, Ordering::Release);
                }
            }
        }
    }
}

fn arm_native_watcher(
    vault_id: &str,
    root: &Path,
    tx: &mpsc::Sender<IndexEvent>,
    saturation: Arc<AtomicBool>,
) -> notify::Result<AnyWatcher> {
    let handler = make_event_handler(
        tx.clone(),
        vault_id.to_string(),
        root.to_path_buf(),
        saturation,
    );
    let mut watcher = notify::recommended_watcher(handler)?;
    watcher.watch(root, RecursiveMode::Recursive)?;
    Ok(Box::new(watcher))
}

fn arm_poll_watcher(
    vault_id: &str,
    root: &Path,
    tx: &mpsc::Sender<IndexEvent>,
    poll_interval: Duration,
    saturation: Arc<AtomicBool>,
) -> notify::Result<AnyWatcher> {
    let handler = make_event_handler(
        tx.clone(),
        vault_id.to_string(),
        root.to_path_buf(),
        saturation,
    );
    let config = Config::default()
        .with_poll_interval(poll_interval)
        .with_compare_contents(true);
    let mut watcher = PollWatcher::new(handler, config)?;
    watcher.watch(root, RecursiveMode::Recursive)?;
    Ok(Box::new(watcher))
}

fn arm_watcher(
    vault_id: &str,
    root: &Path,
    tx: &mpsc::Sender<IndexEvent>,
    saturation: Arc<AtomicBool>,
) -> Result<ArmedWatcher<AnyWatcher>, WatcherInitError> {
    let s1 = saturation.clone();
    let s2 = saturation;
    native_or_poll(
        || arm_native_watcher(vault_id, root, tx, s1.clone()),
        || arm_poll_watcher(vault_id, root, tx, Duration::from_secs(1), s2.clone()),
    )
}

struct WatcherStart {
    vault_id: String,
    result: Result<WatcherBackend, String>,
}

fn spawn_notify_thread(
    vault_id: String,
    root: PathBuf,
    tx: mpsc::Sender<IndexEvent>,
    ready_tx: std::sync::mpsc::Sender<WatcherStart>,
    stop: Arc<AtomicBool>,
    saturation: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(
        move || match arm_watcher(&vault_id, &root, &tx, saturation) {
            Ok(armed) => {
                if let Some(native_failure) = armed.native_failure {
                    tracing::warn!(
                        vault_id = %vault_id,
                        error = %native_failure,
                        "share_index native watcher failed; polling fallback armed"
                    );
                }
                if ready_tx
                    .send(WatcherStart {
                        vault_id: vault_id.clone(),
                        result: Ok(armed.backend),
                    })
                    .is_err()
                {
                    return;
                }

                let _watcher = armed.watcher;
                while !stop.load(Ordering::Acquire) {
                    std::thread::park_timeout(Duration::from_secs(1));
                }
            }
            Err(error) => {
                let _ = ready_tx.send(WatcherStart {
                    vault_id,
                    result: Err(error.to_string()),
                });
            }
        },
    )
}

fn translate_notify_event(ev: &notify::Event, vault_id: &str, root: &Path) -> Vec<IndexEvent> {
    use notify::event::{EventKind, ModifyKind, RenameMode};
    let kind = match ev.kind {
        EventKind::Create(_) | EventKind::Modify(_) => IndexEventKind::Upsert,
        EventKind::Remove(RemoveKind::File)
        | EventKind::Remove(RemoveKind::Folder)
        | EventKind::Remove(RemoveKind::Other)
        | EventKind::Remove(RemoveKind::Any) => IndexEventKind::Tombstone,
        EventKind::Any | EventKind::Access(_) | EventKind::Other => return Vec::new(),
    };

    ev.paths
        .iter()
        .enumerate()
        // DISK-0077: drop events for the server's own stores before they ever
        // reach the index — the watcher would otherwise index the very files
        // the server writes while serving, and that write stream is what
        // starved the MetaDb lock.
        .filter(|(_, p)| p.starts_with(root) && !is_internal_path(root, p))
        .map(|(i, p)| {
            let per_path_kind = match ev.kind {
                EventKind::Modify(ModifyKind::Name(RenameMode::From)) => IndexEventKind::Tombstone,
                EventKind::Modify(ModifyKind::Name(RenameMode::Both)) => {
                    if i == 0 {
                        IndexEventKind::Tombstone
                    } else {
                        IndexEventKind::Upsert
                    }
                }
                _ => kind,
            };
            IndexEvent {
                vault_id: vault_id.to_string(),
                abs_path: p.clone(),
                kind: per_path_kind,
            }
        })
        .collect()
}

async fn run_index_loop(
    mut rx: mpsc::Receiver<IndexEvent>,
    meta_db: MetaDb,
    node_id: String,
    canonical_roots: HashMap<String, PathBuf>,
    saturation: Arc<AtomicBool>,
) -> Result<(), ShareIndexError> {
    const SATURATION_POLL_INTERVAL: Duration = Duration::from_secs(2);

    loop {
        // Before blocking on recv, check whether a prior callback signalled
        // saturation — a full reconcile must run even when no new event
        // arrives to unblock the receiver.
        if saturation.swap(false, Ordering::AcqRel) {
            // Count is logged inside full_reconcile; discarding it here is
            // deliberate — the loop has no caller to report it to.
            let _revived = full_reconcile(&meta_db, &node_id, &canonical_roots).await?;
        }

        let first = match tokio::time::timeout(SATURATION_POLL_INTERVAL, rx.recv()).await {
            Ok(Some(event)) => event,
            Ok(None) => return Ok(()), // channel closed
            Err(_) => continue,        // timeout → loop back to check saturation
        };

        tokio::time::sleep(Duration::from_millis(DEBOUNCE_MS)).await;
        let mut batch = vec![first];
        while let Ok(ev) = rx.try_recv() {
            batch.push(ev);
        }

        for ev in batch {
            let Some(root) = canonical_roots.get(&ev.vault_id) else {
                continue;
            };

            match ev.kind {
                IndexEventKind::Upsert => {
                    if let Err(e) =
                        upsert_local_file(&meta_db, &ev.vault_id, &node_id, root, &ev.abs_path)
                            .await
                    {
                        tracing::warn!(
                            vault_id = %ev.vault_id,
                            path = %ev.abs_path.display(),
                            error = %e,
                            "share_index upsert failed"
                        );
                    }
                }
                IndexEventKind::Tombstone => {
                    // DISK-0071: a remove event does NOT prove the path is gone.
                    // rsync (and any editor doing write-temp-then-rename) emits a
                    // Remove for the temporary name and/or the target while the
                    // final file is present, and tombstoning a live file makes it
                    // permanently undeliverable: the bytes stay on disk, but a
                    // `deleted=1` row is never served to clients and no error is
                    // reported on either side. The Upsert arm already resolves the
                    // path before touching the index; do the same here and treat a
                    // still-existing file as an upsert instead.
                    // Single stat, no retries: `resolve_existing_file` retries for
                    // ~250 ms to let a just-created inode appear, which is right
                    // for Upsert but wrong here — a genuinely deleted path would
                    // pay that cost on every remove event and delay real
                    // tombstones.
                    if let Some(resolved) = resolve_present_file(root, &ev.abs_path) {
                        if let Err(e) =
                            upsert_local_file(&meta_db, &ev.vault_id, &node_id, root, &resolved)
                                .await
                        {
                            tracing::warn!(
                                vault_id = %ev.vault_id,
                                path = %ev.abs_path.display(),
                                error = %e,
                                "share_index upsert-after-remove-event failed"
                            );
                        }
                        continue;
                    }
                    if let Err(e) =
                        tombstone_local_file(&meta_db, &ev.vault_id, &node_id, root, &ev.abs_path)
                            .await
                    {
                        tracing::warn!(
                            vault_id = %ev.vault_id,
                            path = %ev.abs_path.display(),
                            error = %e,
                            "share_index tombstone failed"
                        );
                    }
                }
            }
        }

        // After draining the batch, reconcile if saturation occurred during
        // processing — this recovers events dropped while the channel was full.
        if saturation.swap(false, Ordering::AcqRel) {
            // Count is logged inside full_reconcile; discarding it here is
            // deliberate — the loop has no caller to report it to.
            let _revived = full_reconcile(&meta_db, &node_id, &canonical_roots).await?;
        }
    }
}

/// Walk `root` recursively (no symlink following) and return absolute paths
/// of every regular file.
///
/// Fail-closed: any `read_dir`, `file_type`, or iteration error aborts the
/// entire walk with a typed [`ShareIndexError`] so reconciliation cannot
/// silently miss a subtree.
/// Directory names the server itself writes inside a share root. They must
/// never enter the index.
///
/// DISK-0077: `.version-blobs` is the server's own content-addressed version
/// store, constructed as `cfg.sync_root.join(".version-blobs")` (see
/// `main.rs`) — i.e. *inside* the tree the share-index watcher observes. Every
/// version the server wrote produced a file under the watched root, the
/// watcher indexed it, and the index grew on its own exhaust: measured on the
/// canon host, a 60s window added 22 rows of which all 22 were
/// `.version-blobs` paths while real content added none, and the store grew
/// ~660MB/hour unbounded. That write stream exhausted SQLite's
/// `busy_timeout` (37 of 129 statements ended at exactly 5.004-5.006s, i.e.
/// they never ran), which starved the client's sync cycle while `/status`
/// still reported `state=syncing, last_error=null`.
///
/// Relocating the store would strand the versions already written under
/// existing roots, so the boundary is drawn here instead: the store stays put
/// and the index refuses to look at it.
const INTERNAL_DIR_NAMES: &[&str] = &[".version-blobs"];

/// True when `path` lies inside one of the server's internal directories
/// relative to `root`.
///
/// Compares path *components* rather than a string prefix: a user file named
/// `.version-blobs-notes.md` must stay indexed, and only a real directory
/// boundary counts.
fn is_internal_path(root: &Path, path: &Path) -> bool {
    let Ok(rel) = path.strip_prefix(root) else {
        return false;
    };
    rel.components().any(|c| {
        matches!(c, std::path::Component::Normal(name)
            if INTERNAL_DIR_NAMES.iter().any(|d| name == std::ffi::OsStr::new(d)))
    })
}

fn walk_files(root: &Path) -> Result<Vec<PathBuf>, ShareIndexError> {
    let mut files = Vec::new();
    walk_files_impl(root, root, &mut files)?;
    Ok(files)
}

fn walk_files_impl(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), ShareIndexError> {
    let iter = std::fs::read_dir(dir).map_err(|source| ShareIndexError::Io {
        path: dir.to_path_buf(),
        source,
    })?;

    for entry in iter {
        let entry = entry.map_err(|source| ShareIndexError::Io {
            path: dir.to_path_buf(),
            source,
        })?;

        let ft = entry.file_type().map_err(|source| ShareIndexError::Io {
            path: entry.path(),
            source,
        })?;

        // Never follow symlinks — filesystem index must reflect only
        // regular files physically under the configured root.
        if ft.is_symlink() {
            continue;
        }

        // DISK-0077: never descend into (or index) the server's own stores.
        if is_internal_path(root, &entry.path()) {
            continue;
        }

        if ft.is_file() {
            // Canonicalize the accepted entry and prove it still lives under
            // the configured root — defends against TOCTOU symlink swaps and
            // hardlink trees that escape the root boundary.
            let canonical =
                std::fs::canonicalize(entry.path()).map_err(|source| ShareIndexError::Io {
                    path: entry.path(),
                    source,
                })?;
            // `dir` is canonical (the root is canonicalized at construction;
            // recursive calls pass canonicalized directory paths). Any
            // non-symlink child must canonicalize under `dir`.
            if !canonical.starts_with(dir) {
                tracing::warn!(
                    path = %canonical.display(),
                    root = %dir.display(),
                    "share_index: canonicalized entry escaped configured root — skipped"
                );
                continue;
            }
            out.push(canonical);
        } else if ft.is_dir() {
            let canonical =
                std::fs::canonicalize(entry.path()).map_err(|source| ShareIndexError::Io {
                    path: entry.path(),
                    source,
                })?;
            if !canonical.starts_with(dir) {
                tracing::warn!(
                    path = %canonical.display(),
                    root = %dir.display(),
                    "share_index: canonicalized directory escaped configured root — skipped"
                );
                continue;
            }
            walk_files_impl(root, &canonical, out)?;
        }
        // else: skip block devices, FIFOs, sockets, etc.
    }
    Ok(())
}

/// Full loss-recovery reconciliation across every configured share root.
///
/// * Upserts every regular file found on disk.
/// * Tombstones every non-deleted MetaDb row whose on-disk file no longer
///   exists.
///
/// **Fail-closed**: every filesystem walk and every DB-list runs *before* the
/// first `upsert`/`tombstone` mutation.  A transient unreadable subtree, a
/// broken symlink, or a transient I/O error on any vault aborts the entire
/// reconciliation with a typed [`ShareIndexError`], leaving every existing
/// index row unchanged.
///
/// Called by [`run_index_loop`] when the saturation flag is raised by a
/// callback that could not `try_send` because the bounded channel was full.
/// Returns the number of rows that claimed `deleted=1` while their file was
/// present on disk — silently undeliverable paths this pass revived (DISK-0071).
/// DISK-0080: drop legacy `vault_id = "default"` rows that shadow a configured
/// share.
///
/// `MetaDb::upsert_file()` — the unscoped wrapper — silently wrote
/// `vault_id="default"`. One production caller used it (the client's E2EE wire
/// index, fixed in #171) while every other writer scoped by share name, so a
/// path could end up with two live rows carrying different content hashes. The
/// server then advertised metadata from one row while serving bytes matching
/// the other, and the client's hash check rejected every download and retried
/// forever, because a hash mismatch is never transient.
///
/// Measured on the canon host before this sweep: 669 paths lived under both
/// `datarim-kb` and `default`, of which 6 disagreed on `content_hash`. For all
/// six the share-scoped row matched the bytes on disk — verified by blake3, not
/// by size alone — and the `default` row was an older copy (smaller, and with
/// an earlier mtime in every case).
///
/// The rule is deliberately narrow: a `default` row is removed **only** when
/// the same path also exists under a configured share. A `default` row for a
/// path no share claims is left untouched, because this function cannot know
/// whether some other deployment owns it. Removing rows we cannot attribute
/// would trade a delivery bug for data loss.
async fn sweep_shadowed_default_rows(
    meta_db: &MetaDb,
    canonical_roots: &HashMap<String, PathBuf>,
) -> Result<usize, ShareIndexError> {
    const LEGACY_VAULT: &str = "default";

    // A configured share literally named "default" is its own owner — nothing
    // to sweep, and sweeping would delete live rows.
    if canonical_roots.contains_key(LEGACY_VAULT) {
        return Ok(0);
    }

    let legacy_rows = meta_db.list_files_scoped(None, LEGACY_VAULT).await?;
    if legacy_rows.is_empty() {
        return Ok(0);
    }

    // Paths claimed by a configured share.
    let mut claimed: std::collections::HashSet<String> = std::collections::HashSet::new();
    for vault_id in canonical_roots.keys() {
        for row in meta_db.list_files_scoped(None, vault_id).await? {
            claimed.insert(row.path.to_string_lossy().to_string());
        }
    }

    let mut removed = 0usize;
    for row in legacy_rows {
        let path = row.path.to_string_lossy().to_string();
        if !claimed.contains(&path) {
            continue; // not ours to judge
        }
        if let Err(e) = meta_db.delete_file_scoped(None, LEGACY_VAULT, &path).await {
            tracing::warn!(
                path = %path,
                error = %e,
                "share_index: could not remove shadowed legacy row"
            );
            continue;
        }
        removed += 1;
    }

    if removed > 0 {
        tracing::warn!(
            removed,
            "share_index removed legacy vault_id=\"default\" rows shadowing a configured share (DISK-0080)"
        );
    }
    Ok(removed)
}

async fn full_reconcile(
    meta_db: &MetaDb,
    node_id: &str,
    canonical_roots: &HashMap<String, PathBuf>,
) -> Result<usize, ShareIndexError> {
    // ── Phase 1: gather everything (no mutation) ──
    // Walk filesystem (fail-closed — any I/O error aborts).
    let mut vault_files: HashMap<&str, Vec<PathBuf>> = HashMap::new();
    for (vault_id, root) in canonical_roots {
        vault_files.insert(vault_id, walk_files(root)?);
    }

    // List DB (fail-closed — any query error aborts).
    let mut vault_db_rows: HashMap<&str, Vec<disk_core::types::FileMeta>> = HashMap::new();
    for vault_id in canonical_roots.keys() {
        vault_db_rows.insert(vault_id, meta_db.list_files_scoped(None, vault_id).await?);
    }

    // ── Phase 2: apply mutations ──
    // DISK-0080: clear legacy shadow rows first, so the reconcile below sees a
    // single row per path and cannot re-derive a conflicting hash.
    let _swept = sweep_shadowed_default_rows(meta_db, canonical_roots).await?;
    let mut revived_total = 0usize;
    for (vault_id, root) in canonical_roots {
        let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();

        if let Some(file_list) = vault_files.get(vault_id.as_str()) {
            for abs in file_list {
                seen.insert(abs.clone());
                if let Err(e) = upsert_local_file(meta_db, vault_id, node_id, root, abs).await {
                    tracing::warn!(
                        vault_id = %vault_id,
                        path = %abs.display(),
                        error = %e,
                        "share_index reconcile upsert failed"
                    );
                }
            }
        }

        // Tombstone rows for files that disappeared from disk.
        if let Some(tracked) = vault_db_rows.get(vault_id.as_str()) {
            // DISK-0071: count rows that claim the path is deleted while its bytes
            // are on disk. Such a row is never served to any client and reports no
            // error anywhere — the failure is completely silent, which is how ~332
            // of them accumulated unnoticed on arcana-agents. The upsert pass above
            // has already revived these, so this is the pre-reconcile divergence:
            // a non-zero count means clients were being denied files that existed.
            let revived_from_tombstone = tracked
                .iter()
                .filter(|row| row.deleted && seen.contains(&root.join(&row.path)))
                .count();
            revived_total += revived_from_tombstone;
            if revived_from_tombstone > 0 {
                tracing::warn!(
                    vault_id = %vault_id,
                    revived = revived_from_tombstone,
                    "share_index reconcile revived rows tombstoned while their files \
                     were present on disk — those paths were silently undeliverable"
                );
            }

            for file_meta in tracked {
                if file_meta.deleted {
                    continue;
                }
                let abs = root.join(&file_meta.path);
                if !seen.contains(&abs) {
                    if let Err(e) =
                        tombstone_local_file(meta_db, vault_id, node_id, root, &abs).await
                    {
                        tracing::warn!(
                            vault_id = %vault_id,
                            path = %abs.display(),
                            error = %e,
                            "share_index reconcile tombstone failed"
                        );
                    }
                }
            }
        }
    }
    Ok(revived_total)
}

async fn upsert_local_file(
    meta_db: &MetaDb,
    vault_id: &str,
    node_id: &str,
    root: &Path,
    abs: &Path,
) -> Result<(), ShareIndexError> {
    let canonical_entry = match resolve_existing_file(root, abs).await {
        Some(p) => p,
        None => return Ok(()),
    };
    if !canonical_entry.starts_with(root) {
        return Ok(());
    }
    // Re-check with symlink_metadata — resolve_existing_file already filters
    // symlinks, but this second check guards against TOCTOU races.
    let ft = std::fs::symlink_metadata(&canonical_entry)
        .map_err(|e| ShareIndexError::Io {
            path: canonical_entry.clone(),
            source: e,
        })?
        .file_type();
    if ft.is_symlink() || !ft.is_file() {
        return Ok(());
    }
    let rel = canonical_entry
        .strip_prefix(root)
        .map_err(|_| ShareIndexError::MissingRoot(root.to_path_buf()))?
        .to_path_buf();
    if rel.as_os_str().is_empty() {
        return Ok(());
    }

    let metadata = std::fs::metadata(&canonical_entry).map_err(|e| ShareIndexError::Io {
        path: canonical_entry.clone(),
        source: e,
    })?;
    let content_hash = hash_file(&canonical_entry)?;
    let meta = FileMeta {
        path: rel,
        content_hash,
        size: metadata.len(),
        mtime_ns: mtime_nanos(&metadata),
        inode: disk_core::platform::inode_from_path(&canonical_entry),
        vector_clock: VectorClock::default(),
        deleted: false,
        deleted_at: None,
        node_id: node_id.to_string(),
        encryption_nonce: None,
        version_id: None,
        parent_version_id: None,
    };
    meta_db.upsert_file_scoped(None, vault_id, &meta).await?;
    Ok(())
}

/// Resolve `abs` only if it is a regular file inside `root`, in one stat.
///
/// DISK-0071 uses this on remove events: a rename-over-target (rsync, editors)
/// emits a Remove while the final file is present, and tombstoning a live file
/// makes it permanently undeliverable. Unlike [`resolve_existing_file`] this
/// never retries — a genuinely deleted path must be tombstoned immediately, not
/// after a quarter-second of waiting.
fn resolve_present_file(root: &Path, abs: &Path) -> Option<PathBuf> {
    let meta = std::fs::symlink_metadata(abs).ok()?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return None;
    }
    if !abs.starts_with(root) {
        return None;
    }
    let canonical = std::fs::canonicalize(abs).ok()?;
    canonical.starts_with(root).then_some(canonical)
}

/// `notify` can fire before the inode is visible; retry briefly.
///
/// Never follows symlinks — uses `symlink_metadata` + `is_file` check on the
/// file type, and rejects symlink entries before canonicalization.
async fn resolve_existing_file(root: &Path, abs: &Path) -> Option<PathBuf> {
    for attempt in 0..6 {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        // Use symlink_metadata so we never follow a symlink to a target
        // outside the configured root.
        if let Ok(meta) = std::fs::symlink_metadata(abs) {
            if meta.file_type().is_symlink() {
                return None;
            }
            if !meta.is_file() {
                return None;
            }
            if abs.starts_with(root) {
                if let Ok(c) = std::fs::canonicalize(abs) {
                    if c.starts_with(root) {
                        return Some(c);
                    }
                }
            }
        }
    }
    None
}

async fn tombstone_local_file(
    meta_db: &MetaDb,
    vault_id: &str,
    node_id: &str,
    root: &Path,
    abs: &Path,
) -> Result<(), ShareIndexError> {
    let rel = if let Ok(r) = abs.strip_prefix(root) {
        r.to_path_buf()
    } else if let Ok(c) = std::fs::canonicalize(abs) {
        c.strip_prefix(root)
            .map(|r| r.to_path_buf())
            .unwrap_or_default()
    } else {
        PathBuf::new()
    };
    if rel.as_os_str().is_empty() {
        return Err(ShareIndexError::MissingRoot(root.to_path_buf()));
    }

    let path_str = rel.to_string_lossy().replace('\\', "/");
    let now_secs = unix_now_secs();
    let existing = meta_db.get_file_scoped(None, vault_id, &path_str).await?;
    let tombstone = if let Some(mut row) = existing {
        row.deleted = true;
        row.deleted_at = Some(now_secs);
        row
    } else {
        FileMeta {
            path: rel,
            content_hash: [0u8; 32],
            size: 0,
            mtime_ns: 0,
            inode: None,
            vector_clock: VectorClock::default(),
            deleted: true,
            deleted_at: Some(now_secs),
            node_id: node_id.to_string(),
            encryption_nonce: None,
            version_id: None,
            parent_version_id: None,
        }
    };
    meta_db
        .upsert_file_scoped(None, vault_id, &tombstone)
        .await?;
    Ok(())
}

#[cfg(unix)]
fn mtime_nanos(m: &std::fs::Metadata) -> i64 {
    use std::os::unix::fs::MetadataExt;
    m.mtime() * 1_000_000_000 + i64::from(m.mtime_nsec() as i32)
}

#[cfg(not(unix))]
fn mtime_nanos(m: &std::fs::Metadata) -> i64 {
    m.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

fn unix_now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {

    // ── DISK-0080: legacy shadow rows ──────────────────────────────────────

    async fn seed_row(db: &MetaDb, vault: &str, path: &str, hash: [u8; 32], size: u64) {
        let meta = disk_core::types::FileMeta {
            path: PathBuf::from(path),
            content_hash: hash,
            size,
            mtime_ns: 1,
            inode: None,
            vector_clock: disk_core::VectorClock::default(),
            deleted: false,
            deleted_at: None,
            node_id: "seed".into(),
            encryption_nonce: None,
            version_id: None,
            parent_version_id: None,
        };
        db.upsert_file_scoped(None, vault, &meta).await.unwrap();
    }

    /// A `default` row that shadows a path a configured share also holds is the
    /// exact shape that broke delivery: two live rows, different hashes, so the
    /// server advertised one and served the other and the client retried
    /// forever. It must go.
    #[tokio::test]
    async fn sweep_removes_a_default_row_shadowing_a_configured_share() {
        let dir = tempfile::tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("meta.sqlite")).await.unwrap();
        let root = dir.path().join("kb");
        std::fs::create_dir_all(&root).unwrap();
        let root = std::fs::canonicalize(&root).unwrap();

        seed_row(&db, "kb", "notes/a.md", [0xAA; 32], 10).await;
        seed_row(&db, "default", "notes/a.md", [0xBB; 32], 7).await;

        let mut roots = HashMap::new();
        roots.insert("kb".to_string(), root);

        let removed = sweep_shadowed_default_rows(&db, &roots).await.unwrap();
        assert_eq!(removed, 1, "the shadowing row must be removed");

        let left = db.list_files_scoped(None, "default").await.unwrap();
        assert!(left.is_empty(), "no shadow row may survive: {left:?}");

        let kept = db.list_files_scoped(None, "kb").await.unwrap();
        assert_eq!(kept.len(), 1, "the share-scoped row must survive untouched");
        assert_eq!(
            kept[0].content_hash, [0xAA; 32],
            "the surviving row must be the share's own, not the legacy copy"
        );
    }

    /// The sweep must NOT touch a `default` row for a path no configured share
    /// claims. This function cannot know whether another deployment owns it,
    /// and deleting what we cannot attribute would trade a delivery bug for
    /// data loss.
    #[tokio::test]
    async fn sweep_leaves_unclaimed_default_rows_alone() {
        let dir = tempfile::tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("meta.sqlite")).await.unwrap();
        let root = dir.path().join("kb");
        std::fs::create_dir_all(&root).unwrap();
        let root = std::fs::canonicalize(&root).unwrap();

        seed_row(&db, "kb", "notes/a.md", [0xAA; 32], 10).await;
        seed_row(&db, "default", "somewhere/else.md", [0xCC; 32], 5).await;

        let mut roots = HashMap::new();
        roots.insert("kb".to_string(), root);

        let removed = sweep_shadowed_default_rows(&db, &roots).await.unwrap();
        assert_eq!(removed, 0, "an unclaimed legacy row must not be removed");
        assert_eq!(
            db.list_files_scoped(None, "default").await.unwrap().len(),
            1,
            "the unclaimed row must still be there"
        );
    }

    /// If a share is genuinely named "default" it owns those rows, and sweeping
    /// would delete live data.
    #[tokio::test]
    async fn sweep_is_a_noop_when_default_is_itself_a_configured_share() {
        let dir = tempfile::tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("meta.sqlite")).await.unwrap();
        let root = dir.path().join("default");
        std::fs::create_dir_all(&root).unwrap();
        let root = std::fs::canonicalize(&root).unwrap();

        seed_row(&db, "default", "notes/a.md", [0xAA; 32], 10).await;

        let mut roots = HashMap::new();
        roots.insert("default".to_string(), root);

        let removed = sweep_shadowed_default_rows(&db, &roots).await.unwrap();
        assert_eq!(removed, 0);
        assert_eq!(
            db.list_files_scoped(None, "default").await.unwrap().len(),
            1,
            "a configured share named default must keep its rows"
        );
    }

    // ── DISK-0077: the server's own stores must never enter the index ──

    #[test]
    fn walk_files_skips_the_servers_own_version_store() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();

        // Real content: must be indexed.
        std::fs::write(root.join("note.md"), b"real").unwrap();
        std::fs::create_dir_all(root.join("qa/run-1")).unwrap();
        std::fs::write(root.join("qa/run-1/shot.png"), b"png").unwrap();

        // The server's own version store, nested exactly as main.rs builds it.
        std::fs::create_dir_all(root.join(".version-blobs/ab")).unwrap();
        std::fs::write(root.join(".version-blobs/ab/deadbeef"), b"blob").unwrap();
        std::fs::create_dir_all(root.join(".version-blobs/cd")).unwrap();
        std::fs::write(root.join(".version-blobs/cd/cafebabe"), b"blob").unwrap();

        let found = walk_files(&root).unwrap();
        let rel: Vec<String> = found
            .iter()
            .map(|p| {
                p.strip_prefix(&root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();

        // Without the filter this walk returns 4 entries and the assertion below
        // fails on the two blob paths — that failure is the point of the test.
        assert!(
            rel.contains(&"note.md".to_string()),
            "real content dropped: {rel:?}"
        );
        assert!(
            rel.contains(&"qa/run-1/shot.png".to_string()),
            "nested real content dropped: {rel:?}"
        );
        assert!(
            !rel.iter().any(|r| r.starts_with(".version-blobs/")),
            "server version store leaked into the index: {rel:?}"
        );
        assert_eq!(rel.len(), 2, "unexpected entries: {rel:?}");
    }

    #[test]
    fn watcher_events_for_the_version_store_are_dropped() {
        use notify::event::{CreateKind, EventKind};

        let root = PathBuf::from("/share");
        let blob = root.join(".version-blobs/ab/deadbeef");
        let real = root.join("qa/shot.png");

        let ev = notify::Event {
            kind: EventKind::Create(CreateKind::File),
            paths: vec![blob, real.clone()],
            attrs: notify::event::EventAttributes::default(),
        };

        let out = translate_notify_event(&ev, "v", &root);
        assert_eq!(
            out.len(),
            1,
            "expected only the real path to survive: {out:?}"
        );
        assert_eq!(out[0].abs_path, real);
    }

    #[test]
    fn a_user_file_named_like_the_store_is_still_indexed() {
        // The filter compares path components, not string prefixes: a file whose
        // name merely begins with the store's name is user content.
        let root = PathBuf::from("/share");
        assert!(is_internal_path(&root, &root.join(".version-blobs/ab/x")));
        assert!(!is_internal_path(
            &root,
            &root.join(".version-blobs-notes.md")
        ));
        assert!(!is_internal_path(
            &root,
            &root.join("qa/.version-blobs-report.md")
        ));
        // A path outside the root is not ours to judge.
        assert!(!is_internal_path(
            &root,
            &PathBuf::from("/elsewhere/.version-blobs/x")
        ));
    }

    use super::*;
    use std::cell::Cell;

    /// DISK-0071: the predicate that keeps a remove event from tombstoning a
    /// live file. `translate_notify_event` maps EVERY `Remove` kind to
    /// `Tombstone`, and a rename-over-target (rsync, editors) emits one while the
    /// final file is present. Tombstoning then makes the path permanently
    /// undeliverable — bytes on disk, `deleted=1` in the index, no error on
    /// either side. On arcana-agents that left 19 of 23 re-delivered artefacts
    /// unreachable.
    #[test]
    fn resolve_present_file_distinguishes_live_from_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let live = root.join("live.md");
        std::fs::write(&live, b"content").unwrap();

        assert!(
            resolve_present_file(&root, &live).is_some(),
            "a regular file inside the root must be recognised as present"
        );

        let gone = root.join("gone.md");
        assert!(
            resolve_present_file(&root, &gone).is_none(),
            "a path with no file must NOT be reported present — a genuine delete \
             still has to produce a tombstone"
        );

        // A remove event for a path that was replaced in place: the temporary
        // name is gone, the target is present. Only the target may survive.
        let tmp = root.join(".live.md.a1b2c3");
        std::fs::write(&tmp, b"newer-content").unwrap();
        std::fs::rename(&tmp, &live).unwrap();
        assert!(
            resolve_present_file(&root, &tmp).is_none(),
            "the consumed temporary name must not be reported present"
        );
        assert!(
            resolve_present_file(&root, &live).is_some(),
            "the replaced target must be reported present, so the remove event \
             for it is treated as an upsert instead of a tombstone"
        );

        // A path outside the root must never resolve, even if it exists.
        let outside = dir.path().parent().unwrap().join("escape.md");
        let _ = std::fs::write(&outside, b"x");
        assert!(
            resolve_present_file(&root, &outside).is_none(),
            "a path outside the share root must not resolve"
        );
        let _ = std::fs::remove_file(&outside);
    }

    #[test]
    fn translate_maps_create_to_upsert() {
        use notify::event::{CreateKind, EventKind};
        let root = PathBuf::from("/data/share");
        let ev = notify::Event {
            kind: EventKind::Create(CreateKind::File),
            paths: vec![root.join("a.txt")],
            attrs: notify::event::EventAttributes::default(),
        };
        let out = translate_notify_event(&ev, "hermes-artefacts", &root);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, IndexEventKind::Upsert);
    }

    #[test]
    fn translate_ignores_outside_root() {
        use notify::event::{CreateKind, EventKind};
        let root = PathBuf::from("/data/share");
        let ev = notify::Event {
            kind: EventKind::Create(CreateKind::File),
            paths: vec![PathBuf::from("/other/a.txt")],
            attrs: notify::event::EventAttributes::default(),
        };
        let out = translate_notify_event(&ev, "hermes-artefacts", &root);
        assert!(out.is_empty());
    }

    // ── Rename-mode mapping ──

    #[test]
    fn translate_rename_from_yields_tombstone() {
        use notify::event::{EventKind, ModifyKind, RenameMode};
        let root = PathBuf::from("/data/share");
        let ev = notify::Event {
            kind: EventKind::Modify(ModifyKind::Name(RenameMode::From)),
            paths: vec![root.join("old.txt")],
            attrs: notify::event::EventAttributes::default(),
        };
        let out = translate_notify_event(&ev, "hermes-artefacts", &root);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, IndexEventKind::Tombstone);
        assert_eq!(out[0].abs_path, root.join("old.txt"));
        assert_eq!(out[0].vault_id, "hermes-artefacts");
    }

    #[test]
    fn translate_rename_to_yields_upsert() {
        use notify::event::{EventKind, ModifyKind, RenameMode};
        let root = PathBuf::from("/data/share");
        let ev = notify::Event {
            kind: EventKind::Modify(ModifyKind::Name(RenameMode::To)),
            paths: vec![root.join("new.txt")],
            attrs: notify::event::EventAttributes::default(),
        };
        let out = translate_notify_event(&ev, "hermes-artefacts", &root);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, IndexEventKind::Upsert);
        assert_eq!(out[0].abs_path, root.join("new.txt"));
    }

    #[test]
    fn translate_rename_both_yields_tombstone_from_and_upsert_to() {
        use notify::event::{EventKind, ModifyKind, RenameMode};
        let root = PathBuf::from("/data/share");
        let ev = notify::Event {
            kind: EventKind::Modify(ModifyKind::Name(RenameMode::Both)),
            paths: vec![root.join("old.txt"), root.join("new.txt")],
            attrs: notify::event::EventAttributes::default(),
        };
        let out = translate_notify_event(&ev, "hermes-artefacts", &root);
        assert_eq!(out.len(), 2);
        // From path → Tombstone.
        assert_eq!(out[0].kind, IndexEventKind::Tombstone);
        assert_eq!(out[0].abs_path, root.join("old.txt"));
        // To path → Upsert.
        assert_eq!(out[1].kind, IndexEventKind::Upsert);
        assert_eq!(out[1].abs_path, root.join("new.txt"));
    }

    #[test]
    fn native_success_does_not_construct_poll_fallback() {
        let native_calls = Cell::new(0);
        let poll_calls = Cell::new(0);

        let armed = native_or_poll(
            || {
                native_calls.set(native_calls.get() + 1);
                Ok("native")
            },
            || {
                poll_calls.set(poll_calls.get() + 1);
                Ok("poll")
            },
        )
        .unwrap();

        assert_eq!(armed.backend, WatcherBackend::Native);
        assert_eq!(armed.watcher, "native");
        assert!(armed.native_failure.is_none());
        assert_eq!(native_calls.get(), 1);
        assert_eq!(poll_calls.get(), 0);
    }

    #[test]
    fn native_constructor_failure_arms_poll_fallback() {
        let poll_calls = Cell::new(0);

        let armed = native_or_poll(
            || Err(notify::Error::generic("native constructor failed")),
            || {
                poll_calls.set(poll_calls.get() + 1);
                Ok("poll")
            },
        )
        .unwrap();

        assert_eq!(armed.backend, WatcherBackend::Poll);
        assert_eq!(armed.watcher, "poll");
        assert!(armed
            .native_failure
            .as_deref()
            .is_some_and(|message| message.contains("constructor")));
        assert_eq!(poll_calls.get(), 1);
    }

    #[test]
    fn native_watch_failure_arms_poll_fallback() {
        let armed = native_or_poll(
            || Err(notify::Error::generic("native watch failed")),
            || Ok("poll"),
        )
        .unwrap();

        assert_eq!(armed.backend, WatcherBackend::Poll);
        assert_eq!(armed.watcher, "poll");
        assert!(armed
            .native_failure
            .as_deref()
            .is_some_and(|message| message.contains("watch")));
    }

    #[test]
    fn both_backends_failing_is_fail_closed() {
        let error = native_or_poll::<(), _, _>(
            || Err(notify::Error::generic("native failed")),
            || Err(notify::Error::generic("poll failed")),
        )
        .unwrap_err();

        assert!(error.native.contains("native failed"));
        assert!(error.poll.contains("poll failed"));
    }

    fn sat_flag() -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(false))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn poll_watcher_delivers_an_event() {
        let directory = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(directory.path()).unwrap();
        let target = root.join("poll-probe.txt");
        let (tx, mut rx) = mpsc::channel(8);
        let _watcher = arm_poll_watcher(
            "test-vault",
            &root,
            &tx,
            Duration::from_millis(50),
            sat_flag(),
        )
        .unwrap();

        tokio::time::sleep(Duration::from_millis(100)).await;
        std::fs::write(&target, b"probe").unwrap();

        let received = tokio::time::timeout(Duration::from_secs(3), async {
            while let Some(event) = rx.recv().await {
                if event.abs_path == target {
                    return true;
                }
            }
            false
        })
        .await
        .unwrap_or(false);

        assert!(received, "poll watcher did not emit the file event");
    }

    /// Saturation recovery proof: creates a tiny-capacity channel, fills it,
    /// then performs filesystem mutations (one create, one delete) whose
    /// notify events are guaranteed to be dropped.  A full reconcile driven
    /// by the saturation flag must recover both mutations — the created file
    /// appears as a live MetaDb row and the deleted file is tombstoned —
    /// without any further filesystem event.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn saturation_reconcile_recovers_dropped_create_and_delete() {
        let directory = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(directory.path()).unwrap();
        let db_path = directory.path().join("meta.sqlite");
        let meta_db = MetaDb::open(&db_path).await.unwrap();

        // ── seed a file in MetaDb that we will delete ──
        let delete_target = root.join("recovered-delete.txt");
        std::fs::write(&delete_target, b"delete-me").unwrap();
        meta_db
            .upsert_file_scoped(
                None,
                "v",
                &FileMeta {
                    path: PathBuf::from("recovered-delete.txt"),
                    content_hash: *blake3::hash(b"delete-me").as_bytes(),
                    size: 9,
                    mtime_ns: 0,
                    inode: None,
                    vector_clock: Default::default(),
                    deleted: false,
                    deleted_at: None,
                    node_id: "test".into(),
                    encryption_nonce: None,
                    version_id: None,
                    parent_version_id: None,
                },
            )
            .await
            .unwrap();

        // ── tiny-capacity channel + shared saturation flag ──
        let (tx, mut rx) = mpsc::channel::<IndexEvent>(1);
        let saturation = Arc::new(AtomicBool::new(false));

        // Pre-fill the single slot.
        tx.try_send(IndexEvent {
            vault_id: "v".into(),
            abs_path: root.clone(),
            kind: IndexEventKind::Upsert,
        })
        .unwrap();

        // Arm a poll watcher whose callbacks land on the full channel.
        let _watcher = arm_poll_watcher(
            "v",
            &root,
            &tx,
            Duration::from_millis(50),
            saturation.clone(),
        )
        .unwrap();

        // Let the watcher establish its baseline (one full poll cycle).
        tokio::time::sleep(Duration::from_millis(120)).await;

        // ── mutate: create one file, delete another ──
        let create_target = root.join("recovered-create.txt");
        std::fs::write(&create_target, b"create-me").unwrap();
        std::fs::remove_file(&delete_target).unwrap();

        // Let two poll cycles fire so the watcher detects both mutations
        // and attempts to send through the still-full channel.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // The bounded channel (capacity 1, pre-filled) forces every try_send
        // to return Full — the callback sets the saturation flag.
        assert!(
            saturation.load(Ordering::Acquire),
            "saturation must be signalled after poll detects mutations on full channel"
        );

        // Reset saturation flag, then drain the channel and run the
        // reconcile inline — this is what run_index_loop does.
        saturation.store(false, Ordering::Release);
        while rx.try_recv().is_ok() {}

        let mut roots_map = HashMap::new();
        roots_map.insert("v".to_string(), root.clone());
        full_reconcile(&meta_db, "test", &roots_map).await.unwrap();

        // ── assert: create recovered ──
        let row = meta_db
            .get_file_scoped(None, "v", "recovered-create.txt")
            .await
            .unwrap()
            .expect("created file must be upserted by reconcile");
        assert!(!row.deleted, "created file must not be tombstoned");
        assert_eq!(row.size, 9);

        // ── assert: delete recovered ──
        let row = meta_db
            .get_file_scoped(None, "v", "recovered-delete.txt")
            .await
            .unwrap()
            .expect("deleted file must still have a MetaDb row");
        assert!(row.deleted, "deleted file must be tombstoned by reconcile");

        // ── assert: Drop completes on current thread ──
        drop(_watcher);
    }

    /// Proves `with_compare_contents(true)` detects a content rewrite that
    /// preserves both file size and mtime.  Without `compare_contents` the
    /// PollWatcher would skip the file (no metadata change); the config
    /// set by `arm_poll_watcher` must cause a re-hash and Upsert event.
    #[test]
    fn poll_watcher_detects_same_size_mtime_content_rewrite() {
        let directory = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(directory.path()).unwrap();
        let target = root.join("rewrite.txt");
        let (tx, mut rx) = mpsc::channel(8);

        // Write initial content and capture its mtime.
        std::fs::write(&target, b"AAAA").unwrap();
        let initial_mtime = std::fs::metadata(&target).unwrap().modified().unwrap();

        // Arm a poll watcher that includes compare_contents.
        let _watcher =
            arm_poll_watcher("v", &root, &tx, Duration::from_millis(50), sat_flag()).unwrap();

        // Let the first poll cycle detect the file.
        std::thread::sleep(Duration::from_millis(150));

        // Drain any initial Create event.
        while rx.try_recv().is_ok() {}

        // Rewrite with same length (4 bytes) so size is unchanged.
        std::fs::write(&target, b"BBBB").unwrap();

        // Restore the original mtime — now size AND mtime are identical.
        // Windows requires a write-capable handle for `SetFileTime`; a
        // read-only `File::open` fails with `ERROR_ACCESS_DENIED`.
        std::fs::OpenOptions::new()
            .write(true)
            .open(&target)
            .unwrap()
            .set_modified(initial_mtime)
            .unwrap();

        // Sanity: size and mtime match pre-rewrite state.
        let meta = std::fs::metadata(&target).unwrap();
        assert_eq!(meta.len(), 4);
        assert_eq!(meta.modified().unwrap(), initial_mtime);

        // Poll watcher with compare_contents must detect the content change.
        let deadline = std::time::Instant::now() + Duration::from_secs(8);
        let mut event_received = false;
        while std::time::Instant::now() < deadline {
            if let Ok(event) = rx.try_recv() {
                if event.abs_path == target && event.kind == IndexEventKind::Upsert {
                    event_received = true;
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(60));
        }

        assert!(
            event_received,
            "PollWatcher with compare_contents must emit Upsert for \
             same-size, same-mtime content rewrite"
        );
    }

    // ── Blocker 1: fail-closed walk_files negative control ──

    /// Deterministic negative control: a subdirectory whose read permission
    /// is removed causes `walk_files` to return `Err`, and a subsequent
    /// `full_reconcile` leaves the database unchanged (no partial mutation).
    #[cfg(unix)]
    #[test]
    fn walk_files_fails_on_unreadable_subtree() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();

        // Create a readable file at the top level.
        let visible = root.join("visible.txt");
        std::fs::write(&visible, b"hello").unwrap();

        // Create a subdirectory that we will make unreadable.
        let hidden = root.join("hidden");
        std::fs::create_dir(&hidden).unwrap();
        let secret = hidden.join("secret.txt");
        std::fs::write(&secret, b"classified").unwrap();

        // Prove the walk works before breaking permissions.
        let before = walk_files(&root).unwrap();
        assert!(before.iter().any(|p| p.ends_with("visible.txt")));
        assert!(before.iter().any(|p| p.ends_with("secret.txt")));

        // Remove read permission on the subdirectory.
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&hidden).unwrap().permissions();
        perms.set_mode(0o000);
        std::fs::set_permissions(&hidden, perms).unwrap();

        // walk_files must fail — it cannot read_dir the hidden subdirectory.
        let result = walk_files(&root);
        assert!(
            result.is_err(),
            "walk_files must fail on unreadable subtree"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("hidden") || err_msg.contains("io"),
            "error must mention the inaccessible path: {err_msg}"
        );

        // Restore permissions so tempfile can clean up.
        let mut restore = std::fs::metadata(&hidden).unwrap().permissions();
        restore.set_mode(0o755);
        std::fs::set_permissions(&hidden, restore).unwrap();
    }

    /// A failed `walk_files` (unreadable subtree) must leave every existing
    /// index row unchanged — full_reconcile collects all walks before any
    /// mutation, so the error from the second vault's walk must prevent any
    /// upsert on the first vault.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn full_reconcile_leaves_db_unchanged_on_walk_failure() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("meta.sqlite");
        let meta_db = MetaDb::open(&db_path).await.unwrap();

        // Vault "a" — clean, readable.
        let root_a = dir.path().join("a");
        std::fs::create_dir(&root_a).unwrap();
        let root_a = std::fs::canonicalize(&root_a).unwrap();
        std::fs::write(root_a.join("a.txt"), b"aaa").unwrap();

        // Vault "b" — has a file, then we break the subtree.
        let root_b = dir.path().join("b");
        std::fs::create_dir(&root_b).unwrap();
        let root_b = std::fs::canonicalize(&root_b).unwrap();
        let hidden = root_b.join("hidden");
        std::fs::create_dir(&hidden).unwrap();
        std::fs::write(hidden.join("b.txt"), b"bbb").unwrap();

        // Seed a known row in vault "a" that must survive the failed reconcile.
        let seed_path = PathBuf::from("a.txt");
        let seed_hash = *blake3::hash(b"aaa").as_bytes();
        meta_db
            .upsert_file_scoped(
                None,
                "a",
                &FileMeta {
                    path: seed_path.clone(),
                    content_hash: seed_hash,
                    size: 3,
                    mtime_ns: 0,
                    inode: None,
                    vector_clock: Default::default(),
                    deleted: false,
                    deleted_at: None,
                    node_id: "test".into(),
                    encryption_nonce: None,
                    version_id: None,
                    parent_version_id: None,
                },
            )
            .await
            .unwrap();

        // Break vault "b".
        let mut perms = std::fs::metadata(&hidden).unwrap().permissions();
        perms.set_mode(0o000);
        std::fs::set_permissions(&hidden, perms).unwrap();

        let mut roots = HashMap::new();
        roots.insert("a".to_string(), root_a.clone());
        roots.insert("b".to_string(), root_b.clone());

        let result = full_reconcile(&meta_db, "test", &roots).await;
        assert!(
            result.is_err(),
            "full_reconcile must fail when any vault walk fails"
        );

        // The seed row must be unchanged — no partial mutation from vault "a".
        let row = meta_db
            .get_file_scoped(None, "a", "a.txt")
            .await
            .unwrap()
            .expect("seed row must still exist");
        assert_eq!(row.content_hash, seed_hash);
        assert_eq!(row.size, 3);
        assert!(!row.deleted);

        // Restore permissions.
        let mut restore = std::fs::metadata(&hidden).unwrap().permissions();
        restore.set_mode(0o755);
        std::fs::set_permissions(&hidden, restore).unwrap();
    }

    /// DISK-0071: reconciliation must report how many rows claimed `deleted=1`
    /// while their file was on disk. Those paths are served to nobody and raise
    /// no error anywhere, which is how ~332 of them piled up unnoticed on
    /// arcana-agents. A count is the only way an operator learns it happened.
    #[tokio::test]
    async fn full_reconcile_reports_rows_revived_from_tombstone() {
        let directory = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(directory.path()).unwrap();
        let meta_db = MetaDb::open(&directory.path().join("meta.sqlite"))
            .await
            .unwrap();

        let seed_tombstone = |name: &str| {
            let db = meta_db.clone();
            let name = name.to_string();
            async move {
                db.upsert_file_scoped(
                    None,
                    "v",
                    &FileMeta {
                        path: PathBuf::from(&name),
                        content_hash: [0u8; 32],
                        size: 0,
                        mtime_ns: 0,
                        inode: None,
                        vector_clock: Default::default(),
                        deleted: true,
                        deleted_at: Some(1),
                        node_id: "test".into(),
                        encryption_nonce: None,
                        version_id: None,
                        parent_version_id: None,
                    },
                )
                .await
                .unwrap();
            }
        };

        // Two tombstoned rows whose bytes ARE on disk — the silent-failure case.
        std::fs::write(root.join("present-a.md"), b"aaa").unwrap();
        std::fs::write(root.join("present-b.md"), b"bbbb").unwrap();
        seed_tombstone("present-a.md").await;
        seed_tombstone("present-b.md").await;

        // One tombstoned row whose file really is gone — a correct tombstone that
        // must NOT be counted, or the number would just measure tombstones.
        seed_tombstone("really-gone.md").await;

        let mut roots = HashMap::new();
        roots.insert("v".to_string(), root.clone());

        let revived = full_reconcile(&meta_db, "test", &roots).await.unwrap();
        assert_eq!(
            revived, 2,
            "only the two tombstoned rows whose files exist may be counted"
        );

        // And the count must reflect real repair, not just arithmetic.
        for name in ["present-a.md", "present-b.md"] {
            let row = meta_db
                .get_file_scoped(None, "v", name)
                .await
                .unwrap()
                .expect("row must exist");
            assert!(!row.deleted, "{name} must be live after reconcile");
        }
        let gone = meta_db
            .get_file_scoped(None, "v", "really-gone.md")
            .await
            .unwrap()
            .expect("row must exist");
        assert!(
            gone.deleted,
            "a genuinely missing file must stay tombstoned"
        );

        // A second pass has nothing left to revive.
        let again = full_reconcile(&meta_db, "test", &roots).await.unwrap();
        assert_eq!(again, 0, "a clean reconcile must report zero revivals");
    }

    // ── Blocker 2: never follow symlinks ──

    /// A symlink file whose target resides outside the configured root must
    /// be skipped by `walk_files` and must not produce a MetaDb row during
    /// `full_reconcile`.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn symlink_file_outside_root_is_skipped_no_db_mutation() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();

        // Real file inside root — should be indexed.
        let inside = root.join("inside.txt");
        std::fs::write(&inside, b"inside").unwrap();

        // Real file OUTSIDE the root.
        let outside_dir = tempfile::tempdir().unwrap();
        let outside = outside_dir.path().join("outside.txt");
        std::fs::write(&outside, b"outside").unwrap();

        // Symlink inside root → outside file.
        let symlink = root.join("escape-link.txt");
        std::os::unix::fs::symlink(&outside, &symlink).unwrap();

        // walk_files must only return the real file, not the symlink.
        let files = walk_files(&root).unwrap();
        let paths: Vec<_> = files
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap())
            .collect();
        assert!(paths.contains(&"inside.txt"), "real file must be listed");
        assert!(
            !paths.contains(&"escape-link.txt"),
            "symlink file must be skipped"
        );

        // full_reconcile must not mutate anything for the symlink path.
        let db_path = dir.path().join("meta.sqlite");
        let meta_db = MetaDb::open(&db_path).await.unwrap();
        let mut roots = HashMap::new();
        roots.insert("v".to_string(), root.clone());
        full_reconcile(&meta_db, "test", &roots).await.unwrap();

        // The real file is indexed.
        let row = meta_db
            .get_file_scoped(None, "v", "inside.txt")
            .await
            .unwrap()
            .expect("real file must be indexed");
        assert!(!row.deleted);

        // The symlink path must NOT be indexed.
        assert!(
            meta_db
                .get_file_scoped(None, "v", "escape-link.txt")
                .await
                .unwrap()
                .is_none(),
            "symlink-to-outside must not be indexed"
        );

        // The outside file must NOT leak into the index through the symlink.
        assert!(
            meta_db
                .get_file_scoped(None, "v", "outside.txt")
                .await
                .unwrap()
                .is_none(),
            "outside target must not leak into index"
        );
    }

    /// A symlink directory whose target resides outside the configured root
    /// must be skipped entirely — none of its children must appear.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn symlink_dir_outside_root_is_skipped_no_children_indexed() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();

        // Real file inside root.
        let inside = root.join("inside.txt");
        std::fs::write(&inside, b"inside").unwrap();

        // Directory outside root with a file in it.
        let outside_dir = tempfile::tempdir().unwrap();
        let outside_child = outside_dir.path().join("stowaway.txt");
        std::fs::write(&outside_child, b"stowaway").unwrap();

        // Symlink directory inside root → outside directory.
        let symlink_dir = root.join("escape-dir");
        std::os::unix::fs::symlink(outside_dir.path(), &symlink_dir).unwrap();

        // walk_files must skip the symlink directory and its children.
        let files = walk_files(&root).unwrap();
        let paths: Vec<_> = files
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap())
            .collect();
        assert!(paths.contains(&"inside.txt"), "real file must be listed");
        assert!(
            !paths.contains(&"stowaway.txt"),
            "symlink-dir child must be skipped"
        );

        // full_reconcile must not index the stowaway.
        let db_path = dir.path().join("meta.sqlite");
        let meta_db = MetaDb::open(&db_path).await.unwrap();
        let mut roots = HashMap::new();
        roots.insert("v".to_string(), root.clone());
        full_reconcile(&meta_db, "test", &roots).await.unwrap();

        assert!(
            meta_db
                .get_file_scoped(None, "v", "stowaway.txt")
                .await
                .unwrap()
                .is_none(),
            "symlink-dir child must not be indexed"
        );
        assert!(
            meta_db
                .get_file_scoped(None, "v", "inside.txt")
                .await
                .unwrap()
                .is_some(),
            "real file must still be indexed"
        );
    }

    // ── Blocker 3: real run_index_loop saturation path ──

    /// Drives the real `run_index_loop` with a capacity-1 channel.  Pre-fills
    /// the channel, injects one create, one modify, and one delete mutation
    /// while the channel is full, and proves the loop observes the shared
    /// saturation flag, reconciles once, and persists all three mutations —
    /// all without the test manually clearing the flag or calling
    /// `full_reconcile`.  Asserts bounded successful loop shutdown (the loop
    /// must exit `Ok(())` when the channel closes, not discard a timeout).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_index_loop_saturation_reconciles_autonomously() {
        let directory = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(directory.path()).unwrap();
        let db_path = directory.path().join("meta.sqlite");
        let meta_db = MetaDb::open(&db_path).await.unwrap();

        // ── Seed a file we will modify ──
        let modify_target = root.join("loop-modify.txt");
        std::fs::write(&modify_target, b"original").unwrap();
        let original_hash = *blake3::hash(b"original").as_bytes();
        meta_db
            .upsert_file_scoped(
                None,
                "v",
                &FileMeta {
                    path: PathBuf::from("loop-modify.txt"),
                    content_hash: original_hash,
                    size: 8,
                    mtime_ns: 0,
                    inode: None,
                    vector_clock: Default::default(),
                    deleted: false,
                    deleted_at: None,
                    node_id: "test".into(),
                    encryption_nonce: None,
                    version_id: None,
                    parent_version_id: None,
                },
            )
            .await
            .unwrap();

        // ── Seed a file we will delete ──
        let delete_target = root.join("loop-delete.txt");
        std::fs::write(&delete_target, b"delete-me").unwrap();
        meta_db
            .upsert_file_scoped(
                None,
                "v",
                &FileMeta {
                    path: PathBuf::from("loop-delete.txt"),
                    content_hash: *blake3::hash(b"delete-me").as_bytes(),
                    size: 9,
                    mtime_ns: 0,
                    inode: None,
                    vector_clock: Default::default(),
                    deleted: false,
                    deleted_at: None,
                    node_id: "test".into(),
                    encryption_nonce: None,
                    version_id: None,
                    parent_version_id: None,
                },
            )
            .await
            .unwrap();

        // Capacity-1 channel — pre-fill it.
        let (tx, rx) = mpsc::channel::<IndexEvent>(1);
        tx.try_send(IndexEvent {
            vault_id: "v".into(),
            abs_path: root.clone(),
            kind: IndexEventKind::Upsert,
        })
        .unwrap();

        let saturation = Arc::new(AtomicBool::new(false));

        // Arm a poll watcher that will saturate.
        let _watcher = arm_poll_watcher(
            "v",
            &root,
            &tx,
            Duration::from_millis(50),
            saturation.clone(),
        )
        .unwrap();

        // Let the watcher establish its baseline.
        tokio::time::sleep(Duration::from_millis(120)).await;

        // ── Mutate: create, modify, delete while channel is full ──
        let create_target = root.join("loop-create.txt");
        std::fs::write(&create_target, b"create-me").unwrap();
        // Modify the seeded file — same-length rewrite so size is unchanged.
        std::fs::write(&modify_target, b"MODIFIED").unwrap();
        std::fs::remove_file(&delete_target).unwrap();

        // Let poll cycles fire — callbacks will set saturation flag.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Saturation must be signalled.
        assert!(
            saturation.load(Ordering::Acquire),
            "saturation must be signalled"
        );

        // Build canonical_roots and spawn the real loop.
        let mut roots_map = HashMap::new();
        roots_map.insert("v".to_string(), root.clone());

        // Spawn the loop — it must observe saturation on first iteration
        // and invoke full_reconcile before processing any event.
        let loop_meta = meta_db.clone();
        let loop_roots = roots_map.clone();
        let loop_sat = saturation.clone();
        let loop_handle = tokio::spawn(async move {
            run_index_loop(rx, loop_meta, "test".into(), loop_roots, loop_sat).await
        });

        // Wait for the loop to process.
        tokio::time::sleep(Duration::from_millis(500)).await;

        // ── assert: create recovered by autonomous reconcile ──
        let created = meta_db
            .get_file_scoped(None, "v", "loop-create.txt")
            .await
            .unwrap()
            .expect("created file must be upserted by autonomous reconcile");
        assert!(!created.deleted, "created file must not be tombstoned");
        assert_eq!(created.size, 9);

        // ── assert: modify recovered by autonomous reconcile ──
        let modified = meta_db
            .get_file_scoped(None, "v", "loop-modify.txt")
            .await
            .unwrap()
            .expect("modified file must be updated by autonomous reconcile");
        assert!(!modified.deleted, "modified file must not be tombstoned");
        assert_eq!(modified.size, 8);
        assert_ne!(
            modified.content_hash, original_hash,
            "modified file hash must differ from original content"
        );
        assert_eq!(
            modified.content_hash,
            *blake3::hash(b"MODIFIED").as_bytes(),
            "modified file hash must match new content"
        );

        // ── assert: delete recovered by autonomous reconcile ──
        let deleted = meta_db
            .get_file_scoped(None, "v", "loop-delete.txt")
            .await
            .unwrap()
            .expect("deleted file must still have a MetaDb row");
        assert!(deleted.deleted, "deleted file must be tombstoned");

        // ── Bounded shutdown: drop watcher + tx; loop must exit Ok(()) ──
        drop(_watcher);
        drop(tx);
        let loop_result = tokio::time::timeout(Duration::from_secs(5), loop_handle)
            .await
            .expect("loop must shut down within bounded timeout")
            .expect("loop task must not panic");
        assert!(
            loop_result.is_ok(),
            "loop must exit with Ok when channel closes"
        );
    }

    /// Drives a real watcher for vault "a" to saturation, then proves
    /// cross-vault correctness through the real [`run_index_loop`] with both
    /// vaults in [`canonical_roots`] — respecting the production contract that
    /// [`full_reconcile`] processes every configured root on every invocation.
    ///
    /// **Proof delivered:** no cross-vault misattribution.  Vault "b"'s seeded
    /// row is correctly reconciled (same content hash, same size, not
    /// deleted).  No path owned by vault "a" appears under vault "b" in
    /// MetaDb, and no path owned by vault "b" appears under vault "a".
    /// Deletion and upsert semantics are correct within each vault.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cross_vault_reconcile_no_misattribution() {
        let directory = tempfile::tempdir().unwrap();

        // Vault "a" — the one whose channel saturates.
        std::fs::create_dir_all(directory.path().join("a")).unwrap();
        let root_a = std::fs::canonicalize(directory.path().join("a")).unwrap();

        // Vault "b" — globally reconciled; saturation must not cause misattribution.
        std::fs::create_dir_all(directory.path().join("b")).unwrap();
        let root_b = std::fs::canonicalize(directory.path().join("b")).unwrap();
        let file_b = root_b.join("b.txt");
        std::fs::write(&file_b, b"bbbb").unwrap();

        let db_path = directory.path().join("meta.sqlite");
        let meta_db = MetaDb::open(&db_path).await.unwrap();

        // Seed a vault "b" row whose content identity and live state must survive reconcile.
        let b_hash = *blake3::hash(b"bbbb").as_bytes();
        meta_db
            .upsert_file_scoped(
                None,
                "b",
                &FileMeta {
                    path: PathBuf::from("b.txt"),
                    content_hash: b_hash,
                    size: 4,
                    mtime_ns: 0,
                    inode: None,
                    vector_clock: Default::default(),
                    deleted: false,
                    deleted_at: None,
                    node_id: "test".into(),
                    encryption_nonce: None,
                    version_id: None,
                    parent_version_id: None,
                },
            )
            .await
            .unwrap();

        // Seed a row in vault "a" that we will delete and re-index.
        let a_file = root_a.join("a.txt");
        std::fs::write(&a_file, b"aaaa").unwrap();
        meta_db
            .upsert_file_scoped(
                None,
                "a",
                &FileMeta {
                    path: PathBuf::from("a.txt"),
                    content_hash: *blake3::hash(b"aaaa").as_bytes(),
                    size: 4,
                    mtime_ns: 0,
                    inode: None,
                    vector_clock: Default::default(),
                    deleted: false,
                    deleted_at: None,
                    node_id: "test".into(),
                    encryption_nonce: None,
                    version_id: None,
                    parent_version_id: None,
                },
            )
            .await
            .unwrap();

        // ── Build a real watcher for vault "a" with a capacity-1 channel ──
        let (tx, rx) = mpsc::channel::<IndexEvent>(1);
        // Pre-fill the single slot to guarantee saturation.
        tx.try_send(IndexEvent {
            vault_id: "a".into(),
            abs_path: root_a.clone(),
            kind: IndexEventKind::Upsert,
        })
        .unwrap();

        let saturation = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        let watcher_vault = "a".to_string();
        let watcher_root = root_a.clone();
        let watcher_tx = tx.clone();
        let watcher_sat = saturation.clone();
        let watcher_stop = stop.clone();
        let watcher_ready = ready_tx;

        let watcher_thread = std::thread::spawn(move || {
            match arm_poll_watcher(
                &watcher_vault,
                &watcher_root,
                &watcher_tx,
                Duration::from_millis(50),
                watcher_sat,
            ) {
                Ok(watcher) => {
                    let _ = watcher_ready.send(WatcherStart {
                        vault_id: watcher_vault.clone(),
                        result: Ok(WatcherBackend::Poll),
                    });
                    let _held = watcher;
                    while !watcher_stop.load(Ordering::Acquire) {
                        std::thread::park_timeout(Duration::from_secs(1));
                    }
                }
                Err(error) => {
                    let _ = watcher_ready.send(WatcherStart {
                        vault_id: watcher_vault,
                        result: Err(error.to_string()),
                    });
                }
            }
        });

        // Confirm watcher armed.
        let _ = ready_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("watcher must signal readiness");

        // Let the watcher establish its baseline (one poll cycle).
        tokio::time::sleep(Duration::from_millis(120)).await;

        // ── Mutate vault "a" while channel is full ──
        let create_a = root_a.join("new-a.txt");
        std::fs::write(&create_a, b"fresh").unwrap();
        std::fs::remove_file(&a_file).unwrap();

        // Let poll cycles fire — callbacks will saturate.
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert!(
            saturation.load(Ordering::Acquire),
            "saturation must be signalled by dropped events"
        );

        // ── Drive through the real run_index_loop with BOTH vaults ──
        let mut loop_roots = HashMap::new();
        loop_roots.insert("a".to_string(), root_a.clone());
        loop_roots.insert("b".to_string(), root_b.clone());

        let loop_meta = meta_db.clone();
        let loop_sat = saturation.clone();
        // Reset saturation so the loop observes it fresh.
        saturation.store(true, Ordering::Release);

        let loop_handle = tokio::spawn(async move {
            run_index_loop(rx, loop_meta, "test".into(), loop_roots, loop_sat).await
        });

        // Let the loop process saturation + reconcile.
        tokio::time::sleep(Duration::from_millis(500)).await;

        // ── Vault "a": created file must be upserted, deleted file tombstoned ──
        let a_new = meta_db
            .get_file_scoped(None, "a", "new-a.txt")
            .await
            .unwrap()
            .expect("new-a.txt must be upserted by reconcile");
        assert!(!a_new.deleted, "new-a.txt must not be tombstoned");
        assert_eq!(a_new.size, 5);

        let a_deleted = meta_db
            .get_file_scoped(None, "a", "a.txt")
            .await
            .unwrap()
            .expect("a.txt must still have a MetaDb row");
        assert!(a_deleted.deleted, "a.txt must be tombstoned");

        // ── Vault "b": correctly reconciled, no cross-vault misattribution ──
        // full_reconcile intentionally processes every canonical root, so
        // vault "b"'s row IS reconciled — but it must retain the seed's content
        // identity (same content_hash, size, not deleted) and no A-owned
        // path may appear under B (or vice versa).
        let b_row = meta_db
            .get_file_scoped(None, "b", "b.txt")
            .await
            .unwrap()
            .expect("b.txt must survive reconcile");
        assert!(!b_row.deleted, "vault b row must not be tombstoned");
        assert_eq!(
            b_row.content_hash, b_hash,
            "vault b row hash must match seed"
        );
        assert_eq!(b_row.size, 4, "vault b row size must match seed");

        // No cross-vault path leakage: A-owned paths must not appear under B.
        for a_path in &["a.txt", "new-a.txt"] {
            assert!(
                meta_db
                    .get_file_scoped(None, "b", a_path)
                    .await
                    .unwrap()
                    .is_none(),
                "vault A path '{a_path}' must not appear under vault B"
            );
        }
        // B-owned paths must not appear under A.
        assert!(
            meta_db
                .get_file_scoped(None, "a", "b.txt")
                .await
                .unwrap()
                .is_none(),
            "vault B path 'b.txt' must not appear under vault A"
        );

        // ── Bounded clean shutdown ──
        drop(tx);
        stop.store(true, Ordering::Release);
        watcher_thread.thread().unpark();

        let loop_result = tokio::time::timeout(Duration::from_secs(5), loop_handle)
            .await
            .expect("loop must shut down within bounded timeout")
            .expect("loop task must not panic");
        assert!(loop_result.is_ok(), "loop must exit with Ok");

        let _ = watcher_thread.join();
    }

    // ── Blocker 5 (round-3): deterministic handle drop under saturation ──

    /// Forces [`arm_poll_watcher`] (no native fallback path), a capacity-1
    /// channel pre-filled with a sentinel so every subsequent callback
    /// `try_send` MUST return [`TrySendError::Full`], and a consumer loop
    /// latched behind that full channel.
    ///
    /// **Before drop**, the test observes `saturation.load() == true` —
    /// proving the Full path. **A dedicated watchdog thread** drops the handle;
    /// the test waits with `recv_timeout` and asserts completion (watcher threads
    /// joined, task aborted, no hang or panic) within 5 seconds.
    /// No timing-only sleep is used as proof; every causal link is a
    /// directly observed atomic flag or a channel-capacity invariant.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn share_index_handle_drop_under_saturation_completes() {
        let dir = tempfile::tempdir().unwrap();
        let share_root = dir.path().join("vault");
        std::fs::create_dir_all(&share_root).unwrap();
        // DO NOT create any file yet — the PollWatcher records its baseline on the
        // first scan and only emits events for files that appear AFTER that scan.

        let db_path = dir.path().join("meta.sqlite");
        let meta_db = MetaDb::open(&db_path).await.unwrap();

        // ── Force PollWatcher + capacity-1 channel + pre-fill ──
        let (tx, rx) = mpsc::channel::<IndexEvent>(1);
        let saturation = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        // Pre-fill the single slot — every subsequent try_send MUST return Full.
        tx.try_send(IndexEvent {
            vault_id: "vault".into(),
            abs_path: share_root.clone(),
            kind: IndexEventKind::Upsert,
        })
        .unwrap();

        let watcher_vault = "vault".to_string();
        let watcher_root = share_root.clone();
        let watcher_tx = tx.clone();
        let watcher_sat = saturation.clone();
        let watcher_stop = stop.clone();
        let watcher_ready = ready_tx;

        let watcher_thread = std::thread::spawn(move || {
            match arm_poll_watcher(
                &watcher_vault,
                &watcher_root,
                &watcher_tx,
                Duration::from_millis(50),
                watcher_sat,
            ) {
                Ok(watcher) => {
                    let _ = watcher_ready.send(WatcherStart {
                        vault_id: watcher_vault.clone(),
                        result: Ok(WatcherBackend::Poll),
                    });
                    let _held = watcher;
                    while !watcher_stop.load(Ordering::Acquire) {
                        std::thread::park_timeout(Duration::from_secs(1));
                    }
                }
                Err(error) => {
                    let _ = watcher_ready.send(WatcherStart {
                        vault_id: watcher_vault,
                        result: Err(error.to_string()),
                    });
                }
            }
        });

        // Confirm watcher armed and backend IS Poll (no native escape).
        let start = ready_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("watcher must signal readiness");
        assert!(
            matches!(start.result, Ok(WatcherBackend::Poll)),
            "test must exercise PollWatcher, got {:?}",
            start.result
        );

        // Create a file AFTER the watcher established its baseline — the next
        // poll cycle will emit a Create event whose try_send MUST return Full
        // on the pre-filled capacity-1 channel, setting the saturation flag.
        std::fs::write(share_root.join("f.txt"), b"data").unwrap();

        // ── Spin-wait for saturation — bounded deadline, no fixed sleep ──
        let sat_deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if saturation.load(Ordering::Acquire) {
                break;
            }
            assert!(
                std::time::Instant::now() < sat_deadline,
                "saturation must be signalled within bounded deadline"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        // At this point saturation IS true — the callback exercised
        // TrySendError::Full on the pre-filled capacity-1 channel.

        // ── Spawn consumer loop latched behind the full channel ──
        let loop_meta = meta_db.clone();
        let mut loop_roots = HashMap::new();
        loop_roots.insert("vault".to_string(), share_root.clone());
        let loop_sat = saturation.clone();
        let loop_task = tokio::spawn(async move {
            let _ = run_index_loop(rx, loop_meta, "test".into(), loop_roots, loop_sat).await;
        });

        // Let the loop observe saturation and attempt reconcile.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // ── Build ShareIndexHandle directly (same-crate, private fields visible) ──
        let handle = ShareIndexHandle {
            task: loop_task,
            stop: stop.clone(),
            watcher_threads: vec![watcher_thread],
            saturation: saturation.clone(),
        };

        // ── External watchdog: drop on a dedicated thread, bounded by
        //    recv_timeout. A deadlock in ShareIndexHandle::drop produces
        //    a test failure (timeout) instead of hanging indefinitely —
        //    this is the negative-control structure required by the proof.
        //    If the spawned thread panics during drop, the channel
        //    disconnects without a send, and recv_timeout returns
        //    Err(Disconnected) — also a test failure.
        let (dropped_tx, dropped_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            drop(handle);
            let _ = dropped_tx.send(());
        });

        dropped_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("ShareIndexHandle::drop must complete within bounded watchdog timeout");

        // Producer: watcher thread was joined (handle holds the JoinHandle).
        // Consumer task: aborted by Drop (JoinHandle dropped after abort).
        // tx dropped when this scope ends — channel closes cleanly.
    }

    /// Multi-root readiness: two configured roots both reach the armed state
    /// and produce events.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn multi_root_watchers_both_armed_and_produce_events() {
        let dir = tempfile::tempdir().unwrap();

        let root_a = dir.path().join("a");
        std::fs::create_dir_all(&root_a).unwrap();
        let root_b = dir.path().join("b");
        std::fs::create_dir_all(&root_b).unwrap();

        let db_path = dir.path().join("meta.sqlite");
        let meta_db = MetaDb::open(&db_path).await.unwrap();

        let mut roots = HashMap::new();
        roots.insert("a".to_string(), root_a.clone());
        roots.insert("b".to_string(), root_b.clone());

        let handle = spawn_share_index_watcher(roots, meta_db.clone(), "test")
            .expect("multi-root startup must succeed")
            .expect("handle must be Some");

        // Let watchers establish their baselines.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Write to both vaults.
        std::fs::write(root_a.join("a.txt"), b"alpha").unwrap();
        std::fs::write(root_b.join("b.txt"), b"beta").unwrap();

        // Each vault's file must be indexed.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let (mut a_done, mut b_done) = (false, false);
        while tokio::time::Instant::now() < deadline && !(a_done && b_done) {
            if !a_done {
                if let Ok(Some(row)) = meta_db.get_file_scoped(None, "a", "a.txt").await {
                    if !row.deleted && row.size == 5 {
                        a_done = true;
                    }
                }
            }
            if !b_done {
                if let Ok(Some(row)) = meta_db.get_file_scoped(None, "b", "b.txt").await {
                    if !row.deleted && row.size == 4 {
                        b_done = true;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        assert!(a_done, "vault a file must be indexed");
        assert!(b_done, "vault b file must be indexed");

        drop(handle);
    }

    /// Native + poll dual-failure injection: both backends failing must
    /// return `WatcherInitError` with both failure messages.
    #[test]
    fn arm_watcher_dual_failure_returns_both_errors() {
        // Force both backends to fail — the native constructor will fail,
        // then the poll constructor will also fail.
        let error = native_or_poll::<&str, _, _>(
            || Err(notify::Error::generic("NATIVE_ERR")),
            || Err(notify::Error::generic("POLL_ERR")),
        )
        .unwrap_err();

        assert!(error.native.contains("NATIVE_ERR"));
        assert!(error.poll.contains("POLL_ERR"));
    }

    // ── Blocker 4: server-side same-size/mtime rewrite → MetaDb hash change ──

    /// Forces a [`PollWatcher`] (bypassing native entirely via
    /// [`arm_poll_watcher`]) to prove `with_compare_contents(true)` detects
    /// a content rewrite that preserves both file size and mtime.  The test
    /// asserts the watcher backend is `Poll` so native events cannot
    /// satisfy it.  Drives through the real `run_index_loop`, writes a
    /// file, waits for it to be indexed, then rewrites with same-length
    /// content and restores the original mtime.  The poll watcher's
    /// content-comparing poll must detect the change and the index-loop
    /// must update the MetaDb `content_hash`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn poll_watcher_detects_same_size_mtime_content_change_in_metadb() {
        let dir = tempfile::tempdir().unwrap();
        let share_root = dir.path().join("vault");
        std::fs::create_dir_all(&share_root).unwrap();
        let root = std::fs::canonicalize(&share_root).unwrap();

        let db_path = dir.path().join("meta.sqlite");
        let meta_db = MetaDb::open(&db_path).await.unwrap();

        let mut roots_map = HashMap::new();
        roots_map.insert("vault".to_string(), root.clone());

        // ── Force PollWatcher — no native fallback ──
        let (tx, rx) = mpsc::channel::<IndexEvent>(256);
        let saturation = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        let vault_id = "vault".to_string();
        let poll_root = root.clone();
        let poll_tx = tx.clone();
        let poll_sat = saturation.clone();
        let poll_stop = stop.clone();
        let poll_ready = ready_tx;

        let watcher_thread = std::thread::spawn(move || {
            match arm_poll_watcher(
                &vault_id,
                &poll_root,
                &poll_tx,
                Duration::from_secs(1),
                poll_sat,
            ) {
                Ok(watcher) => {
                    // Prove the backend is Poll — this is what the test exists to verify.
                    let _ = poll_ready.send(WatcherStart {
                        vault_id: vault_id.clone(),
                        result: Ok(WatcherBackend::Poll),
                    });
                    let _held = watcher; // keep watcher alive
                    while !poll_stop.load(Ordering::Acquire) {
                        std::thread::park_timeout(Duration::from_secs(1));
                    }
                }
                Err(error) => {
                    let _ = poll_ready.send(WatcherStart {
                        vault_id,
                        result: Err(error.to_string()),
                    });
                }
            }
        });

        // Confirm watcher armed as Poll.
        let start = ready_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("watcher must signal readiness");
        match start.result {
            Ok(backend) => assert_eq!(
                backend,
                WatcherBackend::Poll,
                "test must exercise PollWatcher, not native"
            ),
            Err(e) => panic!("watcher failed to arm: {e}"),
        }

        // Spawn the index loop.
        let loop_meta = meta_db.clone();
        let loop_roots = roots_map.clone();
        let loop_sat = saturation.clone();
        let loop_handle = tokio::spawn(async move {
            run_index_loop(rx, loop_meta, "test".into(), loop_roots, loop_sat).await
        });

        // Wait for the first poll cycle + debounce so the watcher is live.
        tokio::time::sleep(Duration::from_millis(1200)).await;

        let target = share_root.join("content-rewrite.txt");
        // Write initial content after watcher is armed.
        std::fs::write(&target, b"AAAA").unwrap();
        let initial_hash = *blake3::hash(b"AAAA").as_bytes();

        // Wait for the initial write to be indexed.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        let mut initial_indexed = false;
        while tokio::time::Instant::now() < deadline {
            if let Ok(Some(row)) = meta_db
                .get_file_scoped(None, "vault", "content-rewrite.txt")
                .await
            {
                if !row.deleted && row.content_hash == initial_hash {
                    initial_indexed = true;
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(initial_indexed, "initial file must be indexed");

        // Capture original mtime.
        let initial_mtime = std::fs::metadata(&target).unwrap().modified().unwrap();

        // Rewrite with same length (4 bytes) — size unchanged.
        std::fs::write(&target, b"BBBB").unwrap();
        // Restore original mtime so metadata is identical.
        // Windows requires a write-capable handle for `SetFileTime`; a
        // read-only `File::open` fails with `ERROR_ACCESS_DENIED`.
        std::fs::OpenOptions::new()
            .write(true)
            .open(&target)
            .unwrap()
            .set_modified(initial_mtime)
            .unwrap();

        let meta = std::fs::metadata(&target).unwrap();
        assert_eq!(meta.len(), 4);
        assert_eq!(meta.modified().unwrap(), initial_mtime);

        // The forced PollWatcher with compare_contents must detect the content
        // change and the loop must upsert the updated hash into MetaDb.
        let new_hash = *blake3::hash(b"BBBB").as_bytes();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut hash_changed = false;
        while tokio::time::Instant::now() < deadline {
            if let Ok(Some(row)) = meta_db
                .get_file_scoped(None, "vault", "content-rewrite.txt")
                .await
            {
                if !row.deleted && row.content_hash != initial_hash {
                    assert_eq!(
                        row.content_hash, new_hash,
                        "MetaDb hash must match the rewritten content"
                    );
                    hash_changed = true;
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        assert!(
            hash_changed,
            "PollWatcher with compare_contents must detect same-size/same-mtime \
             content rewrite and update MetaDb content_hash"
        );

        // ── Bounded clean shutdown ──
        drop(tx);
        stop.store(true, Ordering::Release);
        watcher_thread.thread().unpark();

        let loop_result = tokio::time::timeout(Duration::from_secs(5), loop_handle)
            .await
            .expect("loop must shut down within bounded timeout")
            .expect("loop task must not panic");
        assert!(loop_result.is_ok(), "loop must exit with Ok");

        let _ = watcher_thread.join();
    }
}
