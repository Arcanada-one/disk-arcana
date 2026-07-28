//! Local filesystem index for `DISK_SHARE_ROOTS` (POST-R13 follow-up).
//!
//! Hermes and other secondary share roots receive writes outside the gRPC
//! `delta_upload` path. A `notify` watcher keeps the server MetaDb aligned
//! with on-disk state so `exchange_state` can fan out local changes to mesh
//! clients without a manual `disk import-state` re-run.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use disk_core::meta_db::MetaDb;
use disk_core::scanner::hash_file;
use disk_core::types::FileMeta;
use disk_core::vector_clock::VectorClock;
use notify::event::{EventKind, RemoveKind};
use notify::{RecursiveMode, Watcher};
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
    _task: JoinHandle<()>,
}

/// Spawn a debounced watcher over every configured share root. No-op when
/// `share_roots` is empty.
pub fn spawn_share_index_watcher(
    share_roots: HashMap<String, PathBuf>,
    meta_db: MetaDb,
    node_id: impl Into<String>,
) -> Option<ShareIndexHandle> {
    if share_roots.is_empty() {
        return None;
    }

    let node_id = node_id.into();
    let (tx, rx) = mpsc::channel::<IndexEvent>(256);
    let canonical_roots = canonicalize_roots(&share_roots);

    for (vault_id, root) in &share_roots {
        if !root.is_dir() {
            tracing::warn!(
                vault_id = %vault_id,
                root = %root.display(),
                "share_index: root missing — watcher not armed for this share"
            );
            continue;
        }
        spawn_notify_thread(vault_id.clone(), root.clone(), tx.clone());
    }

    let task = tokio::spawn(async move {
        if let Err(e) = run_index_loop(rx, meta_db, node_id, canonical_roots).await {
            tracing::error!(error = %e, "share_index loop exited");
        }
    });

    Some(ShareIndexHandle { _task: task })
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

fn spawn_notify_thread(vault_id: String, root: PathBuf, tx: mpsc::Sender<IndexEvent>) {
    std::thread::spawn(move || {
        let tx_notify = tx.clone();
        let vault_for_cb = vault_id.clone();
        let root_for_cb = root.clone();
        let mut watcher =
            match notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
                if let Ok(ev) = res {
                    for event in translate_notify_event(&ev, &vault_for_cb, &root_for_cb) {
                        let _ = tx_notify.blocking_send(event);
                    }
                }
            }) {
                Ok(w) => w,
                Err(e) => {
                    tracing::error!(
                        vault_id = %vault_id,
                        error = %e,
                        "share_index: failed to create notify watcher"
                    );
                    return;
                }
            };

        if let Err(e) = watcher.watch(&root, RecursiveMode::Recursive) {
            tracing::error!(
                vault_id = %vault_id,
                root = %root.display(),
                error = %e,
                "share_index: failed to watch share root"
            );
            return;
        }

        tracing::info!(
            vault_id = %vault_id,
            root = %root.display(),
            "share_index watcher armed"
        );
        std::thread::park();
    });
}

fn translate_notify_event(ev: &notify::Event, vault_id: &str, root: &Path) -> Vec<IndexEvent> {
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
        .filter(|p| p.starts_with(root))
        .map(|p| IndexEvent {
            vault_id: vault_id.to_string(),
            abs_path: p.clone(),
            kind,
        })
        .collect()
}

async fn run_index_loop(
    mut rx: mpsc::Receiver<IndexEvent>,
    meta_db: MetaDb,
    node_id: String,
    canonical_roots: HashMap<String, PathBuf>,
) -> Result<(), ShareIndexError> {
    while let Some(first) = rx.recv().await {
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
    }
    Ok(())
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
    if !canonical_entry.starts_with(root) || !canonical_entry.is_file() {
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

/// `notify` can fire before the inode is visible; retry briefly.
async fn resolve_existing_file(root: &Path, abs: &Path) -> Option<PathBuf> {
    for attempt in 0..6 {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        if abs.starts_with(root) && abs.is_file() {
            return std::fs::canonicalize(abs).ok();
        }
        if let Ok(p) = std::fs::canonicalize(abs) {
            if p.starts_with(root) && p.is_file() {
                return Some(p);
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
    use super::*;

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
}
