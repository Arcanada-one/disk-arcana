//! `walkdir`-driven traversal that produces [`FileMeta`] snapshots.

use std::collections::HashMap;
use std::path::PathBuf;

use walkdir::WalkDir;

use super::hash::{fast_path_hash, hash_file};
use crate::error::ScannerError;
use crate::filter::Filter;
use crate::types::FileMeta;

/// Stateful filesystem scanner. Walks `root`, applies the filter, and emits
/// a deterministic, path-sorted vector of [`FileMeta`].
#[derive(Debug, Clone)]
pub struct FileScanner {
    root: PathBuf,
    filter: Filter,
    last_known: HashMap<PathBuf, FileMeta>,
    node_id: String,
}

impl FileScanner {
    /// Create a new scanner. `last_known` populates the mtime/size fast-path.
    pub fn new(
        root: PathBuf,
        filter: Filter,
        last_known: HashMap<PathBuf, FileMeta>,
        node_id: String,
    ) -> Self {
        Self {
            root,
            filter,
            last_known,
            node_id,
        }
    }

    /// Walk the tree and produce one [`FileMeta`] per surviving file.
    /// The result is sorted by path for deterministic output.
    pub fn scan(&self) -> Result<Vec<FileMeta>, ScannerError> {
        let mut out = Vec::new();
        let walker = WalkDir::new(&self.root)
            .follow_links(false)
            .sort_by_file_name()
            .into_iter();

        for entry in walker {
            let entry = entry.map_err(|e| ScannerError::Walk(e.to_string()))?;
            if !entry.file_type().is_file() {
                continue;
            }

            let abs = entry.path();
            let rel = match abs.strip_prefix(&self.root) {
                Ok(r) => r.to_path_buf(),
                Err(_) => continue,
            };

            if rel.as_os_str().is_empty() {
                continue;
            }
            if self.filter.is_excluded(&rel) {
                continue;
            }

            let meta = entry
                .metadata()
                .map_err(|e| ScannerError::Walk(e.to_string()))?;
            let size = meta.len();
            let mtime_ns = mtime_nanos(&meta);
            let inode = inode_of(&meta);

            let prior = self.last_known.get(&rel);
            let content_hash = match fast_path_hash(prior, size, mtime_ns) {
                Some(h) => h,
                None => hash_file(abs)?,
            };

            let vector_clock = prior.map(|p| p.vector_clock.clone()).unwrap_or_default();

            out.push(FileMeta {
                path: rel,
                content_hash,
                size,
                mtime_ns,
                inode,
                vector_clock,
                deleted: false,
                deleted_at: None,
                node_id: self.node_id.clone(),
            });
        }

        out.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(out)
    }
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

#[cfg(unix)]
fn inode_of(m: &std::fs::Metadata) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    Some(m.ino())
}

#[cfg(windows)]
fn inode_of(m: &std::fs::Metadata) -> Option<u64> {
    use std::os::windows::fs::MetadataExt;
    Some(m.file_id())
}

#[cfg(not(any(unix, windows)))]
fn inode_of(_: &std::fs::Metadata) -> Option<u64> {
    None
}

/// One-shot helper: instantiate a [`FileScanner`] with no prior cache and
/// scan `root` immediately. Convenience wrapper for callers that don't need
/// to persist the scanner between scans.
pub fn scan_root(
    root: &std::path::Path,
    filter: Filter,
    node_id: String,
) -> Result<Vec<FileMeta>, ScannerError> {
    FileScanner::new(root.to_path_buf(), filter, HashMap::new(), node_id).scan()
}
