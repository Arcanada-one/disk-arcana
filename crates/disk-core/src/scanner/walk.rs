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
            let inode = crate::platform::inode_from_path(abs);

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
                encryption_nonce: None,
                version_id: None,
                parent_version_id: None,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::{Filter, FilterRules};
    use std::collections::HashMap;

    fn scanner_for(root: &std::path::Path, last_known: HashMap<PathBuf, FileMeta>) -> FileScanner {
        FileScanner::new(
            root.to_path_buf(),
            Filter::from_config(&FilterRules::default()).unwrap(),
            last_known,
            "test-node".into(),
        )
    }

    fn meta_for(path: &str, size: u64, mtime_ns: i64, hash: [u8; 32]) -> FileMeta {
        FileMeta {
            path: PathBuf::from(path),
            content_hash: hash,
            size,
            mtime_ns,
            inode: None,
            vector_clock: crate::VectorClock::default(),
            deleted: false,
            deleted_at: None,
            node_id: "test-node".into(),
            encryption_nonce: None,
            version_id: None,
            parent_version_id: None,
        }
    }

    /// DISK-0078: a populated `last_known` cache must actually suppress
    /// re-hashing.
    ///
    /// The sync loop passed `HashMap::new()`, so every cycle streamed and
    /// blake3'd the entire tree — 13k files on the Mac follower — which is the
    /// CPU-bound work behind the 99.3% CPU measured while a cycle looked stuck.
    ///
    /// This asserts the fast path OBSERVABLY, not by timing: the cache is
    /// seeded with a deliberately WRONG hash for an unchanged file. If the
    /// scanner honours the cache it returns that wrong hash; if it re-hashes,
    /// it returns the real one. Timing-based assertions would be flaky; this
    /// cannot be.
    #[test]
    fn a_matching_cache_entry_suppresses_rehashing() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("note.md");
        std::fs::write(&file, b"real content").unwrap();

        let stat = std::fs::metadata(&file).unwrap();
        let size = stat.len();
        let mtime_ns = {
            use std::os::unix::fs::MetadataExt;
            stat.mtime() * 1_000_000_000 + stat.mtime_nsec()
        };

        let sentinel = [0x5A; 32];
        let mut cache = HashMap::new();
        cache.insert(
            PathBuf::from("note.md"),
            meta_for("note.md", size, mtime_ns, sentinel),
        );

        let scanned = scanner_for(dir.path(), cache).scan().unwrap();
        let entry = scanned
            .iter()
            .find(|m| m.path.as_os_str() == "note.md")
            .expect("file must be scanned");

        assert_eq!(
            entry.content_hash, sentinel,
            "an unchanged file must take the cached hash — the scanner re-hashed instead"
        );
    }

    /// The fast path must not survive a real change, or a modified file would
    /// sync with a stale hash. Same sentinel technique, mtime deliberately off.
    #[test]
    fn a_stale_cache_entry_does_not_suppress_rehashing() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("note.md");
        std::fs::write(&file, b"real content").unwrap();

        let sentinel = [0x5A; 32];
        let mut cache = HashMap::new();
        // mtime that cannot match what the filesystem reports.
        cache.insert(
            PathBuf::from("note.md"),
            meta_for("note.md", 12, 1, sentinel),
        );

        let scanned = scanner_for(dir.path(), cache).scan().unwrap();
        let entry = scanned
            .iter()
            .find(|m| m.path.as_os_str() == "note.md")
            .expect("file must be scanned");

        assert_ne!(
            entry.content_hash, sentinel,
            "a stale cache entry must be ignored and the file re-hashed"
        );
        assert_eq!(entry.content_hash, super::hash_file(&file).unwrap());
    }
}
