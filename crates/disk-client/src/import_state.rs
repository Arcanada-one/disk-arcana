//! DISK-0006 R8 — `disk import-state --from-rsync` SQLite seeding.
//!
//! Seeds the local `MetaDb` from a filesystem tree (the legacy rsync /
//! bash-MVP layout under `Projects/Disk Arcana/scripts/`). The operator
//! invokes this exactly once per share as part of the DISK-RB-003
//! cutover sequence; afterwards the daemon takes over and `import-state`
//! is never re-run for the same tree.
//!
//! Safety invariants enforced here (PRD §10 + plan §Threats):
//!
//! 1. **No symlink traversal.** `WalkDir::follow_links(false)` makes
//!    `notify`-style filesystem walks NOT cross symlinks at all; in
//!    addition each entry's canonical path is verified to live under
//!    the canonical share root. A symlink to `/etc/passwd` is reported
//!    by walkdir as `is_symlink() == true` (NOT `is_file()`) and is
//!    skipped without ever opening the target file.
//! 2. **Dry-run never writes.** With `dry_run = true` the SQLite
//!    transaction is never opened — the caller gets a printable plan
//!    via [`ImportReport::entries`].
//! 3. **Pure traversal counts.** [`ImportReport::files_seen`] counts
//!    only regular files surfaced by walkdir; symlinks, sockets, and
//!    devices are skipped silently. [`ImportReport::escapes_blocked`]
//!    counts entries that would have escaped the share root via path
//!    canonicalisation (defence-in-depth above the `is_file` filter).

use std::path::{Path, PathBuf};

use thiserror::Error;
use walkdir::WalkDir;

use disk_core::error::MetaDbError;
use disk_core::types::FileMeta;
use disk_core::vector_clock::VectorClock;
use disk_core::MetaDb;

/// Defence-in-depth `WalkDir` configuration: never cross symlinks.
const FOLLOW_SYMLINKS: bool = false;

/// One file's contribution to the import plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportEntry {
    /// Path relative to the share root (POSIX separators preserved).
    pub relative_path: PathBuf,
    pub size: u64,
    pub content_hash: [u8; 32],
    pub mtime_ns: i64,
}

/// Aggregate result of [`import_state`]. Even in dry-run mode the report
/// is fully populated so the caller can print the plan.
#[derive(Debug, Default)]
pub struct ImportReport {
    pub files_seen: u64,
    pub files_imported: u64,
    pub bytes_total: u64,
    /// Count of entries that would have escaped the share root after
    /// canonicalisation. Should always stay at `0` under the default
    /// `follow_links(false)`; non-zero is a regression / OS-anomaly signal.
    pub escapes_blocked: u64,
    pub dry_run: bool,
    pub entries: Vec<ImportEntry>,
}

#[derive(Debug, Error)]
pub enum ImportError {
    #[error("share root does not exist: {0}")]
    RootMissing(PathBuf),

    #[error("share root is not a directory: {0}")]
    RootNotDir(PathBuf),

    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("walk error: {0}")]
    Walk(String),

    #[error("metadb error: {0}")]
    MetaDb(#[from] MetaDbError),
}

fn io_err(path: &Path, source: std::io::Error) -> ImportError {
    ImportError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// Canonicalize the share root (resolves symlinks once, up front). All
/// subsequent canonicalised entry paths must `starts_with` this value.
fn canonical_root(from: &Path) -> Result<PathBuf, ImportError> {
    if !from.exists() {
        return Err(ImportError::RootMissing(from.to_path_buf()));
    }
    let canonical = std::fs::canonicalize(from).map_err(|e| io_err(from, e))?;
    if !canonical.is_dir() {
        return Err(ImportError::RootNotDir(canonical));
    }
    Ok(canonical)
}

/// Hash a regular file with blake3 streaming. Reads at most ~64KiB at
/// a time so large files do not balloon RSS.
pub fn hash_file(path: &Path) -> Result<[u8; 32], ImportError> {
    use std::io::Read;

    let mut file = std::fs::File::open(path).map_err(|e| io_err(path, e))?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(|e| io_err(path, e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(*hasher.finalize().as_bytes())
}

/// Walk `from`, hash every regular file under the canonical root, and
/// either print the plan (`dry_run = true`) or write rows into `db`.
///
/// `node_id` is recorded as the writer in the resulting [`FileMeta`]
/// rows so the reconciler can attribute the seeded baseline to this
/// host on the first sync.
pub async fn import_state(
    from: &Path,
    node_id: &str,
    db: &MetaDb,
    dry_run: bool,
) -> Result<ImportReport, ImportError> {
    let root = canonical_root(from)?;
    let mut report = ImportReport {
        dry_run,
        ..Default::default()
    };

    let walker = WalkDir::new(&root)
        .follow_links(FOLLOW_SYMLINKS)
        .sort_by_file_name()
        .into_iter();

    for entry in walker {
        let entry = entry.map_err(|e| ImportError::Walk(e.to_string()))?;
        if !entry.file_type().is_file() {
            // Symlinks (including dangling), devices, FIFOs, sockets — skip.
            continue;
        }
        let abs = entry.path();
        // Canonicalise the entry. With follow_links(false) this is largely
        // defensive (walkdir never descends through symlinks), but is the
        // explicit escape-guard the plan §Threats row requires.
        let canonical_entry = match std::fs::canonicalize(abs) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if !canonical_entry.starts_with(&root) {
            report.escapes_blocked += 1;
            continue;
        }
        let rel = match canonical_entry.strip_prefix(&root) {
            Ok(r) => r.to_path_buf(),
            Err(_) => {
                report.escapes_blocked += 1;
                continue;
            }
        };
        if rel.as_os_str().is_empty() {
            continue;
        }
        let metadata = entry.metadata().map_err(|e| io_err(abs, e.into()))?;
        let size = metadata.len();
        let mtime_ns = mtime_nanos(&metadata);
        let content_hash = hash_file(&canonical_entry)?;

        report.files_seen += 1;
        report.bytes_total = report.bytes_total.saturating_add(size);

        let entry_record = ImportEntry {
            relative_path: rel.clone(),
            size,
            content_hash,
            mtime_ns,
        };
        report.entries.push(entry_record);

        if !dry_run {
            let meta = FileMeta {
                path: rel,
                content_hash,
                size,
                mtime_ns,
                inode: inode_of(&metadata),
                vector_clock: VectorClock::default(),
                deleted: false,
                deleted_at: None,
                node_id: node_id.to_string(),
                encryption_nonce: None,
                version_id: None,
                parent_version_id: None,
            };
            db.upsert_file(&meta).await?;
            report.files_imported += 1;
        }
    }

    Ok(report)
}

#[cfg(unix)]
fn mtime_nanos(metadata: &std::fs::Metadata) -> i64 {
    use std::os::unix::fs::MetadataExt;
    metadata.mtime() * 1_000_000_000 + metadata.mtime_nsec()
}

#[cfg(not(unix))]
fn mtime_nanos(metadata: &std::fs::Metadata) -> i64 {
    metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

#[cfg(unix)]
fn inode_of(metadata: &std::fs::Metadata) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    Some(metadata.ino())
}

#[cfg(not(unix))]
fn inode_of(_metadata: &std::fs::Metadata) -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[tokio::test]
    async fn canonicalize_rejects_missing_root() {
        let bogus = std::path::PathBuf::from("/this/path/definitely/does/not/exist");
        let res = canonical_root(&bogus);
        assert!(matches!(res, Err(ImportError::RootMissing(_))));
    }

    #[tokio::test]
    async fn canonicalize_rejects_file_as_root() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("plain.txt");
        fs::write(&file, b"hi").unwrap();
        let res = canonical_root(&file);
        assert!(matches!(res, Err(ImportError::RootNotDir(_))));
    }

    #[tokio::test]
    async fn hash_file_matches_blake3_of_known_input() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("a.txt");
        fs::write(&f, b"disk-arcana").unwrap();
        let h = hash_file(&f).expect("hash_file");
        let expect = blake3::hash(b"disk-arcana");
        assert_eq!(&h[..], expect.as_bytes());
    }

    #[tokio::test]
    async fn empty_dir_imports_zero_rows() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("meta.db");
        let db = MetaDb::open(&db_path).await.unwrap();

        let share = dir.path().join("share");
        fs::create_dir(&share).unwrap();

        let report = import_state(&share, "node-1", &db, false).await.unwrap();
        assert_eq!(report.files_seen, 0);
        assert_eq!(report.files_imported, 0);
        assert_eq!(report.bytes_total, 0);
        assert!(!report.dry_run);
    }

    #[tokio::test]
    async fn dry_run_does_not_write_rows() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("meta.db");
        let db = MetaDb::open(&db_path).await.unwrap();

        let share = dir.path().join("share");
        fs::create_dir(&share).unwrap();
        fs::write(share.join("a.txt"), b"alpha").unwrap();
        fs::write(share.join("b.txt"), b"beta-content").unwrap();

        let report = import_state(&share, "node-1", &db, true).await.unwrap();
        assert!(report.dry_run);
        assert_eq!(report.files_seen, 2);
        assert_eq!(report.files_imported, 0, "dry_run must not write rows");
        assert_eq!(report.bytes_total, 5 + 12);
        assert_eq!(report.entries.len(), 2);

        // Confirm via fresh DB read: no rows.
        let listed = db.list_all_files().await.unwrap();
        assert!(listed.is_empty(), "dry_run must leave MetaDb untouched");
    }

    #[tokio::test]
    async fn live_run_writes_one_row_per_file() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("meta.db");
        let db = MetaDb::open(&db_path).await.unwrap();

        let share = dir.path().join("share");
        fs::create_dir(&share).unwrap();
        fs::write(share.join("a.txt"), b"alpha").unwrap();
        let nested = share.join("nested");
        fs::create_dir(&nested).unwrap();
        fs::write(nested.join("b.txt"), b"beta-content").unwrap();

        let report = import_state(&share, "node-1", &db, false).await.unwrap();
        assert_eq!(report.files_seen, 2);
        assert_eq!(report.files_imported, 2);

        let listed = db.list_all_files().await.unwrap();
        assert_eq!(listed.len(), 2);
        for m in &listed {
            // node_id is not persisted by the current MetaDb schema (DISK-0002);
            // the seed call still threads it through so future schema bumps can
            // start storing it without an API change.
            assert!(!m.deleted);
            assert_eq!(m.content_hash.len(), 32);
        }
    }
}
