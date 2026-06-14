//! Content-addressed local blob cache for 3-way merge base retrieval.
//!
//! After each successful file download the sync-loop stores the bytes in this
//! cache keyed by their blake3 hash.  When a conflict is applied in a later
//! cycle the APPLY path looks up the baseline's `content_hash` here to obtain
//! the common-ancestor bytes needed by `three_way_merge`.
//!
//! Layout: `{cache_dir}/{first_2_hex_chars}/{remaining_62_hex_chars}` — the
//! same two-level fan-out used by Git's object store, chosen for the same
//! reason: it keeps the top-level directory entries in the low thousands even
//! with millions of objects.
//!
//! Writes are atomic: bytes go to a `tempfile` in the cache root and are
//! renamed into place.  Concurrent writers racing on the same hash are
//! harmless — both write identical bytes and the last rename wins.

use std::path::{Path, PathBuf};

/// Errors that can occur while reading or writing a blob.
#[derive(Debug, thiserror::Error)]
pub enum BlobCacheError {
    /// An I/O error while reading or writing a blob file.
    #[error("blob cache I/O: {0}")]
    Io(#[from] std::io::Error),

    /// `tempfile::persist()` failed (e.g. cross-device rename).
    #[error("blob cache persist: {0}")]
    Persist(#[from] tempfile::PersistError),
}

/// Flat, content-addressed blob store backed by the local filesystem.
///
/// Create with [`BlobCache::new`] pointing at a directory that persists
/// between sync cycles.  The directory is created on first use if absent.
#[derive(Debug, Clone)]
pub struct BlobCache {
    root: PathBuf,
}

impl BlobCache {
    /// Open (or create) a blob cache rooted at `root`.
    ///
    /// The root directory is NOT created eagerly — it is created on the first
    /// `put` call that would write into it.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Return the absolute path for a blob with the given `hash`.
    fn blob_path(&self, hash: &[u8; 32]) -> PathBuf {
        let hex = hex::encode(hash);
        // Split into two-character prefix + 62-character suffix.
        self.root.join(&hex[..2]).join(&hex[2..])
    }

    /// Store `bytes` under `hash`, returning immediately if the blob already
    /// exists.  Write is atomic — a concurrent writer storing identical bytes
    /// is safe.
    pub fn put(&self, hash: &[u8; 32], bytes: &[u8]) -> Result<(), BlobCacheError> {
        let dest = self.blob_path(hash);

        // Fast path: blob already cached.
        if dest.exists() {
            return Ok(());
        }

        // Ensure the two-level directory exists.
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Write via temp → rename for atomicity.
        use std::io::Write as _;
        let tmp_parent = dest.parent().unwrap_or_else(|| Path::new("."));
        let mut tmp = tempfile::NamedTempFile::new_in(tmp_parent)?;
        tmp.write_all(bytes)?;
        tmp.flush()?;
        // `persist` uses rename(2); harmless if another writer beat us.
        let _ = tmp.persist(&dest); // ignore AlreadyExists races
        Ok(())
    }

    /// Retrieve the bytes stored under `hash`, or `None` when the blob is not
    /// in the cache.
    pub fn get(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        std::fs::read(self.blob_path(hash)).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_then_get_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let cache = BlobCache::new(dir.path());

        let bytes = b"hello, blob cache";
        let hash: [u8; 32] = *blake3::hash(bytes).as_bytes();

        cache.put(&hash, bytes).expect("put must succeed");
        let got = cache.get(&hash).expect("get must find the blob");
        assert_eq!(got, bytes);
    }

    #[test]
    fn get_returns_none_for_unknown_hash() {
        let dir = tempfile::tempdir().unwrap();
        let cache = BlobCache::new(dir.path());
        let hash = [0u8; 32];
        assert!(cache.get(&hash).is_none());
    }

    #[test]
    fn put_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let cache = BlobCache::new(dir.path());

        let bytes = b"idempotent content";
        let hash: [u8; 32] = *blake3::hash(bytes).as_bytes();

        cache.put(&hash, bytes).expect("first put");
        cache.put(&hash, bytes).expect("second put must not error");

        let got = cache.get(&hash).expect("get after double-put");
        assert_eq!(got, bytes);
    }

    #[test]
    fn blob_path_uses_two_level_fan_out() {
        let dir = tempfile::tempdir().unwrap();
        let cache = BlobCache::new(dir.path());
        let hash = [0xABu8; 32];
        let path = cache.blob_path(&hash);
        let hex = hex::encode(hash);
        assert!(path.to_string_lossy().contains(&hex[..2]));
        assert!(path.to_string_lossy().contains(&hex[2..]));
    }
}
