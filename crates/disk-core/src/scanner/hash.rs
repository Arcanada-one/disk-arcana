//! Streaming blake3 hashing with size+mtime fast-path skip.

use std::io::Read;
use std::path::Path;

use crate::error::ScannerError;
use crate::types::FileMeta;

/// Hash the contents of `path` using blake3 in 64 KiB streaming chunks so
/// large files do not balloon RAM.
pub fn hash_file(path: &Path) -> Result<[u8; 32], ScannerError> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(*hasher.finalize().as_bytes())
}

/// Returns `Some(hash)` when the cached `FileMeta.last_known` row matches the
/// freshly stat'd `(size, mtime_ns)` pair — no rehash required.
pub fn fast_path_hash(prior: Option<&FileMeta>, size: u64, mtime_ns: i64) -> Option<[u8; 32]> {
    let prior = prior?;
    if prior.size == size && prior.mtime_ns == mtime_ns {
        Some(prior.content_hash)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn hash_file_is_deterministic() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("a.bin");
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(b"deterministic content").unwrap();
        drop(f);

        let h1 = hash_file(&p).unwrap();
        let h2 = hash_file(&p).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn fast_path_returns_cached_hash_when_size_mtime_match() {
        let prior = FileMeta {
            path: "x".into(),
            content_hash: [42u8; 32],
            size: 10,
            mtime_ns: 1000,
            inode: None,
            vector_clock: Default::default(),
            deleted: false,
            deleted_at: None,
            node_id: "n".into(),
            encryption_nonce: None,
            version_id: None,
            parent_version_id: None,
        };
        assert_eq!(fast_path_hash(Some(&prior), 10, 1000), Some([42u8; 32]));
        assert_eq!(fast_path_hash(Some(&prior), 11, 1000), None);
        assert_eq!(fast_path_hash(Some(&prior), 10, 1001), None);
        assert_eq!(fast_path_hash(None, 10, 1000), None);
    }
}
