//! ExchangeState wire overlay — align scanned plaintext metadata with E2EE
//! ciphertext hashes (DISK-0015 slice 3).
//!
//! XChaCha20 uses a random nonce per encryption, so ciphertext hashes are not
//! stable across re-encrypts of the same plaintext. Unchanged files therefore
//! reuse the cached `(content_hash, encryption_nonce)` keyed by `(mtime_ns, size)`.

use crate::e2ee::{upload::UploadPayload, VaultKey};
use crate::types::FileMeta;
use crate::E2eeError;

/// Cached wire index for one vault-relative path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct E2eeCachedWire {
    pub content_hash: [u8; 32],
    pub encryption_nonce: Vec<u8>,
    pub mtime_ns: i64,
    /// Plaintext byte length (matches scanner `FileMeta::size`).
    pub size: u64,
}

impl E2eeCachedWire {
    /// Build from a MetaDb / in-memory row that recorded an E2EE upload.
    pub fn from_file_meta(m: &FileMeta) -> Option<Self> {
        let nonce = m.encryption_nonce.as_ref()?;
        if nonce.is_empty() {
            return None;
        }
        Some(Self {
            content_hash: m.content_hash,
            encryption_nonce: nonce.clone(),
            mtime_ns: m.mtime_ns,
            size: m.size,
        })
    }

    /// `true` when the live scan still describes the same plaintext blob.
    pub fn matches_scan(&self, scanned: &FileMeta) -> bool {
        self.mtime_ns == scanned.mtime_ns && self.size == scanned.size
    }
}

/// Rewrite `scanned` in place for `ExchangeState` when E2EE is active.
///
/// Returns `Some(fresh cache entry)` when a new encrypt was performed (caller
/// should persist to MetaDb / in-memory cache). Returns `None` when the cached
/// wire index was reused.
pub fn overlay_scanned_meta(
    scanned: &mut FileMeta,
    key: &VaultKey,
    cached: Option<&E2eeCachedWire>,
    plaintext: &[u8],
) -> Result<Option<E2eeCachedWire>, E2eeError> {
    if let Some(c) = cached {
        if c.matches_scan(scanned) {
            scanned.content_hash = c.content_hash;
            scanned.encryption_nonce = Some(c.encryption_nonce.clone());
            return Ok(None);
        }
    }

    let payload = UploadPayload::from_plaintext_encrypted(plaintext, key)?;
    scanned.content_hash = payload.content_hash;
    scanned.encryption_nonce = Some(payload.encryption_nonce.clone());

    Ok(Some(E2eeCachedWire {
        content_hash: payload.content_hash,
        encryption_nonce: payload.encryption_nonce,
        mtime_ns: scanned.mtime_ns,
        size: scanned.size,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::e2ee::random_salt;
    use std::path::PathBuf;

    fn scanned(path: &str, size: u64, mtime_ns: i64, hash_byte: u8) -> FileMeta {
        FileMeta {
            path: PathBuf::from(path),
            content_hash: [hash_byte; 32],
            size,
            mtime_ns,
            inode: None,
            vector_clock: Default::default(),
            deleted: false,
            deleted_at: None,
            node_id: "n".into(),
            encryption_nonce: None,
            version_id: None,
            parent_version_id: None,
        }
    }

    #[test]
    fn cache_hit_preserves_ciphertext_hash() {
        let salt = random_salt();
        let key = VaultKey::derive_from_passphrase(b"pw", &salt).unwrap();
        let plaintext = b"stable content";

        let mut meta = scanned("doc.md", plaintext.len() as u64, 42, 0x01);
        let fresh = overlay_scanned_meta(&mut meta, &key, None, plaintext)
            .unwrap()
            .expect("first overlay encrypts");
        let ciphertext_hash = meta.content_hash;
        assert_ne!(ciphertext_hash, *blake3::hash(plaintext).as_bytes());

        // Second call with cache — must not rotate nonce/hash.
        let mut again = scanned("doc.md", plaintext.len() as u64, 42, 0x01);
        let reused = overlay_scanned_meta(&mut again, &key, Some(&fresh), plaintext).unwrap();
        assert!(reused.is_none());
        assert_eq!(again.content_hash, ciphertext_hash);
        assert_eq!(again.encryption_nonce, meta.encryption_nonce);
    }

    #[test]
    fn cache_miss_on_mtime_change_reencrypts() {
        let salt = random_salt();
        let key = VaultKey::derive_from_passphrase(b"pw", &salt).unwrap();
        let plaintext = b"v2";

        let mut meta = scanned("doc.md", 2, 100, 0x02);
        let cached = overlay_scanned_meta(&mut meta, &key, None, plaintext)
            .unwrap()
            .unwrap();

        let mut changed = scanned("doc.md", 2, 101, 0x02);
        let fresh = overlay_scanned_meta(&mut changed, &key, Some(&cached), plaintext)
            .unwrap()
            .expect("mtime drift forces re-encrypt");
        assert_ne!(fresh.content_hash, cached.content_hash);
    }

    #[test]
    fn from_file_meta_requires_nonce() {
        let mut m = scanned("x", 1, 0, 0);
        assert!(E2eeCachedWire::from_file_meta(&m).is_none());
        m.encryption_nonce = Some(vec![0u8; 24]);
        assert!(E2eeCachedWire::from_file_meta(&m).is_some());
    }
}
