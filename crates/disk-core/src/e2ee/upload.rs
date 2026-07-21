//! Prepare wire bytes and content hash for `DeltaUpload` (DISK-0015).

use crate::e2ee::{encrypt, VaultKey};
use crate::E2eeError;

/// Payload handed to `DiskClient::delta_upload`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadPayload {
    /// Bytes sent on the wire (plaintext or ciphertext).
    pub wire_bytes: Vec<u8>,
    /// `blake3(wire_bytes)` — matches server `resulting_hash` check.
    pub content_hash: [u8; 32],
    /// Empty when plaintext; 24-byte XChaCha20 nonce when encrypted.
    pub encryption_nonce: Vec<u8>,
}

impl UploadPayload {
    /// Plaintext upload (self-hosted default).
    pub fn from_plaintext(plaintext: &[u8]) -> Self {
        Self {
            wire_bytes: plaintext.to_vec(),
            content_hash: *blake3::hash(plaintext).as_bytes(),
            encryption_nonce: Vec::new(),
        }
    }

    /// Client-side E2EE: encrypt then hash ciphertext.
    pub fn from_plaintext_encrypted(plaintext: &[u8], key: &VaultKey) -> Result<Self, E2eeError> {
        let blob = encrypt(plaintext, key)?;
        Ok(Self {
            content_hash: *blake3::hash(&blob.ciphertext).as_bytes(),
            wire_bytes: blob.ciphertext,
            encryption_nonce: blob.nonce.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::e2ee::random_salt;

    #[test]
    fn plaintext_hash_matches_wire_bytes() {
        let p = UploadPayload::from_plaintext(b"hello");
        assert_eq!(p.content_hash, *blake3::hash(b"hello").as_bytes());
        assert!(p.encryption_nonce.is_empty());
    }

    #[test]
    fn encrypted_hash_is_over_ciphertext() {
        let salt = random_salt();
        let key = VaultKey::derive_from_passphrase(b"pw", &salt).unwrap();
        let p = UploadPayload::from_plaintext_encrypted(b"secret", &key).unwrap();
        assert_eq!(p.content_hash, *blake3::hash(&p.wire_bytes).as_bytes());
        assert_eq!(p.encryption_nonce.len(), 24);
        assert_ne!(p.content_hash, *blake3::hash(b"secret").as_bytes());
    }
}
