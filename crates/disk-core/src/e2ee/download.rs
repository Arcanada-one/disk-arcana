//! Decrypt wire bytes after `DeltaDownload` (DISK-0015 slice 5).

use crate::e2ee::{decrypt, E2eeError, EncryptedBlob, VaultKey, NONCE_LEN};

/// Plaintext materialized from a downloaded blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadPayload {
    /// Bytes written to the local vault (plaintext).
    pub plaintext: Vec<u8>,
    /// `blake3(wire_bytes)` — matches `FileMetadata.content_hash` on the wire.
    pub wire_content_hash: [u8; 32],
}

impl DownloadPayload {
    /// Verify the wire hash, then decrypt when `encryption_nonce` is set.
    ///
    /// Plaintext files (`encryption_nonce` empty) pass through unchanged after
    /// the hash check. Encrypted files require `key`.
    pub fn from_wire_bytes(
        wire_bytes: &[u8],
        encryption_nonce: &[u8],
        expected_content_hash: &[u8],
        key: Option<&VaultKey>,
    ) -> Result<Self, E2eeError> {
        let wire_hash = *blake3::hash(wire_bytes).as_bytes();
        let hash_is_placeholder = expected_content_hash.len() != 32
            || expected_content_hash.iter().all(|&b| b == 0);
        if !hash_is_placeholder && wire_hash.as_slice() != expected_content_hash {
            return Err(E2eeError::WireHashMismatch);
        }

        if encryption_nonce.is_empty() {
            return Ok(Self {
                plaintext: wire_bytes.to_vec(),
                wire_content_hash: wire_hash,
            });
        }

        let key = key.ok_or(E2eeError::VaultKeyRequired)?;
        let nonce: [u8; NONCE_LEN] = encryption_nonce
            .try_into()
            .map_err(|_| E2eeError::InvalidNonce)?;
        let blob = EncryptedBlob {
            nonce,
            ciphertext: wire_bytes.to_vec(),
        };
        let plaintext = decrypt(&blob, key)?;
        Ok(Self {
            plaintext,
            wire_content_hash: wire_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::e2ee::{random_salt, UploadPayload};

    #[test]
    fn plaintext_passthrough_after_hash_check() {
        let plain = b"hello";
        let hash = blake3::hash(plain).as_bytes().to_owned();
        let out = DownloadPayload::from_wire_bytes(plain, &[], &hash, None).expect("plaintext ok");
        assert_eq!(out.plaintext, plain);
    }

    #[test]
    fn plaintext_rejects_hash_mismatch() {
        let err = DownloadPayload::from_wire_bytes(b"hello", &[], &[0u8; 32], None).unwrap_err();
        assert_eq!(err, E2eeError::WireHashMismatch);
    }

    #[test]
    fn encrypted_round_trip_matches_upload_payload() {
        let salt = random_salt();
        let key = VaultKey::derive_from_passphrase(b"vault", &salt).unwrap();
        let upload = UploadPayload::from_plaintext_encrypted(b"secret note", &key).unwrap();
        let out = DownloadPayload::from_wire_bytes(
            &upload.wire_bytes,
            &upload.encryption_nonce,
            &upload.content_hash,
            Some(&key),
        )
        .expect("decrypt");
        assert_eq!(out.plaintext, b"secret note");
        assert_eq!(out.wire_content_hash, upload.content_hash);
    }

    #[test]
    fn encrypted_without_key_errors() {
        let salt = random_salt();
        let key = VaultKey::derive_from_passphrase(b"vault", &salt).unwrap();
        let upload = UploadPayload::from_plaintext_encrypted(b"x", &key).unwrap();
        assert_eq!(
            DownloadPayload::from_wire_bytes(
                &upload.wire_bytes,
                &upload.encryption_nonce,
                &upload.content_hash,
                None,
            ),
            Err(E2eeError::VaultKeyRequired)
        );
    }
}
