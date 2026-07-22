//! Client-side E2EE primitives (DISK-0015 scaffold).
//!
//! The server stores ciphertext only; vault keys never leave the client.
//! When `FileMetadata.encryption_nonce` is non-empty, `content_hash` is
//! `blake3(ciphertext)` — not the plaintext digest.

mod download;
mod error;
mod escrow;
mod exchange_overlay;
mod upload;

pub use download::DownloadPayload;
pub use error::E2eeError;
pub use escrow::{
    create_escrow, escrow_path, read_escrow_file, recover_from_escrow, write_escrow_file,
    EscrowBlob, ESCROW_FILE_SUFFIX, ESCROW_FORMAT_VERSION,
};
pub use exchange_overlay::{overlay_scanned_meta, E2eeCachedWire};
pub use upload::UploadPayload;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

/// XChaCha20-Poly1305 nonce length (bytes).
pub const NONCE_LEN: usize = 24;

/// Vault encryption key length (bytes).
pub const KEY_LEN: usize = 32;

/// Recommended Argon2id salt length for passphrase derivation.
pub const SALT_LEN: usize = 16;

/// 32-byte vault key — derived client-side, never sent to the server.
#[derive(Clone, PartialEq, Eq)]
pub struct VaultKey([u8; KEY_LEN]);

impl VaultKey {
    /// Derive a vault key from a passphrase and salt (Argon2id, OWASP-aligned params).
    pub fn derive_from_passphrase(passphrase: &[u8], salt: &[u8]) -> Result<Self, E2eeError> {
        if salt.len() < 8 {
            return Err(E2eeError::SaltTooShort);
        }
        let params = Params::new(19_456, 2, 1, Some(KEY_LEN))
            .map_err(|e| E2eeError::KeyDerivation(e.to_string()))?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = [0u8; KEY_LEN];
        argon
            .hash_password_into(passphrase, salt, &mut key)
            .map_err(|e| E2eeError::KeyDerivation(e.to_string()))?;
        Ok(Self(key))
    }

    /// Construct from raw key bytes (e.g. loaded from OS keychain).
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Expose key bytes for tests and keychain round-trip.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

/// Ciphertext envelope: random nonce + AEAD output (includes Poly1305 tag).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedBlob {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

impl EncryptedBlob {
    /// Nonce bytes for `FileMetadata.encryption_nonce` (proto field 10).
    pub fn nonce_bytes(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }
}

/// Encrypt `plaintext` with a fresh random nonce.
pub fn encrypt(plaintext: &[u8], key: &VaultKey) -> Result<EncryptedBlob, E2eeError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|e| E2eeError::Cipher(e.to_string()))?;
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(&XNonce::from(nonce), plaintext)
        .map_err(|e| E2eeError::Encrypt(e.to_string()))?;
    Ok(EncryptedBlob { nonce, ciphertext })
}

/// Decrypt an envelope produced by [`encrypt`].
pub fn decrypt(blob: &EncryptedBlob, key: &VaultKey) -> Result<Vec<u8>, E2eeError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|e| E2eeError::Cipher(e.to_string()))?;
    cipher
        .decrypt(&XNonce::from(blob.nonce), blob.ciphertext.as_ref())
        .map_err(|_| E2eeError::DecryptFailed)
}

/// Generate a random salt for [`VaultKey::derive_from_passphrase`].
pub fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_encrypt_decrypt() {
        let salt = random_salt();
        let key = VaultKey::derive_from_passphrase(b"test-passphrase", &salt).unwrap();
        let blob = encrypt(b"hello vault", &key).unwrap();
        let plain = decrypt(&blob, &key).unwrap();
        assert_eq!(plain, b"hello vault");
    }

    #[test]
    fn wrong_key_fails_decrypt() {
        let salt = random_salt();
        let key = VaultKey::derive_from_passphrase(b"one", &salt).unwrap();
        let other = VaultKey::derive_from_passphrase(b"two", &salt).unwrap();
        let blob = encrypt(b"secret", &key).unwrap();
        assert_eq!(decrypt(&blob, &other), Err(E2eeError::DecryptFailed));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let salt = random_salt();
        let key = VaultKey::derive_from_passphrase(b"pw", &salt).unwrap();
        let mut blob = encrypt(b"data", &key).unwrap();
        if let Some(byte) = blob.ciphertext.last_mut() {
            *byte ^= 0xFF;
        }
        assert_eq!(decrypt(&blob, &key), Err(E2eeError::DecryptFailed));
    }

    #[test]
    fn derive_is_deterministic_for_same_inputs() {
        let salt = [0x42u8; SALT_LEN];
        let a = VaultKey::derive_from_passphrase(b"same", &salt).unwrap();
        let b = VaultKey::derive_from_passphrase(b"same", &salt).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }
}
