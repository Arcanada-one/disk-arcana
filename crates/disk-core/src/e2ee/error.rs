use thiserror::Error;

/// Errors from client-side E2EE operations (DISK-0015).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum E2eeError {
    #[error("salt must be at least 8 bytes")]
    SaltTooShort,
    #[error("key derivation failed: {0}")]
    KeyDerivation(String),
    #[error("cipher init failed: {0}")]
    Cipher(String),
    #[error("encrypt failed: {0}")]
    Encrypt(String),
    #[error("decrypt failed (wrong key or tampered ciphertext)")]
    DecryptFailed,
    #[error("wire content hash does not match downloaded bytes")]
    WireHashMismatch,
    #[error("encryption nonce must be 24 bytes")]
    InvalidNonce,
    #[error("vault key required to decrypt encrypted download")]
    VaultKeyRequired,
}
