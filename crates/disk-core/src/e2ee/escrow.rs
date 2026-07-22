//! Multi-device vault key escrow (DISK-0015 slice 6).
//!
//! Wraps the 32-byte vault key with a **recovery passphrase** so a new device
//! can unlock E2EE without copying the primary vault passphrase. The escrow
//! blob is stored locally under `{state_dir}/escrow/` and may be synced by the
//! operator (server never sees plaintext keys).

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{decrypt, encrypt, random_salt, E2eeError, VaultKey};

/// On-disk escrow format version.
pub const ESCROW_FORMAT_VERSION: u8 = 1;

/// Filename suffix for escrow blobs (`{node_id}.escrow.json`).
pub const ESCROW_FILE_SUFFIX: &str = ".escrow.json";

/// Escrow envelope: recovery-passphrase-wrapped vault key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscrowBlob {
    pub v: u8,
    /// Argon2 salt (hex) for the recovery passphrase.
    pub recovery_salt_hex: String,
    /// XChaCha20 nonce (hex).
    pub nonce_hex: String,
    /// AEAD ciphertext of the raw vault key bytes.
    pub ciphertext_hex: String,
}

impl EscrowBlob {
    /// Serialize to JSON for local persistence / sync.
    pub fn to_json(&self) -> Result<String, E2eeError> {
        serde_json::to_string_pretty(self).map_err(|e| E2eeError::KeyDerivation(e.to_string()))
    }

    /// Parse a JSON escrow blob.
    pub fn from_json(s: &str) -> Result<Self, E2eeError> {
        let blob: Self =
            serde_json::from_str(s).map_err(|e| E2eeError::KeyDerivation(e.to_string()))?;
        if blob.v != ESCROW_FORMAT_VERSION {
            return Err(E2eeError::KeyDerivation(format!(
                "unsupported escrow version {}",
                blob.v
            )));
        }
        Ok(blob)
    }
}

/// Derive a recovery wrapping key from the operator-chosen recovery passphrase.
fn recovery_key(recovery_passphrase: &[u8], salt: &[u8]) -> Result<VaultKey, E2eeError> {
    VaultKey::derive_from_passphrase(recovery_passphrase, salt)
}

/// Create an escrow blob wrapping `vault_key` with `recovery_passphrase`.
pub fn create_escrow(
    vault_key: &VaultKey,
    recovery_passphrase: &[u8],
) -> Result<EscrowBlob, E2eeError> {
    if recovery_passphrase.is_empty() {
        return Err(E2eeError::KeyDerivation(
            "recovery passphrase must not be empty".into(),
        ));
    }
    let salt = random_salt();
    let wrap_key = recovery_key(recovery_passphrase, &salt)?;
    let encrypted = encrypt(vault_key.as_bytes(), &wrap_key)?;
    Ok(EscrowBlob {
        v: ESCROW_FORMAT_VERSION,
        recovery_salt_hex: hex::encode(salt),
        nonce_hex: hex::encode(encrypted.nonce),
        ciphertext_hex: hex::encode(&encrypted.ciphertext),
    })
}

/// Recover the vault key from an escrow blob and recovery passphrase.
pub fn recover_from_escrow(
    blob: &EscrowBlob,
    recovery_passphrase: &[u8],
) -> Result<VaultKey, E2eeError> {
    let salt = hex::decode(blob.recovery_salt_hex.trim())
        .map_err(|e| E2eeError::KeyDerivation(format!("invalid recovery_salt_hex: {e}")))?;
    if salt.len() < 8 {
        return Err(E2eeError::SaltTooShort);
    }
    let nonce_bytes = hex::decode(blob.nonce_hex.trim())
        .map_err(|e| E2eeError::KeyDerivation(format!("invalid nonce_hex: {e}")))?;
    if nonce_bytes.len() != super::NONCE_LEN {
        return Err(E2eeError::InvalidNonce);
    }
    let mut nonce = [0u8; super::NONCE_LEN];
    nonce.copy_from_slice(&nonce_bytes);
    let ciphertext = hex::decode(blob.ciphertext_hex.trim())
        .map_err(|e| E2eeError::KeyDerivation(format!("invalid ciphertext_hex: {e}")))?;

    let wrap_key = recovery_key(recovery_passphrase, &salt)?;
    let plain = decrypt(&super::EncryptedBlob { nonce, ciphertext }, &wrap_key)?;
    if plain.len() != super::KEY_LEN {
        return Err(E2eeError::DecryptFailed);
    }
    let mut key_bytes = [0u8; super::KEY_LEN];
    key_bytes.copy_from_slice(&plain);
    Ok(VaultKey::from_bytes(key_bytes))
}

/// Path for a node's escrow file: `{state_dir}/escrow/{node_id}.escrow.json`.
pub fn escrow_path(state_dir: &Path, node_id: &str) -> PathBuf {
    state_dir
        .join("escrow")
        .join(format!("{node_id}{ESCROW_FILE_SUFFIX}"))
}

/// Write an escrow blob to the canonical path (mode 0600 on Unix).
pub fn write_escrow_file(path: &Path, blob: &EscrowBlob) -> Result<(), E2eeError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| E2eeError::KeyDerivation(format!("create escrow dir: {e}")))?;
    }
    let json = blob.to_json()?;
    fs::write(path, json.as_bytes())
        .map_err(|e| E2eeError::KeyDerivation(format!("write escrow file: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|e| E2eeError::KeyDerivation(format!("chmod escrow file: {e}")))?;
    }
    Ok(())
}

/// Read an escrow blob from disk.
pub fn read_escrow_file(path: &Path) -> Result<EscrowBlob, E2eeError> {
    let raw = fs::read_to_string(path)
        .map_err(|e| E2eeError::KeyDerivation(format!("read escrow file: {e}")))?;
    EscrowBlob::from_json(&raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn escrow_round_trip() {
        let salt = random_salt();
        let vault_key = VaultKey::derive_from_passphrase(b"vault-pw", &salt).unwrap();
        let blob = create_escrow(&vault_key, b"recovery-secret").unwrap();
        let recovered = recover_from_escrow(&blob, b"recovery-secret").unwrap();
        assert_eq!(recovered.as_bytes(), vault_key.as_bytes());
    }

    #[test]
    fn wrong_recovery_passphrase_fails() {
        let salt = random_salt();
        let vault_key = VaultKey::derive_from_passphrase(b"vault-pw", &salt).unwrap();
        let blob = create_escrow(&vault_key, b"right").unwrap();
        assert!(recover_from_escrow(&blob, b"wrong").is_err());
    }

    #[test]
    fn file_round_trip() {
        let dir = tempdir().unwrap();
        let salt = [0x11u8; 16];
        let vault_key = VaultKey::derive_from_passphrase(b"v", &salt).unwrap();
        let blob = create_escrow(&vault_key, b"r").unwrap();
        let path = escrow_path(dir.path(), "node-a");
        write_escrow_file(&path, &blob).unwrap();
        let loaded = read_escrow_file(&path).unwrap();
        let recovered = recover_from_escrow(&loaded, b"r").unwrap();
        assert_eq!(recovered.as_bytes(), vault_key.as_bytes());
    }
}
