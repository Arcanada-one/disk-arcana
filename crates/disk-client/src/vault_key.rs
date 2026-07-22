//! E2EE vault key loading — env, OS keychain, and unlock helpers (DISK-0015).

use std::path::Path;

use disk_core::{random_salt, E2eeError, VaultKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::keychain::{
    detect_or_file, validate_label, KeyStore, KeyStoreError, DEFAULT_OS_KEYRING_SERVICE,
};

/// Errors from vault key unlock / load paths.
#[derive(Debug, Error)]
pub enum VaultKeyError {
    #[error("e2ee: {0}")]
    E2ee(#[from] E2eeError),

    #[error("keystore: {0}")]
    KeyStore(#[from] KeyStoreError),

    #[error("passphrase must not be empty")]
    EmptyPassphrase,

    #[error("invalid stored E2EE record: {0}")]
    InvalidRecord(String),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

/// Whether an unlocked E2EE key is present in the keychain/file store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultLockState {
    Locked,
    Unlocked,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredE2eeKey {
    v: u8,
    salt: String,
    key: String,
}

/// Keychain / file-store label for a node's derived E2EE key (`e2ee.<node_id>`).
pub fn e2ee_keystore_label(node_id: &str) -> Result<String, KeyStoreError> {
    let label = format!("e2ee.{node_id}");
    validate_label(&label)?;
    Ok(label)
}

/// Open the platform key store with file fallback under `{state_dir}/keys`.
pub fn open_e2ee_keystore(state_dir: &Path) -> Result<Box<dyn KeyStore>, VaultKeyError> {
    let fallback = state_dir.join("keys");
    Ok(detect_or_file(DEFAULT_OS_KEYRING_SERVICE, fallback)?)
}

/// Load a vault key from `DISK_VAULT_PASSPHRASE` + `DISK_VAULT_SALT` (hex).
///
/// Returns `Ok(None)` when the passphrase env var is unset or empty.
pub fn load_vault_key_from_env() -> Result<Option<VaultKey>, E2eeError> {
    let passphrase = match std::env::var("DISK_VAULT_PASSPHRASE") {
        Ok(v) if !v.is_empty() => v,
        _ => return Ok(None),
    };
    let salt_hex = std::env::var("DISK_VAULT_SALT").map_err(|_| {
        E2eeError::KeyDerivation(
            "DISK_VAULT_SALT required when DISK_VAULT_PASSPHRASE is set".into(),
        )
    })?;
    let salt = hex::decode(salt_hex.trim())
        .map_err(|e| E2eeError::KeyDerivation(format!("invalid DISK_VAULT_SALT hex: {e}")))?;
    Ok(Some(VaultKey::derive_from_passphrase(
        passphrase.as_bytes(),
        &salt,
    )?))
}

/// Load a previously unlocked key from the keychain (no passphrase).
pub fn load_vault_key_from_keystore(
    node_id: &str,
    state_dir: &Path,
) -> Result<Option<VaultKey>, VaultKeyError> {
    let label = e2ee_keystore_label(node_id)?;
    let store = open_e2ee_keystore(state_dir)?;
    let Some(blob) = store.load(&label)? else {
        return Ok(None);
    };
    Ok(Some(parse_stored_key(&blob)?))
}

/// Resolve E2EE key: env vars (dev/CI) take precedence, then keychain unlock.
pub fn resolve_vault_key(
    node_id: &str,
    state_dir: &Path,
) -> Result<Option<VaultKey>, VaultKeyError> {
    if let Some(key) = load_vault_key_from_env()? {
        return Ok(Some(key));
    }
    load_vault_key_from_keystore(node_id, state_dir)
}

/// Derive a vault key from `passphrase`, persist salt + derived key, return lock state.
pub fn unlock_vault_key(
    passphrase: &[u8],
    node_id: &str,
    state_dir: &Path,
    salt_override: Option<&[u8]>,
) -> Result<(), VaultKeyError> {
    if passphrase.is_empty() {
        return Err(VaultKeyError::EmptyPassphrase);
    }

    let label = e2ee_keystore_label(node_id)?;
    let store = open_e2ee_keystore(state_dir)?;

    let salt: Vec<u8> = if let Some(s) = salt_override {
        if s.len() < 8 {
            return Err(VaultKeyError::E2ee(E2eeError::SaltTooShort));
        }
        s.to_vec()
    } else if let Some(existing) = store.load(&label)? {
        let record: StoredE2eeKey = serde_json::from_str(&existing)
            .map_err(|e| VaultKeyError::InvalidRecord(format!("parse stored record: {e}")))?;
        if record.v != 1 {
            return Err(VaultKeyError::InvalidRecord(format!(
                "unsupported record version {}",
                record.v
            )));
        }
        hex::decode(record.salt.trim())
            .map_err(|e| VaultKeyError::InvalidRecord(format!("invalid salt hex: {e}")))?
    } else {
        random_salt().to_vec()
    };

    let key = VaultKey::derive_from_passphrase(passphrase, &salt)?;
    let record = StoredE2eeKey {
        v: 1,
        salt: hex::encode(&salt),
        key: hex::encode(key.as_bytes()),
    };
    store.store(&label, &serde_json::to_string(&record)?)?;
    Ok(())
}

/// Import a raw vault key into the keychain (e.g. after escrow recovery).
pub fn import_vault_key(
    key: &VaultKey,
    node_id: &str,
    state_dir: &Path,
) -> Result<(), VaultKeyError> {
    let label = e2ee_keystore_label(node_id)?;
    let store = open_e2ee_keystore(state_dir)?;
    let salt = random_salt();
    let record = StoredE2eeKey {
        v: 1,
        salt: hex::encode(salt),
        key: hex::encode(key.as_bytes()),
    };
    store.store(&label, &serde_json::to_string(&record)?)?;
    Ok(())
}

/// Remove the unlocked key material from the keychain (idempotent).
pub fn lock_vault_key(node_id: &str, state_dir: &Path) -> Result<bool, VaultKeyError> {
    let label = e2ee_keystore_label(node_id)?;
    let store = open_e2ee_keystore(state_dir)?;
    let had_entry = store.load(&label)?.is_some();
    store.delete(&label)?;
    Ok(had_entry)
}

/// Query whether the keychain holds an unlocked E2EE key for `node_id`.
pub fn vault_key_status(node_id: &str, state_dir: &Path) -> Result<VaultLockState, VaultKeyError> {
    let label = e2ee_keystore_label(node_id)?;
    let store = open_e2ee_keystore(state_dir)?;
    Ok(if store.load(&label)?.is_some() {
        VaultLockState::Unlocked
    } else {
        VaultLockState::Locked
    })
}

fn parse_stored_key(blob: &str) -> Result<VaultKey, VaultKeyError> {
    let record: StoredE2eeKey = serde_json::from_str(blob)
        .map_err(|e| VaultKeyError::InvalidRecord(format!("parse: {e}")))?;
    if record.v != 1 {
        return Err(VaultKeyError::InvalidRecord(format!(
            "unsupported version {}",
            record.v
        )));
    }
    let key_bytes = hex::decode(record.key.trim())
        .map_err(|e| VaultKeyError::InvalidRecord(format!("invalid key hex: {e}")))?;
    let arr: [u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| VaultKeyError::InvalidRecord("key length != 32".into()))?;
    Ok(VaultKey::from_bytes(arr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn env_loader_returns_none_without_passphrase() {
        if std::env::var_os("DISK_VAULT_PASSPHRASE").is_some() {
            return;
        }
        assert!(load_vault_key_from_env().unwrap().is_none());
    }

    #[test]
    fn unlock_lock_round_trip() {
        let tmp = tempdir().unwrap();
        let node_id = "arcana-ai";
        std::env::remove_var("DISK_VAULT_PASSPHRASE");
        std::env::remove_var("DISK_VAULT_SALT");

        unlock_vault_key(b"secret", node_id, tmp.path(), None).unwrap();
        assert_eq!(
            vault_key_status(node_id, tmp.path()).unwrap(),
            VaultLockState::Unlocked
        );
        let loaded = load_vault_key_from_keystore(node_id, tmp.path())
            .unwrap()
            .expect("key");
        unlock_vault_key(b"secret", node_id, tmp.path(), None).unwrap();
        let again = load_vault_key_from_keystore(node_id, tmp.path())
            .unwrap()
            .unwrap();
        assert_eq!(loaded.as_bytes(), again.as_bytes());

        assert!(lock_vault_key(node_id, tmp.path()).unwrap());
        assert_eq!(
            vault_key_status(node_id, tmp.path()).unwrap(),
            VaultLockState::Locked
        );
    }

    #[test]
    fn unlock_reuses_salt_from_existing_record() {
        let tmp = tempdir().unwrap();
        let node_id = "node-a";
        let salt = random_salt();
        unlock_vault_key(b"first", node_id, tmp.path(), Some(&salt)).unwrap();
        let first = load_vault_key_from_keystore(node_id, tmp.path())
            .unwrap()
            .unwrap();

        unlock_vault_key(b"first", node_id, tmp.path(), None).unwrap();
        let again = load_vault_key_from_keystore(node_id, tmp.path())
            .unwrap()
            .unwrap();
        assert_eq!(first.as_bytes(), again.as_bytes());

        unlock_vault_key(b"rotated", node_id, tmp.path(), None).unwrap();
        let rotated = load_vault_key_from_keystore(node_id, tmp.path())
            .unwrap()
            .unwrap();
        assert_ne!(first.as_bytes(), rotated.as_bytes());
    }

    #[test]
    fn e2ee_label_rejects_invalid_node_id() {
        assert!(e2ee_keystore_label("../evil").is_err());
    }
}
