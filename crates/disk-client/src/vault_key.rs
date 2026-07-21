//! Dev/CI vault key loading for client-side E2EE (DISK-0015).

use disk_core::{E2eeError, VaultKey};

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

#[cfg(test)]
mod tests {
    use super::*;
    use disk_core::random_salt;

    #[test]
    fn env_loader_returns_none_without_passphrase() {
        // Do not set env in parallel tests — only assert the unset path when
        // the var is absent in this process.
        if std::env::var_os("DISK_VAULT_PASSPHRASE").is_some() {
            return;
        }
        assert!(load_vault_key_from_env().unwrap().is_none());
    }

    #[test]
    fn env_loader_derives_key_from_hex_salt() {
        let salt = random_salt();
        let hex_salt = hex::encode(salt);
        std::env::set_var("DISK_VAULT_PASSPHRASE", "test-pass");
        std::env::set_var("DISK_VAULT_SALT", &hex_salt);
        let key = load_vault_key_from_env().expect("load").expect("some key");
        let again = VaultKey::derive_from_passphrase(b"test-pass", &salt).unwrap();
        assert_eq!(key.as_bytes(), again.as_bytes());
        std::env::remove_var("DISK_VAULT_PASSPHRASE");
        std::env::remove_var("DISK_VAULT_SALT");
    }
}
