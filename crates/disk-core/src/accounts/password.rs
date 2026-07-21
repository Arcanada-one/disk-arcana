//! Password hashing for SaaS accounts (DISK-0016).

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use thiserror::Error;

/// Minimum password length for signup.
pub const MIN_PASSWORD_LEN: usize = 8;

#[derive(Debug, Error)]
pub enum PasswordError {
    #[error("password must be at least {MIN_PASSWORD_LEN} characters")]
    TooShort,

    #[error("password hash error: {0}")]
    Hash(String),
}

/// Hash a plaintext password for storage (Argon2id).
pub fn hash_password(password: &str) -> Result<String, PasswordError> {
    if password.len() < MIN_PASSWORD_LEN {
        return Err(PasswordError::TooShort);
    }
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| PasswordError::Hash(e.to_string()))
}

/// Verify a plaintext password against a stored PHC string.
pub fn verify_password(password: &str, stored_hash: &str) -> Result<bool, PasswordError> {
    let parsed = PasswordHash::new(stored_hash).map_err(|e| PasswordError::Hash(e.to_string()))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_verify_round_trip() {
        let hash = hash_password("correct-horse").unwrap();
        assert!(verify_password("correct-horse", &hash).unwrap());
        assert!(!verify_password("wrong", &hash).unwrap());
    }

    #[test]
    fn rejects_short_password() {
        assert!(hash_password("short").is_err());
    }
}
