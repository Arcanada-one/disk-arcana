//! Interim HS256 JWT for SaaS accounts (DISK-0016).
//!
//! Migrates to Auth Arcana JWKS verification in a later slice.

use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const DEFAULT_ISSUER: &str = "disk-arcana";
pub const JWT_DEFAULT_TTL_SECS: u64 = 86_400;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiskJwtClaims {
    pub sub: String,
    pub email: String,
    pub tenant_id: String,
    pub email_verified: bool,
    pub exp: usize,
    pub iat: usize,
    pub iss: String,
}

#[derive(Debug, Error)]
pub enum JwtError {
    #[error("signing key must be at least 32 bytes")]
    KeyTooShort,

    #[error("jwt error: {0}")]
    Token(#[from] jsonwebtoken::errors::Error),
}

/// Issue a bearer token for an authenticated user.
pub fn issue_token(
    signing_key: &[u8],
    user_id: &str,
    email: &str,
    tenant_id: &str,
    email_verified: bool,
    ttl_secs: u64,
) -> Result<String, JwtError> {
    if signing_key.len() < 32 {
        return Err(JwtError::KeyTooShort);
    }
    let now = unix_now();
    let claims = DiskJwtClaims {
        sub: user_id.to_owned(),
        email: email.to_owned(),
        tenant_id: tenant_id.to_owned(),
        email_verified,
        iat: now,
        exp: now + ttl_secs as usize,
        iss: DEFAULT_ISSUER.into(),
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(signing_key),
    )
    .map_err(JwtError::from)
}

/// Validate a bearer token and return claims.
pub fn verify_token(signing_key: &[u8], token: &str) -> Result<DiskJwtClaims, JwtError> {
    if signing_key.len() < 32 {
        return Err(JwtError::KeyTooShort);
    }
    let mut validation = Validation::default();
    validation.set_issuer(&[DEFAULT_ISSUER]);
    let data = decode::<DiskJwtClaims>(token, &DecodingKey::from_secret(signing_key), &validation)?;
    Ok(data.claims)
}

fn unix_now() -> usize {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as usize)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_and_verify_round_trip() {
        let key = b"01234567890123456789012345678901";
        let token = issue_token(key, "u1", "a@b.com", "acme", false, 3600).unwrap();
        let claims = verify_token(key, &token).unwrap();
        assert_eq!(claims.sub, "u1");
        assert_eq!(claims.tenant_id, "acme");
        assert!(!claims.email_verified);
    }
}
