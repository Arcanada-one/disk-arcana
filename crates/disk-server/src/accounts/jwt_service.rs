//! Bearer JWT issue/verify — local HS256 + Auth Arcana JWKS (DISK-0016 slice 4).

use std::sync::Arc;

use disk_core::{issue_token, verify_token, JwtError};
use jsonwebtoken::{decode, decode_header, Validation};
use serde::Deserialize;

use super::jwks::{JwksCache, JwksError};
use super::jwt_mode::JwtMode;

/// Normalized access-token claims used by `/auth/*` handlers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAccess {
    pub sub: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub tenant_id: Option<String>,
}

/// Runtime JWT configuration wired into [`super::routes::AuthHttpState`].
#[derive(Clone)]
pub struct JwtConfig {
    pub mode: JwtMode,
    pub local_signing_key: Vec<u8>,
    pub token_ttl_secs: u64,
    pub issuer: String,
    pub jwks: Arc<JwksCache>,
}

#[derive(Debug, thiserror::Error)]
pub enum AccessTokenError {
    #[error("local jwt issue disabled in auth_arcana mode")]
    LocalIssueDisabled,

    #[error("jwt error: {0}")]
    Jwt(#[from] JwtError),

    #[error("jwks error: {0}")]
    Jwks(#[from] JwksError),

    #[error("token invalid")]
    Invalid,

    #[error("token header invalid")]
    Header(#[from] jsonwebtoken::errors::Error),
}

impl JwtConfig {
    pub fn issue_local(
        &self,
        user_id: &str,
        email: &str,
        tenant_id: &str,
        email_verified: bool,
    ) -> Result<String, AccessTokenError> {
        if !self.mode.allows_local_issue() {
            return Err(AccessTokenError::LocalIssueDisabled);
        }
        issue_token(
            &self.local_signing_key,
            user_id,
            email,
            tenant_id,
            email_verified,
            self.token_ttl_secs,
        )
        .map_err(AccessTokenError::from)
    }

    pub async fn verify(&self, token: &str) -> Result<VerifiedAccess, AccessTokenError> {
        if self.mode.allows_jwks_verify() {
            if let Ok(claims) = self.verify_jwks(token).await {
                return Ok(claims);
            }
            if self.mode == JwtMode::AuthArcana {
                return Err(AccessTokenError::Invalid);
            }
        }
        self.verify_local(token)
    }

    fn verify_local(&self, token: &str) -> Result<VerifiedAccess, AccessTokenError> {
        let claims = verify_token(&self.local_signing_key, token)?;
        Ok(VerifiedAccess {
            sub: claims.sub,
            email: Some(claims.email),
            email_verified: claims.email_verified,
            tenant_id: Some(claims.tenant_id),
        })
    }

    async fn verify_jwks(&self, token: &str) -> Result<VerifiedAccess, AccessTokenError> {
        let header = decode_header(token)?;
        let kid = header.kid.ok_or(AccessTokenError::Invalid)?;
        let key = self.jwks.decoding_key(&kid).await?;

        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[&self.issuer]);
        validation.validate_exp = true;

        let data = decode::<OidcAccessClaims>(token, &key, &validation)
            .map_err(|_| AccessTokenError::Invalid)?;

        Ok(VerifiedAccess {
            sub: data.claims.sub,
            email: data.claims.email,
            email_verified: data.claims.email_verified.unwrap_or(false),
            tenant_id: data.claims.tenant_id,
        })
    }
}

#[derive(Debug, Deserialize)]
struct OidcAccessClaims {
    sub: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: Option<bool>,
    #[serde(default)]
    tenant_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_issue_disabled_in_auth_arcana_mode() {
        let cfg = JwtConfig {
            mode: JwtMode::AuthArcana,
            local_signing_key: b"01234567890123456789012345678901".to_vec(),
            token_ttl_secs: 3600,
            issuer: "https://auth.test".into(),
            jwks: Arc::new(JwksCache::new("http://127.0.0.1:9/jwks")),
        };
        assert!(matches!(
            cfg.issue_local("u1", "a@b.com", "acme", false),
            Err(AccessTokenError::LocalIssueDisabled)
        ));
    }
}
