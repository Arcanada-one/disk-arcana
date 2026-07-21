//! SaaS user account primitives (DISK-0016).

mod jwt;
mod password;

pub use jwt::{
    issue_token, verify_token, DiskJwtClaims, JwtError, DEFAULT_ISSUER, JWT_DEFAULT_TTL_SECS,
};
pub use password::{hash_password, verify_password, PasswordError, MIN_PASSWORD_LEN};

/// Sentinel stored in `password_hash` for OAuth-only accounts (DISK-0016 slice 2).
pub const OAUTH_PASSWORD_SENTINEL: &str = "!oauth:no-password!";

/// Generate a random user id (`usr_` + 16 hex bytes).
pub fn new_user_id() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 16];
    rand::rng().fill_bytes(&mut buf);
    format!("usr_{}", hex::encode(buf))
}

/// Normalize email for storage and lookup.
pub fn normalize_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

/// Basic email shape check (not full RFC validation).
pub fn validate_email(email: &str) -> bool {
    let e = normalize_email(email);
    let Some((local, domain)) = e.split_once('@') else {
        return false;
    };
    !local.is_empty() && domain.contains('.') && !domain.starts_with('.')
}

/// Derive a default tenant slug from email local-part when omitted at signup.
pub fn default_tenant_from_email(email: &str) -> Option<String> {
    let normalized = normalize_email(email);
    let local = normalized.split_once('@')?.0;
    sanitize_tenant_slug(local)
}

/// Sanitize tenant slug for storage (matches DISK-0017 tenant id rules).
pub fn sanitize_tenant_slug(raw: &str) -> Option<String> {
    let slug: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let slug = slug.trim_matches('-').to_string();
    if slug.is_empty() || slug.len() > 64 {
        None
    } else {
        Some(slug)
    }
}
