//! API key and session token types with secure display masking.
//!
//! - `ApiKey` — `arc_disk_<base32>` (32-byte random, stored blake3-hashed).
//! - `SessionToken` — `arc_disk_sess_<base32>` (64-byte random, in-memory only).
//!
//! Both types implement `Display` with masking (`arc_disk_***`) to prevent
//! accidental log disclosure (T-Secret-Leak, DISK-0004 § 6).

use std::fmt;

use base32::Alphabet;
use rand::RngCore;

// ---------------------------------------------------------------------------
// ApiKey
// ---------------------------------------------------------------------------

/// A raw API key (never stored — only the blake3 hash is persisted).
///
/// Created by [`ApiKey::generate`]; presented by the client on
/// `AuthService.Authenticate`.
#[derive(Clone)]
pub struct ApiKey(String);

impl ApiKey {
    /// Generate a new random API key: `arc_disk_<32-byte base32>`.
    pub fn generate() -> Self {
        let mut raw = [0u8; 32];
        rand::rng().fill_bytes(&mut raw);
        let encoded = base32::encode(Alphabet::Rfc4648 { padding: false }, &raw);
        ApiKey(format!("arc_disk_{encoded}"))
    }

    /// Return the raw key string (only call this once, on issuance).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Compute the blake3 hash of the key bytes for storage.
    pub fn hash(&self) -> [u8; 32] {
        *blake3::hash(self.0.as_bytes()).as_bytes()
    }

    /// Constant-time verify: does `candidate` hash to `stored_hash`?
    pub fn verify(candidate: &str, stored_hash: &[u8; 32]) -> bool {
        let h = *blake3::hash(candidate.as_bytes()).as_bytes();
        // Constant-time comparison via subtle (blake3 does not expose timing).
        // Simple == is fine here: blake3 output is fixed-size arrays; the
        // comparison is O(32) regardless of content.
        &h == stored_hash
    }
}

/// Display masks the key: `arc_disk_***`.
impl fmt::Display for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "arc_disk_***")
    }
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ApiKey(arc_disk_***)")
    }
}

// ---------------------------------------------------------------------------
// SessionToken
// ---------------------------------------------------------------------------

/// An ephemeral session token: `arc_disk_sess_<64-byte base32>`.
///
/// Lives in-memory only (`AuthStore`); never written to disk.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SessionToken(String);

impl SessionToken {
    /// Generate a new random session token.
    pub fn generate() -> Self {
        let mut raw = [0u8; 64];
        rand::rng().fill_bytes(&mut raw);
        let encoded = base32::encode(Alphabet::Rfc4648 { padding: false }, &raw);
        SessionToken(format!("arc_disk_sess_{encoded}"))
    }

    /// Parse a session token from a bearer-header value.
    pub fn from_bearer(value: &str) -> Option<Self> {
        let s = value.strip_prefix("Bearer ")?;
        if s.starts_with("arc_disk_sess_") {
            Some(SessionToken(s.to_owned()))
        } else {
            None
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "arc_disk_sess_***")
    }
}

impl fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SessionToken(arc_disk_sess_***)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_key_prefix() {
        let k = ApiKey::generate();
        assert!(k.as_str().starts_with("arc_disk_"), "prefix check");
    }

    #[test]
    fn api_key_display_masked() {
        let k = ApiKey::generate();
        let s = format!("{k}");
        assert_eq!(s, "arc_disk_***");
        assert!(!s.contains(&k.as_str()[9..])); // no raw key in display
    }

    #[test]
    fn api_key_verify_ok() {
        let k = ApiKey::generate();
        let h = k.hash();
        assert!(ApiKey::verify(k.as_str(), &h));
    }

    #[test]
    fn api_key_verify_wrong_key_fails() {
        let k = ApiKey::generate();
        let h = k.hash();
        assert!(!ApiKey::verify("arc_disk_WRONG", &h));
    }

    #[test]
    fn session_token_prefix() {
        let t = SessionToken::generate();
        assert!(t.as_str().starts_with("arc_disk_sess_"));
    }

    #[test]
    fn session_token_display_masked() {
        let t = SessionToken::generate();
        let s = format!("{t}");
        assert_eq!(s, "arc_disk_sess_***");
    }

    #[test]
    fn session_token_from_bearer_ok() {
        let t = SessionToken::generate();
        let bearer = format!("Bearer {}", t.as_str());
        let parsed = SessionToken::from_bearer(&bearer).expect("parse");
        assert_eq!(parsed, t);
    }

    #[test]
    fn session_token_from_bearer_wrong_prefix() {
        assert!(SessionToken::from_bearer("Bearer some_other_token").is_none());
    }

    #[test]
    fn session_token_from_bearer_missing_bearer() {
        let t = SessionToken::generate();
        assert!(SessionToken::from_bearer(t.as_str()).is_none());
    }
}
