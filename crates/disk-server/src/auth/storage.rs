//! In-memory authentication store.
//!
//! Holds node registrations (backed by SQLite via `disk-core::meta_db`) and
//! active session tokens (in-memory `DashMap` with TTL).

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;

use super::api_key::{ApiKey, SessionToken};
use super::rate_limit::{AuthAttemptLimiter, SharedAuthAttemptLimiter};

/// TTL for session tokens (24 hours).
pub const SESSION_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// A registered node entry (in-memory after load from SQLite).
#[derive(Debug, Clone)]
pub struct NodeEntry {
    pub node_id: String,
    /// blake3 hash of the api_key.
    pub api_key_hash: [u8; 32],
    pub display_name: String,
    pub platform: String,
    pub registered_at: i64,
}

/// Live session entry.
#[derive(Debug, Clone)]
struct SessionEntry {
    pub node_id: String,
    pub expires_at: u64, // Unix timestamp seconds
}

/// Shared authentication store (cheaply cloneable via `Arc`).
///
/// For Phase 3, node persistence is in-memory (no SQLite migration in server
/// code yet — that is wired in Step 8 through `disk-core::meta_db`).  The
/// session map is always in-memory.
#[derive(Debug, Clone)]
pub struct AuthStore {
    inner: Arc<StoreInner>,
}

#[derive(Debug)]
struct StoreInner {
    nodes: DashMap<String, NodeEntry>,
    sessions: DashMap<SessionToken, SessionEntry>,
    limiter: Option<SharedAuthAttemptLimiter>,
}

impl AuthStore {
    /// Create a new, empty store with default auth rate limiting enabled.
    pub fn new() -> Self {
        Self::with_rate_limiter(Some(Arc::new(AuthAttemptLimiter::default())))
    }

    /// Create a store with an optional per-node failed-auth rate limiter.
    pub fn with_rate_limiter(limiter: Option<SharedAuthAttemptLimiter>) -> Self {
        Self {
            inner: Arc::new(StoreInner {
                nodes: DashMap::new(),
                sessions: DashMap::new(),
                limiter,
            }),
        }
    }

    /// Register a new node.  Returns the raw (unhashed) `ApiKey` — this is
    /// the only time the plaintext key is available.
    ///
    /// Returns `Err(AlreadyExists)` if `node_id` is already registered.
    pub fn register_node(
        &self,
        node_id: &str,
        display_name: &str,
        platform: &str,
    ) -> Result<ApiKey, AuthError> {
        if self.inner.nodes.contains_key(node_id) {
            return Err(AuthError::AlreadyExists);
        }
        let key = ApiKey::generate();
        let entry = NodeEntry {
            node_id: node_id.to_owned(),
            api_key_hash: key.hash(),
            display_name: display_name.to_owned(),
            platform: platform.to_owned(),
            registered_at: unix_now_secs() as i64,
        };
        self.inner.nodes.insert(node_id.to_owned(), entry);
        Ok(key)
    }

    /// Authenticate a node with its `api_key`.
    ///
    /// Returns a fresh `SessionToken` valid for [`SESSION_TTL`].
    /// Returns `Err(Unauthenticated)` on wrong key or unknown node.
    /// Returns `Err(RateLimited)` when too many failed attempts occurred recently.
    pub fn authenticate(
        &self,
        node_id: &str,
        api_key: &str,
    ) -> Result<(SessionToken, i64), AuthError> {
        let now = unix_now_secs();
        if let Some(limiter) = &self.inner.limiter {
            limiter
                .check(node_id, now)
                .map_err(|e| AuthError::RateLimited {
                    retry_after_secs: e.retry_after_secs,
                })?;
        }

        let authed = match self.inner.nodes.get(node_id) {
            Some(entry) => ApiKey::verify(api_key, &entry.api_key_hash),
            None => false,
        };

        if !authed {
            if let Some(limiter) = &self.inner.limiter {
                limiter.record_failure(node_id, now);
            }
            return Err(AuthError::Unauthenticated);
        }

        if let Some(limiter) = &self.inner.limiter {
            limiter.clear(node_id);
        }

        let expires_at = unix_now_secs() + SESSION_TTL.as_secs();
        let token = SessionToken::generate();
        self.inner.sessions.insert(
            token.clone(),
            SessionEntry {
                node_id: node_id.to_owned(),
                expires_at,
            },
        );
        Ok((token, expires_at as i64))
    }

    /// Validate a session token.  Returns the `node_id` if valid.
    pub fn validate_session(&self, token: &SessionToken) -> Option<String> {
        let entry = self.inner.sessions.get(token)?;
        if unix_now_secs() >= entry.expires_at {
            drop(entry);
            self.inner.sessions.remove(token);
            return None;
        }
        Some(entry.node_id.clone())
    }

    /// Return the number of registered nodes.
    pub fn node_count(&self) -> usize {
        self.inner.nodes.len()
    }

    /// Whether `node_id` is already registered.
    pub fn has_node(&self, node_id: &str) -> bool {
        self.inner.nodes.contains_key(node_id)
    }

    /// Return the number of active sessions.
    pub fn session_count(&self) -> usize {
        self.inner.sessions.len()
    }

    /// Insert a session with explicit expiry (tests only).
    #[cfg(test)]
    pub fn insert_test_session(&self, token: SessionToken, node_id: &str, expires_at: u64) {
        self.inner.sessions.insert(
            token,
            SessionEntry {
                node_id: node_id.to_owned(),
                expires_at,
            },
        );
    }
}

impl Default for AuthStore {
    fn default() -> Self {
        Self::new()
    }
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Errors from auth store operations.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("node already registered")]
    AlreadyExists,
    #[error("unauthenticated: bad credentials")]
    Unauthenticated,
    #[error("too many failed auth attempts; retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },
    #[error("session expired or unknown")]
    SessionExpired,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_and_authenticate_ok() {
        let store = AuthStore::new();
        let key = store
            .register_node("node-1", "My Node", "darwin")
            .expect("register");
        let (token, expires_at) = store
            .authenticate("node-1", key.as_str())
            .expect("authenticate");
        assert!(token.as_str().starts_with("arc_disk_sess_"));
        assert!(expires_at > unix_now_secs() as i64);
    }

    #[test]
    fn wrong_key_unauthenticated() {
        let store = AuthStore::new();
        store
            .register_node("node-2", "N", "linux")
            .expect("register");
        let err = store
            .authenticate("node-2", "arc_disk_WRONGKEY")
            .unwrap_err();
        assert_eq!(err, AuthError::Unauthenticated);
    }

    #[test]
    fn unknown_node_unauthenticated() {
        let store = AuthStore::new();
        let err = store
            .authenticate("ghost", "arc_disk_ANYTHING")
            .unwrap_err();
        assert_eq!(err, AuthError::Unauthenticated);
    }

    #[test]
    fn double_register_same_node_id_fails() {
        let store = AuthStore::new();
        store
            .register_node("node-3", "N", "linux")
            .expect("first register");
        let err = store.register_node("node-3", "N", "linux").unwrap_err();
        assert_eq!(err, AuthError::AlreadyExists);
    }

    #[test]
    fn validate_session_ok() {
        let store = AuthStore::new();
        let key = store
            .register_node("node-4", "N", "linux")
            .expect("register");
        let (token, _) = store.authenticate("node-4", key.as_str()).expect("auth");
        let node_id = store.validate_session(&token).expect("validate");
        assert_eq!(node_id, "node-4");
    }

    #[test]
    fn validate_unknown_session_returns_none() {
        let store = AuthStore::new();
        let fake = SessionToken::generate();
        assert!(store.validate_session(&fake).is_none());
    }

    #[test]
    fn validate_expired_session_returns_none_and_evicts() {
        let store = AuthStore::new();
        let token = SessionToken::generate();
        store.insert_test_session(token.clone(), "node-x", 1);
        assert!(store.validate_session(&token).is_none());
        assert_eq!(store.session_count(), 0);
    }

    #[test]
    fn rate_limited_after_repeated_failures() {
        use std::time::Duration;

        use super::super::rate_limit::AuthAttemptLimiter;

        let limiter = Arc::new(AuthAttemptLimiter::new(3, Duration::from_secs(60)));
        let store = AuthStore::with_rate_limiter(Some(limiter));
        store
            .register_node("node-rl", "N", "linux")
            .expect("register");

        for _ in 0..3 {
            let err = store.authenticate("node-rl", "arc_disk_WRONG").unwrap_err();
            assert_eq!(err, AuthError::Unauthenticated);
        }

        let err = store.authenticate("node-rl", "arc_disk_WRONG").unwrap_err();
        assert!(matches!(err, AuthError::RateLimited { .. }));
    }

    #[test]
    fn successful_auth_clears_rate_limit_counter() {
        use std::time::Duration;

        use super::super::rate_limit::AuthAttemptLimiter;

        let limiter = Arc::new(AuthAttemptLimiter::new(2, Duration::from_secs(60)));
        let store = AuthStore::with_rate_limiter(Some(limiter));
        let key = store
            .register_node("node-rl2", "N", "linux")
            .expect("register");

        store
            .authenticate("node-rl2", "arc_disk_WRONG")
            .unwrap_err();
        store
            .authenticate("node-rl2", key.as_str())
            .expect("auth ok");

        // Counter cleared — two more failures should trigger block on third.
        store
            .authenticate("node-rl2", "arc_disk_WRONG")
            .unwrap_err();
        store
            .authenticate("node-rl2", "arc_disk_WRONG")
            .unwrap_err();
        let err = store
            .authenticate("node-rl2", "arc_disk_WRONG")
            .unwrap_err();
        assert!(matches!(err, AuthError::RateLimited { .. }));
    }

    #[test]
    fn node_count_and_session_count() {
        let store = AuthStore::new();
        assert_eq!(store.node_count(), 0);
        assert_eq!(store.session_count(), 0);
        let key = store
            .register_node("node-5", "N", "linux")
            .expect("register");
        assert_eq!(store.node_count(), 1);
        store.authenticate("node-5", key.as_str()).expect("auth");
        assert_eq!(store.session_count(), 1);
    }
}
