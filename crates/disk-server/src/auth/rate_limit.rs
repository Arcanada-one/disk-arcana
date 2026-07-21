//! Per-`node_id` failed authentication rate limiter (OWASP G1 / DISK-0012).

use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;

/// Default: 5 failed attempts per node per minute.
pub const DEFAULT_MAX_FAILURES: u32 = 5;
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitError {
    pub retry_after_secs: u64,
}

/// Sliding-window counter of failed `Authenticate` attempts per `node_id`.
#[derive(Debug)]
pub struct AuthAttemptLimiter {
    failures: DashMap<String, Vec<u64>>,
    max_failures: u32,
    window_secs: u64,
}

impl Default for AuthAttemptLimiter {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_FAILURES, DEFAULT_WINDOW)
    }
}

impl AuthAttemptLimiter {
    pub fn new(max_failures: u32, window: Duration) -> Self {
        Self {
            failures: DashMap::new(),
            max_failures,
            window_secs: window.as_secs().max(1),
        }
    }

    /// Returns `Err` when the node is temporarily blocked.
    pub fn check(&self, node_id: &str, now_secs: u64) -> Result<(), RateLimitError> {
        let count = self.prune_and_count(node_id, now_secs);
        if count >= self.max_failures {
            let retry_after_secs = self.retry_after_secs(node_id, now_secs);
            return Err(RateLimitError { retry_after_secs });
        }
        Ok(())
    }

    pub fn record_failure(&self, node_id: &str, now_secs: u64) {
        let mut entry = self.failures.entry(node_id.to_owned()).or_default();
        entry.retain(|t| now_secs.saturating_sub(*t) < self.window_secs);
        entry.push(now_secs);
    }

    pub fn clear(&self, node_id: &str) {
        self.failures.remove(node_id);
    }

    fn prune_and_count(&self, node_id: &str, now_secs: u64) -> u32 {
        let Some(mut entry) = self.failures.get_mut(node_id) else {
            return 0;
        };
        entry.retain(|t| now_secs.saturating_sub(*t) < self.window_secs);
        entry.len() as u32
    }

    fn retry_after_secs(&self, node_id: &str, now_secs: u64) -> u64 {
        let Some(entry) = self.failures.get(node_id) else {
            return self.window_secs;
        };
        let oldest = entry.iter().min().copied().unwrap_or(now_secs);
        let elapsed = now_secs.saturating_sub(oldest);
        self.window_secs.saturating_sub(elapsed).max(1)
    }
}

/// Shared limiter wired into [`super::storage::AuthStore`].
pub type SharedAuthAttemptLimiter = Arc<AuthAttemptLimiter>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_after_max_failures_in_window() {
        let lim = AuthAttemptLimiter::new(3, Duration::from_secs(60));
        let node = "node-a";
        for i in 0..3 {
            assert!(lim.check(node, i).is_ok());
            lim.record_failure(node, i);
        }
        let err = lim.check(node, 3).unwrap_err();
        assert!(err.retry_after_secs > 0);
    }

    #[test]
    fn success_clears_failures() {
        let lim = AuthAttemptLimiter::new(2, Duration::from_secs(60));
        let node = "node-b";
        lim.record_failure(node, 10);
        lim.record_failure(node, 11);
        assert!(lim.check(node, 12).is_err());
        lim.clear(node);
        assert!(lim.check(node, 12).is_ok());
    }

    #[test]
    fn failures_expire_after_window() {
        let lim = AuthAttemptLimiter::new(2, Duration::from_secs(60));
        let node = "node-c";
        lim.record_failure(node, 0);
        lim.record_failure(node, 1);
        assert!(lim.check(node, 1).is_err());
        assert!(lim.check(node, 61).is_ok());
    }
}
