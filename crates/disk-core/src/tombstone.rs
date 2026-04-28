//! Tombstone records and TTL helpers.
//!
//! [`Tombstone`] is a logical-delete marker propagated between nodes. Local
//! reconcilers consult [`Tombstone::is_expired`] in **read-only** mode: actual
//! GC is performed by the server in DISK-0005.

use serde::{Deserialize, Serialize};

/// Default tombstone TTL: 30 days, per `PRD-DISK-0001 § Sync semantics`.
pub const DEFAULT_TTL_SECS: u64 = 30 * 24 * 60 * 60;

/// Logical-delete record persisted in the `tombstones` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tombstone {
    pub path: String,
    pub last_hash: [u8; 32],
    pub deleted_by: String,
    pub deleted_at: i64,
    pub ttl_expires: i64,
    pub propagated: bool,
}

impl Tombstone {
    /// Build a fresh tombstone with `ttl_expires = deleted_at + ttl_secs`.
    pub fn new(
        path: String,
        last_hash: [u8; 32],
        deleted_by: String,
        deleted_at: i64,
        ttl_secs: u64,
    ) -> Self {
        Self {
            path,
            last_hash,
            deleted_by,
            deleted_at,
            ttl_expires: deleted_at.saturating_add(ttl_secs as i64),
            propagated: false,
        }
    }

    /// `true` once `now >= ttl_expires`. Strictly read-only — never deletes
    /// from the DB; callers in DISK-0003 use this for the reconciler tree.
    pub fn is_expired(&self, now: i64) -> bool {
        now >= self.ttl_expires
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make(deleted_at: i64, ttl_secs: u64) -> Tombstone {
        Tombstone::new(
            "notes/x.md".into(),
            [0u8; 32],
            "node-A".into(),
            deleted_at,
            ttl_secs,
        )
    }

    #[test]
    fn not_expired_one_second_before_ttl() {
        let t = make(0, 100);
        assert!(!t.is_expired(99));
    }

    #[test]
    fn expired_at_exact_ttl_boundary() {
        let t = make(0, 100);
        assert!(t.is_expired(100));
    }

    #[test]
    fn expired_one_second_after_ttl() {
        let t = make(0, 100);
        assert!(t.is_expired(101));
    }

    #[test]
    fn default_ttl_constant_is_thirty_days() {
        assert_eq!(DEFAULT_TTL_SECS, 30 * 86_400);
    }
}
