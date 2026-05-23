//! Vector clock for causal ordering of concurrent sync writes.
//!
//! `VClock` is a `BTreeMap<node_id, u64>` with the standard Lamport vector-clock
//! semantics:
//! - `merge(&self, other) -> VClock` — pointwise maximum.
//! - `advance(&mut self, node_id)` — increment this node's entry.
//!
//! ## Wire format
//!
//! Stored in SQLite `nodes.vclock` as a JSON text column (UTF-8). Serialised with
//! `serde_json`; deserialised on first access. `None` column = never synced node
//! — treated as empty vclock for merge purposes.
//!
//! ## Causal ordering invariant
//!
//! After `server.merge(client_vc)`, the returned merged clock is guaranteed to
//! be `>= server` and `>= client_vc` pointwise. Any node receiving the merged
//! clock can determine which events it has already seen.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Immutable (after construction) vector clock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct VClock(pub BTreeMap<String, u64>);

impl VClock {
    /// Create an empty clock.
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Pointwise maximum of `self` and `other` — satisfies merge-commutative
    /// and idempotent properties required by the proptest suite.
    pub fn merge(&self, other: &VClock) -> VClock {
        let mut result = self.0.clone();
        for (k, v) in &other.0 {
            let entry = result.entry(k.clone()).or_insert(0);
            if *v > *entry {
                *entry = *v;
            }
        }
        VClock(result)
    }

    /// Increment this node's counter, creating the entry at 1 if absent.
    pub fn advance(&mut self, node_id: &str) {
        *self.0.entry(node_id.to_string()).or_insert(0) += 1;
    }

    /// Return the counter for `node_id`, or 0 if not present.
    pub fn get(&self, node_id: &str) -> u64 {
        *self.0.get(node_id).unwrap_or(&0)
    }

    /// Number of distinct node entries.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn advance_creates_and_increments() {
        let mut vc = VClock::new();
        vc.advance("nodeA");
        assert_eq!(vc.get("nodeA"), 1);
        vc.advance("nodeA");
        assert_eq!(vc.get("nodeA"), 2);
    }

    #[test]
    fn merge_pointwise_max() {
        let mut a = VClock::new();
        a.advance("nodeA");
        a.advance("nodeA"); // nodeA=2

        let mut b = VClock::new();
        b.advance("nodeA"); // nodeA=1
        b.advance("nodeB"); // nodeB=1

        let merged = a.merge(&b);
        assert_eq!(merged.get("nodeA"), 2);
        assert_eq!(merged.get("nodeB"), 1);
    }
}

// ---------------------------------------------------------------------------
// Property tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod prop_tests {
    use super::*;
    use proptest::prelude::*;

    fn arb_vclock() -> impl Strategy<Value = VClock> {
        prop::collection::btree_map("[a-z]{1,4}", 0u64..100u64, 0..5usize).prop_map(VClock)
    }

    proptest! {
        #[test]
        fn merge_commutative(a in arb_vclock(), b in arb_vclock()) {
            let ab = a.merge(&b);
            let ba = b.merge(&a);
            prop_assert_eq!(ab, ba, "merge must be commutative");
        }

        #[test]
        fn merge_idempotent(a in arb_vclock()) {
            let merged = a.merge(&a);
            prop_assert_eq!(merged, a.clone(), "merge(a, a) == a");
        }

        #[test]
        fn merge_monotonic(a in arb_vclock(), b in arb_vclock()) {
            let merged = a.merge(&b);
            // Every node in `a` must have counter >= its value in `a`.
            for (k, v) in &a.0 {
                prop_assert!(merged.get(k) >= *v, "merge must not decrease a");
            }
            // Every node in `b` must have counter >= its value in `b`.
            for (k, v) in &b.0 {
                prop_assert!(merged.get(k) >= *v, "merge must not decrease b");
            }
        }
    }
}
