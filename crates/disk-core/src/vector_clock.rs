//! Vector clocks for causal ordering of file edits.
//!
//! Each node maintains a monotonic counter; merge takes the per-key max,
//! advance bumps the local counter. [`VectorClock::compare`] yields one of
//! [`Causality::Equal`], [`Before`](Causality::Before), [`After`](Causality::After),
//! or [`Concurrent`](Causality::Concurrent).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Per-node monotonic counters, ordered by node id for stable serialization.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VectorClock(pub BTreeMap<String, u64>);

/// Causal relationship between two vector clocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Causality {
    Equal,
    Before,
    After,
    Concurrent,
}

impl VectorClock {
    /// Construct an empty clock.
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Bump the counter for `node_id` by one (saturating at `u64::MAX`).
    pub fn advance(&mut self, node_id: &str) {
        let entry = self.0.entry(node_id.to_string()).or_insert(0);
        *entry = entry.saturating_add(1);
    }

    /// Take the per-key max of `other`. Idempotent: `merge(a, a) == a`.
    pub fn merge(&mut self, other: &VectorClock) {
        for (k, v) in &other.0 {
            let slot = self.0.entry(k.clone()).or_insert(0);
            if v > slot {
                *slot = *v;
            }
        }
    }

    /// Read the counter for `node_id` (defaults to `0`).
    pub fn get(&self, node_id: &str) -> u64 {
        self.0.get(node_id).copied().unwrap_or(0)
    }

    /// Classify the causal relationship between `self` and `other`.
    pub fn compare(&self, other: &VectorClock) -> Causality {
        let mut keys: std::collections::BTreeSet<&String> = self.0.keys().collect();
        keys.extend(other.0.keys());

        let mut self_lt_other = false;
        let mut other_lt_self = false;

        for k in keys {
            let a = self.get(k);
            let b = other.get(k);
            if a < b {
                self_lt_other = true;
            } else if a > b {
                other_lt_self = true;
            }
        }

        match (self_lt_other, other_lt_self) {
            (false, false) => Causality::Equal,
            (true, false) => Causality::Before,
            (false, true) => Causality::After,
            (true, true) => Causality::Concurrent,
        }
    }

    /// Convenience: `self` strictly happens-before `other`.
    pub fn happens_before(&self, other: &VectorClock) -> bool {
        matches!(self.compare(other), Causality::Before)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vc(pairs: &[(&str, u64)]) -> VectorClock {
        let mut c = VectorClock::new();
        for (k, v) in pairs {
            c.0.insert((*k).to_string(), *v);
        }
        c
    }

    #[test]
    fn equal_when_identical() {
        let a = vc(&[("n1", 1), ("n2", 2)]);
        let b = vc(&[("n1", 1), ("n2", 2)]);
        assert_eq!(a.compare(&b), Causality::Equal);
    }

    #[test]
    fn before_when_dominated() {
        let a = vc(&[("n1", 1)]);
        let b = vc(&[("n1", 2)]);
        assert_eq!(a.compare(&b), Causality::Before);
        assert!(a.happens_before(&b));
    }

    #[test]
    fn after_when_dominates() {
        let a = vc(&[("n1", 3), ("n2", 1)]);
        let b = vc(&[("n1", 2), ("n2", 1)]);
        assert_eq!(a.compare(&b), Causality::After);
    }

    #[test]
    fn concurrent_when_neither_dominates() {
        let a = vc(&[("n1", 2), ("n2", 1)]);
        let b = vc(&[("n1", 1), ("n2", 2)]);
        assert_eq!(a.compare(&b), Causality::Concurrent);
    }

    #[test]
    fn advance_is_monotonic() {
        let mut c = VectorClock::new();
        c.advance("X");
        let after_one = c.get("X");
        c.advance("X");
        assert!(c.get("X") > after_one);
    }

    #[test]
    fn merge_takes_per_key_max() {
        let mut a = vc(&[("n1", 1), ("n2", 5)]);
        let b = vc(&[("n1", 3), ("n2", 2)]);
        a.merge(&b);
        assert_eq!(a.get("n1"), 3);
        assert_eq!(a.get("n2"), 5);
    }

    #[test]
    fn merge_idempotent() {
        let a0 = vc(&[("n1", 1), ("n2", 4)]);
        let mut a = a0.clone();
        a.merge(&a0);
        assert_eq!(a, a0);
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig {
            cases: 64,
            ..proptest::prelude::ProptestConfig::default()
        })]

        #[test]
        fn axiom_reflexive(seed in proptest::collection::btree_map("[a-z]{1,4}", 0u64..1000, 0..6)) {
            let c = VectorClock(seed);
            proptest::prop_assert_eq!(c.compare(&c), Causality::Equal);
        }

        #[test]
        fn axiom_antisymmetric(
            sa in proptest::collection::btree_map("[a-z]{1,4}", 0u64..200, 0..5),
            sb in proptest::collection::btree_map("[a-z]{1,4}", 0u64..200, 0..5),
        ) {
            let a = VectorClock(sa);
            let b = VectorClock(sb);
            match a.compare(&b) {
                Causality::Before => proptest::prop_assert_eq!(b.compare(&a), Causality::After),
                Causality::After => proptest::prop_assert_eq!(b.compare(&a), Causality::Before),
                Causality::Equal => proptest::prop_assert_eq!(b.compare(&a), Causality::Equal),
                Causality::Concurrent => proptest::prop_assert_eq!(b.compare(&a), Causality::Concurrent),
            }
        }

        #[test]
        fn axiom_advance_strictly_increases(
            seed in proptest::collection::btree_map("[a-z]{1,4}", 0u64..1000, 0..6),
            node in "[a-z]{1,4}",
        ) {
            let mut c = VectorClock(seed);
            let before = c.get(&node);
            c.advance(&node);
            proptest::prop_assert!(c.get(&node) > before);
        }

        #[test]
        fn axiom_merge_idempotent(
            sa in proptest::collection::btree_map("[a-z]{1,4}", 0u64..200, 0..5),
        ) {
            let a0 = VectorClock(sa);
            let mut a = a0.clone();
            a.merge(&a0);
            proptest::prop_assert_eq!(a, a0);
        }

        #[test]
        fn axiom_transitivity_before(
            sa in proptest::collection::btree_map("[a-z]{1,4}", 0u64..50, 1..4),
        ) {
            // Build b > a > start by advancing two nodes.
            let a = VectorClock(sa.clone());
            let mut b = a.clone();
            b.advance("nodeX");
            let mut c = b.clone();
            c.advance("nodeX");
            proptest::prop_assert!(a.happens_before(&b));
            proptest::prop_assert!(b.happens_before(&c));
            proptest::prop_assert!(a.happens_before(&c));
        }
    }
}
