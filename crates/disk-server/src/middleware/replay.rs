//! Anti-replay protection for `SyncService`.
//!
//! Per-stream monotonic sequence IDs (`SyncStateAck.sequence_id`) ensure that
//! a captured and re-submitted stream message is rejected (T-Replay, DISK-0004 § 6).
//!
//! The `ReplayGuard` tracks the last-seen `sequence_id` per `(node_id, stream_id)`.
//! A sequence_id that is less than or equal to the last-seen value is rejected.

use std::sync::Arc;

use dashmap::DashMap;

/// Per-stream monotonic sequence tracker.
#[derive(Debug, Clone)]
pub struct ReplayGuard {
    /// Maps `(node_id, stream_id)` → last-seen sequence_id.
    last_seen: Arc<DashMap<(String, u64), u64>>,
}

impl ReplayGuard {
    pub fn new() -> Self {
        Self {
            last_seen: Arc::new(DashMap::new()),
        }
    }

    /// Validate and advance the sequence counter.
    ///
    /// Returns `Ok(())` if `seq_id > last_seen` (or this is the first message
    /// on the stream). Returns `Err(ReplayError)` otherwise.
    pub fn check_and_advance(
        &self,
        node_id: &str,
        stream_id: u64,
        seq_id: u64,
    ) -> Result<(), ReplayError> {
        let key = (node_id.to_owned(), stream_id);
        let mut entry = self.last_seen.entry(key).or_insert(0);
        if seq_id <= *entry {
            return Err(ReplayError::Replayed {
                received: seq_id,
                last_seen: *entry,
            });
        }
        *entry = seq_id;
        Ok(())
    }

    /// Remove state for a completed/closed stream.
    pub fn close_stream(&self, node_id: &str, stream_id: u64) {
        self.last_seen.remove(&(node_id.to_owned(), stream_id));
    }
}

impl Default for ReplayGuard {
    fn default() -> Self {
        Self::new()
    }
}

/// Error variants from replay detection.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReplayError {
    #[error("replay detected: received seq_id {received} <= last_seen {last_seen}")]
    Replayed { received: u64, last_seen: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_sequence_accepted() {
        let g = ReplayGuard::new();
        assert!(g.check_and_advance("node-1", 0, 1).is_ok());
    }

    #[test]
    fn monotonically_increasing_accepted() {
        let g = ReplayGuard::new();
        for i in 1u64..=100 {
            g.check_and_advance("node-1", 0, i).unwrap();
        }
    }

    #[test]
    fn duplicate_sequence_rejected() {
        let g = ReplayGuard::new();
        g.check_and_advance("node-1", 0, 5).unwrap();
        let err = g.check_and_advance("node-1", 0, 5).unwrap_err();
        assert!(matches!(
            err,
            ReplayError::Replayed {
                received: 5,
                last_seen: 5
            }
        ));
    }

    #[test]
    fn old_sequence_rejected() {
        let g = ReplayGuard::new();
        g.check_and_advance("node-1", 0, 10).unwrap();
        let err = g.check_and_advance("node-1", 0, 3).unwrap_err();
        assert!(matches!(
            err,
            ReplayError::Replayed {
                received: 3,
                last_seen: 10
            }
        ));
    }

    #[test]
    fn different_streams_independent() {
        let g = ReplayGuard::new();
        g.check_and_advance("node-1", 0, 5).unwrap();
        // Stream 1 starts fresh
        g.check_and_advance("node-1", 1, 1).unwrap();
    }

    #[test]
    fn different_nodes_independent() {
        let g = ReplayGuard::new();
        g.check_and_advance("node-A", 0, 5).unwrap();
        g.check_and_advance("node-B", 0, 1).unwrap();
    }

    #[test]
    fn close_stream_resets_state() {
        let g = ReplayGuard::new();
        g.check_and_advance("node-1", 42, 10).unwrap();
        g.close_stream("node-1", 42);
        // After close, a new stream-42 starts fresh.
        g.check_and_advance("node-1", 42, 1).unwrap();
    }
}
