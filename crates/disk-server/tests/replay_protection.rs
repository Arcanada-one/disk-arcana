//! Anti-replay protection integration test (V-9, T-Replay).
//!
//! Exercises the `ReplayGuard` to verify that:
//! - Monotonically increasing sequence IDs are accepted.
//! - Duplicate or out-of-order IDs are rejected.
//! - Independent streams and nodes are isolated.
//!
//! DISK-0004 Step 11.

use disk_server::middleware::replay::{ReplayError, ReplayGuard};

#[test]
fn monotonic_sequence_accepted() {
    let g = ReplayGuard::new();
    for i in 1u64..=1000 {
        g.check_and_advance("node", 0, i).unwrap();
    }
}

#[test]
fn replay_duplicate_rejected() {
    let g = ReplayGuard::new();
    g.check_and_advance("node", 0, 42).unwrap();
    let err = g.check_and_advance("node", 0, 42).unwrap_err();
    assert!(matches!(
        err,
        ReplayError::Replayed {
            received: 42,
            last_seen: 42
        }
    ));
}

#[test]
fn replay_older_seq_rejected() {
    let g = ReplayGuard::new();
    g.check_and_advance("node", 0, 100).unwrap();
    let err = g.check_and_advance("node", 0, 1).unwrap_err();
    assert!(matches!(
        err,
        ReplayError::Replayed {
            received: 1,
            last_seen: 100
        }
    ));
}

#[test]
fn different_streams_isolated() {
    let g = ReplayGuard::new();
    g.check_and_advance("node", 1, 100).unwrap();
    // Stream 2 starts fresh — seq 1 is fine.
    g.check_and_advance("node", 2, 1).unwrap();
}

#[test]
fn different_nodes_isolated() {
    let g = ReplayGuard::new();
    g.check_and_advance("node-A", 0, 50).unwrap();
    // node-B starts fresh.
    g.check_and_advance("node-B", 0, 1).unwrap();
}

#[test]
fn stream_close_allows_reuse() {
    let g = ReplayGuard::new();
    g.check_and_advance("n", 7, 10).unwrap();
    g.close_stream("n", 7);
    g.check_and_advance("n", 7, 1).unwrap(); // fresh start after close
}

/// Proptest: 10K random messages from a single node/stream must form a
/// strictly increasing sequence without false rejects.
#[test]
fn proptest_monotonic_accepts() {
    let g = ReplayGuard::new();
    let mut seq = 0u64;
    for delta in [1u64, 1, 2, 100, 1, 50, 1000, 1]
        .iter()
        .cycle()
        .take(10_000)
    {
        seq += delta;
        g.check_and_advance("n", 0, seq).unwrap();
    }
}
