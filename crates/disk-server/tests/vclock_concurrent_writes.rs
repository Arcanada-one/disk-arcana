//! Integration test — concurrent writes from two nodes merge vector clocks.
//!
//! Step 19 P4b: two nodes advance their own VClock entries concurrently.
//! The merge must be commutative, idempotent, and never lose either write.

use disk_server::multi_node::vclock::VClock;

#[test]
fn two_node_concurrent_no_lost_write() {
    let mut node_a = VClock::new();
    let mut node_b = VClock::new();

    // Both nodes write simultaneously.
    node_a.advance("node-a");
    node_b.advance("node-b");

    // Server merges both perspectives.
    let merged_from_a = node_a.merge(&node_b);
    let merged_from_b = node_b.merge(&node_a);

    // Both writes preserved.
    assert_eq!(merged_from_a.get("node-a"), 1, "node-a write not lost");
    assert_eq!(merged_from_a.get("node-b"), 1, "node-b write not lost");

    // Merge is commutative.
    assert_eq!(merged_from_a, merged_from_b, "merge must be commutative");
}

#[test]
fn concurrent_write_to_same_key_takes_max() {
    let mut a = VClock::new();
    let mut b = VClock::new();

    a.advance("shared");
    a.advance("shared");
    a.advance("shared"); // shared = 3 in a

    b.advance("shared"); // shared = 1 in b

    let merged = a.merge(&b);
    // Pointwise max: max(3,1) = 3.
    assert_eq!(merged.get("shared"), 3, "must take pointwise max");
}

#[test]
fn three_node_merge_chain() {
    let mut a = VClock::new();
    let mut b = VClock::new();
    let mut c = VClock::new();

    a.advance("n-a");
    b.advance("n-b");
    c.advance("n-c");

    // Simulate gossip: a sees b, then result sees c.
    let ab = a.merge(&b);
    let abc = ab.merge(&c);

    assert_eq!(abc.get("n-a"), 1);
    assert_eq!(abc.get("n-b"), 1);
    assert_eq!(abc.get("n-c"), 1);
}

#[tokio::test]
async fn vclock_merge_under_concurrent_advance() {
    // Spawn two tasks advancing their own VClock entries in a tight loop.
    // After joining, the merged result must contain contributions from both.
    use std::sync::{Arc, Mutex};

    let vc_a = Arc::new(Mutex::new(VClock::new()));
    let vc_b = Arc::new(Mutex::new(VClock::new()));

    let a_clone = Arc::clone(&vc_a);
    let b_clone = Arc::clone(&vc_b);

    let task_a = tokio::spawn(async move {
        for _ in 0..50 {
            a_clone.lock().unwrap().advance("node-a");
            tokio::task::yield_now().await;
        }
    });
    let task_b = tokio::spawn(async move {
        for _ in 0..50 {
            b_clone.lock().unwrap().advance("node-b");
            tokio::task::yield_now().await;
        }
    });

    task_a.await.unwrap();
    task_b.await.unwrap();

    let final_a = vc_a.lock().unwrap().clone();
    let final_b = vc_b.lock().unwrap().clone();
    let merged = final_a.merge(&final_b);

    assert_eq!(merged.get("node-a"), 50, "node-a must have 50 advances");
    assert_eq!(merged.get("node-b"), 50, "node-b must have 50 advances");
}
