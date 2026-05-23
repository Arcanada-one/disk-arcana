//! Concurrent RPC ↔ ACL reload interleaving test (P4a Step 8 + Step 11).
//!
//! Verifies that concurrent operations on the ACL enforcer (reads from
//! `resolve` + writes from `try_swap`) are safe under `tokio::join!`.
//!
//! Note: `loom` is not a dev-dep in this workspace (per operator note in
//! round-3 mandate — do not add new surface). We use `tokio::join!` with
//! multiple racing tasks to exercise the `Arc<RwLock<>>` boundary.

use std::sync::Arc;

use disk_server::{
    acl::{AclEnforcer, AclState, CertFingerprint, EnforcedRole, EnforcementTable},
};

fn fp(seed: u8) -> CertFingerprint {
    [seed; 32]
}

fn table_v(version: u64, role: EnforcedRole) -> EnforcementTable {
    let mut t = EnforcementTable::new(version);
    t.insert(fp(0x01), "wiki", role);
    t
}

#[tokio::test]
async fn concurrent_resolve_and_swap_no_deadlock() {
    let enforcer = Arc::new(AclEnforcer::new_loaded(table_v(1, EnforcedRole::ReceiveOnly)));

    // Spawn 8 readers and 2 writers racing for 50 iterations each.
    let readers: Vec<_> = (0..8)
        .map(|_| {
            let e = Arc::clone(&enforcer);
            tokio::spawn(async move {
                for _ in 0..50 {
                    let result = e.resolve(&fp(0x01), "wiki").await;
                    // Result can be Ok or Err depending on current state; either is safe.
                    let _ = result;
                    tokio::task::yield_now().await;
                }
            })
        })
        .collect();

    let writers: Vec<_> = (0..2)
        .map(|i| {
            let e = Arc::clone(&enforcer);
            tokio::spawn(async move {
                for v in 0..50u64 {
                    let role = if v % 2 == 0 {
                        EnforcedRole::ReceiveOnly
                    } else {
                        EnforcedRole::Bidirectional
                    };
                    let new_state = if i == 0 {
                        AclState::Loaded(table_v(v + 100, role))
                    } else {
                        AclState::Loaded(table_v(v + 200, role))
                    };
                    e.try_swap(new_state).await;
                    tokio::task::yield_now().await;
                }
            })
        })
        .collect();

    // Join everything — any panic inside a task propagates here.
    for r in readers {
        r.await.expect("reader task must not panic");
    }
    for w in writers {
        w.await.expect("writer task must not panic");
    }

    // Enforcer must still be functional after all concurrent access.
    let version = enforcer.current_version().await;
    assert!(version.is_some(), "enforcer must be Loaded after all swaps");
}

#[tokio::test]
async fn swap_to_unhealthy_and_back_concurrent() {
    use disk_server::acl::UnhealthyReason;

    let enforcer = Arc::new(AclEnforcer::new_loaded(table_v(1, EnforcedRole::Publisher)));

    let e1 = Arc::clone(&enforcer);
    let e2 = Arc::clone(&enforcer);
    let e3 = Arc::clone(&enforcer);

    // Task 1: swap to unhealthy
    let t1 = tokio::spawn(async move {
        for _ in 0..20 {
            e1.try_swap(AclState::Unhealthy(UnhealthyReason::ParseError(
                "test error".into(),
            )))
            .await;
            tokio::task::yield_now().await;
        }
    });

    // Task 2: swap back to loaded
    let t2 = tokio::spawn(async move {
        for v in 0..20u64 {
            e2.try_swap(AclState::Loaded(table_v(v + 10, EnforcedRole::Publisher)))
                .await;
            tokio::task::yield_now().await;
        }
    });

    // Task 3: read current health concurrently
    let t3 = tokio::spawn(async move {
        for _ in 0..40 {
            let _ = e3.unhealthy_reason().await;
            let _ = e3.current_version().await;
            tokio::task::yield_now().await;
        }
    });

    t1.await.expect("t1 must not panic");
    t2.await.expect("t2 must not panic");
    t3.await.expect("t3 must not panic");

    // Final state is deterministic only in that it must not crash.
    // Both Loaded and Unhealthy are acceptable end-states depending on
    // last-writer-wins timing.
}

#[tokio::test]
async fn session_invalidate_broadcast_received_by_subscriber() {
    use disk_server::acl::reload::SessionInvalidate;
    use tokio::sync::broadcast;

    let (tx, mut rx) = broadcast::channel::<SessionInvalidate>(16);

    // Spawn a sender that fires an invalidation.
    let send_handle = tokio::spawn(async move {
        tx.send(SessionInvalidate {
            fingerprint: fp(0xAB),
            new_role: Some(EnforcedRole::ReceiveOnly),
        })
        .expect("send invalidation");
    });

    send_handle.await.unwrap();

    let ev = rx
        .try_recv()
        .expect("subscriber must receive the invalidation");
    assert_eq!(ev.fingerprint, fp(0xAB));
    assert_eq!(ev.new_role, Some(EnforcedRole::ReceiveOnly));
}
