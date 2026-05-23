//! Integration test — node revocation broadcasts SessionInvalidate.
//!
//! Step 19 P4b: `revoke_node(cert_fp)` sets `revoked_at` and broadcasts
//! `SessionInvalidate` on the ACL reload channel.

use tokio::sync::broadcast;

use disk_server::multi_node::lifecycle::revoke_node;
use sqlx::SqlitePool;

async fn make_pool() -> SqlitePool {
    let pool = SqlitePool::connect(":memory:").await.unwrap();
    sqlx::migrate!("../../crates/disk-core/migrations")
        .run(&pool)
        .await
        .unwrap();
    pool
}

async fn insert_node_and_cert(pool: &SqlitePool, node_id: &str, fp: &[u8; 32]) {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

    sqlx::query(
        "INSERT INTO nodes (node_id, display_name, platform, api_key_hash, registered_at)
         VALUES (?1, ?1, 'linux', '', ?2)",
    )
    .bind(node_id)
    .bind(now_ms)
    .execute(pool)
    .await
    .unwrap();

    let (id,): (i64,) = sqlx::query_as("SELECT id FROM nodes WHERE node_id = ?1")
        .bind(node_id)
        .fetch_one(pool)
        .await
        .unwrap();

    sqlx::query(
        "INSERT INTO node_certs (cert_fingerprint, node_id, enrolled_at, expires_at)
         VALUES (?1, ?2, ?3, ?4)",
    )
    .bind(&fp[..])
    .bind(id)
    .bind(now_ms)
    .bind(now_ms + 86_400_000)
    .execute(pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn revoke_known_cert_broadcasts_and_sets_revoked_at() {
    let pool = make_pool().await;
    let (tx, mut rx) = broadcast::channel(8);
    let fp = [0x99u8; 32];

    insert_node_and_cert(&pool, "node-rev-1", &fp).await;

    let revoked = revoke_node(fp, &pool, &tx).await.unwrap();
    assert!(revoked, "revoke must succeed for existing cert");

    // Broadcast must be received.
    let ev = rx.try_recv().expect("SessionInvalidate must be broadcast");
    assert_eq!(ev.fingerprint, fp);
    assert!(ev.new_role.is_none());

    // DB row must have revoked_at set.
    let revoked_at: (Option<i64>,) =
        sqlx::query_as("SELECT revoked_at FROM node_certs WHERE cert_fingerprint = ?1")
            .bind(&fp[..])
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(revoked_at.0.is_some(), "revoked_at must be set");
}

#[tokio::test]
async fn revoke_unknown_cert_returns_false() {
    let pool = make_pool().await;
    let (tx, _rx) = broadcast::channel(8);
    let fp = [0xFFu8; 32]; // not inserted

    let revoked = revoke_node(fp, &pool, &tx).await.unwrap();
    assert!(!revoked, "revoke of unknown cert must return false");
}

#[tokio::test]
async fn revoke_twice_is_idempotent() {
    let pool = make_pool().await;
    let (tx, mut rx) = broadcast::channel(8);
    let fp = [0x77u8; 32];

    insert_node_and_cert(&pool, "node-rev-2", &fp).await;

    revoke_node(fp, &pool, &tx).await.unwrap();
    let _ = rx.try_recv(); // consume first broadcast

    // Second revoke: row already revoked → no rows affected → false.
    let second = revoke_node(fp, &pool, &tx).await.unwrap();
    assert!(!second, "second revoke must return false (already revoked)");
    assert!(rx.try_recv().is_err(), "no second broadcast expected");
}
