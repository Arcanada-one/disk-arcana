//! Multi-node lifecycle management: node revocation and publisher-key hygiene.
//!
//! ## Node revocation
//!
//! `revoke_node(cert_fp, pool, tx)` sets `node_certs.revoked_at = now_ms`
//! for the given cert fingerprint and then broadcasts a `SessionInvalidate`
//! event on the ACL reload channel so active sync handlers abort their streams.
//!
//! ## Publisher-key tombstone task
//!
//! `spawn_tombstone_publisher(pool)` launches a background tokio task that
//! runs every hour and deletes `publisher_keys` rows last seen more than 30
//! days ago (R-DIR-3 hygiene, per plan §Implementation Steps P4b step 17).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sqlx::SqlitePool;
use tokio::sync::broadcast;

use crate::acl::reload::SessionInvalidate;
use crate::acl::CertFingerprint;

/// 30-day TTL in milliseconds for publisher key tombstone sweep.
const PUBLISHER_KEY_TTL_MS: u64 = 30 * 24 * 3600 * 1_000;

/// How often the tombstone sweep runs.
const TOMBSTONE_INTERVAL: Duration = Duration::from_secs(3600); // 1 hour

#[derive(Debug, thiserror::Error)]
pub enum LifecycleError {
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),

    #[error("system clock before unix epoch")]
    Clock,
}

fn unix_now_ms() -> Result<u64, LifecycleError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .map_err(|_| LifecycleError::Clock)
}

/// Revoke the node certificate identified by `cert_fp`.
///
/// Steps:
/// 1. Sets `node_certs.revoked_at = now_ms` for `cert_fp`.
/// 2. Broadcasts `SessionInvalidate` so active RPC handlers abort.
///
/// Returns `Ok(true)` if a row was updated, `Ok(false)` if cert not found.
pub async fn revoke_node(
    cert_fp: CertFingerprint,
    pool: &SqlitePool,
    invalidate_tx: &broadcast::Sender<SessionInvalidate>,
) -> Result<bool, LifecycleError> {
    let now_ms = unix_now_ms()? as i64;

    let result = sqlx::query(
        "UPDATE node_certs SET revoked_at = ?1
         WHERE cert_fingerprint = ?2 AND revoked_at IS NULL",
    )
    .bind(now_ms)
    .bind(&cert_fp[..])
    .execute(pool)
    .await?;

    let revoked = result.rows_affected() > 0;
    if revoked {
        // Broadcast session invalidation — active sync handlers unsubscribe.
        let _ = invalidate_tx.send(SessionInvalidate {
            fingerprint: cert_fp,
            new_role: None, // removed from ACL
        });
    }
    Ok(revoked)
}

/// Spawn the publisher-key tombstone background sweep.
///
/// Deletes `publisher_keys` rows whose `last_seen_at` is older than 30 days.
/// Runs every hour. The returned `JoinHandle` can be dropped (detached task).
pub fn spawn_tombstone_publisher(pool: SqlitePool) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(TOMBSTONE_INTERVAL).await;
            if let Err(e) = run_tombstone_sweep(&pool).await {
                tracing::warn!("publisher tombstone sweep error: {e}");
            }
        }
    })
}

async fn run_tombstone_sweep(pool: &SqlitePool) -> Result<(), LifecycleError> {
    let cutoff_ms = unix_now_ms()? - PUBLISHER_KEY_TTL_MS;
    let deleted = sqlx::query("DELETE FROM publisher_keys WHERE fetched_at < ?1")
        .bind(cutoff_ms as i64)
        .execute(pool)
        .await?
        .rows_affected();

    if deleted > 0 {
        tracing::info!("publisher tombstone: deleted {deleted} stale key rows");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::SqlitePool;
    use tokio::sync::broadcast;

    async fn make_pool() -> SqlitePool {
        let pool = SqlitePool::connect(":memory:").await.unwrap();
        sqlx::migrate!("../../crates/disk-core/migrations")
            .run(&pool)
            .await
            .unwrap();
        pool
    }

    #[tokio::test]
    async fn revoke_node_unknown_cert_returns_false() {
        let pool = make_pool().await;
        let (tx, _rx) = broadcast::channel(8);
        let fp = [0xAAu8; 32];
        let result = revoke_node(fp, &pool, &tx).await.unwrap();
        assert!(!result, "revoke of unknown cert should return false");
    }

    #[tokio::test]
    async fn revoke_node_broadcasts_invalidate() {
        let pool = make_pool().await;
        let (tx, mut rx) = broadcast::channel(8);

        // Insert a node + cert row.
        let now_ms = unix_now_ms().unwrap() as i64;
        sqlx::query(
            "INSERT INTO nodes (node_id, display_name, platform, api_key_hash, registered_at)
             VALUES ('n1', 'h1', 'linux', '', ?1)",
        )
        .bind(now_ms)
        .execute(&pool)
        .await
        .unwrap();

        let node_id_row: (i64,) = sqlx::query_as("SELECT id FROM nodes WHERE node_id = 'n1'")
            .fetch_one(&pool)
            .await
            .unwrap();

        let fp = [0x01u8; 32];
        sqlx::query(
            "INSERT INTO node_certs (cert_fingerprint, node_id, enrolled_at, expires_at)
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(&fp[..])
        .bind(node_id_row.0)
        .bind(now_ms)
        .bind(now_ms + 86_400_000)
        .execute(&pool)
        .await
        .unwrap();

        let revoked = revoke_node(fp, &pool, &tx).await.unwrap();
        assert!(revoked, "revoke should succeed for existing cert");

        // Check broadcast received.
        let ev = rx.try_recv().expect("expected SessionInvalidate broadcast");
        assert_eq!(ev.fingerprint, fp);
        assert_eq!(ev.new_role, None);

        // Verify DB row is revoked.
        let revoked_at: (Option<i64>,) =
            sqlx::query_as("SELECT revoked_at FROM node_certs WHERE cert_fingerprint = ?1")
                .bind(&fp[..])
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(revoked_at.0.is_some());
    }
}
