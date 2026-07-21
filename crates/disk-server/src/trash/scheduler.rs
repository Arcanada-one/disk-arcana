//! Background scheduled prune of expired trash rows (DISK-0024 slice 3).

use std::sync::Arc;
use std::time::Duration;

use disk_core::billing::PlanTier;

use crate::accounts::routes::AuthHttpState;

/// Run periodic trash retention prune until the process exits.
pub fn spawn_periodic_prune(state: Arc<AuthHttpState>) {
    tokio::spawn(async move {
        let interval_secs = std::env::var("DISK_TRASH_PRUNE_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(3600);
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            if let Err(e) = prune_all_tenants(&state).await {
                tracing::warn!(error = %e, "scheduled trash prune failed");
            }
        }
    });
}

async fn prune_all_tenants(state: &AuthHttpState) -> anyhow::Result<u32> {
    let tenant_ids = state.meta_db.list_trash_tenant_ids().await?;
    let mut total = 0u32;
    for tenant_id in tenant_ids {
        let tenant_key = tenant_id.as_deref();
        let tier = state
            .meta_db
            .get_plan_tier(tenant_key, PlanTier::Free)
            .await?;
        let retention = tier.trash_retention();
        let db = state.tenant_router.tenant_data(tenant_key).await?;
        let vaults = db.list_vaults_with_trash(tenant_key).await?;
        for vault_id in vaults {
            let pruned = db
                .prune_expired_trash(tenant_key, &vault_id, &retention)
                .await?;
            if pruned > 0 {
                tracing::info!(
                    tenant = ?tenant_key,
                    vault = %vault_id,
                    pruned,
                    "scheduled trash prune"
                );
            }
            total = total.saturating_add(pruned);
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use disk_core::meta_db::MetaDb;
    use disk_core::types::FileMeta;
    use disk_core::vector_clock::VectorClock;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn deleted(path: &str, deleted_at: i64) -> FileMeta {
        FileMeta {
            path: PathBuf::from(path),
            content_hash: [1u8; 32],
            size: 1,
            mtime_ns: 1,
            inode: None,
            vector_clock: VectorClock::new(),
            deleted: true,
            deleted_at: Some(deleted_at),
            node_id: "n".into(),
            encryption_nonce: None,
            version_id: None,
            parent_version_id: None,
        }
    }

    #[tokio::test]
    async fn scheduled_prune_removes_expired_rows() {
        let dir = tempdir().unwrap();
        let meta_db = MetaDb::open(&dir.path().join("sched.sqlite"))
            .await
            .unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let retention = PlanTier::Free.trash_retention();

        meta_db
            .upsert_file_scoped(
                Some("corp"),
                "default",
                &deleted("old.md", now - retention.max_age_secs - 10),
            )
            .await
            .unwrap();
        meta_db
            .upsert_file_scoped(Some("corp"), "default", &deleted("fresh.md", now - 10))
            .await
            .unwrap();

        let state = Arc::new(crate::accounts::routes::auth_http_state_for_tests(meta_db));

        let pruned = prune_all_tenants(&state).await.unwrap();
        assert_eq!(pruned, 1);
        assert_eq!(
            state
                .meta_db
                .count_trash(Some("corp"), "default")
                .await
                .unwrap(),
            1
        );
    }
}
