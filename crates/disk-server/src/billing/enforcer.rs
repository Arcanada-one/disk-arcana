//! Storage quota gate on `DeltaUpload`.

use disk_core::billing::{check_storage_delta, PlanTier, QuotaLimits};
use disk_core::meta_db::MetaDb;
use tonic::Status;

use super::mode::{default_plan_tier_from_env, BillingMode};

use crate::config::ConfigError;

/// Enforces per-tenant storage quotas before upload commit.
#[derive(Debug, Clone)]
pub struct QuotaEnforcer {
    pub mode: BillingMode,
    pub meta_db: MetaDb,
    pub default_tier: PlanTier,
    /// Test-only override; production uses tier limits from `PlanTier`.
    test_limits: Option<QuotaLimits>,
}

impl QuotaEnforcer {
    pub fn new(mode: BillingMode, meta_db: MetaDb) -> Result<Self, ConfigError> {
        let default_tier = default_plan_tier_from_env()?;
        Ok(Self {
            mode,
            meta_db,
            default_tier,
            test_limits: None,
        })
    }

    /// Override limits (integration tests only).
    #[doc(hidden)]
    pub fn with_test_limits(mut self, limits: QuotaLimits) -> Self {
        self.test_limits = Some(limits);
        self
    }

    fn limits_for_tier(&self, tier: PlanTier) -> QuotaLimits {
        self.test_limits.unwrap_or_else(|| tier.limits())
    }

    fn tenant_from_metadata(tenant_header: Option<&str>) -> Option<&str> {
        tenant_header.filter(|s| !s.is_empty())
    }

    /// Reject upload when projected storage exceeds the tenant plan.
    pub async fn check_upload(
        &self,
        tenant_header: Option<&str>,
        path: &str,
        new_size: u64,
    ) -> Result<(), Status> {
        if !self.mode.is_active() {
            return Ok(());
        }

        let tenant_id = Self::tenant_from_metadata(tenant_header);
        let tier = self
            .meta_db
            .get_plan_tier(tenant_id, self.default_tier)
            .await
            .map_err(|e| Status::internal(format!("billing lookup: {e}")))?;
        let limits = self.limits_for_tier(tier);

        let used = self
            .meta_db
            .sum_storage_bytes(tenant_id)
            .await
            .map_err(|e| Status::internal(format!("storage sum: {e}")))?;

        let old_size = self
            .meta_db
            .get_file(path)
            .await
            .map_err(|e| Status::internal(format!("file lookup: {e}")))?
            .map(|m| m.size)
            .unwrap_or(0);

        let delta = new_size as i64 - old_size as i64;
        check_storage_delta(used, delta, limits).map_err(|e| {
            Status::resource_exhausted(format!("storage quota: {e}"))
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn disabled_mode_allows_any_upload() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("q.sqlite")).await.unwrap();
        let enforcer = QuotaEnforcer {
            mode: BillingMode::Disabled,
            meta_db: db,
            default_tier: PlanTier::Free,
            test_limits: Some(QuotaLimits {
                max_storage_bytes: 1,
                max_nodes: 1,
                max_vaults: 1,
            }),
        };
        enforcer
            .check_upload(None, "a.txt", 1_000_000)
            .await
            .unwrap();
    }
}
