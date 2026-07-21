//! Plan-tier quota gates on nodes, vaults, and storage (DISK-0018).

use disk_core::billing::{
    check_node_capacity, check_storage_delta, check_vault_capacity, PlanTier, QuotaLimits,
};
use disk_core::TenantMetaRouter;
use tonic::Status;

use super::mode::{default_plan_tier_from_env, BillingMode};

use crate::config::ConfigError;

/// Enforces per-tenant commercial quotas.
#[derive(Debug, Clone)]
pub struct QuotaEnforcer {
    pub mode: BillingMode,
    pub router: TenantMetaRouter,
    pub default_tier: PlanTier,
    /// Test-only override; production uses tier limits from `PlanTier`.
    test_limits: Option<QuotaLimits>,
}

impl QuotaEnforcer {
    pub fn new(mode: BillingMode, router: TenantMetaRouter) -> Result<Self, ConfigError> {
        let default_tier = default_plan_tier_from_env()?;
        Ok(Self {
            mode,
            router,
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

    async fn tier_and_limits(&self, tenant_id: Option<&str>) -> Result<QuotaLimits, Status> {
        let tier = self
            .router
            .control()
            .get_plan_tier(tenant_id, self.default_tier)
            .await
            .map_err(|e| Status::internal(format!("billing lookup: {e}")))?;
        Ok(self.limits_for_tier(tier))
    }

    fn tenant_from_metadata(tenant_header: Option<&str>) -> Option<&str> {
        tenant_header.filter(|s| !s.is_empty())
    }

    /// Reject `RegisterNode` when the tenant is at the node cap.
    pub async fn check_register_node(
        &self,
        tenant_header: Option<&str>,
        active_nodes: u32,
    ) -> Result<(), Status> {
        if !self.mode.is_active() {
            return Ok(());
        }
        let tenant_id = Self::tenant_from_metadata(tenant_header);
        let limits = self.tier_and_limits(tenant_id).await?;
        check_node_capacity(active_nodes, limits)
            .map_err(|e| Status::resource_exhausted(format!("node quota: {e}")))?;
        Ok(())
    }

    /// Reject upload when projected storage exceeds the tenant plan.
    pub async fn check_upload(
        &self,
        tenant_header: Option<&str>,
        share: &str,
        path: &str,
        new_size: u64,
    ) -> Result<(), Status> {
        if !self.mode.is_active() {
            return Ok(());
        }

        let tenant_id = Self::tenant_from_metadata(tenant_header);
        let limits = self.tier_and_limits(tenant_id).await?;

        let known_vaults = self
            .router
            .control()
            .count_tenant_vaults(tenant_id)
            .await
            .map_err(|e| Status::internal(format!("vault count: {e}")))?;
        let vault_known = self
            .router
            .control()
            .tenant_vault_exists(tenant_id, share)
            .await
            .map_err(|e| Status::internal(format!("vault lookup: {e}")))?;
        check_vault_capacity(known_vaults, vault_known, limits)
            .map_err(|e| Status::resource_exhausted(format!("vault quota: {e}")))?;

        let used = self
            .router
            .sum_storage_bytes(tenant_id)
            .await
            .map_err(|e| Status::internal(format!("storage sum: {e}")))?;

        let old_size = self
            .router
            .get_file_scoped(tenant_id, share, path)
            .await
            .map_err(|e| Status::internal(format!("file lookup: {e}")))?
            .map(|m| m.size)
            .unwrap_or(0);

        let delta = new_size as i64 - old_size as i64;
        check_storage_delta(used, delta, limits)
            .map_err(|e| Status::resource_exhausted(format!("storage quota: {e}")))?;
        Ok(())
    }

    /// Register vault usage after a successful upload (idempotent).
    pub async fn record_vault_usage(
        &self,
        tenant_header: Option<&str>,
        share: &str,
    ) -> Result<(), Status> {
        if !self.mode.is_active() {
            return Ok(());
        }
        let tenant_id = Self::tenant_from_metadata(tenant_header);
        self.router
            .control()
            .register_tenant_vault(tenant_id, share)
            .await
            .map_err(|e| Status::internal(format!("vault register: {e}")))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    use disk_core::meta_db::MetaDb;
    use disk_core::TenantMetaRouter;

    #[tokio::test]
    async fn disabled_mode_allows_any_upload() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("q.sqlite")).await.unwrap();
        let router = TenantMetaRouter::single(db);
        let enforcer = QuotaEnforcer {
            mode: BillingMode::Disabled,
            router,
            default_tier: PlanTier::Free,
            test_limits: Some(QuotaLimits {
                max_storage_bytes: 1,
                max_nodes: 1,
                max_vaults: 1,
            }),
        };
        enforcer
            .check_upload(None, "default", "a.txt", 1_000_000)
            .await
            .unwrap();
    }
}
