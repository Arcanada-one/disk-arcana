//! Plan quota checks (pure logic).

use thiserror::Error;

use super::QuotaLimits;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum QuotaError {
    #[error(
        "storage quota exceeded: used {used_bytes} + delta {delta_bytes} > limit {limit_bytes}"
    )]
    StorageExceeded {
        used_bytes: u64,
        delta_bytes: i64,
        limit_bytes: u64,
    },
    #[error("node quota exceeded: active {active_nodes} >= limit {limit_nodes}")]
    NodesExceeded { active_nodes: u32, limit_nodes: u32 },
    #[error("vault quota exceeded: known {known_vaults} >= limit {limit_vaults}")]
    VaultsExceeded {
        known_vaults: u32,
        limit_vaults: u32,
    },
}

/// Returns `Ok(())` when `used_bytes + delta_bytes` stays within `limits.max_storage_bytes`.
pub fn check_storage_delta(
    used_bytes: u64,
    delta_bytes: i64,
    limits: QuotaLimits,
) -> Result<(), QuotaError> {
    let limit = limits.max_storage_bytes;
    let projected = if delta_bytes >= 0 {
        used_bytes.saturating_add(delta_bytes as u64)
    } else {
        used_bytes.saturating_sub((-delta_bytes) as u64)
    };
    if projected > limit {
        return Err(QuotaError::StorageExceeded {
            used_bytes,
            delta_bytes,
            limit_bytes: limit,
        });
    }
    Ok(())
}

/// Reject registering an additional node when at capacity.
pub fn check_node_capacity(active_nodes: u32, limits: QuotaLimits) -> Result<(), QuotaError> {
    if active_nodes >= limits.max_nodes {
        return Err(QuotaError::NodesExceeded {
            active_nodes,
            limit_nodes: limits.max_nodes,
        });
    }
    Ok(())
}

/// Reject using a new vault/share when at capacity.
pub fn check_vault_capacity(
    known_vaults: u32,
    vault_already_known: bool,
    limits: QuotaLimits,
) -> Result<(), QuotaError> {
    if vault_already_known {
        return Ok(());
    }
    if known_vaults >= limits.max_vaults {
        return Err(QuotaError::VaultsExceeded {
            known_vaults,
            limit_vaults: limits.max_vaults,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::billing::PlanTier;

    #[test]
    fn allows_within_storage_limit() {
        let limits = PlanTier::Free.limits();
        assert!(check_storage_delta(100, 50, limits).is_ok());
    }

    #[test]
    fn rejects_storage_over_limit() {
        let limits = QuotaLimits {
            max_storage_bytes: 100,
            max_nodes: 1,
            max_vaults: 1,
        };
        let err = check_storage_delta(90, 20, limits).unwrap_err();
        assert!(matches!(err, QuotaError::StorageExceeded { .. }));
    }

    #[test]
    fn rejects_node_at_capacity() {
        let limits = QuotaLimits {
            max_storage_bytes: 1,
            max_nodes: 2,
            max_vaults: 1,
        };
        let err = check_node_capacity(2, limits).unwrap_err();
        assert!(matches!(err, QuotaError::NodesExceeded { .. }));
    }

    #[test]
    fn allows_known_vault() {
        let limits = QuotaLimits {
            max_storage_bytes: 1,
            max_nodes: 1,
            max_vaults: 1,
        };
        assert!(check_vault_capacity(1, true, limits).is_ok());
    }

    #[test]
    fn rejects_new_vault_at_capacity() {
        let limits = QuotaLimits {
            max_storage_bytes: 1,
            max_nodes: 1,
            max_vaults: 1,
        };
        let err = check_vault_capacity(1, false, limits).unwrap_err();
        assert!(matches!(err, QuotaError::VaultsExceeded { .. }));
    }
}
