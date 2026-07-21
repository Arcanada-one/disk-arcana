//! Storage quota checks (pure logic).

use thiserror::Error;

use super::QuotaLimits;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum QuotaError {
    #[error("storage quota exceeded: used {used_bytes} + delta {delta_bytes} > limit {limit_bytes}")]
    StorageExceeded {
        used_bytes: u64,
        delta_bytes: i64,
        limit_bytes: u64,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::billing::PlanTier;

    #[test]
    fn allows_within_limit() {
        let limits = PlanTier::Free.limits();
        assert!(check_storage_delta(100, 50, limits).is_ok());
    }

    #[test]
    fn rejects_over_limit() {
        let limits = QuotaLimits {
            max_storage_bytes: 100,
            max_nodes: 1,
            max_vaults: 1,
        };
        let err = check_storage_delta(90, 20, limits).unwrap_err();
        assert!(matches!(err, QuotaError::StorageExceeded { .. }));
    }

    #[test]
    fn shrink_frees_headroom() {
        let limits = QuotaLimits {
            max_storage_bytes: 100,
            max_nodes: 1,
            max_vaults: 1,
        };
        assert!(check_storage_delta(100, -50, limits).is_ok());
    }
}
