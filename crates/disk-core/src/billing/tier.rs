//! Commercial plan tiers and per-tier quota limits.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// SaaS subscription tier (DISK-0018).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanTier {
    Free,
    Pro,
    Team,
}

#[derive(Debug, Error)]
pub enum TierParseError {
    #[error("unknown plan tier: {0}")]
    Unknown(String),
}

impl PlanTier {
    pub fn parse(raw: &str) -> Result<Self, TierParseError> {
        match raw.to_ascii_lowercase().as_str() {
            "free" => Ok(Self::Free),
            "pro" => Ok(Self::Pro),
            "team" => Ok(Self::Team),
            other => Err(TierParseError::Unknown(other.to_string())),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Free => "free",
            Self::Pro => "pro",
            Self::Team => "team",
        }
    }

    /// Static quota limits for this tier.
    pub fn limits(self) -> QuotaLimits {
        match self {
            Self::Free => QuotaLimits {
                max_storage_bytes: 5 * 1024 * 1024 * 1024,
                max_nodes: 2,
                max_vaults: 1,
            },
            Self::Pro => QuotaLimits {
                max_storage_bytes: 100 * 1024 * 1024 * 1024,
                max_nodes: 10,
                max_vaults: 5,
            },
            Self::Team => QuotaLimits {
                max_storage_bytes: 1024 * 1024 * 1024 * 1024,
                max_nodes: 50,
                max_vaults: 20,
            },
        }
    }

    /// Map Stripe Price `lookup_key` values to a tier.
    pub fn from_stripe_lookup_key(key: &str) -> Option<Self> {
        match key {
            "disk_free" => Some(Self::Free),
            "disk_pro" => Some(Self::Pro),
            "disk_team" => Some(Self::Team),
            _ => None,
        }
    }
}

/// Per-tenant resource caps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaLimits {
    pub max_storage_bytes: u64,
    pub max_nodes: u32,
    pub max_vaults: u32,
}

/// File version history retention (DISK-0020).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionRetention {
    pub max_versions: u32,
    pub max_age_secs: i64,
}

/// Point-in-time vault snapshot retention (DISK-0020 slice 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotRetention {
    pub max_snapshots: u32,
    pub max_age_secs: i64,
}

/// Trash / recycle-bin retention (DISK-0024).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrashRetention {
    pub max_age_secs: i64,
}

impl PlanTier {
    /// How many historical revisions to keep per file path.
    pub fn version_retention(self) -> VersionRetention {
        match self {
            Self::Free => VersionRetention {
                max_versions: 5,
                max_age_secs: 7 * 24 * 3600,
            },
            Self::Pro => VersionRetention {
                max_versions: 30,
                max_age_secs: 90 * 24 * 3600,
            },
            Self::Team => VersionRetention {
                max_versions: 100,
                max_age_secs: 365 * 24 * 3600,
            },
        }
    }

    /// How many vault-wide snapshots to keep per tenant vault.
    pub fn snapshot_retention(self) -> SnapshotRetention {
        match self {
            Self::Free => SnapshotRetention {
                max_snapshots: 2,
                max_age_secs: 7 * 24 * 3600,
            },
            Self::Pro => SnapshotRetention {
                max_snapshots: 20,
                max_age_secs: 90 * 24 * 3600,
            },
            Self::Team => SnapshotRetention {
                max_snapshots: 100,
                max_age_secs: 365 * 24 * 3600,
            },
        }
    }

    /// How long soft-deleted files remain recoverable before permanent purge.
    pub fn trash_retention(self) -> TrashRetention {
        match self {
            Self::Free => TrashRetention {
                max_age_secs: 7 * 24 * 3600,
            },
            Self::Pro => TrashRetention {
                max_age_secs: 90 * 24 * 3600,
            },
            Self::Team => TrashRetention {
                max_age_secs: 365 * 24 * 3600,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_round_trip_parse() {
        for tier in [PlanTier::Free, PlanTier::Pro, PlanTier::Team] {
            assert_eq!(PlanTier::parse(tier.as_str()).unwrap(), tier);
        }
    }

    #[test]
    fn stripe_lookup_keys_map() {
        assert_eq!(
            PlanTier::from_stripe_lookup_key("disk_pro"),
            Some(PlanTier::Pro)
        );
    }
}
