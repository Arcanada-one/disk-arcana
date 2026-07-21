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
