//! Billing mode from environment.

use disk_core::billing::PlanTier;

use crate::config::ConfigError;

/// How the server applies commercial quotas (DISK-0018).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BillingMode {
    /// Self-hosted default — no quota checks.
    Disabled,
    /// Enforce plan-tier storage limits from `tenant_billing` / default tier.
    Enforce,
    /// Accept Stripe webhooks and enforce quotas (signature verify deferred).
    Stripe,
}

impl BillingMode {
    pub fn parse(raw: &str) -> Result<Self, ConfigError> {
        match raw.to_ascii_lowercase().as_str() {
            "disabled" | "" => Ok(Self::Disabled),
            "enforce" | "local" => Ok(Self::Enforce),
            "stripe" => Ok(Self::Stripe),
            other => Err(ConfigError::InvalidValue(
                "DISK_BILLING_MODE",
                format!("unknown value '{other}'; expected disabled, enforce, or stripe"),
            )),
        }
    }

    pub fn is_active(self) -> bool {
        matches!(self, Self::Enforce | Self::Stripe)
    }
}

/// Default tier for tenants without a `tenant_billing` row.
pub fn default_plan_tier_from_env() -> Result<PlanTier, ConfigError> {
    let raw = std::env::var("DISK_BILLING_DEFAULT_TIER")
        .unwrap_or_else(|_| "free".to_string());
    PlanTier::parse(&raw)
        .map_err(|e| ConfigError::InvalidValue("DISK_BILLING_DEFAULT_TIER", e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_modes() {
        assert_eq!(BillingMode::parse("disabled").unwrap(), BillingMode::Disabled);
        assert_eq!(BillingMode::parse("enforce").unwrap(), BillingMode::Enforce);
        assert_eq!(BillingMode::parse("stripe").unwrap(), BillingMode::Stripe);
    }
}
