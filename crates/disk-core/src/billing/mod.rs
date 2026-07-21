//! SaaS billing scaffold — plan tiers and storage quota math (DISK-0018).

mod quota;
mod stripe;
mod stripe_sig;
mod tier;

pub use quota::{check_node_capacity, check_storage_delta, check_vault_capacity, QuotaError};
pub use stripe::{parse_stripe_subscription_event, StripeSubscriptionEvent};
pub use stripe_sig::{compute_v1_signature, verify_stripe_webhook_signature, StripeSigError};
pub use tier::{PlanTier, QuotaLimits, SnapshotRetention, TrashRetention, VersionRetention};
