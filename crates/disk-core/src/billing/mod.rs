//! SaaS billing scaffold — plan tiers and storage quota math (DISK-0018).

mod quota;
mod stripe;
mod tier;

pub use quota::{check_storage_delta, QuotaError};
pub use stripe::{parse_stripe_subscription_event, StripeSubscriptionEvent};
pub use tier::{PlanTier, QuotaLimits};
