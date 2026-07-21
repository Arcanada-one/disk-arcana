//! Stripe webhook payload parsing (structure-only stub — no live API calls).

use serde::Deserialize;
use thiserror::Error;

use super::PlanTier;

#[derive(Debug, Error)]
pub enum StripeParseError {
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported event type: {0}")]
    UnsupportedEvent(String),
    #[error("subscription not active: {0}")]
    InactiveSubscription(String),
    #[error("missing price lookup_key")]
    MissingLookupKey,
    #[error("unknown lookup_key: {0}")]
    UnknownLookupKey(String),
}

/// Normalized subscription update extracted from a Stripe webhook body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StripeSubscriptionEvent {
    pub event_type: String,
    pub stripe_customer_id: String,
    pub stripe_subscription_id: String,
    pub plan_tier: PlanTier,
}

#[derive(Debug, Deserialize)]
struct StripeEnvelope {
    #[serde(rename = "type")]
    event_type: String,
    data: StripeData,
}

#[derive(Debug, Deserialize)]
struct StripeData {
    object: StripeSubscription,
}

#[derive(Debug, Deserialize)]
struct StripeSubscription {
    customer: String,
    id: String,
    status: String,
    items: StripeItems,
}

#[derive(Debug, Deserialize)]
struct StripeItems {
    data: Vec<StripeItem>,
}

#[derive(Debug, Deserialize)]
struct StripeItem {
    price: StripePrice,
}

#[derive(Debug, Deserialize)]
struct StripePrice {
    lookup_key: Option<String>,
}

/// Parse a Stripe `customer.subscription.*` webhook JSON body (DISK-0018 slice 1).
///
/// HMAC signature verification is deferred to slice 2; callers must gate on
/// `DISK_BILLING_MODE=stripe` and network ACLs until then.
pub fn parse_stripe_subscription_event(
    body: &str,
) -> Result<StripeSubscriptionEvent, StripeParseError> {
    let envelope: StripeEnvelope = serde_json::from_str(body)?;
    if !envelope.event_type.starts_with("customer.subscription.") {
        return Err(StripeParseError::UnsupportedEvent(envelope.event_type));
    }
    let sub = envelope.data.object;
    if sub.status != "active" && sub.status != "trialing" {
        return Err(StripeParseError::InactiveSubscription(sub.status));
    }
    let lookup_key = sub
        .items
        .data
        .first()
        .and_then(|item| item.price.lookup_key.clone())
        .ok_or(StripeParseError::MissingLookupKey)?;
    let plan_tier = PlanTier::from_stripe_lookup_key(&lookup_key)
        .ok_or(StripeParseError::UnknownLookupKey(lookup_key))?;
    Ok(StripeSubscriptionEvent {
        event_type: envelope.event_type,
        stripe_customer_id: sub.customer,
        stripe_subscription_id: sub.id,
        plan_tier,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
        "type": "customer.subscription.updated",
        "data": {
            "object": {
                "id": "sub_123",
                "customer": "cus_456",
                "status": "active",
                "items": {
                    "data": [{ "price": { "lookup_key": "disk_pro" } }]
                }
            }
        }
    }"#;

    #[test]
    fn parses_active_subscription() {
        let ev = parse_stripe_subscription_event(SAMPLE).unwrap();
        assert_eq!(ev.plan_tier, PlanTier::Pro);
        assert_eq!(ev.stripe_customer_id, "cus_456");
    }
}
