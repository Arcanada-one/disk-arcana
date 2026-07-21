//! Stripe webhook signature verification (DISK-0018 slice 2).
//!
//! Implements Stripe's `Stripe-Signature` HMAC-SHA256 scheme:
//! https://stripe.com/docs/webhooks/signatures

use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StripeSigError {
    #[error("missing Stripe-Signature header")]
    MissingHeader,
    #[error("malformed Stripe-Signature header")]
    MalformedHeader,
    #[error("missing timestamp in Stripe-Signature")]
    MissingTimestamp,
    #[error("missing v1 signature in Stripe-Signature")]
    MissingV1Signature,
    #[error("timestamp outside tolerance ({age_secs}s > {tolerance_secs}s)")]
    TimestampSkew { age_secs: u64, tolerance_secs: u64 },
    #[error("signature mismatch")]
    SignatureMismatch,
    #[error("invalid webhook secret")]
    InvalidSecret,
}

/// Verify a Stripe webhook request.
///
/// `tolerance_secs` — max age of the `t=` timestamp (Stripe default 300).
pub fn verify_stripe_webhook_signature(
    signature_header: &str,
    body: &[u8],
    webhook_secret: &str,
    tolerance_secs: u64,
) -> Result<(), StripeSigError> {
    if webhook_secret.is_empty() {
        return Err(StripeSigError::InvalidSecret);
    }

    let (timestamp, v1_sigs) = parse_signature_header(signature_header)?;
    check_timestamp_skew(timestamp, tolerance_secs)?;

    let expected = compute_v1_signature(webhook_secret, timestamp, body);
    if v1_sigs
        .iter()
        .any(|sig| constant_time_eq_hex(sig, &expected))
    {
        Ok(())
    } else {
        Err(StripeSigError::SignatureMismatch)
    }
}

/// Compute the `v1` hex digest Stripe expects (test helper + verifier).
pub fn compute_v1_signature(webhook_secret: &str, timestamp: i64, body: &[u8]) -> String {
    let signed_payload = format!("{timestamp}.{}", String::from_utf8_lossy(body));
    let mut mac =
        HmacSha256::new_from_slice(webhook_secret.as_bytes()).expect("HMAC accepts any key size");
    mac.update(signed_payload.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn parse_signature_header(header: &str) -> Result<(i64, Vec<String>), StripeSigError> {
    let mut timestamp: Option<i64> = None;
    let mut v1_sigs: Vec<String> = Vec::new();

    for part in header.split(',') {
        let part = part.trim();
        if let Some(ts) = part.strip_prefix("t=") {
            timestamp = Some(ts.parse().map_err(|_| StripeSigError::MalformedHeader)?);
        } else if let Some(sig) = part.strip_prefix("v1=") {
            if !sig.is_empty() {
                v1_sigs.push(sig.to_string());
            }
        }
    }

    let timestamp = timestamp.ok_or(StripeSigError::MissingTimestamp)?;
    if v1_sigs.is_empty() {
        return Err(StripeSigError::MissingV1Signature);
    }
    Ok((timestamp, v1_sigs))
}

fn check_timestamp_skew(timestamp: i64, tolerance_secs: u64) -> Result<(), StripeSigError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let age = now.saturating_sub(timestamp).unsigned_abs();
    if age > tolerance_secs {
        return Err(StripeSigError::TimestampSkew {
            age_secs: age,
            tolerance_secs,
        });
    }
    Ok(())
}

fn constant_time_eq_hex(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "whsec_test_secret";
    const BODY: &str = r#"{"id":"evt_test"}"#;

    fn signed_header(secret: &str, body: &str, timestamp: i64) -> String {
        let sig = compute_v1_signature(secret, timestamp, body.as_bytes());
        format!("t={timestamp},v1={sig}")
    }

    #[test]
    fn accepts_valid_signature() {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let header = signed_header(SECRET, BODY, ts);
        verify_stripe_webhook_signature(&header, BODY.as_bytes(), SECRET, 300).unwrap();
    }

    #[test]
    fn rejects_tampered_body() {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let header = signed_header(SECRET, BODY, ts);
        let err = verify_stripe_webhook_signature(&header, b"{}", SECRET, 300).unwrap_err();
        assert_eq!(err, StripeSigError::SignatureMismatch);
    }

    #[test]
    fn rejects_stale_timestamp() {
        let ts = 1_000_000_i64;
        let header = signed_header(SECRET, BODY, ts);
        let err =
            verify_stripe_webhook_signature(&header, BODY.as_bytes(), SECRET, 10).unwrap_err();
        assert!(matches!(err, StripeSigError::TimestampSkew { .. }));
    }
}
