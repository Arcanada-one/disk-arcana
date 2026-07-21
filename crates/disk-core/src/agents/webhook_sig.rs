//! Outbound agent webhook HMAC signing (DISK-0028 slice 2).
//!
//! Header: `X-Disk-Signature: t=<unix_secs>,v1=<hex_hmac_sha256>`
//! Signed payload: `{timestamp}.{body}`

use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DiskWebhookSigError {
    #[error("missing X-Disk-Signature header")]
    MissingHeader,
    #[error("malformed signature header")]
    MalformedHeader,
    #[error("timestamp outside tolerance")]
    TimestampSkew,
    #[error("signature mismatch")]
    Mismatch,
    #[error("invalid webhook secret")]
    InvalidSecret,
}

/// Compute the `v1` HMAC-SHA256 hex digest for an outbound webhook body.
pub fn compute_disk_webhook_signature(signing_secret: &str, timestamp: i64, body: &[u8]) -> String {
    let signed = format!("{timestamp}.{}", String::from_utf8_lossy(body));
    let mut mac =
        HmacSha256::new_from_slice(signing_secret.as_bytes()).expect("HMAC accepts any key size");
    mac.update(signed.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Format the `X-Disk-Signature` header value.
pub fn format_disk_signature_header(timestamp: i64, v1_hex: &str) -> String {
    format!("t={timestamp},v1={v1_hex}")
}

/// Verify an inbound webhook request (consumer-side helper).
pub fn verify_disk_webhook_signature(
    header: &str,
    body: &[u8],
    signing_secret: &str,
    tolerance_secs: i64,
) -> Result<i64, DiskWebhookSigError> {
    if signing_secret.is_empty() {
        return Err(DiskWebhookSigError::InvalidSecret);
    }
    let (timestamp, v1) = parse_signature_header(header)?;
    let now = unix_now_secs();
    if (now - timestamp).abs() > tolerance_secs {
        return Err(DiskWebhookSigError::TimestampSkew);
    }
    let expected = compute_disk_webhook_signature(signing_secret, timestamp, body);
    if constant_time_eq(&expected, &v1) {
        Ok(timestamp)
    } else {
        Err(DiskWebhookSigError::Mismatch)
    }
}

fn parse_signature_header(header: &str) -> Result<(i64, String), DiskWebhookSigError> {
    let mut timestamp = None;
    let mut v1 = None;
    for part in header.split(',') {
        let part = part.trim();
        if let Some(ts) = part.strip_prefix("t=") {
            timestamp = ts.parse().ok();
        } else if let Some(sig) = part.strip_prefix("v1=") {
            v1 = Some(sig.to_string());
        }
    }
    match (timestamp, v1) {
        (Some(ts), Some(sig)) if !sig.is_empty() => Ok((ts, sig)),
        _ => Err(DiskWebhookSigError::MalformedHeader),
    }
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

fn unix_now_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "whsec_deadbeef";
    const BODY: &[u8] = br#"{"event":"agent.write_ok"}"#;

    #[test]
    fn sign_and_verify_round_trip() {
        let ts = unix_now_secs();
        let v1 = compute_disk_webhook_signature(SECRET, ts, BODY);
        let header = format_disk_signature_header(ts, &v1);
        verify_disk_webhook_signature(&header, BODY, SECRET, 300).unwrap();
    }

    #[test]
    fn verify_rejects_tampered_body() {
        let ts = unix_now_secs();
        let v1 = compute_disk_webhook_signature(SECRET, ts, BODY);
        let header = format_disk_signature_header(ts, &v1);
        let err = verify_disk_webhook_signature(&header, b"tampered", SECRET, 300).unwrap_err();
        assert_eq!(err, DiskWebhookSigError::Mismatch);
    }
}
