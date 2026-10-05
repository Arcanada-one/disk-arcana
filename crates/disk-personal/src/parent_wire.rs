//! Exact bounded reference/error records from disk-wire-closure/1-proposed.
//! Parsing is structural only; a reference contains no resource selector/grant.
use crate::parent_adapter::Refusal;
use serde::{Deserialize, Serialize};

const WIRE: &str = "strict-disk/1-proposed";
const AMENDMENT: &str = "disk-wire-closure/1-proposed";
const PROFILE: &str = "organize-me.synthetic/1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceRequest {
    wire_version: String,
    amendment_version: String,
    profile_id: String,
    request_id: String,
}
impl ReferenceRequest {
    pub fn parse(bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.len() > 4096 {
            return Err(Refusal::NotAvailable);
        }
        let r: Self = serde_json::from_slice(bytes).map_err(|_| Refusal::NotAvailable)?;
        let id = &r.request_id;
        if r.wire_version != WIRE
            || r.amendment_version != AMENDMENT
            || r.profile_id != PROFILE
            || id.len() != 36
            || !id.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
                }
            })
        {
            return Err(Refusal::NotAvailable);
        }
        Ok(r)
    }
    /// Fixed vocabulary only: never serialize an underlying error or resource.
    /// All errors conservatively prohibit automatic retry; unknown requires
    /// reconciliation with original identity, not a fresh mutation.
    pub fn error(&self, refusal: Refusal) -> Vec<u8> {
        #[derive(Serialize)]
        struct Error<'a> {
            wire_version: &'a str,
            amendment_version: &'a str,
            profile_id: &'a str,
            request_id: &'a str,
            result: &'a str,
            retryable: bool,
        }
        let result = match refusal {
            Refusal::NotAvailable => "not_available",
            Refusal::Pending => "pending",
            Refusal::Conflict => "conflict",
            Refusal::Backpressure => "backpressure",
            Refusal::Unavailable => "unavailable",
        };
        // Only validated strings and constants are serialized; serialization
        // cannot invoke user code or contain byte bodies/authority credentials.
        serde_json::to_vec(&Error {
            wire_version: WIRE,
            amendment_version: AMENDMENT,
            profile_id: PROFILE,
            request_id: &self.request_id,
            result,
            retryable: false,
        })
        .expect("fixed strict Disk error serializes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const GOOD: &str = r#"{"wire_version":"strict-disk/1-proposed","amendment_version":"disk-wire-closure/1-proposed","profile_id":"organize-me.synthetic/1","request_id":"10000000-0000-4000-8000-000000000001"}"#;
    #[test]
    fn strict_reference_rejects_resource_override_duplicates_and_oversize() {
        assert!(ReferenceRequest::parse(GOOD.as_bytes()).is_ok());
        for bad in [
            GOOD.replace("strict-disk/1-proposed", "strict-disk/2"),
            GOOD.replace("10000000-0000", "INVALID0-0000"),
            GOOD.replace("}", ",\"realm_id\":\"foreign\"}"),
            GOOD.replace("}", ",\"request_id\":\"duplicate\"}"),
            format!("{}{}", GOOD, " ".repeat(4096)),
        ] {
            assert!(ReferenceRequest::parse(bad.as_bytes()).is_err());
        }
    }
    #[test]
    fn errors_have_only_native_closed_fields_and_never_retry_unknown() {
        let req = ReferenceRequest::parse(GOOD.as_bytes()).unwrap();
        for e in [
            Refusal::NotAvailable,
            Refusal::Pending,
            Refusal::Conflict,
            Refusal::Backpressure,
            Refusal::Unavailable,
        ] {
            let v: serde_json::Value = serde_json::from_slice(&req.error(e)).unwrap();
            assert_eq!(v.as_object().unwrap().len(), 6);
            assert_eq!(v["retryable"], false);
            assert!(v.get("realm_id").is_none());
        }
    }
}
