//! Structural parity with Shared personal-capture/v1; never an authority.
use serde::{Deserialize, Deserializer};
use serde_json::json;
use sha2::{Digest, Sha256};

const VERSION: &str = "personal-capture/v1";
const MEDIA: &str = "text/plain;charset=utf-8";
const MAX_COUNTER: u64 = 9_007_199_254_740_990;

#[derive(Debug, thiserror::Error)]
#[error("invalid capture binding")]
pub struct InvalidBinding;

// JavaScript's input is a Number, so JSON 1.0, 1e0 and -0 have integer semantics.
fn integer<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    let value = serde_json::Number::deserialize(d)?;
    let n = value
        .as_f64()
        .ok_or_else(|| serde::de::Error::custom("integer"))?;
    if n < 0.0 || n.fract() != 0.0 || n > 9_007_199_254_740_991.0 {
        return Err(serde::de::Error::custom("integer"));
    }
    Ok(n as u64)
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Part {
    part_id: String,
    role: String,
    object_id: String,
    object_revision: String,
    sha256: String,
    #[serde(deserialize_with = "integer")]
    size_bytes: u64,
    media_type: String,
}

/// Private fields ensure downstream code cannot create an unvalidated descriptor.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireDescriptor {
    schema_version: String,
    realm_id: String,
    capture_id: String,
    conversation_id: String,
    message_id: String,
    #[serde(deserialize_with = "integer")]
    expected_conversation_revision: u64,
    operation: String,
    idempotency_key: String,
    request_fingerprint: String,
    #[serde(deserialize_with = "integer")]
    cancellation_generation: u64,
    parts: Vec<Part>,
}

fn identifier(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}
fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub struct CaptureDescriptor(WireDescriptor);

impl CaptureDescriptor {
    pub fn parse(bytes: &[u8]) -> Result<Self, InvalidBinding> {
        let d: WireDescriptor = serde_json::from_slice(bytes).map_err(|_| InvalidBinding)?;
        if d.schema_version != VERSION
            || d.operation != "append_message"
            || ![
                &d.realm_id,
                &d.capture_id,
                &d.conversation_id,
                &d.message_id,
                &d.idempotency_key,
            ]
            .into_iter()
            .all(|v| identifier(v))
            || !digest(&d.request_fingerprint)
            || d.expected_conversation_revision > MAX_COUNTER
            || d.cancellation_generation > MAX_COUNTER
            || d.parts.is_empty()
            || d.parts.len() > 2
        {
            return Err(InvalidBinding);
        }
        for (i, part) in d.parts.iter().enumerate() {
            if part.role != if i == 0 { "note" } else { "attachment" }
                || part.media_type != MEDIA
                || part.size_bytes > if i == 0 { 65_536 } else { 1_048_576 }
                || ![&part.part_id, &part.object_id, &part.object_revision]
                    .into_iter()
                    .all(|v| identifier(v))
                || !digest(&part.sha256)
            {
                return Err(InvalidBinding);
            }
        }
        if d.parts.len() == 2
            && (d.parts[0].part_id == d.parts[1].part_id
                || d.parts[0].object_id == d.parts[1].object_id)
        {
            return Err(InvalidBinding);
        }
        let d = Self(d);
        if format!("{:x}", Sha256::digest(d.fingerprint_input().as_bytes()))
            != d.0.request_fingerprint
        {
            return Err(InvalidBinding);
        }
        Ok(d)
    }

    /// Exact Shared fingerprint input; it intentionally excludes allocated IDs.
    pub fn fingerprint_input(&self) -> String {
        json!([
            VERSION,
            self.0.realm_id,
            self.0.operation,
            self.0.conversation_id,
            self.0.expected_conversation_revision,
            self.0
                .parts
                .iter()
                .map(|p| json!([p.role, p.sha256, p.size_bytes, p.media_type]))
                .collect::<Vec<_>>()
        ])
        .to_string()
    }

    /// Full retry identity, including allocation IDs omitted by the fingerprint.
    pub fn descriptor_identity(&self) -> String {
        json!([
            self.0.schema_version,
            self.0.realm_id,
            self.0.capture_id,
            self.0.conversation_id,
            self.0.message_id,
            self.0.expected_conversation_revision,
            self.0.operation,
            self.0.idempotency_key,
            self.0.request_fingerprint,
            self.0.cancellation_generation,
            self.0
                .parts
                .iter()
                .map(|p| json!([
                    p.part_id,
                    p.role,
                    p.object_id,
                    p.object_revision,
                    p.sha256,
                    p.size_bytes,
                    p.media_type
                ]))
                .collect::<Vec<_>>()
        ])
        .to_string()
    }
}

#[cfg(all(target_os = "linux", feature = "synthetic-fixtures"))]
impl CaptureDescriptor {
    pub(crate) fn allocation(
        &self,
        realm: &str,
        part_id: &str,
        request: &crate::provider::types::Request,
    ) -> crate::provider::types::Result<()> {
        use crate::provider::types::{Error, Kind};
        request.validate()?;
        let p = self
            .0
            .parts
            .iter()
            .find(|p| p.part_id == part_id)
            .ok_or(Error::InvalidInput)?;
        if self.0.realm_id != realm
            || p.object_id != request.object_id
            || p.object_revision != request.revision_id
            || p.size_bytes != request.expected_len
            || p.sha256 != request.sha256
            || (p.role == "note") != (request.kind == Kind::Note)
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    pub(crate) fn realm(&self) -> &str {
        &self.0.realm_id
    }
    pub(crate) fn capture(&self) -> &str {
        &self.0.capture_id
    }
    pub(crate) fn generation(&self) -> i64 {
        self.0.cancellation_generation as i64
    }
}
