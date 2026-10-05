//! Concrete native type/storage binding for the disabled PERSIST parent.
//! The upstream closed records are disk-wire-closure/1-proposed. None of these
//! parsers authenticate an issuer, admit a mount, or create a release ticket.
use crate::capture_binding::{CaptureDescriptor, ObjectReceipt};
use crate::parent_adapter::{Authority, Commit, Contract, Observation, Refusal, Result, Storage};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Id(String);
impl<'de> Deserialize<'de> for Id {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        if s.len() != 36
            || !s.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
                }
            })
        {
            return Err(serde::de::Error::custom("native id"));
        }
        Ok(Self(s))
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Counter(u64);
impl<'de> Deserialize<'de> for Counter {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        if s.is_empty()
            || s.len() > 20
            || (s.len() > 1 && s.starts_with('0'))
            || !s.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(serde::de::Error::custom("native counter"));
        }
        s.parse()
            .map(Self)
            .map_err(|_| serde::de::Error::custom("native counter"))
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Digest(String);
impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        if s.len() != 64
            || !s
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(serde::de::Error::custom("native digest"));
        }
        Ok(Self(s))
    }
}

/// Internal provisioner selection, NOT a bootstrap response or proof. Auth/mount
/// adapters must compare actual authenticated observation before admitting IO.
#[derive(Clone, PartialEq, Eq)]
pub struct DeploymentBinding {
    pub issuer: String,
    pub realm_id: Id,
    pub deployment_generation: Counter,
    pub participant_config_version: Counter,
    pub key_domain_ref: String,
    pub executable_sha256: Digest,
    pub config_sha256: Digest,
}
pub struct ProtectedConfigReferences {
    pub provisioner_reference: String,
    pub auth_reference: String,
}

/// Descriptor parsed with the existing Shared consumer. It remains structural.
pub struct Request {
    descriptor: CaptureDescriptor,
    selected: Option<ObjectReceipt>,
    expected: Vec<ObjectReceipt>,
}
impl Request {
    pub fn parse(descriptor: &[u8], part_id: Option<&str>) -> Result<Self> {
        if descriptor.len() > 8192 {
            return Err(Refusal::NotAvailable);
        }
        let descriptor = CaptureDescriptor::parse(descriptor).map_err(|_| Refusal::NotAvailable)?;
        let expected = descriptor.expected_receipts();
        let selected = match part_id {
            Some(id) => Some(
                expected
                    .iter()
                    .find(|p| p.part_id == id)
                    .ok_or(Refusal::NotAvailable)?
                    .clone(),
            ),
            None => None,
        };
        Ok(Self {
            descriptor,
            selected,
            expected,
        })
    }
    pub fn descriptor_identity(&self) -> String {
        self.descriptor.descriptor_identity()
    }
    pub fn realm(&self) -> &str {
        &self.expected[0].realm_id
    }
    fn selected(&self) -> Result<&ObjectReceipt> {
        self.selected.as_ref().ok_or(Refusal::NotAvailable)
    }
    pub fn verify_body(&self, bytes: &[u8]) -> Result<()> {
        let expected = self.selected()?;
        let encoded = serde_json::to_vec(expected).map_err(|_| Refusal::Unavailable)?;
        self.descriptor
            .verify_receipt_bytes(&encoded, bytes)
            .map_err(|_| Refusal::Conflict)
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Stored {
    owner_receipt_id: Id,
    realm_id: Id,
    deployment_generation: Counter,
    participant_id: Id,
    process_generation: Counter,
    operation_id: Id,
    intent_id: Id,
    owner_commit_id: Id,
    local_seq: Counter,
    resource_binding_digest: Digest,
    object_receipt: ObjectReceipt,
    storage_receipt_id: Id,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Cancellation {
    schema_version: String,
    purpose: String,
    realm_id: Id,
    capture_id: Id,
    request_fingerprint: Digest,
    #[serde(deserialize_with = "crate::capture_binding::integer")]
    intent_revision: u64,
    #[serde(deserialize_with = "crate::capture_binding::integer")]
    cancellation_generation: u64,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ObjectKey {
    part_id: Id,
    object_id: Id,
    object_revision: Id,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Cleaned {
    owner_receipt_id: Id,
    realm_id: Id,
    deployment_generation: Counter,
    participant_id: Id,
    process_generation: Counter,
    operation_id: Id,
    intent_id: Id,
    owner_commit_id: Id,
    local_seq: Counter,
    resource_binding_digest: Digest,
    cancelled_owner_outcome_id: Id,
    cancellation: Cancellation,
    cleaned_objects: Vec<ObjectKey>,
}
/// Exact native Disk variants only. Product terminal assertions cannot parse.
#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind")]
pub enum Outcome {
    #[serde(rename = "disk_stored")]
    Stored(Stored),
    #[serde(rename = "disk_cleaned")]
    Cleaned(Cleaned),
}
#[derive(Clone)]
pub struct Receipt(ObjectReceipt);
impl Outcome {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 8192 {
            return Err(Refusal::NotAvailable);
        }
        serde_json::from_slice(bytes).map_err(|_| Refusal::NotAvailable)
    }
    /// Projection is usable only after the matching native durable outcome
    /// passes validation; it never wraps a synthetic02F LocalCommit.
    pub(crate) fn receipt(&self, request: &Request) -> Result<Receipt> {
        match self {
            Self::Stored(s)
                if s.realm_id.0 == request.realm()
                    && s.intent_id.0 == request.expected[0].capture_id
                    && s.object_receipt == *request.selected()? =>
            {
                Ok(Receipt(s.object_receipt.clone()))
            }
            _ => Err(Refusal::NotAvailable),
        }
    }
}

/// Exact original durable identity expected from AUTH's authenticated original
/// effect/owner-binding readback, not from current process identity or a client.
/// Comparing this never rewrites a historical producer generation on recovery.
#[derive(Clone, PartialEq, Eq)]
pub struct OriginalEffect {
    pub owner_receipt_id: Id,
    pub realm_id: Id,
    pub deployment_generation: Counter,
    pub participant_id: Id,
    pub process_generation: Counter,
    pub operation_id: Id,
    pub intent_id: Id,
    pub owner_commit_id: Id,
    pub local_seq: Counter,
    pub resource_binding_digest: Digest,
}
impl Outcome {
    pub fn matches_original_effect(&self, expected: &OriginalEffect) -> bool {
        let actual = match self {
            Self::Stored(s) => OriginalEffect {
                owner_receipt_id: s.owner_receipt_id.clone(),
                realm_id: s.realm_id.clone(),
                deployment_generation: s.deployment_generation.clone(),
                participant_id: s.participant_id.clone(),
                process_generation: s.process_generation.clone(),
                operation_id: s.operation_id.clone(),
                intent_id: s.intent_id.clone(),
                owner_commit_id: s.owner_commit_id.clone(),
                local_seq: s.local_seq.clone(),
                resource_binding_digest: s.resource_binding_digest.clone(),
            },
            Self::Cleaned(s) => OriginalEffect {
                owner_receipt_id: s.owner_receipt_id.clone(),
                realm_id: s.realm_id.clone(),
                deployment_generation: s.deployment_generation.clone(),
                participant_id: s.participant_id.clone(),
                process_generation: s.process_generation.clone(),
                operation_id: s.operation_id.clone(),
                intent_id: s.intent_id.clone(),
                owner_commit_id: s.owner_commit_id.clone(),
                local_seq: s.local_seq.clone(),
                resource_binding_digest: s.resource_binding_digest.clone(),
            },
        };
        actual == *expected
    }
    pub fn storage_receipt_id(&self) -> Option<&str> {
        match self {
            Self::Stored(s) => Some(&s.storage_receipt_id.0),
            _ => None,
        }
    }
}

/// Native cancelled resource. Structural decoding alone is not terminal proof;
/// Authority::cancelled must authenticate Product outcome under its live fence.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CancelledResource {
    kind: String,
    intent_id: Id,
    #[serde(deserialize_with = "crate::capture_binding::integer")]
    terminal_intent_revision: u64,
    #[serde(deserialize_with = "crate::capture_binding::integer")]
    cancellation_generation: u64,
    owner_outcome_id: Id,
    part_ids: Vec<Id>,
    cancellation: Cancellation,
}
impl CancelledResource {
    pub fn parse(bytes: &[u8], request: &Request) -> Result<Self> {
        if bytes.len() > 4096 {
            return Err(Refusal::NotAvailable);
        }
        let p: Self = serde_json::from_slice(bytes).map_err(|_| Refusal::NotAvailable)?;
        p.validate(request)?;
        Ok(p)
    }
    fn validate(&self, r: &Request) -> Result<()> {
        let p = &r.expected[0];
        let c = &self.cancellation;
        let mut ids = self
            .part_ids
            .iter()
            .map(|v| v.0.as_str())
            .collect::<Vec<_>>();
        ids.sort();
        let mut expected = r
            .expected
            .iter()
            .map(|p| p.part_id.as_str())
            .collect::<Vec<_>>();
        expected.sort();
        if r.selected.is_some()
            || self.kind != "cancellation"
            || self.intent_id.0 != p.capture_id
            || c.schema_version != "personal-capture/v1"
            || c.purpose != "cancel_unpublished_capture"
            || c.realm_id.0 != p.realm_id
            || c.capture_id.0 != p.capture_id
            || c.request_fingerprint.0 != p.request_fingerprint
            || ids != expected
            || self.cancellation_generation != p.cancellation_generation + 1
            || c.cancellation_generation != self.cancellation_generation
            || self.terminal_intent_revision < 2
            || self.terminal_intent_revision > 9_007_199_254_740_991
            || c.intent_revision != self.terminal_intent_revision
        {
            return Err(Refusal::NotAvailable);
        }
        Ok(())
    }
    pub(crate) fn objects(&self, r: &Request) -> Result<Vec<ObjectKey>> {
        self.validate(r)?;
        Ok(r.expected
            .iter()
            .map(|p| ObjectKey {
                part_id: Id(p.part_id.clone()),
                object_id: Id(p.object_id.clone()),
                object_revision: Id(p.object_revision.clone()),
            })
            .collect())
    }
    pub(crate) fn verify_cleaned(&self, r: &Request, o: &Outcome) -> Result<()> {
        let s = match o {
            Outcome::Cleaned(s) => s,
            _ => return Err(Refusal::NotAvailable),
        };
        let expected = self.objects(r)?;
        if s.realm_id.0 != r.realm()
            || s.intent_id != self.intent_id
            || s.cancelled_owner_outcome_id != self.owner_outcome_id
            || s.cancellation != self.cancellation
            || s.cleaned_objects.len() != expected.len()
            || expected
                .iter()
                .any(|k| s.cleaned_objects.iter().filter(|x| *x == k).count() != 1)
        {
            return Err(Refusal::NotAvailable);
        }
        Ok(())
    }
}

pub struct NativeContract;
impl Contract for NativeContract {
    type Deployment = DeploymentBinding;
    type ConfigReferences = ProtectedConfigReferences;
    type Request = Request;
    type Receipt = Receipt;
    type Outcome = Outcome;
}

/// Production IO boundary: implemented only by an admitted handle-relative VFS
/// and durable native journal. This module supplies concrete binding/verification
/// around it; the old synthetic provider is deliberately NOT an implementation.
pub trait NativeBackend<E> {
    fn observe(&self, effect: &E, request: &Request) -> Result<Observation<(), Outcome>>;
    fn stage(&self, effect: &E, request: &Request, bytes: &[u8]) -> Result<Option<Outcome>>;
    /// Must enforce max_bytes before allocation; returned bytes never go public.
    fn read_exact(&self, effect: &E, request: &Request, max_bytes: usize) -> Result<Vec<u8>>;
    fn tombstone_exact(
        &self,
        effect: &E,
        request: &Request,
        objects: &[ObjectKey],
        cancelled: &CancelledResource,
    ) -> Result<()>;
    fn cleanup_exact(
        &self,
        effect: &E,
        request: &Request,
        objects: &[ObjectKey],
        cancelled: &CancelledResource,
    ) -> Result<Option<Outcome>>;
}
pub struct NativeStorage<B>(pub B);
impl<A, B> Storage<NativeContract, A> for NativeStorage<B>
where
    A: Authority<NativeContract, Cancellation = CancelledResource>,
    B: NativeBackend<A::Effect>,
{
    fn observe(&self, e: &A::Effect, r: &Request) -> Result<Observation<Receipt, Outcome>> {
        Ok(match self.0.observe(e, r)? {
            Observation::Durable { outcome, .. } => Observation::Durable {
                receipt: outcome.receipt(r)?,
                outcome,
            },
            Observation::CancelledCleaned { outcome } => {
                if !matches!(outcome, Outcome::Cleaned(_)) {
                    return Err(Refusal::Unavailable);
                }
                Observation::CancelledCleaned { outcome }
            }
            Observation::Unseen => Observation::Unseen,
            Observation::Prepared => Observation::Prepared,
            Observation::Unknown => Observation::Unknown,
            Observation::Corrupt => Observation::Corrupt,
            Observation::CleanupPending => Observation::CleanupPending,
        })
    }
    fn verify_body(&self, _: &A::Effect, r: &Request, b: &[u8]) -> Result<()> {
        r.verify_body(b)
    }
    fn stage(&self, e: &A::Effect, r: &Request, b: &[u8]) -> Result<Commit<Receipt, Outcome>> {
        r.verify_body(b)?;
        match self.0.stage(e, r, b)? {
            Some(outcome) => Ok(Commit::Committed {
                receipt: outcome.receipt(r)?,
                outcome,
            }),
            None => Ok(Commit::Unknown),
        }
    }
    fn verify_exact_readback(&self, e: &A::Effect, r: &Request, receipt: &Receipt) -> Result<()> {
        if receipt.0 != *r.selected()? {
            return Err(Refusal::NotAvailable);
        }
        let bytes = self.0.read_exact(e, r, receipt.0.size_bytes as usize)?;
        r.verify_body(&bytes).map_err(|_| Refusal::NotAvailable)
    }
    fn tombstone(&self, e: &A::Effect, r: &Request, c: &CancelledResource) -> Result<()> {
        self.0.tombstone_exact(e, r, &c.objects(r)?, c)
    }
    fn finish_cleanup(
        &self,
        e: &A::Effect,
        r: &Request,
        c: &CancelledResource,
    ) -> Result<Option<Outcome>> {
        let o = self.0.cleanup_exact(e, r, &c.objects(r)?, c)?;
        if let Some(ref value) = o {
            c.verify_cleaned(r, value)?;
        }
        Ok(o)
    }
}

impl DeploymentBinding {
    pub fn realm(&self) -> &str {
        &self.realm_id.0
    }
    pub(crate) fn selection_valid(&self) -> bool {
        !self.issuer.is_empty()
            && self.issuer.len() <= 256
            && !self.key_domain_ref.is_empty()
            && self.key_domain_ref.len() <= 256
    }
}
impl Request {
    pub(crate) fn accepts_operation(&self, op: crate::parent_adapter::Operation) -> bool {
        match op {
            crate::parent_adapter::Operation::CleanupCancelled => self.selected.is_none(),
            _ => self.selected.is_some(),
        }
    }
}
impl Outcome {
    pub(crate) fn verify_receipt(&self, r: &Request, receipt: &Receipt) -> Result<()> {
        if self.receipt(r)?.0 != receipt.0 {
            return Err(Refusal::NotAvailable);
        }
        Ok(())
    }
    pub(crate) fn matches_operation(&self, op: crate::parent_adapter::Operation) -> bool {
        matches!(
            (self, op),
            (Self::Stored(_), crate::parent_adapter::Operation::Stage)
                | (
                    Self::Cleaned(_),
                    crate::parent_adapter::Operation::CleanupCancelled
                )
        )
    }
}

impl Serialize for Counter {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.0.to_string())
    }
}
impl Request {
    /// Internal exact resource comparison, not an Auth request fingerprint.
    pub fn resource_identity(&self) -> String {
        serde_json::json!([
            self.descriptor_identity(),
            self.selected.as_ref().map(|p| p.part_id.as_str())
        ])
        .to_string()
    }
    pub(crate) fn selected_size(&self) -> Result<usize> {
        usize::try_from(self.selected()?.size_bytes).map_err(|_| Refusal::Unavailable)
    }
    pub(crate) fn capture_id(&self) -> &str {
        &self.expected[0].capture_id
    }
    pub(crate) fn selected_receipt_json(&self) -> Result<String> {
        serde_json::to_string(self.selected()?).map_err(|_| Refusal::Unavailable)
    }
    pub(crate) fn part_resource_identities(&self) -> Vec<String> {
        self.expected
            .iter()
            .map(|p| {
                serde_json::json!([self.descriptor_identity(), Some(p.part_id.as_str())])
                    .to_string()
            })
            .collect()
    }
    pub fn selected_object(&self) -> Result<ObjectKey> {
        let p = self.selected()?;
        Ok(ObjectKey {
            part_id: Id(p.part_id.clone()),
            object_id: Id(p.object_id.clone()),
            object_revision: Id(p.object_revision.clone()),
        })
    }
}
impl ObjectKey {
    pub fn part_id(&self) -> &str {
        &self.part_id.0
    }
    pub fn object_id(&self) -> &str {
        &self.object_id.0
    }
    pub fn object_revision(&self) -> &str {
        &self.object_revision.0
    }
}
impl Outcome {
    /// Native registration payload. Not JCS or an Auth signature/digest; the
    /// control adapter must perform canonical signing as specified upstream.
    pub fn registration_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|_| Refusal::Unavailable)
    }
}

impl Id {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl Outcome {
    pub fn owner_receipt_id(&self) -> &str {
        match self {
            Self::Stored(s) => &s.owner_receipt_id.0,
            Self::Cleaned(s) => &s.owner_receipt_id.0,
        }
    }
    pub fn local_sequence(&self) -> u64 {
        match self {
            Self::Stored(s) => s.local_seq.0,
            Self::Cleaned(s) => s.local_seq.0,
        }
    }
    /// Exact local lineage projection, not authenticated original-effect proof.
    pub fn original_identity(&self) -> OriginalEffect {
        match self {
            Self::Stored(s) => OriginalEffect {
                owner_receipt_id: s.owner_receipt_id.clone(),
                realm_id: s.realm_id.clone(),
                deployment_generation: s.deployment_generation.clone(),
                participant_id: s.participant_id.clone(),
                process_generation: s.process_generation.clone(),
                operation_id: s.operation_id.clone(),
                intent_id: s.intent_id.clone(),
                owner_commit_id: s.owner_commit_id.clone(),
                local_seq: s.local_seq.clone(),
                resource_binding_digest: s.resource_binding_digest.clone(),
            },
            Self::Cleaned(s) => OriginalEffect {
                owner_receipt_id: s.owner_receipt_id.clone(),
                realm_id: s.realm_id.clone(),
                deployment_generation: s.deployment_generation.clone(),
                participant_id: s.participant_id.clone(),
                process_generation: s.process_generation.clone(),
                operation_id: s.operation_id.clone(),
                intent_id: s.intent_id.clone(),
                owner_commit_id: s.owner_commit_id.clone(),
                local_seq: s.local_seq.clone(),
                resource_binding_digest: s.resource_binding_digest.clone(),
            },
        }
    }
}

#[cfg(test)]
#[path = "parent_native_tests.rs"]
mod tests;
