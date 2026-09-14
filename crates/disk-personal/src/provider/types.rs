use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(crate) const MAX_BLOB: usize = 1_048_576;
pub(crate) const MAX_RECORDS: i64 = 128;
pub(crate) const MAX_RESERVED_BYTES: i64 = 64 * 1_048_576;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid synthetic input")]
    InvalidInput,
    #[error("unsafe or substituted fixture path")]
    UnsafePath,
    #[error("fixture writer already held")]
    WriterBusy,
    #[error("unacknowledged SQLite shutdown; exit this synthetic process before reopening")]
    LifecycleAbandoned,
    #[error("immutable identity conflict")]
    Conflict,
    #[error("no matching synthetic operation")]
    NotFound,
    #[error("retained prepared attempt is unresolved")]
    UnresolvedPrepared,
    #[error("provider poisoned; retained evidence requires a new fixture root")]
    Poisoned,
    #[error("poison persistence uncertain; provider unavailable")]
    PoisonUncertain,
    #[error("fixture capacity exceeded")]
    Capacity,
    #[error("unsupported or unexpected inventory schema")]
    Schema,
    #[error("injected filesystem failure at {0}")]
    Injected(&'static str),
    #[error("filesystem failure: {0}")]
    Io(#[from] std::io::Error),
    #[error("inventory failure: {0}")]
    Sql(#[from] sqlx::Error),
    #[error("fixture JSON failure: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub realm_id: String,
    pub deployment_id: String,
}

impl Binding {
    pub(crate) fn validate(&self) -> Result<()> {
        valid_id(&self.realm_id)?;
        valid_id(&self.deployment_id)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Note,
    Attachment,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub operation_id: String,
    pub attempt_id: String,
    pub object_id: String,
    pub revision_id: String,
    pub kind: Kind,
    pub expected_len: u64,
    pub sha256: String,
}

impl Request {
    pub(crate) fn validate(&self) -> Result<()> {
        for id in [
            &self.operation_id,
            &self.attempt_id,
            &self.object_id,
            &self.revision_id,
        ] {
            valid_id(id)?;
        }
        let max = match self.kind {
            Kind::Note => 65_536,
            Kind::Attachment => MAX_BLOB as u64,
        };
        if self.expected_len > max
            || self.sha256.len() != 64
            || !self
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }

    pub(crate) fn verifies(&self, bytes: &[u8]) -> bool {
        bytes.len() as u64 == self.expected_len
            && digest(bytes) == self.sha256
            && (self.kind != Kind::Note || std::str::from_utf8(bytes).is_ok())
    }

    pub(crate) fn staging_name(&self) -> String {
        format!("{}.part", self.attempt_id)
    }

    pub(crate) fn object_name(&self) -> String {
        format!("{}.blob", self.revision_id)
    }
}

/// Local fixture evidence only; never an Auth-registered storage outcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalCommit {
    pub local_commit_id: String,
    pub sequence: i64,
    pub request: Request,
}

#[derive(Debug, Serialize)]
pub struct Inspection {
    pub prepared: usize,
    pub durable: Vec<LocalCommit>,
    pub sqlite_policy: Vec<(String, i64)>,
}

pub(crate) fn valid_id(id: &str) -> Result<()> {
    let parsed = uuid::Uuid::parse_str(id).map_err(|_| Error::InvalidInput)?;
    if parsed.is_nil() || parsed.hyphenated().to_string() != id {
        return Err(Error::InvalidInput);
    }
    Ok(())
}

pub fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
