//! ACL enforcement for DISK-0005 v1.1.
//!
//! Per-share × per-node role enforcement keyed by mTLS client cert SHA-256.
//! See:
//! - PRD-DISK-0001 v1.1 §4.11 (Per-Host Directional Policy)
//! - `datarim/creative/creative-DISK-0005-architecture-acl-reload.md`
//!
//! Authority contract: the client's declared `intended_direction` in `disk.toml`
//! is a non-authoritative hint. The server side MUST resolve role from this
//! enforcer, keyed by cert fingerprint — never branch on incoming metadata.
//!
//! Default-deny: when [`AclState`] is [`AclState::Unhealthy`] every [`resolve`]
//! returns [`AclError::Unavailable`]. Cold-boot failure (no successful load
//! yet) leaves the enforcer in `Unhealthy`; refuse-and-keep semantics for
//! reload failures are layered in `acl::reload` (later step of P4a).
//!
//! [`resolve`]: AclEnforcer::resolve

pub mod loader;
pub mod reload;

pub use loader::{
    load_from_yaml, AclLoadError, AclYamlFile, AlwaysFailVerifier, GpgVerifier, LoadOutcome,
    NoopVerifier, RevokedSignerVerifier, SignatureVerifier,
};

use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub type CertFingerprint = [u8; 32];

/// Roles enforced server-side. String values match the SQLite CHECK constraint
/// in `migrations/003_acl_enrollment.sql` and the PRD §4.11 enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcedRole {
    Bidirectional,
    ReceiveOnly,
    SendOnly,
    Publisher,
}

impl EnforcedRole {
    pub fn as_str(self) -> &'static str {
        match self {
            EnforcedRole::Bidirectional => "bidirectional",
            EnforcedRole::ReceiveOnly => "receive_only",
            EnforcedRole::SendOnly => "send_only",
            EnforcedRole::Publisher => "publisher",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "bidirectional" => Some(Self::Bidirectional),
            "receive_only" => Some(Self::ReceiveOnly),
            "send_only" => Some(Self::SendOnly),
            "publisher" => Some(Self::Publisher),
            _ => None,
        }
    }
}

/// In-memory snapshot of the loaded ACL keyed by (cert_fp, share).
#[derive(Debug, Default, Clone)]
pub struct EnforcementTable {
    pub version: u64,
    entries: BTreeMap<(CertFingerprint, String), EnforcedRole>,
}

impl EnforcementTable {
    pub fn new(version: u64) -> Self {
        Self {
            version,
            entries: BTreeMap::new(),
        }
    }

    pub fn insert(
        &mut self,
        cert_fp: CertFingerprint,
        share: impl Into<String>,
        role: EnforcedRole,
    ) {
        self.entries.insert((cert_fp, share.into()), role);
    }

    pub fn lookup(&self, cert_fp: &CertFingerprint, share: &str) -> Option<EnforcedRole> {
        self.entries.get(&(*cert_fp, share.to_string())).copied()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Why the ACL is currently unhealthy. Maps 1:1 to the failure rows in
/// creative-DISK-0005-architecture-acl-reload §Failure Mode Table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnhealthyReason {
    NeverLoaded,
    ParseError(String),
    SignatureFailed(String),
    VersionRegress { stored: u64, attempted: u64 },
    FileMissing,
    SignerRevoked,
}

#[derive(Debug, Clone)]
pub enum AclState {
    Loaded(EnforcementTable),
    Unhealthy(UnhealthyReason),
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum AclError {
    #[error("ACL unavailable: {0:?}")]
    Unavailable(UnhealthyReason),
    #[error("share `{share}` unknown for cert {cert_fp_short}; client should retry on backoff")]
    ShareUnknown {
        share: String,
        cert_fp_short: String,
    },
}

/// Enforcer wraps shared mutable ACL state. Cheap to clone (just an Arc).
#[derive(Debug, Clone)]
pub struct AclEnforcer {
    state: Arc<RwLock<AclState>>,
}

impl AclEnforcer {
    /// Cold-boot enforcer: state begins `Unhealthy::NeverLoaded` so RPC paths
    /// must default-deny until [`try_swap`] succeeds. This matches the
    /// authority contract — production deployments cannot regress to a
    /// permissive default if the loader fails on boot.
    pub fn new_unhealthy() -> Self {
        Self {
            state: Arc::new(RwLock::new(AclState::Unhealthy(
                UnhealthyReason::NeverLoaded,
            ))),
        }
    }

    /// Construct an enforcer pre-seeded with an `EnforcementTable`. Intended
    /// for tests and for callers that have already loaded + validated YAML.
    pub fn new_loaded(table: EnforcementTable) -> Self {
        Self {
            state: Arc::new(RwLock::new(AclState::Loaded(table))),
        }
    }

    /// Resolve role for `(cert_fp, share)`. Returns:
    /// - `Ok(role)` when the ACL is Loaded and the entry exists.
    /// - `Err(ShareUnknown)` when ACL is Loaded but no entry — client should
    ///   retry on backoff (R-DIR-7).
    /// - `Err(Unavailable)` when ACL is Unhealthy — default-deny (R-DIR-5).
    pub async fn resolve(
        &self,
        cert_fp: &CertFingerprint,
        share: &str,
    ) -> Result<EnforcedRole, AclError> {
        match &*self.state.read().await {
            AclState::Loaded(table) => {
                table
                    .lookup(cert_fp, share)
                    .ok_or_else(|| AclError::ShareUnknown {
                        share: share.to_string(),
                        cert_fp_short: short_fp(cert_fp),
                    })
            }
            AclState::Unhealthy(reason) => Err(AclError::Unavailable(reason.clone())),
        }
    }

    /// Atomically swap the loaded state. Used by `acl::reload` after a
    /// successful parse / signature / version-monotonic check pipeline.
    pub async fn try_swap(&self, new_state: AclState) {
        *self.state.write().await = new_state;
    }

    /// Inspect current health for `/status` endpoints and audit logging.
    /// Returns `None` when Loaded, `Some(reason)` when Unhealthy.
    pub async fn unhealthy_reason(&self) -> Option<UnhealthyReason> {
        match &*self.state.read().await {
            AclState::Loaded(_) => None,
            AclState::Unhealthy(r) => Some(r.clone()),
        }
    }

    /// Current ACL version, if Loaded. None when Unhealthy.
    pub async fn current_version(&self) -> Option<u64> {
        match &*self.state.read().await {
            AclState::Loaded(t) => Some(t.version),
            AclState::Unhealthy(_) => None,
        }
    }
}

fn short_fp(fp: &CertFingerprint) -> String {
    hex_first_n(fp, 8)
}

fn hex_first_n(b: &[u8], n: usize) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(n * 2);
    for byte in b.iter().take(n) {
        let _ = write!(&mut out, "{:02x}", byte);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(seed: u8) -> CertFingerprint {
        [seed; 32]
    }

    #[tokio::test]
    async fn cold_boot_enforcer_is_unhealthy_never_loaded() {
        let enforcer = AclEnforcer::new_unhealthy();
        let err = enforcer.resolve(&fp(0xAA), "any-share").await.unwrap_err();
        assert_eq!(
            err,
            AclError::Unavailable(UnhealthyReason::NeverLoaded),
            "cold boot MUST default-deny — R-DIR-5"
        );
    }

    #[tokio::test]
    async fn loaded_state_returns_role_for_known_entry() {
        let mut table = EnforcementTable::new(7);
        table.insert(fp(0x01), "hermes-artefacts", EnforcedRole::Publisher);
        let enforcer = AclEnforcer::new_loaded(table);

        let role = enforcer
            .resolve(&fp(0x01), "hermes-artefacts")
            .await
            .expect("entry present");
        assert_eq!(role, EnforcedRole::Publisher);
    }

    #[tokio::test]
    async fn loaded_state_returns_share_unknown_for_missing_entry() {
        let table = EnforcementTable::new(7);
        let enforcer = AclEnforcer::new_loaded(table);

        let err = enforcer
            .resolve(&fp(0x02), "unknown-share")
            .await
            .unwrap_err();
        match err {
            AclError::ShareUnknown { share, .. } => assert_eq!(share, "unknown-share"),
            other => panic!("expected ShareUnknown, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn try_swap_promotes_unhealthy_to_loaded() {
        let enforcer = AclEnforcer::new_unhealthy();
        assert!(enforcer.unhealthy_reason().await.is_some());

        let mut table = EnforcementTable::new(1);
        table.insert(fp(0x03), "wiki", EnforcedRole::Bidirectional);
        enforcer.try_swap(AclState::Loaded(table)).await;

        assert_eq!(enforcer.current_version().await, Some(1));
        assert!(enforcer.unhealthy_reason().await.is_none());
        let role = enforcer
            .resolve(&fp(0x03), "wiki")
            .await
            .expect("post-swap lookup");
        assert_eq!(role, EnforcedRole::Bidirectional);
    }

    #[tokio::test]
    async fn try_swap_demotes_loaded_to_unhealthy_on_failed_reload() {
        let mut table = EnforcementTable::new(5);
        table.insert(fp(0x04), "any", EnforcedRole::ReceiveOnly);
        let enforcer = AclEnforcer::new_loaded(table);

        enforcer
            .try_swap(AclState::Unhealthy(UnhealthyReason::SignatureFailed(
                "test reason".into(),
            )))
            .await;

        let err = enforcer.resolve(&fp(0x04), "any").await.unwrap_err();
        assert_eq!(
            err,
            AclError::Unavailable(UnhealthyReason::SignatureFailed("test reason".into()))
        );
    }

    #[test]
    fn enforced_role_string_round_trip_matches_sql_check_constraint() {
        for role in [
            EnforcedRole::Bidirectional,
            EnforcedRole::ReceiveOnly,
            EnforcedRole::SendOnly,
            EnforcedRole::Publisher,
        ] {
            let s = role.as_str();
            let parsed = EnforcedRole::parse(s).expect("parse round-trip");
            assert_eq!(parsed, role);
        }
        assert_eq!(EnforcedRole::parse("not-a-role"), None);
    }
}
