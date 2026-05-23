//! ACL YAML loader.
//!
//! Reads `disk-acl.yaml` from disk, validates schema, checks the monotonic
//! `version` counter, and builds an [`EnforcementTable`]. Signature verification
//! goes through a pluggable [`SignatureVerifier`] trait — production code wires
//! a GPG shell-out verifier (deferred to /dr-do round 3); tests use
//! [`NoopVerifier`] (always trust) or [`AlwaysFailVerifier`] (always reject).
//!
//! Pipeline (creative-DISK-0005-architecture-acl-reload.md §5):
//!   1. read file bytes (FileMissing on `std::io::ErrorKind::NotFound`)
//!   2. verify signature via injected verifier (SignatureFailed / SignerRevoked)
//!   3. parse YAML schema (ParseError)
//!   4. version > stored.version (VersionRegress)
//!   5. build EnforcementTable
//!
//! The caller (ACL reload loop, P4a step 8) uses [`AclEnforcer::try_swap`] to
//! atomically promote Loaded/Unhealthy state and emit audit events.

use std::path::Path;

use serde::Deserialize;

use super::{CertFingerprint, EnforcedRole, EnforcementTable, UnhealthyReason};

/// Maps to PRD-DISK-0001 v1.1 §4.11.4 ACL schema.
#[derive(Debug, Deserialize)]
pub struct AclYamlFile {
    pub version: u64,
    pub updated_at: String,
    pub signed_by: String,
    #[serde(default)]
    pub nodes: Vec<AclNodeEntry>,
}

#[derive(Debug, Deserialize)]
pub struct AclNodeEntry {
    /// Hex-encoded SHA-256 of DER-encoded client cert.
    /// We accept the conventional `sha256:<hex>` form (matches PRD example)
    /// and tolerate raw hex without prefix for ergonomics.
    pub cert_fingerprint: String,
    #[serde(default)]
    pub node_id_hint: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub shares: std::collections::BTreeMap<String, String>,
}

fn default_enabled() -> bool {
    true
}

#[derive(thiserror::Error, Debug)]
pub enum AclLoadError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("file missing at {path}")]
    FileMissing { path: String },

    #[error("yaml parse error: {0}")]
    Parse(String),

    #[error("signature verification failed: {0}")]
    SignatureFailed(String),

    #[error("signer key is revoked: {0}")]
    SignerRevoked(String),

    #[error("version regress: stored={stored}, attempted={attempted}")]
    VersionRegress { stored: u64, attempted: u64 },

    #[error("invalid cert fingerprint at node[{index}]: {detail}")]
    BadFingerprint { index: usize, detail: String },

    #[error("invalid role `{role}` at node[{index}].shares[{share}]")]
    BadRole {
        index: usize,
        share: String,
        role: String,
    },
}

impl AclLoadError {
    /// Map a load error into the canonical UnhealthyReason for the enforcer.
    pub fn into_unhealthy_reason(self) -> UnhealthyReason {
        match self {
            AclLoadError::Io(e) if e.kind() == std::io::ErrorKind::NotFound => {
                UnhealthyReason::FileMissing
            }
            AclLoadError::FileMissing { .. } => UnhealthyReason::FileMissing,
            AclLoadError::Io(e) => UnhealthyReason::ParseError(format!("io: {e}")),
            AclLoadError::Parse(s) => UnhealthyReason::ParseError(s),
            AclLoadError::SignatureFailed(s) => UnhealthyReason::SignatureFailed(s),
            AclLoadError::SignerRevoked(_) => UnhealthyReason::SignerRevoked,
            AclLoadError::VersionRegress { stored, attempted } => {
                UnhealthyReason::VersionRegress { stored, attempted }
            }
            AclLoadError::BadFingerprint { index, detail } => {
                UnhealthyReason::ParseError(format!("node[{index}].cert_fingerprint: {detail}"))
            }
            AclLoadError::BadRole { index, share, role } => UnhealthyReason::ParseError(format!(
                "node[{index}].shares[{share}]: invalid role `{role}`"
            )),
        }
    }
}

/// Pluggable signature verifier. Production: GPG shell-out (round 3).
/// Tests: NoopVerifier / AlwaysFailVerifier.
pub trait SignatureVerifier: Send + Sync {
    /// Verify the YAML file content against an external signature.
    /// `file_bytes` is the YAML body; signature source (e.g. git-attached
    /// commit signature, detached `.asc` file) is implementation-defined.
    fn verify(&self, file_bytes: &[u8]) -> Result<(), AclLoadError>;
}

/// Always trusts the file. **Tests only.**
pub struct NoopVerifier;

impl SignatureVerifier for NoopVerifier {
    fn verify(&self, _file_bytes: &[u8]) -> Result<(), AclLoadError> {
        Ok(())
    }
}

/// Always rejects with `SignatureFailed`. Used by negative-path tests.
pub struct AlwaysFailVerifier(pub &'static str);

impl SignatureVerifier for AlwaysFailVerifier {
    fn verify(&self, _file_bytes: &[u8]) -> Result<(), AclLoadError> {
        Err(AclLoadError::SignatureFailed(self.0.to_string()))
    }
}

/// Always rejects with `SignerRevoked`. Used by negative-path tests.
pub struct RevokedSignerVerifier(pub &'static str);

impl SignatureVerifier for RevokedSignerVerifier {
    fn verify(&self, _file_bytes: &[u8]) -> Result<(), AclLoadError> {
        Err(AclLoadError::SignerRevoked(self.0.to_string()))
    }
}

/// Successful load result. Caller wraps `table` in `AclState::Loaded` and
/// swaps it into the enforcer.
#[derive(Debug)]
pub struct LoadOutcome {
    pub table: EnforcementTable,
    pub new_version: u64,
    pub signed_by: String,
    pub file_sha256: [u8; 32],
}

/// Load and validate an ACL YAML file. `stored_version` is the monotonic
/// counter persisted in `acl_meta.version`; pass `0` on cold boot (any version
/// is acceptable as the first load).
pub fn load_from_yaml<P, V>(
    path: P,
    stored_version: u64,
    verifier: &V,
) -> Result<LoadOutcome, AclLoadError>
where
    P: AsRef<Path>,
    V: SignatureVerifier + ?Sized,
{
    let path_ref = path.as_ref();
    let bytes = match std::fs::read(path_ref) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(AclLoadError::FileMissing {
                path: path_ref.display().to_string(),
            });
        }
        Err(e) => return Err(AclLoadError::Io(e)),
    };

    verifier.verify(&bytes)?;

    let parsed: AclYamlFile = serde_yaml_ng::from_slice(&bytes)
        .map_err(|e| AclLoadError::Parse(e.to_string()))?;

    if parsed.version <= stored_version && stored_version > 0 {
        return Err(AclLoadError::VersionRegress {
            stored: stored_version,
            attempted: parsed.version,
        });
    }

    let mut table = EnforcementTable::new(parsed.version);
    for (idx, node) in parsed.nodes.iter().enumerate() {
        if !node.enabled {
            continue;
        }
        let fp = parse_fingerprint(idx, &node.cert_fingerprint)?;
        for (share, role_str) in &node.shares {
            let role = EnforcedRole::parse(role_str).ok_or_else(|| AclLoadError::BadRole {
                index: idx,
                share: share.clone(),
                role: role_str.clone(),
            })?;
            table.insert(fp, share.clone(), role);
        }
    }

    let file_sha256: [u8; 32] = blake3::hash(&bytes).into();

    Ok(LoadOutcome {
        table,
        new_version: parsed.version,
        signed_by: parsed.signed_by,
        file_sha256,
    })
}

/// Parse a fingerprint of the form `sha256:<64-hex-chars>` or `<64-hex-chars>`.
fn parse_fingerprint(index: usize, raw: &str) -> Result<CertFingerprint, AclLoadError> {
    let hex_part = raw.strip_prefix("sha256:").unwrap_or(raw);
    if hex_part.len() != 64 {
        return Err(AclLoadError::BadFingerprint {
            index,
            detail: format!("expected 64 hex chars, got {}", hex_part.len()),
        });
    }
    let mut out = [0u8; 32];
    for (i, byte_out) in out.iter_mut().enumerate() {
        let s = &hex_part[i * 2..i * 2 + 2];
        *byte_out = u8::from_str_radix(s, 16).map_err(|_| AclLoadError::BadFingerprint {
            index,
            detail: format!("non-hex char near offset {}", i * 2),
        })?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const VALID_YAML: &str = r#"
version: 7
updated_at: "2026-05-24T12:00:00Z"
signed_by: pavel.valentov@arcanada.one
nodes:
  - cert_fingerprint: sha256:0101010101010101010101010101010101010101010101010101010101010101
    node_id_hint: arcana-ai
    enabled: true
    shares:
      hermes-artefacts: publisher
  - cert_fingerprint: 0202020202020202020202020202020202020202020202020202020202020202
    node_id_hint: macbook-ug
    shares:
      hermes-artefacts: receive_only
      wiki: bidirectional
"#;

    fn write_tmp(content: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("disk-acl.yaml");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        (dir, path)
    }

    #[test]
    fn loads_valid_yaml_with_noop_verifier() {
        let (_dir, path) = write_tmp(VALID_YAML);
        let out = load_from_yaml(&path, 0, &NoopVerifier).expect("load ok");
        assert_eq!(out.new_version, 7);
        assert_eq!(out.signed_by, "pavel.valentov@arcanada.one");
        // Two cert entries × shares each = 3 rules total.
        assert_eq!(out.table.len(), 3);

        let arcana_ai = [0x01; 32];
        assert_eq!(
            out.table.lookup(&arcana_ai, "hermes-artefacts"),
            Some(EnforcedRole::Publisher)
        );

        let macbook = [0x02; 32];
        assert_eq!(
            out.table.lookup(&macbook, "wiki"),
            Some(EnforcedRole::Bidirectional)
        );
    }

    #[test]
    fn rejects_file_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("no-such-file.yaml");
        let err = load_from_yaml(&path, 0, &NoopVerifier).unwrap_err();
        let reason = err.into_unhealthy_reason();
        assert_eq!(reason, UnhealthyReason::FileMissing);
    }

    #[test]
    fn rejects_signature_failed() {
        let (_dir, path) = write_tmp(VALID_YAML);
        let err = load_from_yaml(&path, 0, &AlwaysFailVerifier("gpg verify exit=1")).unwrap_err();
        let reason = err.into_unhealthy_reason();
        assert_eq!(
            reason,
            UnhealthyReason::SignatureFailed("gpg verify exit=1".into())
        );
    }

    #[test]
    fn rejects_signer_revoked() {
        let (_dir, path) = write_tmp(VALID_YAML);
        let err =
            load_from_yaml(&path, 0, &RevokedSignerVerifier("revoked key 0xDEAD")).unwrap_err();
        let reason = err.into_unhealthy_reason();
        assert_eq!(reason, UnhealthyReason::SignerRevoked);
    }

    #[test]
    fn rejects_parse_error() {
        // Malformed YAML: unclosed bracket.
        let (_dir, path) = write_tmp("version: 1\nnodes: [");
        let err = load_from_yaml(&path, 0, &NoopVerifier).unwrap_err();
        match err.into_unhealthy_reason() {
            UnhealthyReason::ParseError(_) => {}
            other => panic!("expected ParseError, got {other:?}"),
        }
    }

    #[test]
    fn rejects_version_regress_when_stored_is_higher() {
        let (_dir, path) = write_tmp(VALID_YAML);
        let err = load_from_yaml(&path, 8, &NoopVerifier).unwrap_err();
        let reason = err.into_unhealthy_reason();
        assert_eq!(
            reason,
            UnhealthyReason::VersionRegress {
                stored: 8,
                attempted: 7
            }
        );
    }

    #[test]
    fn rejects_version_regress_when_stored_equals_attempted() {
        // attempted == stored is treated as regress per «monotonic, strictly
        // increasing» contract — re-loading the same version is a no-op-or-
        // dedup, not a successful new load.
        let (_dir, path) = write_tmp(VALID_YAML);
        let err = load_from_yaml(&path, 7, &NoopVerifier).unwrap_err();
        assert!(matches!(
            err.into_unhealthy_reason(),
            UnhealthyReason::VersionRegress { .. }
        ));
    }

    #[test]
    fn rejects_invalid_role_string() {
        let bad = r#"
version: 1
updated_at: "now"
signed_by: x
nodes:
  - cert_fingerprint: sha256:0303030303030303030303030303030303030303030303030303030303030303
    shares:
      wiki: arbitrary-not-a-role
"#;
        let (_dir, path) = write_tmp(bad);
        let err = load_from_yaml(&path, 0, &NoopVerifier).unwrap_err();
        match err.into_unhealthy_reason() {
            UnhealthyReason::ParseError(msg) => {
                assert!(msg.contains("arbitrary-not-a-role"), "msg={msg}");
            }
            other => panic!("expected ParseError, got {other:?}"),
        }
    }

    #[test]
    fn rejects_bad_fingerprint_length() {
        let bad = r#"
version: 1
updated_at: "now"
signed_by: x
nodes:
  - cert_fingerprint: sha256:dead
    shares: {}
"#;
        let (_dir, path) = write_tmp(bad);
        let err = load_from_yaml(&path, 0, &NoopVerifier).unwrap_err();
        assert!(matches!(
            err.into_unhealthy_reason(),
            UnhealthyReason::ParseError(_)
        ));
    }

    #[test]
    fn disabled_nodes_are_skipped() {
        let with_disabled = r#"
version: 1
updated_at: "now"
signed_by: x
nodes:
  - cert_fingerprint: sha256:0404040404040404040404040404040404040404040404040404040404040404
    enabled: false
    shares:
      wiki: bidirectional
"#;
        let (_dir, path) = write_tmp(with_disabled);
        let out = load_from_yaml(&path, 0, &NoopVerifier).expect("load ok");
        assert_eq!(out.table.len(), 0, "disabled node MUST not contribute rules");
    }

    #[test]
    fn cold_boot_accepts_any_version() {
        let (_dir, path) = write_tmp(VALID_YAML);
        // stored_version=0 ⇒ cold boot; ACL version=7 must be accepted.
        let out = load_from_yaml(&path, 0, &NoopVerifier).expect("cold-boot load");
        assert_eq!(out.new_version, 7);
    }

    #[test]
    fn file_sha256_is_deterministic_per_content() {
        let (_dir, path) = write_tmp(VALID_YAML);
        let a = load_from_yaml(&path, 0, &NoopVerifier).unwrap();
        let b = load_from_yaml(&path, 0, &NoopVerifier).unwrap();
        assert_eq!(a.file_sha256, b.file_sha256);
        assert_ne!(a.file_sha256, [0u8; 32]);
    }
}
