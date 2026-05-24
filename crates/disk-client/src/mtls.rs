//! mTLS cert/key handling for `disk-client` (DISK-0006 R4).
//!
//! Loads PEM-encoded client cert + private key from filesystem paths
//! recorded in `disk.toml § [server]`, audits the key file permissions
//! (fail-closed on group/world-readable), and assembles a
//! [`tonic::transport::ClientTlsConfig`] suitable for the disk-server
//! mTLS listener (PRD-DISK-0001 §4.11).
//!
//! ## Permission audit
//!
//! On Unix the key file MUST have mode `<= 0600` — group/world bits set
//! cause `MtlsError::InsecureKeyPerms`. Rationale: a private key on a
//! shared box that is `0644` is functionally compromised the moment a
//! second user logs in, and rustls itself cannot enforce the constraint
//! since the bytes still parse. The audit is loader-level so daemon boot
//! fails before any RPC is made (PRD-DISK-0001 §10 fail-closed).
//!
//! On non-Unix targets the audit is a no-op (NTFS ACLs are out of scope
//! for R4 — tracked separately when Windows support lands).

use std::fs;
use std::path::{Path, PathBuf};

use thiserror::Error;
use tonic::transport::{Certificate, ClientTlsConfig, Identity};

use crate::config::ServerSection;

/// Maximum allowed permission bits on a private-key file on Unix.
///
/// Owner read/write only; any group or world bit set → reject.
#[cfg(unix)]
pub const MAX_KEY_MODE: u32 = 0o600;

/// Errors emitted by mTLS material loading.
#[derive(Debug, Error)]
pub enum MtlsError {
    #[error("io reading {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "private key {path} has insecure permissions: mode 0{mode:o} \
         (max allowed 0{max:o}); run `chmod 0600 {path}`"
    )]
    InsecureKeyPerms { path: PathBuf, mode: u32, max: u32 },

    #[error("invalid PEM in {path}: {reason}")]
    InvalidPem { path: PathBuf, reason: String },
}

/// Audit Unix mode bits on a private-key file.
///
/// Returns `Ok` when mode bits AND'd with the world+group mask (`0o077`)
/// are zero — i.e. no permission is granted to anyone but the owner.
/// On non-Unix targets returns `Ok` unconditionally.
pub fn audit_key_permissions(path: &Path) -> Result<(), MtlsError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::metadata(path).map_err(|e| MtlsError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        let mode = meta.mode() & 0o777;
        if mode & !MAX_KEY_MODE != 0 {
            return Err(MtlsError::InsecureKeyPerms {
                path: path.to_path_buf(),
                mode,
                max: MAX_KEY_MODE,
            });
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        // Existence still required.
        fs::metadata(path).map_err(|e| MtlsError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        Ok(())
    }
}

fn read_pem(path: &Path) -> Result<Vec<u8>, MtlsError> {
    fs::read(path).map_err(|e| MtlsError::Io {
        path: path.to_path_buf(),
        source: e,
    })
}

fn sanity_check_pem(path: &Path, bytes: &[u8], expected_tag: &str) -> Result<(), MtlsError> {
    let text = std::str::from_utf8(bytes).map_err(|e| MtlsError::InvalidPem {
        path: path.to_path_buf(),
        reason: format!("not valid UTF-8: {e}"),
    })?;
    let needle = format!("-----BEGIN {expected_tag}");
    if !text.contains(&needle) {
        return Err(MtlsError::InvalidPem {
            path: path.to_path_buf(),
            reason: format!("no `BEGIN {expected_tag}` block found"),
        });
    }
    Ok(())
}

/// Load a client cert + private key as a tonic [`Identity`].
///
/// Audits the key file's permission bits before reading (Unix only).
/// PEM files are sanity-checked for the expected block tag — any
/// other parse failure is deferred to tonic / rustls at handshake.
pub fn load_client_identity(cert_path: &Path, key_path: &Path) -> Result<Identity, MtlsError> {
    audit_key_permissions(key_path)?;
    let cert_pem = read_pem(cert_path)?;
    sanity_check_pem(cert_path, &cert_pem, "CERTIFICATE")?;
    let key_pem = read_pem(key_path)?;
    // rustls accepts PRIVATE KEY / EC PRIVATE KEY / RSA PRIVATE KEY blocks.
    // Sanity-check for any PRIVATE KEY tag without binding to a specific algo.
    let key_text = std::str::from_utf8(&key_pem).map_err(|e| MtlsError::InvalidPem {
        path: key_path.to_path_buf(),
        reason: format!("not valid UTF-8: {e}"),
    })?;
    if !key_text.contains("PRIVATE KEY-----") {
        return Err(MtlsError::InvalidPem {
            path: key_path.to_path_buf(),
            reason: "no `BEGIN ... PRIVATE KEY` block found".into(),
        });
    }
    Ok(Identity::from_pem(cert_pem, key_pem))
}

/// Load the server CA bundle as a tonic [`Certificate`].
pub fn load_server_ca(ca_path: &Path) -> Result<Certificate, MtlsError> {
    let ca_pem = read_pem(ca_path)?;
    sanity_check_pem(ca_path, &ca_pem, "CERTIFICATE")?;
    Ok(Certificate::from_pem(ca_pem))
}

/// Build a [`ClientTlsConfig`] from the parsed `[server]` section.
///
/// Strategy:
/// - Always attach a client `Identity` (mTLS — disk-server requires it).
/// - When `tls == "auto"` and `server_ca` is unset, rely on the system
///   trust store (tonic default); operator override happens by setting
///   `server_ca` regardless of `tls` mode.
/// - When `server_ca` is supplied, pin to it (CA-pinning for self-signed
///   PROD certs and dev / IT environments).
///
/// Domain-name binding is left to the caller (constructed from the URL
/// scheme and host extracted from `server.address`) so this helper stays
/// pure with respect to URL parsing.
pub fn build_client_tls_config(server: &ServerSection) -> Result<ClientTlsConfig, MtlsError> {
    let identity = load_client_identity(&server.client_cert, &server.client_key)?;
    let mut cfg = ClientTlsConfig::new().identity(identity);
    if let Some(ca_path) = server.server_ca.as_deref() {
        let ca = load_server_ca(ca_path)?;
        cfg = cfg.ca_certificate(ca);
    }
    Ok(cfg)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    fn write_with_mode(dir: &Path, name: &str, contents: &[u8], mode: u32) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, contents).unwrap();
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(mode);
        fs::set_permissions(&path, perms).unwrap();
        path
    }

    fn ephemeral_cert_pair() -> (String, String) {
        let bundle = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        (bundle.cert.pem(), bundle.key_pair.serialize_pem())
    }

    #[test]
    fn audit_accepts_mode_0600() {
        let dir = tempdir().unwrap();
        let key = write_with_mode(dir.path(), "k", b"x", 0o600);
        audit_key_permissions(&key).expect("0600 must pass");
    }

    #[test]
    fn audit_accepts_mode_0400() {
        let dir = tempdir().unwrap();
        let key = write_with_mode(dir.path(), "k", b"x", 0o400);
        audit_key_permissions(&key).expect("0400 must pass");
    }

    #[test]
    fn audit_rejects_mode_0644() {
        let dir = tempdir().unwrap();
        let key = write_with_mode(dir.path(), "k", b"x", 0o644);
        let err = audit_key_permissions(&key).unwrap_err();
        match err {
            MtlsError::InsecureKeyPerms { mode, .. } => assert_eq!(mode, 0o644),
            other => panic!("expected InsecureKeyPerms, got {other:?}"),
        }
    }

    #[test]
    fn audit_rejects_mode_0640() {
        let dir = tempdir().unwrap();
        let key = write_with_mode(dir.path(), "k", b"x", 0o640);
        assert!(matches!(
            audit_key_permissions(&key),
            Err(MtlsError::InsecureKeyPerms { .. })
        ));
    }

    #[test]
    fn audit_rejects_mode_0666() {
        let dir = tempdir().unwrap();
        let key = write_with_mode(dir.path(), "k", b"x", 0o666);
        assert!(matches!(
            audit_key_permissions(&key),
            Err(MtlsError::InsecureKeyPerms { .. })
        ));
    }

    #[test]
    fn audit_reports_missing_file() {
        let dir = tempdir().unwrap();
        let key = dir.path().join("nope");
        match audit_key_permissions(&key).unwrap_err() {
            MtlsError::Io { .. } => {}
            other => panic!("expected Io, got {other:?}"),
        }
    }

    #[test]
    fn load_identity_round_trip_at_0600() {
        let dir = tempdir().unwrap();
        let (cert_pem, key_pem) = ephemeral_cert_pair();
        let cert = write_with_mode(dir.path(), "client.crt", cert_pem.as_bytes(), 0o644);
        let key = write_with_mode(dir.path(), "client.key", key_pem.as_bytes(), 0o600);
        let _identity = load_client_identity(&cert, &key).expect("must load");
    }

    #[test]
    fn load_identity_rejects_loose_key_perms() {
        let dir = tempdir().unwrap();
        let (cert_pem, key_pem) = ephemeral_cert_pair();
        let cert = write_with_mode(dir.path(), "client.crt", cert_pem.as_bytes(), 0o644);
        let key = write_with_mode(dir.path(), "client.key", key_pem.as_bytes(), 0o644);
        let err = load_client_identity(&cert, &key).unwrap_err();
        assert!(matches!(err, MtlsError::InsecureKeyPerms { .. }));
    }

    #[test]
    fn load_identity_rejects_missing_pem_blocks() {
        let dir = tempdir().unwrap();
        let cert = write_with_mode(dir.path(), "c", b"not pem at all", 0o644);
        let key = write_with_mode(dir.path(), "k", b"not pem either", 0o600);
        let err = load_client_identity(&cert, &key).unwrap_err();
        assert!(matches!(err, MtlsError::InvalidPem { .. }));
    }

    #[test]
    fn load_server_ca_reads_pem_block() {
        let dir = tempdir().unwrap();
        let (cert_pem, _) = ephemeral_cert_pair();
        let ca = write_with_mode(dir.path(), "ca.crt", cert_pem.as_bytes(), 0o644);
        let _cert = load_server_ca(&ca).expect("CA must parse");
    }

    #[test]
    fn build_tls_config_round_trip_with_ca_pin() {
        let dir = tempdir().unwrap();
        let (cert_pem, key_pem) = ephemeral_cert_pair();
        let cert = write_with_mode(dir.path(), "client.crt", cert_pem.as_bytes(), 0o644);
        let key = write_with_mode(dir.path(), "client.key", key_pem.as_bytes(), 0o600);
        let (ca_pem, _) = ephemeral_cert_pair();
        let ca = write_with_mode(dir.path(), "ca.crt", ca_pem.as_bytes(), 0o644);

        let server = ServerSection {
            address: "disk.local:9443".to_string(),
            tls: "manual".to_string(),
            client_cert: cert,
            client_key: key,
            server_ca: Some(ca),
        };
        let _ = build_client_tls_config(&server).expect("must build");
    }

    #[test]
    fn build_tls_config_round_trip_without_ca_pin() {
        let dir = tempdir().unwrap();
        let (cert_pem, key_pem) = ephemeral_cert_pair();
        let cert = write_with_mode(dir.path(), "client.crt", cert_pem.as_bytes(), 0o644);
        let key = write_with_mode(dir.path(), "client.key", key_pem.as_bytes(), 0o600);

        let server = ServerSection {
            address: "disk.local:9443".to_string(),
            tls: "auto".to_string(),
            client_cert: cert,
            client_key: key,
            server_ca: None,
        };
        let _ = build_client_tls_config(&server).expect("must build");
    }
}
