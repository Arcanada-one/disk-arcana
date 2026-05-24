//! OS-keychain abstraction for client-side private key storage (DISK-0006 R4).
//!
//! PRD-DISK-0001 §4.11.3 (closing paragraph): «key in OS keychain when
//! available else 0600 file». R4 ships two [`KeyStore`] implementations
//! and a `detect` constructor that picks the best one for the host:
//!
//! - [`OsKeyStore`] — backed by the [`keyring`] crate, which routes to
//!   macOS Keychain, Linux Secret-Service / GNOME Keyring, or Windows
//!   Credential Manager depending on platform. Failures (no daemon
//!   running, missing service entry) surface as
//!   [`KeyStoreError::Backend`] and the caller MAY fall back to the
//!   file store.
//!
//! - [`FileKeyStore`] — writes a PEM file at `<dir>/<label>.key` with
//!   mode `0600`. Loader-side reads re-audit permissions via
//!   [`crate::mtls::audit_key_permissions`] so a later world-readable
//!   `chmod` is caught before the bytes are exposed.
//!
//! The trait is intentionally synchronous: every backend's underlying
//! call is a single blocking syscall + a small JSON / Keychain RPC, well
//! below the threshold where async indirection pays off.

use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::mtls::{audit_key_permissions, MtlsError};

/// Default service name used by [`OsKeyStore::new_default`].
pub const DEFAULT_OS_KEYRING_SERVICE: &str = "disk-arcana";

/// Errors emitted by [`KeyStore`] implementations.
#[derive(Debug, Error)]
pub enum KeyStoreError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("key permission audit failed: {0}")]
    PermAudit(#[from] MtlsError),

    #[error("OS keychain backend: {0}")]
    Backend(#[from] keyring::Error),

    #[error("invalid label {0:?}: must match /^[a-z0-9][a-z0-9._-]{{0,127}}$/")]
    InvalidLabel(String),
}

/// Synchronous key-material store.
///
/// `label` MUST match `^[a-z0-9][a-z0-9._-]{0,127}$` — this rules out
/// path-traversal segments and shell-metacharacter mishaps regardless
/// of backend (file naming on the filesystem side, service-account
/// naming on the OS-keychain side).
pub trait KeyStore: Send + Sync {
    /// Persist a PEM-encoded key under `label`.
    fn store(&self, label: &str, pem: &str) -> Result<(), KeyStoreError>;

    /// Retrieve the PEM bytes previously stored under `label`.
    /// Returns `Ok(None)` when the label is unknown.
    fn load(&self, label: &str) -> Result<Option<String>, KeyStoreError>;

    /// Remove a label. Missing labels are not an error (idempotent).
    fn delete(&self, label: &str) -> Result<(), KeyStoreError>;
}

/// Reject labels that contain path / shell metacharacters or are empty.
pub fn validate_label(label: &str) -> Result<(), KeyStoreError> {
    if label.is_empty() || label.len() > 128 {
        return Err(KeyStoreError::InvalidLabel(label.to_owned()));
    }
    let mut chars = label.chars();
    let first = chars.next().unwrap();
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return Err(KeyStoreError::InvalidLabel(label.to_owned()));
    }
    for c in label.chars() {
        let ok = c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '_' || c == '-';
        if !ok {
            return Err(KeyStoreError::InvalidLabel(label.to_owned()));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// FileKeyStore
// ---------------------------------------------------------------------------

/// On-disk PEM store rooted at `dir`. Files are written `0600` on Unix.
pub struct FileKeyStore {
    dir: PathBuf,
}

impl FileKeyStore {
    /// Construct a new file-backed store. The directory is created if
    /// missing; permissions are not adjusted (callers control the parent).
    pub fn new(dir: PathBuf) -> Result<Self, KeyStoreError> {
        if !dir.exists() {
            std::fs::create_dir_all(&dir)?;
        }
        Ok(Self { dir })
    }

    fn path_for(&self, label: &str) -> PathBuf {
        self.dir.join(format!("{label}.key"))
    }
}

impl KeyStore for FileKeyStore {
    fn store(&self, label: &str, pem: &str) -> Result<(), KeyStoreError> {
        validate_label(label)?;
        let path = self.path_for(label);
        write_pem_0600(&path, pem)?;
        Ok(())
    }

    fn load(&self, label: &str) -> Result<Option<String>, KeyStoreError> {
        validate_label(label)?;
        let path = self.path_for(label);
        if !path.exists() {
            return Ok(None);
        }
        audit_key_permissions(&path)?;
        let bytes = std::fs::read(&path)?;
        let text = String::from_utf8(bytes).map_err(|e| {
            KeyStoreError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })?;
        Ok(Some(text))
    }

    fn delete(&self, label: &str) -> Result<(), KeyStoreError> {
        validate_label(label)?;
        let path = self.path_for(label);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(unix)]
fn write_pem_0600(path: &Path, pem: &str) -> Result<(), KeyStoreError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(pem.as_bytes())?;
    Ok(())
}

#[cfg(not(unix))]
fn write_pem_0600(path: &Path, pem: &str) -> Result<(), KeyStoreError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(path, pem.as_bytes())?;
    Ok(())
}

// ---------------------------------------------------------------------------
// OsKeyStore
// ---------------------------------------------------------------------------

/// OS-keychain-backed key store.
///
/// `service` is the keyring service identifier (`disk-arcana` by
/// default). The `label` argument becomes the username/account field
/// in the underlying keyring entry — callers MUST treat labels as
/// stable identifiers (e.g. node id) across runs.
pub struct OsKeyStore {
    service: String,
}

impl OsKeyStore {
    /// Construct with an explicit service name.
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    /// Construct with the [`DEFAULT_OS_KEYRING_SERVICE`] name.
    pub fn new_default() -> Self {
        Self::new(DEFAULT_OS_KEYRING_SERVICE)
    }

    fn entry(&self, label: &str) -> Result<keyring::Entry, KeyStoreError> {
        validate_label(label)?;
        Ok(keyring::Entry::new(&self.service, label)?)
    }
}

impl KeyStore for OsKeyStore {
    fn store(&self, label: &str, pem: &str) -> Result<(), KeyStoreError> {
        let entry = self.entry(label)?;
        entry.set_password(pem)?;
        Ok(())
    }

    fn load(&self, label: &str) -> Result<Option<String>, KeyStoreError> {
        let entry = self.entry(label)?;
        match entry.get_password() {
            Ok(pem) => Ok(Some(pem)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn delete(&self, label: &str) -> Result<(), KeyStoreError> {
        let entry = self.entry(label)?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

/// Try to construct an [`OsKeyStore`]; on failure, fall back to
/// [`FileKeyStore`] rooted at `fallback_dir`.
///
/// The probe is a no-op store/load round-trip on a synthetic label
/// (`__probe__`) — if either call fails (e.g. no Secret Service daemon
/// running on a headless Linux box), we treat the OS keychain as
/// unavailable and return the file store instead. The probe label is
/// cleaned up best-effort.
pub fn detect_or_file(
    service: &str,
    fallback_dir: PathBuf,
) -> Result<Box<dyn KeyStore>, KeyStoreError> {
    let os = OsKeyStore::new(service);
    if probe_os_keystore(&os).is_ok() {
        Ok(Box::new(os))
    } else {
        Ok(Box::new(FileKeyStore::new(fallback_dir)?))
    }
}

fn probe_os_keystore(os: &OsKeyStore) -> Result<(), KeyStoreError> {
    const PROBE_LABEL: &str = "__probe__";
    const PROBE_VALUE: &str = "ok";
    os.store(PROBE_LABEL, PROBE_VALUE)?;
    let got = os.load(PROBE_LABEL)?;
    let _ = os.delete(PROBE_LABEL);
    match got.as_deref() {
        Some(PROBE_VALUE) => Ok(()),
        _ => Err(KeyStoreError::Backend(keyring::Error::NoEntry)),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn keystore_dir() -> (tempfile::TempDir, FileKeyStore) {
        let tmp = tempdir().unwrap();
        let ks = FileKeyStore::new(tmp.path().join("keys")).unwrap();
        (tmp, ks)
    }

    #[test]
    fn validate_label_accepts_valid() {
        validate_label("arcana-ai").unwrap();
        validate_label("node.01").unwrap();
        validate_label("a").unwrap();
        validate_label("0node").unwrap();
    }

    #[test]
    fn validate_label_rejects_path_traversal() {
        assert!(validate_label("../etc/passwd").is_err());
        assert!(validate_label("a/b").is_err());
        assert!(validate_label("a\\b").is_err());
        assert!(validate_label("a b").is_err());
        assert!(validate_label("a;rm -rf /").is_err());
        assert!(validate_label("").is_err());
        assert!(validate_label("ABC").is_err());
    }

    #[test]
    fn validate_label_rejects_too_long() {
        let too_long = "a".repeat(129);
        assert!(validate_label(&too_long).is_err());
    }

    #[test]
    fn file_store_round_trip() {
        let (_tmp, ks) = keystore_dir();
        ks.store(
            "nodea",
            "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----",
        )
        .unwrap();
        let loaded = ks.load("nodea").unwrap().expect("must exist");
        assert!(loaded.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn file_store_load_missing_returns_none() {
        let (_tmp, ks) = keystore_dir();
        assert!(ks.load("ghost").unwrap().is_none());
    }

    #[test]
    fn file_store_delete_is_idempotent() {
        let (_tmp, ks) = keystore_dir();
        ks.delete("ghost").unwrap();
        ks.store("real", "pem").unwrap();
        ks.delete("real").unwrap();
        ks.delete("real").unwrap(); // second delete is a no-op
        assert!(ks.load("real").unwrap().is_none());
    }

    #[test]
    fn file_store_store_rejects_invalid_label() {
        let (_tmp, ks) = keystore_dir();
        assert!(matches!(
            ks.store("../evil", "x"),
            Err(KeyStoreError::InvalidLabel(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn file_store_writes_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let (_tmp, ks) = keystore_dir();
        ks.store("nodea", "pem").unwrap();
        let path = ks.path_for("nodea");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn file_store_load_audits_perms() {
        use std::os::unix::fs::PermissionsExt;
        let (_tmp, ks) = keystore_dir();
        ks.store("nodea", "pem").unwrap();
        let path = ks.path_for("nodea");
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&path, perms).unwrap();
        let err = ks.load("nodea").unwrap_err();
        assert!(matches!(
            err,
            KeyStoreError::PermAudit(MtlsError::InsecureKeyPerms { .. })
        ));
    }

    #[test]
    fn detect_falls_back_when_os_unavailable() {
        // Use a deliberately implausible service name so any persistent
        // keychain still routes through the probe. On a CI box without
        // Secret Service this returns FileKeyStore directly; on a
        // workstation with a working keychain this returns OsKeyStore
        // (still valid — we only assert the call succeeds and returns
        // a usable trait object).
        let tmp = tempdir().unwrap();
        let store = detect_or_file(
            "disk-arcana-test-probe-DISK-0006",
            tmp.path().join("fallback"),
        )
        .unwrap();
        // Sanity round-trip on whichever backend was selected.
        store.store("probe", "pem").unwrap();
        let got = store.load("probe").unwrap();
        assert_eq!(got.as_deref(), Some("pem"));
        store.delete("probe").unwrap();
    }
}
