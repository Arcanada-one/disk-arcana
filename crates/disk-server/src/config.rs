//! Server configuration loaded from environment variables.
//!
//! ### Required environment variables
//!
//! | Variable | Purpose |
//! |---|---|
//! | `DISK_BIND_ADDR` | gRPC bind address, e.g. `0.0.0.0:9443`. Default `127.0.0.1:9443`. |
//! | `DISK_ENROLLMENT_BIND_ADDR` | TLS-only enrollment public listener address. Default `0.0.0.0:9445`. |
//! | `DISK_DB_PATH` | SQLite database file. Use `:memory:` for ephemeral tests. |
//! | `DISK_SYNC_ROOT` | Filesystem root where SyncService stores artefacts. |
//! | `DISK_TLS_CERT_PATH` | PEM file with server certificate chain. |
//! | `DISK_TLS_KEY_PATH` | PEM file with server private key. |
//! | `DISK_TLS_CA_PATH` | PEM file with CA root that signed client certs. |
//! | `DISK_ACL_YAML_PATH` | Path to signed ACL YAML. |
//!
//! ### Optional environment variables
//!
//! | Variable | Purpose |
//! |---|---|
//! | `OPS_BOT_URL` / `OPS_BOT_KEY` | Forwarder destination. Without `OPS_BOT_KEY` forwarder runs no-op. |
//! | `DISK_ADMIN_TOKEN` | Override for the admin metadata token (enrollment helpers). |
//! | `DISK_USE_STUB_CA=1` | Force `StubCaClient` instead of `HttpCaClient::from_env`. Also implies `DISK_ACL_ALLOW_UNSIGNED`. |
//! | `DISK_ACL_ALLOW_UNSIGNED=1` | Dev/test-only: start with an unsigned ACL (NoopVerifier) when no `DISK_ACL_SIG_PATH` is set, WITHOUT forcing the stub CA. Production MUST leave unset. |
//! | `DISK_ACL_SIG_PATH` | Path to the detached `.asc` GPG signature for the ACL YAML (production). When absent and neither `DISK_ACL_ALLOW_UNSIGNED` nor `DISK_USE_STUB_CA` is `1`, the binary panics (fail-closed). |
//! | `DISK_ACL_GNUPGHOME` | Override `GNUPGHOME` for the GPG verifier. |
//! | `DISK_HEALTH_BIND_ADDR` | HTTP health listener bind address. Default `0.0.0.0:9446`. |
//!
//! Missing required vars surface as `ConfigError::MissingEnv` so the binary
//! refuses to start (fail-closed per Appendix A).

use std::net::SocketAddr;
use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("missing required env var: {0}")]
    MissingEnv(&'static str),

    #[error("invalid value for {0}: {1}")]
    InvalidValue(&'static str, String),
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub bind_addr: SocketAddr,
    pub enrollment_bind_addr: SocketAddr,
    pub db_path: PathBuf,
    pub sync_root: PathBuf,
    pub tls_cert_path: PathBuf,
    pub tls_key_path: PathBuf,
    pub tls_ca_path: PathBuf,
    pub acl_yaml_path: PathBuf,
    /// Path to detached `.asc` GPG signature for the ACL YAML. `None` only
    /// when `DISK_USE_STUB_CA=1` (dev/test mode); production must set this.
    pub acl_sig_path: Option<PathBuf>,
    /// Optional GNUPGHOME override passed to the GPG verifier subprocess.
    pub acl_gnupghome: Option<PathBuf>,
    /// HTTP health listener (plain HTTP, proxied via Cloudflare). Default `0.0.0.0:9446`.
    pub health_bind_addr: SocketAddr,
    pub ops_bot_url: Option<String>,
    pub admin_token: Option<String>,
    pub use_stub_ca: bool,
    /// Allow the server to start with an unsigned ACL (NoopVerifier) when no
    /// `DISK_ACL_SIG_PATH` is set. Dev/test-only escape hatch, orthogonal to
    /// the CA client choice: `DISK_ACL_ALLOW_UNSIGNED=1` lets a test exercise
    /// the real `HttpCaClient` path while still skipping ACL signature
    /// verification. Implied by `use_stub_ca` for backward compatibility.
    /// Production MUST leave this unset and provide `DISK_ACL_SIG_PATH`.
    pub acl_allow_unsigned: bool,
}

impl ServerConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        let bind_addr_raw =
            std::env::var("DISK_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:9443".to_string());
        let bind_addr: SocketAddr =
            bind_addr_raw
                .parse()
                .map_err(|e: std::net::AddrParseError| {
                    ConfigError::InvalidValue("DISK_BIND_ADDR", e.to_string())
                })?;

        let health_bind_raw =
            std::env::var("DISK_HEALTH_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:9446".to_string());
        let health_bind_addr: SocketAddr =
            health_bind_raw
                .parse()
                .map_err(|e: std::net::AddrParseError| {
                    ConfigError::InvalidValue("DISK_HEALTH_BIND_ADDR", e.to_string())
                })?;

        let enrollment_bind_addr_raw = std::env::var("DISK_ENROLLMENT_BIND_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:9445".to_string());
        let enrollment_bind_addr: SocketAddr =
            enrollment_bind_addr_raw
                .parse()
                .map_err(|e: std::net::AddrParseError| {
                    ConfigError::InvalidValue("DISK_ENROLLMENT_BIND_ADDR", e.to_string())
                })?;

        Ok(Self {
            bind_addr,
            enrollment_bind_addr,
            db_path: require_path("DISK_DB_PATH")?,
            sync_root: require_path("DISK_SYNC_ROOT")?,
            tls_cert_path: require_path("DISK_TLS_CERT_PATH")?,
            tls_key_path: require_path("DISK_TLS_KEY_PATH")?,
            tls_ca_path: require_path("DISK_TLS_CA_PATH")?,
            acl_yaml_path: require_path("DISK_ACL_YAML_PATH")?,
            acl_sig_path: opt_path("DISK_ACL_SIG_PATH"),
            acl_gnupghome: opt_path("DISK_ACL_GNUPGHOME"),
            health_bind_addr,
            ops_bot_url: std::env::var("OPS_BOT_URL").ok().filter(|s| !s.is_empty()),
            admin_token: std::env::var("DISK_ADMIN_TOKEN")
                .ok()
                .filter(|s| !s.is_empty()),
            use_stub_ca: std::env::var("DISK_USE_STUB_CA").ok().as_deref() == Some("1"),
            // `use_stub_ca` implies allow-unsigned for backward compatibility
            // (existing dev harnesses set only DISK_USE_STUB_CA); the dedicated
            // DISK_ACL_ALLOW_UNSIGNED flag lets a real-CA test skip ACL signing
            // without forcing the stub CA client.
            acl_allow_unsigned: std::env::var("DISK_USE_STUB_CA").ok().as_deref() == Some("1")
                || std::env::var("DISK_ACL_ALLOW_UNSIGNED").ok().as_deref() == Some("1"),
        })
    }
}

fn require_path(var: &'static str) -> Result<PathBuf, ConfigError> {
    let raw = std::env::var(var).map_err(|_| ConfigError::MissingEnv(var))?;
    if raw.is_empty() {
        return Err(ConfigError::MissingEnv(var));
    }
    Ok(PathBuf::from(raw))
}

fn opt_path(var: &'static str) -> Option<PathBuf> {
    std::env::var(var)
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Process-global lock — these tests mutate `std::env` which is shared
    /// across the test binary's threads. Without this, cargo's parallel test
    /// runner produces flaky failures (one test's DISK_BIND_ADDR override
    /// leaks into another's `clear_env` window).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Helper: clear all DISK_* env vars + OPS_BOT_* to isolate the test.
    fn clear_env() {
        for v in [
            "DISK_BIND_ADDR",
            "DISK_ENROLLMENT_BIND_ADDR",
            "DISK_DB_PATH",
            "DISK_SYNC_ROOT",
            "DISK_TLS_CERT_PATH",
            "DISK_TLS_KEY_PATH",
            "DISK_TLS_CA_PATH",
            "DISK_ACL_YAML_PATH",
            "DISK_ACL_SIG_PATH",
            "DISK_ACL_GNUPGHOME",
            "DISK_HEALTH_BIND_ADDR",
            "DISK_ADMIN_TOKEN",
            "DISK_USE_STUB_CA",
            "DISK_ACL_ALLOW_UNSIGNED",
            "OPS_BOT_URL",
        ] {
            std::env::remove_var(v);
        }
    }

    fn set_required() {
        std::env::set_var("DISK_DB_PATH", "/tmp/d.db");
        std::env::set_var("DISK_SYNC_ROOT", "/tmp/sync");
        std::env::set_var("DISK_TLS_CERT_PATH", "/tmp/cert.pem");
        std::env::set_var("DISK_TLS_KEY_PATH", "/tmp/key.pem");
        std::env::set_var("DISK_TLS_CA_PATH", "/tmp/ca.pem");
        std::env::set_var("DISK_ACL_YAML_PATH", "/tmp/acl.yaml");
    }

    /// NOTE: these tests mutate process env, so they MUST run serially. The
    /// cargo test runner already serialises tests within one binary by default
    /// for unit tests in `#[cfg(test)]` modules of a single file.
    #[test]
    fn missing_db_path_fails() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_env();
        let err = ServerConfig::from_env().unwrap_err();
        match err {
            ConfigError::MissingEnv(v) => assert_eq!(v, "DISK_DB_PATH"),
            other => panic!("expected MissingEnv(DISK_DB_PATH), got {other:?}"),
        }
    }

    #[test]
    fn invalid_bind_addr_fails() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_env();
        set_required();
        std::env::set_var("DISK_BIND_ADDR", "not-a-socket");
        let err = ServerConfig::from_env().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::InvalidValue("DISK_BIND_ADDR", _)
        ));
    }

    #[test]
    fn happy_path_with_optional_unset() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_env();
        set_required();
        std::env::set_var("DISK_BIND_ADDR", "127.0.0.1:0");
        let cfg = ServerConfig::from_env().unwrap();
        assert_eq!(cfg.bind_addr.to_string(), "127.0.0.1:0");
        assert_eq!(cfg.db_path, PathBuf::from("/tmp/d.db"));
        assert!(cfg.ops_bot_url.is_none());
        assert!(cfg.admin_token.is_none());
        assert!(!cfg.use_stub_ca);
        // Fail-closed default: neither stub CA nor allow-unsigned without flags.
        assert!(!cfg.acl_allow_unsigned);
        assert!(cfg.acl_sig_path.is_none());
        assert!(cfg.acl_gnupghome.is_none());
        // Default health bind addr
        assert_eq!(cfg.health_bind_addr.to_string(), "0.0.0.0:9446");
    }

    #[test]
    fn acl_allow_unsigned_explicit_flag() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_env();
        set_required();
        std::env::set_var("DISK_ACL_ALLOW_UNSIGNED", "1");
        let cfg = ServerConfig::from_env().unwrap();
        // The dedicated flag allows unsigned ACL WITHOUT forcing the stub CA.
        assert!(cfg.acl_allow_unsigned);
        assert!(!cfg.use_stub_ca);
    }

    #[test]
    fn acl_allow_unsigned_implied_by_stub_ca() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_env();
        set_required();
        std::env::set_var("DISK_USE_STUB_CA", "1");
        let cfg = ServerConfig::from_env().unwrap();
        // Backward compatibility: stub CA implies allow-unsigned.
        assert!(cfg.use_stub_ca);
        assert!(cfg.acl_allow_unsigned);
    }

    #[test]
    fn acl_allow_unsigned_off_by_default() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_env();
        set_required();
        let cfg = ServerConfig::from_env().unwrap();
        assert!(!cfg.acl_allow_unsigned);
    }

    #[test]
    fn verifier_wiring_produces_verifier() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_env();
        set_required();
        std::env::set_var("DISK_BIND_ADDR", "127.0.0.1:0");
        std::env::set_var("DISK_ACL_SIG_PATH", "/tmp/disk-acl.yaml.asc");
        std::env::set_var("DISK_ACL_GNUPGHOME", "/etc/disk-arcana/gpg");
        let cfg = ServerConfig::from_env().unwrap();
        assert_eq!(
            cfg.acl_sig_path,
            Some(PathBuf::from("/tmp/disk-acl.yaml.asc"))
        );
        assert_eq!(
            cfg.acl_gnupghome,
            Some(PathBuf::from("/etc/disk-arcana/gpg"))
        );
    }

    #[test]
    fn health_bind_addr_custom() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_env();
        set_required();
        std::env::set_var("DISK_BIND_ADDR", "127.0.0.1:0");
        std::env::set_var("DISK_HEALTH_BIND_ADDR", "127.0.0.1:19446");
        let cfg = ServerConfig::from_env().unwrap();
        assert_eq!(cfg.health_bind_addr.to_string(), "127.0.0.1:19446");
    }

    #[test]
    fn invalid_health_bind_addr_fails() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_env();
        set_required();
        std::env::set_var("DISK_BIND_ADDR", "127.0.0.1:0");
        std::env::set_var("DISK_HEALTH_BIND_ADDR", "not-a-socket");
        let err = ServerConfig::from_env().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::InvalidValue("DISK_HEALTH_BIND_ADDR", _)
        ));
    }

    #[test]
    fn invalid_enrollment_bind_addr_fails() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_env();
        set_required();
        std::env::set_var("DISK_ENROLLMENT_BIND_ADDR", "not-a-socket");
        let err = ServerConfig::from_env().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::InvalidValue("DISK_ENROLLMENT_BIND_ADDR", _)
        ));
    }

    #[test]
    fn enrollment_bind_addr_defaults_to_9445() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_env();
        set_required();
        let cfg = ServerConfig::from_env().unwrap();
        assert_eq!(cfg.enrollment_bind_addr.port(), 9445);
        assert!(cfg.enrollment_bind_addr.ip().is_unspecified());
    }

    #[test]
    fn enrollment_bind_addr_override_applied() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_env();
        set_required();
        std::env::set_var("DISK_ENROLLMENT_BIND_ADDR", "127.0.0.1:7777");
        let cfg = ServerConfig::from_env().unwrap();
        assert_eq!(cfg.enrollment_bind_addr.to_string(), "127.0.0.1:7777");
    }
}
