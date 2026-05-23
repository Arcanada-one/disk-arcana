//! Server configuration loaded from environment variables.
//!
//! DISK-0006 R1 — production server bootstrap. Earlier rounds had no `main.rs`
//! consumer; tests built bootstrap inline. This module is the single source of
//! truth for runtime parameters the binary needs.
//!
//! ### Required environment variables
//!
//! | Variable | Purpose |
//! |---|---|
//! | `DISK_BIND_ADDR` | gRPC bind address, e.g. `0.0.0.0:9443`. Default `127.0.0.1:9443`. |
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
//! | `DISK_USE_STUB_CA=1` | Force `StubCaClient` instead of `HttpCaClient::from_env`. |
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
    pub db_path: PathBuf,
    pub sync_root: PathBuf,
    pub tls_cert_path: PathBuf,
    pub tls_key_path: PathBuf,
    pub tls_ca_path: PathBuf,
    pub acl_yaml_path: PathBuf,
    pub ops_bot_url: Option<String>,
    pub admin_token: Option<String>,
    pub use_stub_ca: bool,
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

        Ok(Self {
            bind_addr,
            db_path: require_path("DISK_DB_PATH")?,
            sync_root: require_path("DISK_SYNC_ROOT")?,
            tls_cert_path: require_path("DISK_TLS_CERT_PATH")?,
            tls_key_path: require_path("DISK_TLS_KEY_PATH")?,
            tls_ca_path: require_path("DISK_TLS_CA_PATH")?,
            acl_yaml_path: require_path("DISK_ACL_YAML_PATH")?,
            ops_bot_url: std::env::var("OPS_BOT_URL").ok().filter(|s| !s.is_empty()),
            admin_token: std::env::var("DISK_ADMIN_TOKEN")
                .ok()
                .filter(|s| !s.is_empty()),
            use_stub_ca: std::env::var("DISK_USE_STUB_CA").ok().as_deref() == Some("1"),
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
            "DISK_DB_PATH",
            "DISK_SYNC_ROOT",
            "DISK_TLS_CERT_PATH",
            "DISK_TLS_KEY_PATH",
            "DISK_TLS_CA_PATH",
            "DISK_ACL_YAML_PATH",
            "DISK_ADMIN_TOKEN",
            "DISK_USE_STUB_CA",
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
    }
}
