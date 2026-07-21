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
//! | `DISK_CA_MODE` | CA client mode: `http` (default, requires `AUTH_ARCANA_CA_TOKEN`), `stub` (test-only, same as `DISK_USE_STUB_CA=1`), or `offline` (Approach A-a: pre-provisioned leaf certs, enrollment endpoint not used). |
//! | `DISK_USE_STUB_CA=1` | Legacy alias for `DISK_CA_MODE=stub`. Force `StubCaClient`. Also implies `DISK_ACL_ALLOW_UNSIGNED`. |
//! | `DISK_ACL_ALLOW_UNSIGNED=1` | Dev/test-only: start with an unsigned ACL (NoopVerifier) when no `DISK_ACL_SIG_PATH` is set, WITHOUT forcing the stub CA. Production MUST leave unset. |
//! | `DISK_ACL_SIG_PATH` | Path to the detached `.asc` GPG signature for the ACL YAML (production). When absent and neither `DISK_ACL_ALLOW_UNSIGNED` nor `DISK_USE_STUB_CA` is `1`, the binary panics (fail-closed). |
//! | `DISK_ACL_GNUPGHOME` | Override `GNUPGHOME` for the GPG verifier. |
//! | `DISK_HEALTH_BIND_ADDR` | HTTP health listener bind address. Default `0.0.0.0:9446`. |
//! | `DISK_REGISTER_NODE_MODE` | `RegisterNode` gate: `open` (dev), `enrolled` (prod default), `disabled`, or `admin`. |
//!
//! Missing required vars surface as `ConfigError::MissingEnv` so the binary
//! refuses to start (fail-closed per Appendix A).
//!
//! ### `DISK_CA_MODE` values
//!
//! | Value | CA client | Enrollment listener |
//! |---|---|---|
//! | `http` (default) | `HttpCaClient` — calls Auth Arcana CA endpoint | Bound on `DISK_ENROLLMENT_BIND_ADDR` |
//! | `stub` | `StubCaClient` — returns fixed test cert | Bound (returns stub cert) |
//! | `offline` | `OfflineCaClient` — returns `EnrollmentDisabled` error | **Not bound** (Approach A-a: enrollment not needed) |

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

/// CA client selection mode.
///
/// Controlled by `DISK_CA_MODE` env var. The legacy `DISK_USE_STUB_CA=1` flag
/// maps to `Stub` for backward compatibility.
///
/// - `Http` (default): `HttpCaClient` — posts CSR to Auth Arcana CA. Requires
///   `AUTH_ARCANA_CA_TOKEN`. Used when `AUTH-0085` is live.
/// - `Stub`: `StubCaClient` — returns a fixed cert pair. Dev/test only.
/// - `Offline`: `OfflineCaClient` — enrollment endpoint disabled. The
///   enrollment public listener is not bound. Use when leaf certs are
///   pre-provisioned (Approach A-a, DISK-0058).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaMode {
    Http,
    Stub,
    Offline,
}

/// Production gate for `AuthService::RegisterNode`.
///
/// - `Open`: legacy dev/test — no extra checks (in-memory registration only).
/// - `Enrolled` (production default when `DISK_CA_MODE` is not `stub`): peer
///   mTLS cert must match an active `node_certs` row for the requested `node_id`.
/// - `Disabled`: always reject (bootstrap via admin tooling only).
/// - `Admin`: require `x-disk-admin-token` bearer (same as enrollment admin RPCs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterNodeMode {
    Open,
    Enrolled,
    Disabled,
    Admin,
}

impl RegisterNodeMode {
    fn parse(raw: &str) -> Result<Self, ConfigError> {
        match raw.to_ascii_lowercase().as_str() {
            "open" => Ok(Self::Open),
            "enrolled" => Ok(Self::Enrolled),
            "disabled" => Ok(Self::Disabled),
            "admin" => Ok(Self::Admin),
            other => Err(ConfigError::InvalidValue(
                "DISK_REGISTER_NODE_MODE",
                format!("unknown value '{other}'; expected open, enrolled, disabled, or admin"),
            )),
        }
    }
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
    /// CA client mode. Set by `DISK_CA_MODE` env var. `DISK_USE_STUB_CA=1`
    /// is a legacy alias that maps to `CaMode::Stub` and additionally implies
    /// `acl_allow_unsigned`.
    pub ca_mode: CaMode,
    /// Allow the server to start with an unsigned ACL (NoopVerifier) when no
    /// `DISK_ACL_SIG_PATH` is set. Dev/test-only escape hatch, orthogonal to
    /// the CA client choice: `DISK_ACL_ALLOW_UNSIGNED=1` lets a test exercise
    /// the real `HttpCaClient` path while still skipping ACL signature
    /// verification. Implied by `use_stub_ca` for backward compatibility.
    /// Production MUST leave this unset and provide `DISK_ACL_SIG_PATH`.
    pub acl_allow_unsigned: bool,
    /// `RegisterNode` production gate (OWASP T2.10).
    pub register_node_mode: RegisterNodeMode,
    /// Commercial quota enforcement (DISK-0018). Default `disabled` for self-hosted.
    pub billing_mode: crate::billing::BillingMode,
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

        // Parse DISK_CA_MODE. DISK_USE_STUB_CA=1 is a legacy alias for `stub`.
        let use_stub_ca_legacy = std::env::var("DISK_USE_STUB_CA").ok().as_deref() == Some("1");
        let ca_mode = match std::env::var("DISK_CA_MODE")
            .ok()
            .as_deref()
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            None | Some("http") => {
                if use_stub_ca_legacy {
                    CaMode::Stub
                } else {
                    CaMode::Http
                }
            }
            Some("stub") => CaMode::Stub,
            Some("offline") => CaMode::Offline,
            Some(other) => {
                return Err(ConfigError::InvalidValue(
                    "DISK_CA_MODE",
                    format!("unknown value '{other}'; expected http, stub, or offline"),
                ))
            }
        };

        let register_node_mode = match std::env::var("DISK_REGISTER_NODE_MODE").ok().as_deref() {
            None => {
                if ca_mode == CaMode::Stub {
                    RegisterNodeMode::Open
                } else {
                    RegisterNodeMode::Enrolled
                }
            }
            Some(raw) => RegisterNodeMode::parse(raw)?,
        };

        let billing_mode_raw =
            std::env::var("DISK_BILLING_MODE").unwrap_or_else(|_| "disabled".to_string());
        let billing_mode = crate::billing::BillingMode::parse(&billing_mode_raw)?;

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
            use_stub_ca: ca_mode == CaMode::Stub,
            ca_mode,
            // `use_stub_ca` (legacy flag) implies allow-unsigned for backward
            // compatibility. Explicit DISK_CA_MODE=stub does NOT imply it —
            // only the legacy DISK_USE_STUB_CA=1 path does.
            // DISK_CA_MODE=offline does NOT imply allow-unsigned (fail-closed).
            acl_allow_unsigned: use_stub_ca_legacy
                || std::env::var("DISK_ACL_ALLOW_UNSIGNED").ok().as_deref() == Some("1"),
            register_node_mode,
            billing_mode,
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
            "DISK_CA_MODE",
            "DISK_REGISTER_NODE_MODE",
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

    // --- DISK-0058: offline CA mode ---

    #[test]
    fn ca_mode_default_is_http() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_env();
        set_required();
        let cfg = ServerConfig::from_env().unwrap();
        assert_eq!(cfg.ca_mode, CaMode::Http);
        // Backward-compat: use_stub_ca stays false when DISK_CA_MODE not set.
        assert!(!cfg.use_stub_ca);
    }

    #[test]
    fn ca_mode_offline_parsed_without_ca_token() {
        // Core requirement: DISK_CA_MODE=offline must parse successfully even
        // when AUTH_ARCANA_CA_TOKEN is absent. No panic, no CA token required.
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_env();
        set_required();
        std::env::set_var("DISK_CA_MODE", "offline");
        let cfg = ServerConfig::from_env().unwrap();
        assert_eq!(cfg.ca_mode, CaMode::Offline);
        // Offline mode must NOT imply acl_allow_unsigned (fail-closed on ACL).
        assert!(!cfg.acl_allow_unsigned);
        // use_stub_ca stays false in offline mode.
        assert!(!cfg.use_stub_ca);
    }

    #[test]
    fn ca_mode_stub_set_by_disk_use_stub_ca() {
        // Backward compat: DISK_USE_STUB_CA=1 continues to produce CaMode::Stub.
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_env();
        set_required();
        std::env::set_var("DISK_USE_STUB_CA", "1");
        let cfg = ServerConfig::from_env().unwrap();
        assert_eq!(cfg.ca_mode, CaMode::Stub);
        assert!(cfg.use_stub_ca);
        assert!(cfg.acl_allow_unsigned);
    }

    #[test]
    fn ca_mode_stub_set_explicitly_by_disk_ca_mode() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_env();
        set_required();
        std::env::set_var("DISK_CA_MODE", "stub");
        let cfg = ServerConfig::from_env().unwrap();
        assert_eq!(cfg.ca_mode, CaMode::Stub);
        // Explicit stub via DISK_CA_MODE does NOT imply acl_allow_unsigned
        // (only DISK_USE_STUB_CA=1 historically implied it).
        assert!(cfg.use_stub_ca);
    }

    #[test]
    fn ca_mode_invalid_value_fails() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_env();
        set_required();
        std::env::set_var("DISK_CA_MODE", "bogus");
        let err = ServerConfig::from_env().unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidValue("DISK_CA_MODE", _)),
            "expected InvalidValue(DISK_CA_MODE, _), got {err:?}"
        );
    }

    #[test]
    fn register_node_mode_defaults_enrolled_for_http_ca() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_env();
        set_required();
        let cfg = ServerConfig::from_env().unwrap();
        assert_eq!(cfg.register_node_mode, RegisterNodeMode::Enrolled);
    }

    #[test]
    fn register_node_mode_defaults_open_for_stub_ca() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_env();
        set_required();
        std::env::set_var("DISK_USE_STUB_CA", "1");
        let cfg = ServerConfig::from_env().unwrap();
        assert_eq!(cfg.register_node_mode, RegisterNodeMode::Open);
    }

    #[test]
    fn register_node_mode_explicit_override() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_env();
        set_required();
        std::env::set_var("DISK_REGISTER_NODE_MODE", "disabled");
        let cfg = ServerConfig::from_env().unwrap();
        assert_eq!(cfg.register_node_mode, RegisterNodeMode::Disabled);
    }
}
