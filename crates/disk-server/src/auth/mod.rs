//! Authentication service: node registration and API-key → session-token flow.

pub mod api_key;
pub mod cert_fingerprint;
pub mod cert_identity;
pub mod rate_limit;
pub mod register_gate;
pub mod storage;

pub use api_key::{ApiKey, SessionToken};
pub use cert_fingerprint::{fingerprint_der, fingerprint_from_pem, FingerprintError};
pub use cert_identity::CertIdentity;
pub use rate_limit::{AuthAttemptLimiter, RateLimitError, SharedAuthAttemptLimiter};
pub use register_gate::{check_register_gate, verify_enrolled_register};
pub use storage::AuthStore;
