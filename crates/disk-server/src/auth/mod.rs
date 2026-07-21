//! Authentication service: node registration and API-key → session-token flow.

pub mod api_key;
pub mod cert_identity;
pub mod rate_limit;
pub mod storage;

pub use api_key::{ApiKey, SessionToken};
pub use cert_identity::CertIdentity;
pub use rate_limit::{AuthAttemptLimiter, RateLimitError, SharedAuthAttemptLimiter};
pub use storage::AuthStore;
