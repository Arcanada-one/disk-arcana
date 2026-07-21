//! SaaS account HTTP API (DISK-0016).

mod email_verify;
mod email_verify_mode;
mod mode;
mod oauth;
mod oauth_mode;
pub mod routes;

pub use email_verify::{
    deliver_verification, resend_verification, verify_email, EmailVerifyConfig,
    VerificationDelivery,
};
pub use email_verify_mode::EmailVerifyMode;
pub use mode::AuthMode;
pub use oauth::{oauth_callback, oauth_start, OAuthConfig};
pub use oauth_mode::OAuthMode;
