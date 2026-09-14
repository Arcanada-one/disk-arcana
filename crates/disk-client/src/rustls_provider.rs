//! Process-wide rustls `CryptoProvider` selection (DISK-0074).
//!
//! The workspace links both `ring` (tonic/reqwest) and `aws-lc-rs` (aws-sdk-s3).
//! rustls 0.23 requires an explicit provider when both features are present.

use std::sync::Once;

static INSTALL: Once = Once::new();

/// Install the ring-backed rustls provider once per process.
pub fn ensure_rustls_crypto_provider() {
    INSTALL.call_once(|| {
        use rustls::crypto::CryptoProvider;
        if CryptoProvider::get_default().is_none() {
            rustls::crypto::ring::default_provider()
                .install_default()
                .expect("install rustls ring CryptoProvider");
        }
    });
}
