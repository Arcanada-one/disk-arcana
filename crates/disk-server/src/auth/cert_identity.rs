//! Certificate-based identity extraction (P4a Step 6).
//!
//! When mTLS is enabled, the TLS layer places the peer's client certificate in
//! the tonic request extensions as `rustls::pki_types::CertificateDer<'static>`.
//! This module extracts that certificate, hashes it with blake3 (32-byte
//! output), and returns a `CertIdentity` that the ACL enforcer can look up.
//!
//! `from_request` returns `None` when no peer cert is present (one-way TLS,
//! dev/test environments) allowing callers to fall back to API-key auth.
//!
//! Note: tonic 0.13 + tonic-transport does NOT automatically inject
//! `CertificateDer` into request extensions on the server side.  This module
//! provides the extraction logic; the caller must pass the DER bytes they
//! obtain from the TLS connection state (e.g. via a tonic server interceptor
//! or from the rustls `ServerConnection::peer_certificates()`).
//! For now, `from_der` is the primary entry point; `from_request` is provided
//! as a forward-compatible shim that checks the extension slot.

use rustls::pki_types::CertificateDer;

use crate::acl::CertFingerprint;

/// Identity derived from a peer mTLS client certificate.
///
/// The `fingerprint` is blake3(DER bytes) — 32-byte output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertIdentity {
    pub fingerprint: CertFingerprint,
}

impl CertIdentity {
    /// Derive a `CertIdentity` from raw DER-encoded certificate bytes.
    pub fn from_der(der: &[u8]) -> Self {
        let hash = blake3::hash(der);
        let fp: [u8; 32] = *hash.as_bytes();
        Self { fingerprint: fp }
    }

    /// Extract a `CertIdentity` from a tonic request's extension map.
    ///
    /// Returns `None` when no `CertificateDer` extension is present (i.e.
    /// the connection is one-way TLS or the interceptor has not injected the
    /// peer cert).
    pub fn from_request<T>(req: &tonic::Request<T>) -> Option<Self> {
        req.extensions()
            .get::<CertificateDer<'static>>()
            .map(|der| Self::from_der(der.as_ref()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_cert_der(seed: u8) -> Vec<u8> {
        // Deterministic fake DER bytes for testing.
        vec![seed; 64]
    }

    #[test]
    fn from_der_is_deterministic() {
        let der = sample_cert_der(0x42);
        let a = CertIdentity::from_der(&der);
        let b = CertIdentity::from_der(&der);
        assert_eq!(a.fingerprint, b.fingerprint);
        assert_ne!(a.fingerprint, [0u8; 32]);
    }

    #[test]
    fn different_certs_produce_different_fingerprints() {
        let a = CertIdentity::from_der(&sample_cert_der(0x01));
        let b = CertIdentity::from_der(&sample_cert_der(0x02));
        assert_ne!(a.fingerprint, b.fingerprint);
    }

    #[test]
    fn fingerprint_is_32_bytes() {
        let id = CertIdentity::from_der(&sample_cert_der(0xFF));
        assert_eq!(id.fingerprint.len(), 32);
    }

    #[test]
    fn from_request_returns_none_without_extension() {
        let req = tonic::Request::new(());
        let id = CertIdentity::from_request(&req);
        assert!(id.is_none(), "no cert extension → must return None");
    }

    #[test]
    fn from_request_returns_identity_when_cert_extension_present() {
        use rustls::pki_types::CertificateDer;
        let der_bytes: Vec<u8> = sample_cert_der(0xAA);
        let cert = CertificateDer::from(der_bytes.clone());
        let mut req = tonic::Request::new(());
        req.extensions_mut().insert(cert);
        let id = CertIdentity::from_request(&req).expect("cert extension present → Some");
        let expected = CertIdentity::from_der(&der_bytes);
        assert_eq!(id.fingerprint, expected.fingerprint);
    }
}
