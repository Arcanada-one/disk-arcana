//! Canonical certificate fingerprint for `node_certs` storage.
//!
//! Uses blake3(DER) — the same algorithm as [`CertIdentity::from_der`] so an
//! mTLS peer certificate matches enrollment rows after DER extraction from CA PEM.

use thiserror::Error;

/// Errors parsing PEM for fingerprint extraction.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum FingerprintError {
    #[error("invalid PEM: {0}")]
    PemParse(String),
}

/// Fingerprint of DER-encoded certificate bytes (`blake3(DER)`).
pub fn fingerprint_der(der: &[u8]) -> [u8; 32] {
    *blake3::hash(der).as_bytes()
}

/// Fingerprint from a PEM certificate block returned by the CA during `Enroll`.
pub fn fingerprint_from_pem(pem_bytes: &[u8]) -> Result<[u8; 32], FingerprintError> {
    let pem = pem::parse(pem_bytes).map_err(|e| FingerprintError::PemParse(e.to_string()))?;
    Ok(fingerprint_der(&pem.into_contents()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_and_pem_fingerprints_match() {
        let der = vec![0x30, 0x82, 0x01, 0x00, 0x42];
        let pem = pem::encode(&pem::Pem::new("CERTIFICATE", der.clone()));
        assert_eq!(
            fingerprint_der(&der),
            fingerprint_from_pem(pem.as_bytes()).unwrap()
        );
    }
}
