//! TLS certificate providers for `disk-server`.
//!
//! Three providers are supported:
//!
//! - [`DevSelfSignedProvider`] — generates an ephemeral `rcgen` self-signed
//!   certificate at startup.  For development and integration tests **only**.
//! - [`StaticPemProvider`] — loads cert + key from PEM files on disk (operator
//!   override via `disk.toml` `[tls] cert_path / key_path`).
//! - `AcmeProvider` — wraps `rustls-acme`; activated when `disk.toml`
//!   `[tls] mode = "acme"`. **Deferred to DISK-0006** (server daemon); not
//!   instantiated in Phase 3 server.
//!
//! All providers produce a `rustls::ServerConfig` pinned to **TLS 1.3 only**
//! (T-Downgrade mitigation, DISK-0004 § 6).
//!
//! ## mTLS (P4a Step 5)
//!
//! The `with_client_auth` variants require a CA root PEM to be supplied, sourced
//! from the environment variable `DISK_INTERNAL_CA_ROOT_PEM` (path to PEM file).
//! When the env var is absent, the server falls back to one-way TLS (no client
//! cert required); this is the default for dev/test setups. Production
//! deployments MUST set `DISK_INTERNAL_CA_ROOT_PEM` to enable mTLS enforcement
//! and cert-identity extraction in `auth::cert_identity`.

use std::sync::Arc;

use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::ServerConfig;
use thiserror::Error;

/// Errors from TLS provider construction.
#[derive(Debug, Error)]
pub enum TlsError {
    #[error("rcgen certificate generation failed: {0}")]
    RcgenError(#[from] rcgen::Error),

    #[error("rustls config error: {0}")]
    RustlsError(#[from] rustls::Error),

    #[error("PEM parse error: {0}")]
    PemParseError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Common interface for all TLS cert providers.
pub trait CertProvider: Send + Sync {
    /// Build a `rustls::ServerConfig` for TLS 1.3-only with ALPN `h2`.
    fn server_config(&self) -> Result<Arc<ServerConfig>, TlsError>;
}

// ---------------------------------------------------------------------------
// DevSelfSignedProvider
// ---------------------------------------------------------------------------

/// Ephemeral self-signed certificate for development and integration tests.
///
/// Generates a new ECDSA P-256 certificate valid for `localhost` and
/// `127.0.0.1` on each call to [`Self::server_config`].
pub struct DevSelfSignedProvider;

impl DevSelfSignedProvider {
    /// Generate a self-signed cert and return both the `ServerConfig` and
    /// the DER-encoded certificate bytes (for client pinning in tests).
    pub fn generate() -> Result<(Arc<ServerConfig>, Vec<u8>), TlsError> {
        let CertifiedKey {
            cert,
            signing_key: key_pair,
        } = generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])?;

        let cert_der = cert.der().to_vec();
        let key_der = key_pair.serialize_der();

        let cert_chain = vec![rustls::pki_types::CertificateDer::from(cert_der.clone())];
        let private_key = rustls::pki_types::PrivateKeyDer::Pkcs8(key_der.into());

        let cfg = tls13_server_config(cert_chain, private_key)?;
        Ok((cfg, cert_der))
    }
}

impl CertProvider for DevSelfSignedProvider {
    fn server_config(&self) -> Result<Arc<ServerConfig>, TlsError> {
        let (cfg, _) = Self::generate()?;
        Ok(cfg)
    }
}

// ---------------------------------------------------------------------------
// StaticPemProvider
// ---------------------------------------------------------------------------

/// Load a certificate chain + private key from PEM files.
///
/// Both files may contain multiple PEM blocks; the first matching block is
/// used.
pub struct StaticPemProvider {
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
}

impl StaticPemProvider {
    /// Construct from raw PEM bytes (useful in tests).
    pub fn from_bytes(cert_pem: Vec<u8>, key_pem: Vec<u8>) -> Self {
        Self { cert_pem, key_pem }
    }

    /// Read from disk paths.
    pub fn from_files(
        cert_path: &std::path::Path,
        key_path: &std::path::Path,
    ) -> Result<Self, TlsError> {
        let cert_pem = std::fs::read(cert_path)?;
        let key_pem = std::fs::read(key_path)?;
        Ok(Self { cert_pem, key_pem })
    }
}

impl CertProvider for StaticPemProvider {
    fn server_config(&self) -> Result<Arc<ServerConfig>, TlsError> {
        let certs = parse_cert_pem(&self.cert_pem)?;
        let key = parse_key_pem(&self.key_pem)?;
        tls13_server_config(certs, key)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a `rustls::ServerConfig` restricted to TLS 1.3 with ALPN `["h2"]`.
/// No client authentication (one-way TLS).
fn tls13_server_config(
    certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<Arc<ServerConfig>, TlsError> {
    let mut cfg = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Ok(Arc::new(cfg))
}

/// Build a `rustls::ServerConfig` with **mutual TLS** (client cert required).
///
/// `ca_root_pem` is the DER or PEM-encoded CA root that signed client certs.
/// Activated by setting `DISK_INTERNAL_CA_ROOT_PEM` to the path of the CA cert
/// file; this function is called by [`DevSelfSignedMtlsProvider`] and by any
/// provider that reads that env var.
pub fn tls13_mtls_server_config(
    server_certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    server_key: rustls::pki_types::PrivateKeyDer<'static>,
    ca_root_pem: &[u8],
) -> Result<Arc<ServerConfig>, TlsError> {
    let ca_certs = parse_cert_pem(ca_root_pem)?;
    let mut root_store = rustls::RootCertStore::empty();
    for ca_cert in ca_certs {
        root_store.add(ca_cert).map_err(TlsError::RustlsError)?;
    }
    let client_verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .map_err(|e| TlsError::RustlsError(rustls::Error::General(e.to_string())))?;
    let mut cfg = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(server_certs, server_key)?;
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Ok(Arc::new(cfg))
}

/// Ephemeral self-signed provider with **mutual TLS** — server cert is
/// self-signed, client certs are verified against the supplied CA root.
/// For integration tests only; production wires a real CA.
pub struct DevSelfSignedMtlsProvider {
    pub ca_root_pem: Vec<u8>,
}

impl DevSelfSignedMtlsProvider {
    /// Generate ephemeral server cert + return `(ServerConfig, server_cert_der)`.
    pub fn generate(ca_root_pem: Vec<u8>) -> Result<(Arc<ServerConfig>, Vec<u8>), TlsError> {
        let rcgen::CertifiedKey {
            cert,
            signing_key: key_pair,
        } = rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])?;
        let cert_der = cert.der().to_vec();
        let key_der = key_pair.serialize_der();
        let cert_chain = vec![rustls::pki_types::CertificateDer::from(cert_der.clone())];
        let private_key = rustls::pki_types::PrivateKeyDer::Pkcs8(key_der.into());
        let cfg = tls13_mtls_server_config(cert_chain, private_key, &ca_root_pem)?;
        Ok((cfg, cert_der))
    }
}

fn parse_cert_pem(
    pem_bytes: &[u8],
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, TlsError> {
    let pem_str =
        std::str::from_utf8(pem_bytes).map_err(|e| TlsError::PemParseError(e.to_string()))?;
    let items = pem::parse_many(pem_str).map_err(|e| TlsError::PemParseError(e.to_string()))?;
    let certs: Vec<_> = items
        .into_iter()
        .filter(|p| p.tag() == "CERTIFICATE")
        .map(|p| rustls::pki_types::CertificateDer::from(p.into_contents()))
        .collect();
    if certs.is_empty() {
        return Err(TlsError::PemParseError(
            "no CERTIFICATE blocks found".into(),
        ));
    }
    Ok(certs)
}

/// Production mTLS provider: load server cert + key + client CA root from PEM files.
///
/// Returned `ServerConfig` requires every client to present a certificate
/// signed by `ca_root_path`. Used by `disk-arcana-server` boot in `main.rs`.
pub fn build_mtls_from_files(
    server_cert_path: &std::path::Path,
    server_key_path: &std::path::Path,
    ca_root_path: &std::path::Path,
) -> Result<Arc<ServerConfig>, TlsError> {
    let server_cert_pem = std::fs::read(server_cert_path)?;
    let server_key_pem = std::fs::read(server_key_path)?;
    let ca_root_pem = std::fs::read(ca_root_path)?;

    let server_certs = parse_cert_pem(&server_cert_pem)?;
    let server_key = parse_key_pem(&server_key_pem)?;
    tls13_mtls_server_config(server_certs, server_key, &ca_root_pem)
}

fn parse_key_pem(pem_bytes: &[u8]) -> Result<rustls::pki_types::PrivateKeyDer<'static>, TlsError> {
    let pem_str =
        std::str::from_utf8(pem_bytes).map_err(|e| TlsError::PemParseError(e.to_string()))?;
    let items = pem::parse_many(pem_str).map_err(|e| TlsError::PemParseError(e.to_string()))?;
    for item in items {
        match item.tag() {
            "EC PRIVATE KEY" => {
                return Ok(rustls::pki_types::PrivateKeyDer::Sec1(
                    item.into_contents().into(),
                ));
            }
            "RSA PRIVATE KEY" => {
                return Ok(rustls::pki_types::PrivateKeyDer::Pkcs1(
                    item.into_contents().into(),
                ));
            }
            "PRIVATE KEY" => {
                return Ok(rustls::pki_types::PrivateKeyDer::Pkcs8(
                    item.into_contents().into(),
                ));
            }
            _ => continue,
        }
    }
    Err(TlsError::PemParseError("no private key block found".into()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_self_signed_generates_valid_server_config() {
        let (cfg, cert_der) = DevSelfSignedProvider::generate().expect("generate");
        assert!(!cert_der.is_empty(), "cert DER must not be empty");
        // ServerConfig should be TLS 1.3 only.
        assert_eq!(cfg.alpn_protocols, vec![b"h2".to_vec()], "ALPN must be h2");
    }

    #[test]
    fn dev_cert_provider_trait_works() {
        let provider = DevSelfSignedProvider;
        let cfg = provider.server_config().expect("server_config");
        assert!(!cfg.alpn_protocols.is_empty());
    }

    #[test]
    fn static_pem_provider_roundtrip() {
        // Generate a cert with rcgen, export to PEM, then load via StaticPemProvider.
        use rcgen::generate_simple_self_signed;
        let CertifiedKey {
            cert,
            signing_key: key_pair,
        } = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.pem().into_bytes();
        let key_pem = key_pair.serialize_pem().into_bytes();

        let provider = StaticPemProvider::from_bytes(cert_pem, key_pem);
        let cfg = provider.server_config().expect("static pem config");
        assert_eq!(cfg.alpn_protocols, vec![b"h2".to_vec()]);
    }
}
