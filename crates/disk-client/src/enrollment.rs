// `tonic::Status` is ~176 B which inflates `Result<_, EnrollmentError>` past
// the 128 B `clippy::result_large_err` threshold. Boxing would shift this cost
// to the heap on every fallible call across a hot gRPC path; the existing
// `disk_client::connection::ClientError` makes the same tradeoff (no boxing),
// so we keep the API uniform.
#![allow(clippy::result_large_err)]

//! Enrollment client — gRPC wrapper + CSR helpers + bootstrap file parsing.
//!
//! DISK-0006 R2 F-2: provides the client-side primitives consumed by the
//! `disk enroll` and `disk admin pending-token` CLI subcommands.
//!
//! ## Transport
//!
//! Production `EnrollmentService.Enroll` is exposed on the **TLS-only public
//! listener** (`DISK_ENROLLMENT_BIND_ADDR`, default `:9445`) — no client
//! certificate required (DISK-0037 / DISK-0044). Admin RPCs and post-enroll
//! sync use the mTLS listener (`:9443`). See `docs/design/DISK-0044-enrollment-bootstrap.md`.
//!
//! ## CSR
//!
//! Ed25519 keypair + PKCS#10 CSR generated via `rcgen 0.13` with `PKCS_ED25519`
//! signature algorithm. Subject CN equals the supplied `node_id_hint` — the
//! server cross-checks it against the pending token row.

use std::path::Path;

use disk_proto::disk::{
    enrollment_service_client::EnrollmentServiceClient, EnrollRequest, EnrollResponse,
    EnrollmentTokenRequest, EnrollmentTokenResponse,
};
use serde::Deserialize;
use tonic::{
    metadata::MetadataValue,
    transport::{Channel, ClientTlsConfig, Endpoint},
    Request,
};

const ADMIN_TOKEN_METADATA_KEY: &str = "x-disk-admin-token";

/// Errors surfaced by the enrollment client.
#[derive(Debug, thiserror::Error)]
pub enum EnrollmentError {
    #[error("transport: {0}")]
    Transport(#[from] tonic::transport::Error),

    #[error("grpc status: {0}")]
    Status(#[from] tonic::Status),

    #[error("csr generation: {0}")]
    Csr(String),

    #[error("invalid metadata value: {0}")]
    InvalidMetadata(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("bootstrap file parse: {0}")]
    Bootstrap(#[from] toml::de::Error),

    #[error("hex decode: {0}")]
    Hex(#[from] hex::FromHexError),
}

/// gRPC wrapper for `EnrollmentService`.
#[derive(Clone)]
pub struct EnrollmentClient {
    channel: Channel,
}

impl EnrollmentClient {
    /// Connect to the enrollment endpoint. `tls_ca_cert_pem` MUST be supplied
    /// for any non-loopback target. `insecure_localhost = true` disables TLS
    /// entirely; only callable when `server` begins with `http://`.
    pub async fn connect(
        server: &str,
        tls_ca_cert_pem: Option<&[u8]>,
        insecure_localhost: bool,
    ) -> Result<Self, EnrollmentError> {
        let mut endpoint = Endpoint::new(server.to_owned())?;

        if !insecure_localhost {
            let mut tls = ClientTlsConfig::new();
            if let Some(pem) = tls_ca_cert_pem {
                tls = tls.ca_certificate(tonic::transport::Certificate::from_pem(pem));
            }
            endpoint = endpoint.tls_config(tls)?;
        }

        let channel = endpoint.connect().await?;
        Ok(Self { channel })
    }

    /// Admin-bearer-protected `IssuePendingToken` RPC.
    pub async fn issue_pending_token(
        &self,
        admin_token: &str,
        hostname: &str,
        ttl_secs: u64,
        tenant_id: Option<&str>,
    ) -> Result<EnrollmentTokenResponse, EnrollmentError> {
        let mut client = EnrollmentServiceClient::new(self.channel.clone());
        let mut req = Request::new(EnrollmentTokenRequest {
            node_id_hint: hostname.to_owned(),
            ttl_seconds: ttl_secs,
            tenant_id: tenant_id.unwrap_or("").to_owned(),
        });
        let admin: MetadataValue<tonic::metadata::Ascii> =
            admin_token
                .parse()
                .map_err(|e: tonic::metadata::errors::InvalidMetadataValue| {
                    EnrollmentError::InvalidMetadata(e.to_string())
                })?;
        req.metadata_mut().insert(ADMIN_TOKEN_METADATA_KEY, admin);

        if let Some(t) = tenant_id.filter(|s| !s.is_empty()) {
            let tenant: MetadataValue<tonic::metadata::Ascii> =
                t.parse()
                    .map_err(|e: tonic::metadata::errors::InvalidMetadataValue| {
                        EnrollmentError::InvalidMetadata(e.to_string())
                    })?;
            req.metadata_mut().insert("x-disk-tenant", tenant);
        }

        Ok(client.issue_pending_token(req).await?.into_inner())
    }

    /// Public-scope `Enroll` RPC. Bearer = `opaque_token` (raw 32 bytes).
    pub async fn enroll(
        &self,
        opaque_token: Vec<u8>,
        csr_pem: Vec<u8>,
        node_id_hint: String,
    ) -> Result<EnrollResponse, EnrollmentError> {
        let mut client = EnrollmentServiceClient::new(self.channel.clone());
        let req = Request::new(EnrollRequest {
            opaque_token,
            csr_pem,
            node_id_hint,
        });
        Ok(client.enroll(req).await?.into_inner())
    }
}

/// Ed25519 keypair + PKCS#10 CSR. Returns `(private_key_pem, csr_pem)`.
///
/// The key is serialised as PKCS#8 v1; the CSR signature algorithm is
/// Ed25519. Subject CN is set to `common_name`.
pub fn gen_keypair_and_csr(common_name: &str) -> Result<(String, String), EnrollmentError> {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ED25519};

    let key_pair = KeyPair::generate_for(&PKCS_ED25519)
        .map_err(|e| EnrollmentError::Csr(format!("keypair: {e}")))?;

    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|e| EnrollmentError::Csr(format!("params: {e}")))?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    params.distinguished_name = dn;

    let csr = params
        .serialize_request(&key_pair)
        .map_err(|e| EnrollmentError::Csr(format!("serialize_request: {e}")))?;

    let csr_pem = csr
        .pem()
        .map_err(|e| EnrollmentError::Csr(format!("pem encode: {e}")))?;
    Ok((key_pair.serialize_pem(), csr_pem))
}

/// Mask a hex token for log output. First 4 + last 4 chars retained,
/// middle replaced by `…`. Token shorter than 12 chars is fully masked.
pub fn redact_token(token_hex: &str) -> String {
    if token_hex.len() < 12 {
        return "***".to_owned();
    }
    let (head, tail) = (&token_hex[..4], &token_hex[token_hex.len() - 4..]);
    format!("{head}…{tail}")
}

/// Bootstrap TOML schema for `--from-bootstrap-file <PATH>`.
#[derive(Debug, Clone, Deserialize)]
pub struct BootstrapFile {
    /// gRPC endpoint URI (e.g. `https://disk.arcanada.ai:9445`).
    pub server: String,
    /// Hex-encoded opaque token from `disk admin pending-token`.
    pub token: String,
    /// Optional node_id_hint override (defaults to system hostname).
    #[serde(default)]
    pub node_id_hint: Option<String>,
    /// Optional PEM-encoded CA cert to pin TLS.
    #[serde(default)]
    pub ca_cert_pem: Option<String>,
}

/// Parse a bootstrap TOML file.
pub fn parse_bootstrap_file(toml_str: &str) -> Result<BootstrapFile, EnrollmentError> {
    Ok(toml::from_str::<BootstrapFile>(toml_str)?)
}

/// Write a PEM-encoded key file with mode 0600 (rw-------).
#[cfg(unix)]
pub fn write_key_file(path: &Path, pem: &str) -> Result<(), EnrollmentError> {
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    std::io::Write::write_all(&mut file, pem.as_bytes())?;
    Ok(())
}

/// Windows fallback — no mode bits; ACL hardening is a separate concern.
#[cfg(not(unix))]
pub fn write_key_file(path: &Path, pem: &str) -> Result<(), EnrollmentError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(path, pem.as_bytes())?;
    Ok(())
}

/// Write a PEM cert file (world-readable mode 0644 on unix).
pub fn write_cert_file(path: &Path, pem: &str) -> Result<(), EnrollmentError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(path, pem.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csr_round_trip_ed25519() {
        let (key_pem, csr_pem) = gen_keypair_and_csr("test-node-01").unwrap();
        assert!(key_pem.contains("BEGIN PRIVATE KEY"));
        assert!(csr_pem.contains("BEGIN CERTIFICATE REQUEST"));
        // Re-parse via pem crate (workspace dep) to confirm structure.
        let pem = pem::parse(&csr_pem).unwrap();
        assert_eq!(pem.tag(), "CERTIFICATE REQUEST");
        assert!(!pem.contents().is_empty());
    }

    #[test]
    fn csr_subject_cn_matches() {
        let cn = "host-cn-check";
        let (_k, csr_pem) = gen_keypair_and_csr(cn).unwrap();
        // Cheap structural check: CN bytes appear in the DER. A full ASN.1
        // walk would require an extra dependency; this guards against the
        // common foot-gun of forgetting to set the DN.
        let der = pem::parse(&csr_pem).unwrap().into_contents();
        let needle = cn.as_bytes();
        assert!(
            der.windows(needle.len()).any(|w| w == needle),
            "CN {cn} not present in CSR DER"
        );
    }

    #[test]
    fn redact_token_masks_middle() {
        let red = redact_token("deadbeefcafef00d1234567890abcdef");
        assert_eq!(red, "dead…cdef");
    }

    #[test]
    fn redact_token_short_fully_masked() {
        assert_eq!(redact_token("abc"), "***");
        assert_eq!(redact_token("0123456789a"), "***"); // 11 chars
    }

    #[test]
    fn bootstrap_file_parses_minimal() {
        let toml_str = r#"
server = "https://disk.arcanada.ai:9445"
token = "deadbeef"
"#;
        let bf = parse_bootstrap_file(toml_str).unwrap();
        assert_eq!(bf.server, "https://disk.arcanada.ai:9445");
        assert_eq!(bf.token, "deadbeef");
        assert!(bf.node_id_hint.is_none());
        assert!(bf.ca_cert_pem.is_none());
    }

    #[test]
    fn bootstrap_file_parses_full() {
        let toml_str = r#"
server = "https://disk.arcanada.ai:9445"
token = "0123456789abcdef"
node_id_hint = "macos-laptop-1"
ca_cert_pem = "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"
"#;
        let bf = parse_bootstrap_file(toml_str).unwrap();
        assert_eq!(bf.node_id_hint.as_deref(), Some("macos-laptop-1"));
        assert!(bf.ca_cert_pem.unwrap().contains("BEGIN CERTIFICATE"));
    }

    #[test]
    #[cfg(unix)]
    fn write_key_file_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nested/client.key");
        write_key_file(&path, "PEM-DATA").unwrap();

        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "PEM-DATA");
    }

    #[test]
    fn write_cert_file_creates_parent() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nested/dir/client.crt");
        write_cert_file(&path, "CERT").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "CERT");
    }
}
