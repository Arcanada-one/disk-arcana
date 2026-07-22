//! gRPC connection management with TLS and bearer-token auth.
//!
//! `DiskClient` wraps the tonic-generated stubs and adds:
//! - TLS channel construction (server-cert pinning for dev/test).
//! - Bearer token injection on each RPC call.
//! - Session token caching from `Authenticate`.

use std::collections::HashMap;
use std::sync::Arc;

use disk_proto::disk::{
    auth_service_client::AuthServiceClient, sync_service_client::SyncServiceClient,
    DeltaDownloadRequest, FileMetadata, NodeAuthRequest, NodeRegisterRequest, SyncStateRequest,
    SyncStateResponse,
};
use tonic::{
    metadata::MetadataValue,
    transport::{Channel, ClientTlsConfig, Endpoint},
    Request,
};

/// Configuration for connecting to a `disk-arcana-server`.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// gRPC endpoint URI (e.g. `https://disk.arcanada.ai:9443`).
    pub endpoint: String,
    /// PEM-encoded CA certificate for TLS verification.
    /// If `None`, the system trust store is used.
    pub tls_ca_cert_pem: Option<Vec<u8>>,
    /// Expected server domain for TLS SNI / certificate-name verification.
    ///
    /// Set this when `endpoint` is an IP address but the server certificate
    /// only carries a DNS SAN (e.g. endpoint `https://65.108.236.39:9443`,
    /// cert SAN `disk.arcanada.ai`).  When `None`, tonic derives the name
    /// from the endpoint URI host — which fails when the host is an IP and
    /// the cert has no matching IP SAN (DISK-0060).
    pub tls_domain: Option<String>,
    /// PEM-encoded client certificate for mTLS.
    /// When combined with `client_key_pem`, the channel presents this
    /// certificate to the server during the TLS handshake.  Both fields
    /// must be `Some` for the identity to be wired; a partial pair is
    /// silently ignored (connect still proceeds without a client cert).
    pub client_cert_pem: Option<Vec<u8>>,
    /// PEM-encoded private key matching `client_cert_pem`.
    pub client_key_pem: Option<Vec<u8>>,
    /// Node ID for registration / authentication.
    pub node_id: String,
    /// API key (obtained after `register_node`).
    pub api_key: Option<String>,
    /// SaaS tenant id sent as `x-disk-tenant` on sync RPCs (DISK-0017).
    pub tenant_id: Option<String>,
}

/// High-level client wrapping tonic stubs.
#[derive(Clone)]
pub struct DiskClient {
    channel: Channel,
    pub node_id: String,
    pub api_key: Option<String>,
    tenant_id: Option<String>,
    session_token: Arc<tokio::sync::RwLock<Option<String>>>,
}

impl DiskClient {
    /// Update the SaaS tenant sent as `x-disk-tenant` on subsequent sync RPCs.
    pub fn set_tenant_id(&mut self, tenant_id: Option<String>) {
        self.tenant_id = tenant_id.filter(|t| !t.is_empty());
    }

    /// Active tenant id for sync RPC metadata (DISK-0017 / DISK-0030).
    pub fn tenant_id(&self) -> Option<&str> {
        self.tenant_id.as_deref()
    }
}

/// Errors from client operations.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("transport error: {0}")]
    Transport(#[from] tonic::transport::Error),

    #[error("gRPC status: {0}")]
    Status(#[from] tonic::Status),

    #[error("not authenticated: call authenticate() first")]
    NotAuthenticated,

    #[error("invalid metadata value: {0}")]
    MetadataError(String),
}

impl DiskClient {
    /// Connect to the server at `config.endpoint`.
    pub async fn connect(config: ClientConfig) -> Result<Self, ClientError> {
        let mut endpoint = Endpoint::new(config.endpoint.clone())?;

        let mut tls_config = ClientTlsConfig::new();
        if let Some(ref ca_pem) = config.tls_ca_cert_pem {
            let ca_cert = tonic::transport::Certificate::from_pem(ca_pem.clone());
            tls_config = tls_config.ca_certificate(ca_cert);
        }
        // Wire mTLS client identity when both cert and key are present.
        // A partial pair (only cert or only key) is silently skipped so
        // the connection degrades to one-way TLS rather than panicking.
        if let (Some(ref cert), Some(ref key)) = (&config.client_cert_pem, &config.client_key_pem) {
            let identity = tonic::transport::Identity::from_pem(cert.clone(), key.clone());
            tls_config = tls_config.identity(identity);
        }
        // Override the TLS server-name used for SNI and cert-name verification.
        // Required when `endpoint` is an IP address but the server cert only
        // carries a DNS SAN (DISK-0060).  When `None`, tonic's default
        // behaviour (derive name from the URI host) is preserved.
        if let Some(ref domain) = config.tls_domain {
            tls_config = tls_config.domain_name(domain.clone());
        }
        endpoint = endpoint.tls_config(tls_config)?;

        let channel = endpoint.connect().await?;

        Ok(Self {
            channel,
            node_id: config.node_id,
            api_key: config.api_key,
            tenant_id: config.tenant_id,
            session_token: Arc::new(tokio::sync::RwLock::new(None)),
        })
    }

    fn insert_tenant_metadata<T>(
        req: &mut Request<T>,
        tenant_id: Option<&str>,
    ) -> Result<(), ClientError> {
        if let Some(t) = tenant_id.filter(|s| !s.is_empty()) {
            let value: MetadataValue<tonic::metadata::Ascii> =
                t.parse()
                    .map_err(|e: tonic::metadata::errors::InvalidMetadataValue| {
                        ClientError::MetadataError(format!("x-disk-tenant: {e}"))
                    })?;
            req.metadata_mut().insert("x-disk-tenant", value);
        }
        Ok(())
    }

    /// Build a `DiskClient` without establishing a TCP connection.
    ///
    /// The underlying channel is created with `connect_lazy` — the actual
    /// connection is deferred until the first RPC call.  This constructor is
    /// intended for tests that exercise construction and wiring (e.g.
    /// asserting that `RemoteSync` receives a blob cache) without requiring a
    /// live server.  It MUST NOT be used in production paths where a connected
    /// channel is expected before any sync work begins.
    // `ClientError` contains `tonic::Status` (>= 176 bytes) which Clippy flags;
    // this mirrors the `connect` async fn (same return type, same lint scope).
    #[allow(clippy::result_large_err)]
    pub fn connect_lazy_for_test(config: ClientConfig) -> Result<Self, ClientError> {
        let mut endpoint = Endpoint::new(config.endpoint.clone())?;

        let mut tls_config = ClientTlsConfig::new();
        if let Some(ref ca_pem) = config.tls_ca_cert_pem {
            let ca_cert = tonic::transport::Certificate::from_pem(ca_pem.clone());
            tls_config = tls_config.ca_certificate(ca_cert);
        }
        if let (Some(ref cert), Some(ref key)) = (&config.client_cert_pem, &config.client_key_pem) {
            let identity = tonic::transport::Identity::from_pem(cert.clone(), key.clone());
            tls_config = tls_config.identity(identity);
        }
        if let Some(ref domain) = config.tls_domain {
            tls_config = tls_config.domain_name(domain.clone());
        }
        endpoint = endpoint.tls_config(tls_config)?;

        let channel = endpoint.connect_lazy();

        Ok(Self {
            channel,
            node_id: config.node_id,
            api_key: config.api_key,
            tenant_id: config.tenant_id,
            session_token: Arc::new(tokio::sync::RwLock::new(None)),
        })
    }

    /// Register this node with the server.  Returns the raw API key.
    pub async fn register_node(
        &self,
        display_name: &str,
        platform: &str,
    ) -> Result<String, ClientError> {
        let mut client = AuthServiceClient::new(self.channel.clone());
        let mut req = Request::new(NodeRegisterRequest {
            node_id: self.node_id.clone(),
            display_name: display_name.to_owned(),
            platform: platform.to_owned(),
            tenant_id: self.tenant_id.clone().unwrap_or_default(),
            ..Default::default()
        });
        Self::insert_tenant_metadata(&mut req, self.tenant_id.as_deref())?;
        let resp = client.register_node(req).await?.into_inner();
        Ok(resp.api_key)
    }

    /// Authenticate with the stored API key, caching the session token.
    pub async fn authenticate(&self) -> Result<String, ClientError> {
        let api_key = self
            .api_key
            .as_ref()
            .ok_or(ClientError::NotAuthenticated)?
            .clone();

        let mut client = AuthServiceClient::new(self.channel.clone());
        let resp = client
            .authenticate(Request::new(NodeAuthRequest {
                node_id: self.node_id.clone(),
                api_key,
            }))
            .await?
            .into_inner();

        let token = resp.session_token.clone();
        *self.session_token.write().await = Some(token.clone());
        Ok(token)
    }

    /// Return the cached session token or error if not authenticated.
    pub async fn session_token(&self) -> Result<String, ClientError> {
        self.session_token
            .read()
            .await
            .clone()
            .ok_or(ClientError::NotAuthenticated)
    }

    /// Inject a session token directly into the cache.
    ///
    /// Production code should obtain a token via [`authenticate`]; this entry
    /// point exists for resuming a persisted session and for in-process
    /// integration tests that bypass the AuthService round-trip.
    ///
    /// [`authenticate`]: Self::authenticate
    pub async fn set_session_token(&self, token: String) {
        *self.session_token.write().await = Some(token);
    }

    /// Call `SyncService::ExchangeState` with the cached session token and
    /// the `x-disk-share` metadata header set to `share`.
    ///
    /// DISK-0006 R6: this is the minimal gRPC wire-up the [`SyncLoop`] uses
    /// to probe ACL admission. The unary RPC is sufficient for ACL/share
    /// classification — the streaming `SyncState` path lands in a later
    /// round once the Scan/Hash/Reconcile pipeline is in place.
    ///
    /// [`SyncLoop`]: crate::sync_loop::SyncLoop
    pub async fn exchange_state(
        &self,
        share: &str,
        files: Vec<FileMetadata>,
        node_clock: HashMap<String, u64>,
    ) -> Result<SyncStateResponse, ClientError> {
        let token = self.session_token().await?;
        let mut client = SyncServiceClient::new(self.channel.clone());

        let mut req = Request::new(SyncStateRequest {
            node_id: self.node_id.clone(),
            session_token: token.clone(),
            files,
            node_clock,
            tenant_id: self.tenant_id.clone().unwrap_or_default(),
            vault_id: String::new(),
        });

        let bearer: MetadataValue<tonic::metadata::Ascii> = format!("Bearer {token}")
            .parse()
            .map_err(|e: tonic::metadata::errors::InvalidMetadataValue| {
                ClientError::MetadataError(e.to_string())
            })?;
        req.metadata_mut().insert("authorization", bearer);

        let share_value: MetadataValue<tonic::metadata::Ascii> =
            share
                .parse()
                .map_err(|e: tonic::metadata::errors::InvalidMetadataValue| {
                    ClientError::MetadataError(format!("x-disk-share: {e}"))
                })?;
        req.metadata_mut().insert("x-disk-share", share_value);
        Self::insert_tenant_metadata(&mut req, self.tenant_id.as_deref())?;

        let resp = client.exchange_state(req).await?.into_inner();
        Ok(resp)
    }

    /// Upload `bytes` to the server for the given `share` and relative `path`.
    ///
    /// Mirrors `download_file` in structure (DISK-0043):
    /// - Chunks bytes via `disk_core::delta::chunks`.
    /// - Streams `DeltaUploadRequest` with auth headers + `x-disk-share`.
    /// - Asserts `response.accepted && resulting_hash == blake3(bytes)`.
    ///
    /// Returns `Ok(())` on success or a `ClientError` on any failure.
    pub async fn delta_upload(
        &self,
        share: &str,
        path: &str,
        payload: &disk_core::UploadPayload,
    ) -> Result<(), ClientError> {
        let token = self.session_token().await?;
        let mut client = SyncServiceClient::new(self.channel.clone());

        let bytes = &payload.wire_bytes;
        let content_hash = payload.content_hash;

        // Build the stream of DeltaUploadRequest messages.
        let bearer_val: MetadataValue<tonic::metadata::Ascii> =
            format!("Bearer {token}").parse().map_err(
                |e: tonic::metadata::errors::InvalidMetadataValue| {
                    ClientError::MetadataError(e.to_string())
                },
            )?;
        let share_val: MetadataValue<tonic::metadata::Ascii> =
            share
                .parse()
                .map_err(|e: tonic::metadata::errors::InvalidMetadataValue| {
                    ClientError::MetadataError(format!("x-disk-share: {e}"))
                })?;

        // Build messages: first message carries path + content_hash + first chunk;
        // subsequent messages carry only chunk data (server accumulates them).
        let mut msgs: Vec<disk_proto::disk::DeltaUploadRequest> = Vec::new();
        let mut first = true;
        for chunk_result in disk_core::delta::chunks(bytes.as_slice()) {
            let chunk = chunk_result
                .map_err(|e| ClientError::MetadataError(format!("chunking error: {e}")))?;
            let proto_chunk = disk_proto::disk::DeltaChunk {
                offset: chunk.offset,
                weak_checksum: chunk.weak,
                strong_hash: chunk.strong.to_vec(),
                data: chunk.data,
            };
            if first {
                msgs.push(disk_proto::disk::DeltaUploadRequest {
                    path: path.to_owned(),
                    content_hash: content_hash.to_vec(),
                    chunks: vec![proto_chunk],
                    ..Default::default()
                });
                first = false;
            } else {
                msgs.push(disk_proto::disk::DeltaUploadRequest {
                    path: String::new(),
                    content_hash: Vec::new(),
                    chunks: vec![proto_chunk],
                    ..Default::default()
                });
            }
        }
        // Edge case: empty content → send single message with no chunks.
        if msgs.is_empty() {
            msgs.push(disk_proto::disk::DeltaUploadRequest {
                path: path.to_owned(),
                content_hash: content_hash.to_vec(),
                chunks: vec![],
                ..Default::default()
            });
        }

        let stream = tokio_stream::iter(msgs);
        let mut req = Request::new(stream);
        req.metadata_mut().insert("authorization", bearer_val);
        req.metadata_mut().insert("x-disk-share", share_val);
        Self::insert_tenant_metadata(&mut req, self.tenant_id.as_deref())?;

        let resp = client.delta_upload(req).await?.into_inner();

        if !resp.accepted {
            return Err(ClientError::MetadataError(
                "server did not accept upload".into(),
            ));
        }
        // Verify resulting hash matches what we sent.
        let resp_hash: [u8; 32] = resp
            .resulting_hash
            .as_slice()
            .try_into()
            .map_err(|_| ClientError::MetadataError("invalid resulting_hash length".into()))?;
        if resp_hash != content_hash {
            return Err(ClientError::MetadataError(format!(
                "resulting_hash mismatch: server={} local={}",
                hex::encode(resp_hash),
                hex::encode(content_hash),
            )));
        }
        Ok(())
    }

    /// Download a file as a stream of `DeltaChunk`s, returning reassembled bytes.
    ///
    /// `share` is the share name sent in the `x-disk-share` gRPC metadata header
    /// so the server's ACL enforcer can route the request to the correct share.
    /// Mirrors the header pattern used by [`Self::exchange_state`] and
    /// [`Self::delta_upload`] (DISK-0062).
    pub async fn download_file(&self, share: &str, path: &str) -> Result<Vec<u8>, ClientError> {
        let token = self.session_token().await?;
        let mut client = SyncServiceClient::new(self.channel.clone());

        let mut req = Request::new(DeltaDownloadRequest {
            path: path.to_owned(),
            ..Default::default()
        });
        let bearer: MetadataValue<tonic::metadata::Ascii> = format!("Bearer {token}")
            .parse()
            .map_err(|e: tonic::metadata::errors::InvalidMetadataValue| {
                ClientError::MetadataError(e.to_string())
            })?;
        req.metadata_mut().insert("authorization", bearer);

        let share_value: MetadataValue<tonic::metadata::Ascii> =
            share
                .parse()
                .map_err(|e: tonic::metadata::errors::InvalidMetadataValue| {
                    ClientError::MetadataError(format!("x-disk-share: {e}"))
                })?;
        req.metadata_mut().insert("x-disk-share", share_value);
        Self::insert_tenant_metadata(&mut req, self.tenant_id.as_deref())?;

        use tokio_stream::StreamExt;
        let mut stream = client.delta_download(req).await?.into_inner();
        let mut out = Vec::new();
        while let Some(chunk) = stream.next().await {
            out.extend_from_slice(&chunk?.data);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_config_fields() {
        let cfg = ClientConfig {
            endpoint: "https://localhost:9443".into(),
            tls_ca_cert_pem: None,
            tls_domain: None,
            client_cert_pem: None,
            client_key_pem: None,
            node_id: "test-node".into(),
            api_key: Some("arc_disk_KEY".into()),
            tenant_id: Some("acme".into()),
        };
        assert_eq!(cfg.tenant_id.as_deref(), Some("acme"));
        assert_eq!(cfg.node_id, "test-node");
        assert!(cfg.api_key.is_some());
    }

    #[test]
    fn client_error_display() {
        let e = ClientError::NotAuthenticated;
        assert!(e.to_string().contains("authenticate"));
    }

    // ── DISK-0043 Step 5: delta_upload builds correct chunk stream ───────

    /// Verify that delta_upload produces the correct number of chunks for
    /// content that spans multiple 4 KiB blocks.  The actual gRPC call is
    /// tested in crates/disk-server/tests/delta_upload_commit.rs (round-trip).
    #[test]
    fn delta_upload_chunking_produces_correct_count() {
        use disk_core::delta::chunks;

        // 9 KiB content → 3 chunks (4K + 4K + 1K).
        let content: Vec<u8> = (0u8..=255u8).cycle().take(9 * 1024).collect();
        let chunk_count = chunks(content.as_slice()).count();
        assert_eq!(chunk_count, 3, "9 KiB must produce 3 chunks");

        // Verify blake3 of reassembled content matches original.
        let expected_hash = disk_core::delta::blake3_hash(&content);
        let mut reassembled = Vec::new();
        for c in chunks(content.as_slice()) {
            reassembled.extend_from_slice(&c.unwrap().data);
        }
        let actual_hash = disk_core::delta::blake3_hash(&reassembled);
        assert_eq!(expected_hash, actual_hash, "reassembled hash must match");
    }
}
