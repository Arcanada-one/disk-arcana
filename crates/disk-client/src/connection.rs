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
    /// Node ID for registration / authentication.
    pub node_id: String,
    /// API key (obtained after `register_node`).
    pub api_key: Option<String>,
}

/// High-level client wrapping tonic stubs.
#[derive(Clone)]
pub struct DiskClient {
    channel: Channel,
    pub node_id: String,
    pub api_key: Option<String>,
    session_token: Arc<tokio::sync::RwLock<Option<String>>>,
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
        endpoint = endpoint.tls_config(tls_config)?;

        let channel = endpoint.connect().await?;

        Ok(Self {
            channel,
            node_id: config.node_id,
            api_key: config.api_key,
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
        let resp = client
            .register_node(Request::new(NodeRegisterRequest {
                node_id: self.node_id.clone(),
                display_name: display_name.to_owned(),
                platform: platform.to_owned(),
                ..Default::default()
            }))
            .await?
            .into_inner();
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
            tenant_id: String::new(),
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

        let resp = client.exchange_state(req).await?.into_inner();
        Ok(resp)
    }

    /// Download a file as a stream of `DeltaChunk`s, returning reassembled bytes.
    pub async fn download_file(&self, path: &str) -> Result<Vec<u8>, ClientError> {
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
            node_id: "test-node".into(),
            api_key: Some("arc_disk_KEY".into()),
        };
        assert_eq!(cfg.node_id, "test-node");
        assert!(cfg.api_key.is_some());
    }

    #[test]
    fn client_error_display() {
        let e = ClientError::NotAuthenticated;
        assert!(e.to_string().contains("authenticate"));
    }
}
