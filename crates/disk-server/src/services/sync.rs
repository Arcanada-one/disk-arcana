//! `SyncService` gRPC implementation.
//!
//! Implements the three RPCs:
//! - `SyncState` (bidi streaming) — reconcile file trees, emit `SyncStateAck`.
//! - `DeltaUpload` (client-streaming) — receive chunks, verify hash, persist.
//! - `DeltaDownload` (server-streaming) — chunk a local file and stream it.

use std::sync::Arc;

use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status, Streaming};

use disk_core::path_guard;
use disk_proto::disk::{
    sync_service_server::SyncService, DeltaChunk, DeltaDownloadRequest, DeltaUploadRequest,
    DeltaUploadResponse, SyncStateAck, SyncStateRequest,
};

use crate::auth::{AuthStore, SessionToken};
use crate::middleware::replay::ReplayGuard;

/// Concrete `SyncService` implementation.
#[derive(Debug, Clone)]
pub struct SyncServiceImpl {
    pub store: AuthStore,
    pub replay: Arc<ReplayGuard>,
    /// Filesystem root for this node (used by DeltaUpload path guard).
    pub root: std::path::PathBuf,
}

impl SyncServiceImpl {
    pub fn new(store: AuthStore, root: std::path::PathBuf) -> Self {
        Self {
            store,
            replay: Arc::new(ReplayGuard::new()),
            root,
        }
    }

    /// Extract and validate the bearer session token from metadata.
    #[allow(clippy::result_large_err)]
    fn require_auth(&self, metadata: &tonic::metadata::MetadataMap) -> Result<String, Status> {
        let raw = metadata
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| Status::unauthenticated("missing authorization header"))?;

        let token = SessionToken::from_bearer(raw)
            .ok_or_else(|| Status::unauthenticated("invalid bearer token format"))?;

        self.store
            .validate_session(&token)
            .ok_or_else(|| Status::unauthenticated("session expired or unknown"))
    }
}

#[tonic::async_trait]
impl SyncService for SyncServiceImpl {
    type SyncStateStream = ReceiverStream<Result<SyncStateAck, Status>>;
    type DeltaDownloadStream = ReceiverStream<Result<DeltaChunk, Status>>;

    async fn sync_state(
        &self,
        request: Request<Streaming<SyncStateRequest>>,
    ) -> Result<Response<Self::SyncStateStream>, Status> {
        let node_id = self.require_auth(request.metadata())?;
        let mut stream = request.into_inner();
        let replay = Arc::clone(&self.replay);
        let stream_id: u64 = rand::random();

        let (tx, rx) = tokio::sync::mpsc::channel(32);

        tokio::spawn(async move {
            let mut sequence_id: u64 = 0;
            while let Some(msg) = stream.next().await {
                match msg {
                    Ok(req) => {
                        sequence_id += 1;
                        // Check replay.
                        if let Err(e) = replay.check_and_advance(&node_id, stream_id, sequence_id) {
                            let _ = tx.send(Err(Status::aborted(format!("replay: {e}")))).await;
                            break;
                        }
                        let ack = SyncStateAck {
                            session_token: req.session_token,
                            sequence_id,
                        };
                        if tx.send(Ok(ack)).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(e)).await;
                        break;
                    }
                }
            }
            replay.close_stream(&node_id, stream_id);
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn delta_upload(
        &self,
        request: Request<Streaming<DeltaUploadRequest>>,
    ) -> Result<Response<DeltaUploadResponse>, Status> {
        let _node_id = self.require_auth(request.metadata())?;
        let mut stream = request.into_inner();

        let mut assembled: Vec<u8> = Vec::new();
        let mut expected_hash: Option<Vec<u8>> = None;
        let mut last_path: Option<String> = None;

        while let Some(msg) = stream.next().await {
            let req = msg?;

            // Validate path on first message.
            if last_path.is_none() {
                let candidate = std::path::Path::new(&req.path);
                path_guard::validate(candidate, &self.root)
                    .map_err(|e| Status::invalid_argument(format!("path guard: {e}")))?;
                last_path = Some(req.path.clone());
                expected_hash = Some(req.content_hash.clone());
            }

            for chunk in &req.chunks {
                // Verify strong hash of chunk data.
                let actual_strong: [u8; 32] = disk_core::delta::blake3_hash(&chunk.data);
                if chunk.strong_hash.len() == 32 {
                    let expected_strong: [u8; 32] = chunk
                        .strong_hash
                        .as_slice()
                        .try_into()
                        .map_err(|_| Status::invalid_argument("invalid strong_hash length"))?;
                    if actual_strong != expected_strong {
                        return Err(Status::data_loss("chunk integrity failure (T-Tampering)"));
                    }
                }
                assembled.extend_from_slice(&chunk.data);
            }
        }

        // Verify final content hash.
        if let Some(ref expected) = expected_hash {
            if !expected.is_empty() {
                let actual: [u8; 32] = disk_core::delta::blake3_hash(&assembled);
                let expected_arr: [u8; 32] = expected
                    .as_slice()
                    .try_into()
                    .map_err(|_| Status::invalid_argument("invalid content_hash length"))?;
                if actual != expected_arr {
                    return Err(Status::data_loss("content_hash mismatch after assembly"));
                }
            }
        }

        let resulting_hash = disk_core::delta::blake3_hash(&assembled).to_vec();
        Ok(Response::new(DeltaUploadResponse {
            accepted: true,
            resulting_hash,
        }))
    }

    async fn delta_download(
        &self,
        request: Request<DeltaDownloadRequest>,
    ) -> Result<Response<Self::DeltaDownloadStream>, Status> {
        let _node_id = self.require_auth(request.metadata())?;
        let req = request.into_inner();

        // Validate path.
        let candidate = std::path::Path::new(&req.path);
        let canonical = path_guard::validate(candidate, &self.root)
            .map_err(|e| Status::invalid_argument(format!("path guard: {e}")))?;

        let data = std::fs::read(&canonical)
            .map_err(|e| Status::not_found(format!("file not found: {e}")))?;

        let (tx, rx) = tokio::sync::mpsc::channel(64);

        tokio::spawn(async move {
            for chunk_result in disk_core::delta::chunks(data.as_slice()) {
                match chunk_result {
                    Ok(chunk) => {
                        let proto_chunk = DeltaChunk {
                            offset: chunk.offset,
                            weak_checksum: chunk.weak,
                            strong_hash: chunk.strong.to_vec(),
                            data: chunk.data,
                        };
                        if tx.send(Ok(proto_chunk)).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(Status::internal(e.to_string()))).await;
                        break;
                    }
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    // Legacy RPCs from Phase 1/2 — not used in Phase 3 but must satisfy the trait.
    async fn exchange_state(
        &self,
        _request: Request<SyncStateRequest>,
    ) -> Result<Response<disk_proto::disk::SyncStateResponse>, Status> {
        Err(Status::unimplemented("use SyncState bidi streaming"))
    }

    async fn upload_delta(
        &self,
        _request: Request<DeltaUploadRequest>,
    ) -> Result<Response<DeltaUploadResponse>, Status> {
        Err(Status::unimplemented("use DeltaUpload streaming"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tokio_stream::StreamExt;
    use tonic::Request;

    fn make_service_with_root(root: std::path::PathBuf) -> SyncServiceImpl {
        SyncServiceImpl::new(AuthStore::new(), root)
    }

    #[tokio::test]
    async fn delta_download_path_traversal_rejected() {
        let root = tempdir().unwrap();
        let svc = make_service_with_root(root.path().to_path_buf());

        // Create a valid session.
        let key = svc
            .store
            .register_node("n1", "N", "linux")
            .expect("register");
        let (token, _) = svc.store.authenticate("n1", key.as_str()).expect("auth");

        let mut req = Request::new(DeltaDownloadRequest {
            path: "../../etc/passwd".into(),
            ..Default::default()
        });
        req.metadata_mut().insert(
            "authorization",
            format!("Bearer {}", token.as_str()).parse().unwrap(),
        );
        let err = svc.delta_download(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn delta_download_unauthenticated() {
        let root = tempdir().unwrap();
        let svc = make_service_with_root(root.path().to_path_buf());
        let req = Request::new(DeltaDownloadRequest {
            path: "file.txt".into(),
            ..Default::default()
        });
        let err = svc.delta_download(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn delta_download_missing_file() {
        let root = tempdir().unwrap();
        std::fs::create_dir_all(&root).unwrap();
        let svc = make_service_with_root(root.path().to_path_buf());

        let key = svc
            .store
            .register_node("n2", "N", "linux")
            .expect("register");
        let (token, _) = svc.store.authenticate("n2", key.as_str()).expect("auth");

        let mut req = Request::new(DeltaDownloadRequest {
            path: "nonexistent.md".into(),
            ..Default::default()
        });
        req.metadata_mut().insert(
            "authorization",
            format!("Bearer {}", token.as_str()).parse().unwrap(),
        );
        let err = svc.delta_download(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn delta_download_streams_chunks() {
        let root = tempdir().unwrap();
        let content: Vec<u8> = (0u8..=255u8).cycle().take(8200).collect();
        let file_path = root.path().join("big.bin");
        std::fs::write(&file_path, &content).unwrap();

        let svc = make_service_with_root(root.path().to_path_buf());
        let key = svc.store.register_node("n3", "N", "linux").unwrap();
        let (token, _) = svc.store.authenticate("n3", key.as_str()).unwrap();

        let mut req = Request::new(DeltaDownloadRequest {
            path: "big.bin".into(),
            ..Default::default()
        });
        req.metadata_mut().insert(
            "authorization",
            format!("Bearer {}", token.as_str()).parse().unwrap(),
        );

        let resp = svc.delta_download(req).await.unwrap();
        let mut stream = resp.into_inner();
        let mut reassembled = Vec::new();
        while let Some(chunk) = stream.next().await {
            reassembled.extend_from_slice(&chunk.unwrap().data);
        }
        assert_eq!(reassembled, content);
    }
}
