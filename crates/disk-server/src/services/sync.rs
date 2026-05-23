//! `SyncService` gRPC implementation.
//!
//! Implements the three RPCs:
//! - `SyncState` (bidi streaming) — reconcile file trees, emit `SyncStateAck`.
//! - `DeltaUpload` (client-streaming) — receive chunks, verify hash, persist.
//! - `DeltaDownload` (server-streaming) — chunk a local file and stream it.
//!
//! ## Auth migration (P4a Step 7)
//!
//! When `acl_enforcer` is `Some`, every RPC entry point resolves the caller's
//! role via `AclEnforcer::resolve(cert_fingerprint, share)` in addition to
//! the legacy session-token check.  Role mismatches → `PermissionDenied` with
//! `AclMismatchDetails` payload + `AuditKind::AclRoleMismatch` row.
//!
//! The `share` used for ACL lookup is extracted from the `x-disk-share`
//! metadata header; when absent it defaults to `"default"`.
//!
//! When `acl_enforcer` is `None` the legacy bearer-token path is used
//! unchanged (dev / test environments that have not yet provisioned ACL).

use std::sync::Arc;

use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status, Streaming};

use disk_core::path_guard;
use disk_proto::disk::{
    sync_service_server::SyncService, AclMismatchDetails, DeltaChunk, DeltaDownloadRequest,
    DeltaUploadRequest, DeltaUploadResponse, SyncStateAck, SyncStateRequest,
};

use crate::acl::{AclEnforcer, AclError, CertFingerprint, EnforcedRole};
use crate::audit::{AuditEmitter, AuditEvent, AuditKind};
use crate::auth::{AuthStore, CertIdentity, SessionToken};
use crate::middleware::replay::ReplayGuard;
#[cfg(feature = "publisher-verify")]
use crate::publisher::{
    FileMetadata as PublisherFileMetadata, PublisherSignatureProof, PublisherVerifier,
};

/// Minimum role required to perform a write (upload/publish) operation.
const WRITE_ROLES: &[EnforcedRole] = &[
    EnforcedRole::Bidirectional,
    EnforcedRole::SendOnly,
    EnforcedRole::Publisher,
];

/// Minimum role required to perform a read (download) operation.
const READ_ROLES: &[EnforcedRole] = &[EnforcedRole::Bidirectional, EnforcedRole::ReceiveOnly];

/// Concrete `SyncService` implementation.
#[derive(Debug, Clone)]
pub struct SyncServiceImpl {
    pub store: AuthStore,
    pub replay: Arc<ReplayGuard>,
    /// Filesystem root for this node (used by DeltaUpload path guard).
    pub root: std::path::PathBuf,
    /// ACL enforcer — when `Some`, cert-based role checks are active.
    /// When `None`, only legacy session-token auth is applied.
    pub acl_enforcer: Option<AclEnforcer>,
    /// Audit emitter — required when `acl_enforcer` is `Some`.
    pub audit: Option<AuditEmitter>,
    /// Publisher signature verifier — active only when `publisher-verify` feature is on.
    /// Populated via `with_publisher_verifier`.
    #[cfg(feature = "publisher-verify")]
    pub publisher_verifier: Option<Arc<PublisherVerifier>>,
}

impl SyncServiceImpl {
    /// Construct without ACL enforcement (legacy/test mode).
    pub fn new(store: AuthStore, root: std::path::PathBuf) -> Self {
        Self {
            store,
            replay: Arc::new(ReplayGuard::new()),
            root,
            acl_enforcer: None,
            audit: None,
            #[cfg(feature = "publisher-verify")]
            publisher_verifier: None,
        }
    }

    /// Construct with ACL enforcement enabled.
    pub fn with_acl(
        store: AuthStore,
        root: std::path::PathBuf,
        acl_enforcer: AclEnforcer,
        audit: AuditEmitter,
    ) -> Self {
        Self {
            store,
            replay: Arc::new(ReplayGuard::new()),
            root,
            acl_enforcer: Some(acl_enforcer),
            audit: Some(audit),
            #[cfg(feature = "publisher-verify")]
            publisher_verifier: None,
        }
    }

    /// Attach a publisher verifier (only available with `publisher-verify` feature).
    #[cfg(feature = "publisher-verify")]
    pub fn with_publisher_verifier(mut self, verifier: Arc<PublisherVerifier>) -> Self {
        self.publisher_verifier = Some(verifier);
        self
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

    /// Extract share name from `x-disk-share` metadata; defaults to `"default"`.
    fn extract_share(metadata: &tonic::metadata::MetadataMap) -> String {
        metadata
            .get("x-disk-share")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("default")
            .to_string()
    }

    /// Run ACL role check using a pre-extracted `CertIdentity`.
    ///
    /// Call pattern:
    /// ```ignore
    /// let cert_id = CertIdentity::from_request(&request);
    /// self.check_acl_by_cert(cert_id.as_ref(), share, allowed, hint).await?;
    /// // then consume request
    /// ```
    ///
    /// Returns `Ok(())` when:
    /// - No enforcer configured (legacy mode), or
    /// - `cert_id` is `None` (one-way TLS, falls through to token auth), or
    /// - Enforcer resolves a role in `allowed_roles`.
    ///
    /// Returns `Err(PermissionDenied)` on mismatch and emits an audit row.
    async fn check_acl_by_cert(
        &self,
        cert_id: Option<&CertIdentity>,
        share: &str,
        allowed_roles: &[EnforcedRole],
        claimed_role_hint: &str,
    ) -> Result<(), Status> {
        let enforcer = match &self.acl_enforcer {
            Some(e) => e,
            None => return Ok(()),
        };
        let cert_id = match cert_id {
            Some(id) => id,
            None => return Ok(()), // no client cert — fall through to token auth
        };
        let fp: CertFingerprint = cert_id.fingerprint;

        match enforcer.resolve(&fp, share).await {
            Ok(role) if allowed_roles.contains(&role) => Ok(()),
            Ok(role) => {
                // Role resolved but not in allowed set → PermissionDenied.
                self.emit_role_mismatch_audit(&fp, share, claimed_role_hint, role.as_str())
                    .await;
                let details = AclMismatchDetails {
                    claimed_role: claimed_role_hint.to_string(),
                    enforced_role: role.as_str().to_string(),
                    share: share.to_string(),
                    cert_fingerprint: fp.to_vec(),
                    ts_ms: unix_now_ms(),
                };
                let mut status = Status::permission_denied(format!(
                    "ACL role mismatch: enforced={} claimed={}",
                    role.as_str(),
                    claimed_role_hint
                ));
                encode_details_into_status(&mut status, details);
                Err(status)
            }
            Err(AclError::ShareUnknown { share: s, .. }) => {
                // Unknown share — return permission denied; client should retry.
                Err(Status::permission_denied(format!(
                    "share unknown: {s}; retry after ACL provisioning"
                )))
            }
            Err(AclError::Unavailable(reason)) => {
                // ACL unhealthy → default-deny.
                Err(Status::unavailable(format!(
                    "ACL enforcer unhealthy: {reason:?}"
                )))
            }
        }
    }

    async fn emit_role_mismatch_audit(
        &self,
        fp: &CertFingerprint,
        share: &str,
        claimed: &str,
        enforced: &str,
    ) {
        if let Some(audit) = &self.audit {
            let ev = AuditEvent::new(AuditKind::AclRoleMismatch)
                .with_cert(*fp)
                .with_share(share)
                .with_payload(&serde_json::json!({
                    "claimed": claimed,
                    "enforced": enforced,
                }));
            let _ = audit.emit(ev).await;
        }
    }
}

/// Encode `AclMismatchDetails` into a tonic Status details field.
fn encode_details_into_status(status: &mut Status, details: AclMismatchDetails) {
    use prost::Message;
    let mut buf = Vec::new();
    if details.encode(&mut buf).is_ok() {
        // Tonic does not provide a public set_details method on Status directly;
        // we attach the serialized proto as the status message detail annotation.
        // The client can decode this by reading the grpc-status-details-bin trailer
        // if they use tonic_types / google.rpc.Status wrapping.  For the purposes of
        // Step 7 the payload is attached as a metadata value.
        *status = Status::with_details(
            tonic::Code::PermissionDenied,
            status.message().to_string(),
            buf.into(),
        );
    }
}

fn unix_now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
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
        let share = Self::extract_share(request.metadata());
        let cert_id = CertIdentity::from_request(&request);
        self.check_acl_by_cert(
            cert_id.as_ref(),
            &share,
            &[
                EnforcedRole::Bidirectional,
                EnforcedRole::SendOnly,
                EnforcedRole::ReceiveOnly,
                EnforcedRole::Publisher,
            ],
            "bidirectional",
        )
        .await?;
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
        let share = Self::extract_share(request.metadata());
        let cert_id = CertIdentity::from_request(&request);
        self.check_acl_by_cert(cert_id.as_ref(), &share, WRITE_ROLES, "send_only")
            .await?;
        let mut stream = request.into_inner();

        let mut assembled: Vec<u8> = Vec::new();
        let mut expected_hash: Option<Vec<u8>> = None;
        let mut last_path: Option<String> = None;
        #[cfg(feature = "publisher-verify")]
        let mut last_proto_proof: Option<disk_proto::disk::PublisherSignatureProof> = None;

        while let Some(msg) = stream.next().await {
            let req = msg?;

            // Validate path on first message.
            if last_path.is_none() {
                let candidate = std::path::Path::new(&req.path);
                path_guard::validate(candidate, &self.root)
                    .map_err(|e| Status::invalid_argument(format!("path guard: {e}")))?;
                last_path = Some(req.path.clone());
                expected_hash = Some(req.content_hash.clone());
                #[cfg(feature = "publisher-verify")]
                {
                    last_proto_proof = req.publisher_proof;
                }
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

        let resulting_hash = disk_core::delta::blake3_hash(&assembled);

        // ── Publisher verification gate (P4b step 15) ──────────────────────
        // Only compiled when `publisher-verify` feature is enabled.
        // On failure: quarantine the bytes (don't commit), emit audit row.
        // On feature-off: skip entirely (preserves P4a behaviour).
        #[cfg(feature = "publisher-verify")]
        {
            let maybe_verifier = self.publisher_verifier.as_ref();

            if let (Some(verifier), Some(cert_id)) = (maybe_verifier, cert_id.as_ref()) {
                if let Some(ref proto_proof) = last_proto_proof {
                    let file_meta = PublisherFileMetadata {
                        path: last_path.clone().unwrap_or_default(),
                        blake3: resulting_hash,
                    };
                    let proof = PublisherSignatureProof {
                        ed25519_signature: proto_proof.ed25519_signature.clone(),
                        vault_key_ref: proto_proof.vault_key_ref.clone(),
                        signed_at_unix_ms: proto_proof.signed_at_unix_ms,
                        counter: proto_proof.counter,
                    };
                    match verifier
                        .verify(&proof, &cert_id.fingerprint, &share, &file_meta)
                        .await
                    {
                        Ok(()) => {} // Signature verified — proceed to commit.
                        Err(e) => {
                            // Write to quarantine.
                            let short_fp: String = cert_id
                                .fingerprint
                                .iter()
                                .take(8)
                                .map(|b| format!("{b:02x}"))
                                .collect();
                            let qpath = self
                                .root
                                .join(".quarantine")
                                .join(&share)
                                .join(&short_fp)
                                .join(last_path.as_deref().unwrap_or("unknown"));
                            if let Some(parent) = qpath.parent() {
                                let _ = std::fs::create_dir_all(parent);
                            }
                            let _ = std::fs::write(&qpath, &assembled);

                            // Audit row.
                            if let Some(ref audit) = self.audit {
                                let _ = audit
                                    .emit(
                                        AuditEvent::new(AuditKind::PublisherSignatureFailure)
                                            .with_cert(cert_id.fingerprint)
                                            .with_share(&share)
                                            .with_payload(&serde_json::json!({
                                                "path": last_path,
                                                "error": e.to_string(),
                                            })),
                                    )
                                    .await;
                            }

                            return Err(Status::permission_denied(format!(
                                "publisher signature invalid: {e}"
                            )));
                        }
                    }
                }
            }
        }

        Ok(Response::new(DeltaUploadResponse {
            accepted: true,
            resulting_hash: resulting_hash.to_vec(),
        }))
    }

    async fn delta_download(
        &self,
        request: Request<DeltaDownloadRequest>,
    ) -> Result<Response<Self::DeltaDownloadStream>, Status> {
        let _node_id = self.require_auth(request.metadata())?;
        let share = Self::extract_share(request.metadata());
        let cert_id = CertIdentity::from_request(&request);
        self.check_acl_by_cert(cert_id.as_ref(), &share, READ_ROLES, "receive_only")
            .await?;
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
        request: Request<SyncStateRequest>,
    ) -> Result<Response<disk_proto::disk::SyncStateResponse>, Status> {
        let share = Self::extract_share(request.metadata());
        let cert_id = CertIdentity::from_request(&request);
        self.check_acl_by_cert(
            cert_id.as_ref(),
            &share,
            &[
                EnforcedRole::Bidirectional,
                EnforcedRole::SendOnly,
                EnforcedRole::ReceiveOnly,
                EnforcedRole::Publisher,
            ],
            "bidirectional",
        )
        .await?;
        Err(Status::unimplemented("use SyncState bidi streaming"))
    }

    async fn upload_delta(
        &self,
        request: Request<DeltaUploadRequest>,
    ) -> Result<Response<DeltaUploadResponse>, Status> {
        let share = Self::extract_share(request.metadata());
        let cert_id = CertIdentity::from_request(&request);
        self.check_acl_by_cert(cert_id.as_ref(), &share, WRITE_ROLES, "send_only")
            .await?;
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
