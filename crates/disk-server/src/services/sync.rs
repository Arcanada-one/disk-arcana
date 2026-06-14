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

use disk_core::meta_db::MetaDb;
use disk_core::path_guard;
use disk_core::reconciler::ReconciliationEngine;
use disk_core::types::{ActionType, FileMeta};
use disk_core::vector_clock::VectorClock;
use disk_proto::disk::{
    sync_service_server::SyncService, AclMismatchDetails, DeltaChunk, DeltaDownloadRequest,
    DeltaUploadRequest, DeltaUploadResponse, FileMetadata, SyncStateAck, SyncStateRequest,
    SyncStateResponse,
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
    /// SQLite metadata index — authoritative server state (DISK-0043).
    /// `None` in legacy/test mode constructed via `new()`; `Some` when
    /// constructed via `with_acl()` or `with_meta_db()`.
    pub meta_db: Option<MetaDb>,
    /// Stable server node identifier used as the writer in MetaDb upserts
    /// and as the `node_id` for `ReconciliationEngine`.
    pub server_node_id: String,
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
            meta_db: None,
            server_node_id: "server".into(),
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
            meta_db: None,
            server_node_id: "server".into(),
            acl_enforcer: Some(acl_enforcer),
            audit: Some(audit),
            #[cfg(feature = "publisher-verify")]
            publisher_verifier: None,
        }
    }

    /// Attach a `MetaDb` handle and optional server node id to an existing instance.
    /// Called from `main.rs` after the database is opened.
    pub fn with_meta_db(mut self, db: MetaDb, node_id: impl Into<String>) -> Self {
        self.meta_db = Some(db);
        self.server_node_id = node_id.into();
        self
    }

    /// Return the server node id.
    pub fn server_node_id(&self) -> &str {
        &self.server_node_id
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

        // ── Commit assembled bytes to sync_root (DISK-0043) ────────────────
        //
        // SRE write-order (binding): bytes DURABLE first, then MetaDb row.
        // Crash between rename and upsert → next sync re-derives row from
        // disk (convergent).
        //
        // Security precondition: path_guard::validate before any rename.
        // Path was already checked on the first chunk arrival (above), but
        // re-validate here with the canonical root for the write gate so the
        // check is co-located with the write (defence-in-depth).
        if let Some(file_path) = last_path.as_deref() {
            let candidate = std::path::Path::new(file_path);

            // Security: path_guard::validate BEFORE any write (V-AC-6 binding).
            let target = path_guard::validate(candidate, &self.root)
                .map_err(|e| Status::invalid_argument(format!("path guard: {e}")))?;

            // Ensure parent directory exists.
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| Status::internal(format!("create parent dir: {e}")))?;
            }

            // 1. Write to a temp file inside sync_root (same device → atomic rename).
            let tmp_name = format!(".tmp-{}", rand::random::<u64>());
            let tmp_path = self.root.join(&tmp_name);
            std::fs::write(&tmp_path, &assembled)
                .map_err(|e| Status::internal(format!("write temp: {e}")))?;

            // 2. fsync the temp file for durability.
            {
                let f = std::fs::OpenOptions::new()
                    .write(true)
                    .open(&tmp_path)
                    .map_err(|e| Status::internal(format!("open temp for fsync: {e}")))?;
                f.sync_all()
                    .map_err(|e| Status::internal(format!("fsync temp: {e}")))?;
            }

            // 3. Atomic rename (bytes durable before MetaDb row — SRE binding).
            std::fs::rename(&tmp_path, &target)
                .map_err(|e| Status::internal(format!("rename temp to target: {e}")))?;

            // 4. MetaDb upsert (after bytes are durable on disk).
            if let Some(ref db) = self.meta_db {
                let mtime_ns = target
                    .metadata()
                    .ok()
                    .and_then(|m| {
                        use std::time::UNIX_EPOCH;
                        m.modified().ok()?.duration_since(UNIX_EPOCH).ok()
                    })
                    .map(|d| d.as_nanos() as i64)
                    .unwrap_or(0);

                let file_size = assembled.len() as u64;

                // Advance the server's vector clock for this write.
                let mut vc = VectorClock::new();
                vc.advance(&self.server_node_id);

                // `target` is canonical (path_guard resolved it); strip the
                // canonical root so the stored path is always relative even
                // when the runtime root path contains symlinks (e.g. macOS
                // /var → /private/var tempdir paths).
                let canonical_root = self
                    .root
                    .canonicalize()
                    .unwrap_or_else(|_| self.root.clone());
                let relative_path = target
                    .strip_prefix(&canonical_root)
                    .unwrap_or(&target)
                    .to_path_buf();

                let meta = FileMeta {
                    path: relative_path,
                    content_hash: resulting_hash,
                    size: file_size,
                    mtime_ns,
                    inode: None,
                    vector_clock: vc,
                    deleted: false,
                    deleted_at: None,
                    node_id: self.server_node_id.clone(),
                };
                // Upsert failure is non-fatal: bytes are durable; next sync
                // rebuilds the row from disk (convergent recovery).
                let _ = db.upsert_file(&meta).await;
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

    // Real reconcile over unary ExchangeState with per-client baseline tracking.
    async fn exchange_state(
        &self,
        request: Request<SyncStateRequest>,
    ) -> Result<Response<SyncStateResponse>, Status> {
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
        let req = request.into_inner();

        // Build the server's current state.
        //
        // ReconciliationEngine::reconcile(local, remote, indexed) perspective:
        //
        //   local   = server's own MetaDb rows  (the server is the engine's node)
        //   remote  = client-submitted files    (the other peer)
        //   indexed = per-client baseline       (last-synced snapshot for this node)
        //
        // Action semantics from the server's perspective, inverted for the client:
        //   Upload      → server has a file the client lacks  → to_download
        //   Download    → client has a file the server lacks  → to_upload
        //   DeleteLocal → file was in baseline but client no longer reports it
        //                 and server still holds it — client should delete locally
        //                 → to_delete
        //
        // Per-client baseline tracking enables delete propagation: a file deleted
        // on the client (present in indexed, absent from remote) is now reachable
        // via the DeleteLocal branch of resolve_one.
        let (server_files, client_files, db) = if let Some(ref db) = self.meta_db {
            let server = db
                .list_all_files()
                .await
                .map_err(|e| Status::internal(format!("meta_db list_all_files: {e}")))?;
            let client: Vec<FileMeta> = req.files.iter().map(proto_to_file_meta).collect();
            (server, client, db)
        } else {
            // No MetaDb wired — return empty response (legacy / test mode
            // without a database; clients see no required actions).
            return Ok(Response::new(SyncStateResponse::default()));
        };

        // Load the persistent per-client baseline for this node.
        let vault_id = "default";
        let baseline = db
            .load_node_baseline(&node_id, vault_id)
            .await
            .map_err(|e| Status::internal(format!("baseline load: {e}")))?;

        let engine = ReconciliationEngine::new(self.server_node_id.clone());
        let actions = engine
            .reconcile(&server_files, &client_files, &baseline)
            .map_err(|e| Status::internal(format!("reconcile: {e}")))?;

        let mut to_upload: Vec<FileMetadata> = Vec::new();
        let mut to_download: Vec<FileMetadata> = Vec::new();
        let mut to_delete: Vec<FileMetadata> = Vec::new();
        let mut conflict_reports: Vec<disk_proto::disk::ConflictReport> = Vec::new();

        for action in &actions {
            match action.action {
                // Server has file; client should download it.
                ActionType::Upload => {
                    if let Some(ref m) = action.server_version {
                        to_download.push(file_meta_to_proto(m));
                    } else if let Some(m) = server_files.iter().find(|m| m.path == action.path) {
                        to_download.push(file_meta_to_proto(m));
                    }
                }
                // Client has file; client should upload it.
                ActionType::Download => {
                    if let Some(ref m) = action.server_version {
                        to_upload.push(file_meta_to_proto(m));
                    } else if let Some(m) = client_files.iter().find(|m| m.path == action.path) {
                        to_upload.push(file_meta_to_proto(m));
                    }
                }
                // Client should delete their local copy.
                ActionType::DeleteLocal | ActionType::DeleteRemote => {
                    let path_str = action.path.to_string_lossy().to_string();
                    to_delete.push(FileMetadata {
                        path: path_str,
                        ..Default::default()
                    });
                }
                // Conflict detected — surface in response and persist to meta_db.
                ActionType::ConflictFork | ActionType::ConflictMerge => {
                    let path_str = action.path.to_string_lossy().to_string();

                    // Determine the suggested resolution from the conflict kind.
                    let suggested = action
                        .conflict
                        .as_ref()
                        .map(|c| suggested_resolution_for(c.kind))
                        .unwrap_or("fork-local");

                    // Build proto ConflictReport.
                    let local_meta = client_files
                        .iter()
                        .find(|m| m.path == action.path)
                        .map(file_meta_to_proto);
                    let remote_meta = server_files
                        .iter()
                        .find(|m| m.path == action.path)
                        .map(file_meta_to_proto);

                    conflict_reports.push(disk_proto::disk::ConflictReport {
                        path: path_str.clone(),
                        local: local_meta,
                        remote: remote_meta,
                        suggested_resolution: suggested.to_string(),
                    });

                    // Compute fork filename for persistence.
                    let fork_rel = disk_core::conflict::fork_filename(
                        &action.path,
                        &node_id,
                        std::time::SystemTime::now(),
                    );
                    let fork_path_str = fork_rel.to_string_lossy().to_string();

                    // Persist conflict record to meta_db.
                    let conflict_record = disk_core::types::ConflictRecord {
                        id: None,
                        vault_id: vault_id.to_string(),
                        path: path_str,
                        conflict_type: action
                            .conflict
                            .as_ref()
                            .map(|c| format!("{:?}", c.kind))
                            .unwrap_or_else(|| "Concurrent".to_string()),
                        local_hash: action.conflict.as_ref().and_then(|c| c.local_hash),
                        remote_hash: action.conflict.as_ref().and_then(|c| c.remote_hash),
                        base_hash: action.conflict.as_ref().and_then(|c| c.base_hash),
                        resolution: None,
                        fork_path: Some(fork_path_str),
                        resolved: false,
                        created_at: 0,
                        resolved_at: None,
                    };
                    if let Err(e) = db.create_conflict(&conflict_record).await {
                        tracing::warn!(
                            path = %action.path.display(),
                            error = %e,
                            "failed to persist conflict record"
                        );
                    }
                }
                // Skip and rename variants — no action needed here.
                _ => {}
            }
        }

        // Build server_clock from the server's MetaDb rows.
        let mut server_clock: std::collections::HashMap<String, u64> =
            std::collections::HashMap::new();
        for m in &server_files {
            for (node, tick) in &m.vector_clock.0 {
                let entry = server_clock.entry(node.clone()).or_insert(0);
                if *tick > *entry {
                    *entry = *tick;
                }
            }
        }

        // Tombstone the server's authoritative files row for every DeleteLocal
        // action so that other clients' next reconcile sees a tombstone rather
        // than a live file (enabling cross-client delete fan-out).
        //
        // Invariants:
        // - Only DeleteLocal triggers this: the reconciler determined that THIS
        //   authenticated client holds delete authority for the path.
        // - The existing row's vector_clock is preserved verbatim (no new tick);
        //   the causal order established by the initiator is carried through.
        // - Idempotent: re-tombstoning an already-deleted row is a no-op.
        {
            use std::time::{SystemTime, UNIX_EPOCH};
            let now_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            for action in &actions {
                if action.action == ActionType::DeleteLocal {
                    if let Some(m) = server_files.iter().find(|m| m.path == action.path) {
                        let tombstone = disk_core::types::FileMeta {
                            deleted: true,
                            deleted_at: Some(now_secs),
                            ..m.clone()
                        };
                        db.upsert_file(&tombstone)
                            .await
                            .map_err(|e| Status::internal(format!("tombstone upsert: {e}")))?;
                    }
                }
            }
        }

        // Write back the updated baseline for this client.
        //
        // The new baseline represents what the client should hold after applying
        // the actions emitted above. This is internally transactional inside
        // upsert_node_baselines (single tx). A failure here returns an error to
        // the client; no silent fallback to an empty baseline (which would
        // re-introduce the original empty-indexed bug on the next sync pass).
        let new_baseline = build_post_sync_baseline(&server_files, &actions);
        db.upsert_node_baselines(&node_id, vault_id, &new_baseline)
            .await
            .map_err(|e| Status::internal(format!("baseline writeback: {e}")))?;

        Ok(Response::new(SyncStateResponse {
            to_upload,
            to_download,
            to_delete,
            conflicts: conflict_reports,
            server_clock,
        }))
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

// ── Conflict helpers ───────────────────────────────────────────────────────

/// Map a `ConflictKind` to the canonical `suggested_resolution` string.
///
/// Mapping:
/// - `Concurrent`           → `"merge"` (3-way merge may resolve it cleanly)
/// - `ModifiedDeleted`      → `"keep-local"` (preserve the modified version)
/// - `RenameRename`         → `"fork-local"` (keep both names via fork)
/// - `DirDeleteChildModify` → `"keep-local"` (child modified — preserve it)
fn suggested_resolution_for(kind: disk_core::types::ConflictKind) -> &'static str {
    use disk_core::types::ConflictKind;
    match kind {
        ConflictKind::Concurrent => "merge",
        ConflictKind::ModifiedDeleted => "keep-local",
        ConflictKind::RenameRename => "fork-local",
        ConflictKind::DirDeleteChildModify => "keep-local",
    }
}

// ── Post-sync baseline builder ─────────────────────────────────────────────

/// Build the baseline snapshot the client should hold after applying `actions`.
///
/// For each path:
/// - `Upload` (client should download) → keep the server's current FileMeta;
///   the client will hold this file after the download.
/// - `Download` (client should upload) → keep the client's version (not in
///   server_files yet); tracked via server_version in the action.
/// - `DeleteLocal` → emit a tombstone entry so the next sync knows the path
///   was previously baseline and was instructed to delete; prevents the path
///   from being re-emitted as to_download on the subsequent pass.
/// - `Skip` → keep the server's version unchanged.
/// - Other variants (ConflictFork, Rename, …) → omit from baseline; the next
///   sync will re-derive from server state.
///
/// Only paths that appear in `actions` are included; paths not mentioned have
/// no action (they are already consistent) and are carried forward from the
/// caller's existing baseline via upsert idempotency.
fn build_post_sync_baseline(
    server_files: &[FileMeta],
    actions: &[disk_core::types::SyncAction],
) -> Vec<FileMeta> {
    use disk_core::types::ActionType;
    use std::time::{SystemTime, UNIX_EPOCH};

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    actions
        .iter()
        .filter_map(|action| match action.action {
            ActionType::Upload | ActionType::Skip => {
                // Find the server's version for this path.
                server_files.iter().find(|m| m.path == action.path).cloned()
            }
            ActionType::Download => {
                // Client has a file the server lacks — baseline the client's version.
                action.server_version.clone()
            }
            ActionType::DeleteLocal | ActionType::DeleteRemote => {
                // Client was told to delete this path — record a tombstone in the
                // baseline so the path is not re-emitted as to_download or to_delete
                // on the next pass (stabilisation / bounce-back prevention).
                server_files
                    .iter()
                    .find(|m| m.path == action.path)
                    .map(|m| FileMeta {
                        deleted: true,
                        deleted_at: Some(now_secs),
                        ..m.clone()
                    })
            }
            // ConflictFork, RenameLocal, RenameRemote — omit.
            _ => None,
        })
        .collect()
}

// ── Proto ↔ domain conversion helpers ──────────────────────────────────────

/// Convert a proto `FileMetadata` into a domain `FileMeta`.
fn proto_to_file_meta(m: &FileMetadata) -> FileMeta {
    let content_hash: [u8; 32] = m.content_hash.as_slice().try_into().unwrap_or([0u8; 32]);

    let mut vc = VectorClock::new();
    for (node, tick) in &m.vector_clock {
        vc.0.insert(node.clone(), *tick);
    }

    FileMeta {
        path: std::path::PathBuf::from(&m.path),
        content_hash,
        size: m.size,
        mtime_ns: m.mtime_ns,
        inode: if m.inode == 0 { None } else { Some(m.inode) },
        vector_clock: vc,
        deleted: m.deleted,
        deleted_at: if m.deleted_at == 0 {
            None
        } else {
            Some(m.deleted_at)
        },
        node_id: m.node_id.clone(),
    }
}

/// Convert a domain `FileMeta` into a proto `FileMetadata`.
fn file_meta_to_proto(m: &FileMeta) -> FileMetadata {
    FileMetadata {
        path: m.path.to_string_lossy().to_string(),
        content_hash: m.content_hash.to_vec(),
        size: m.size,
        mtime_ns: m.mtime_ns,
        inode: m.inode.unwrap_or(0),
        vector_clock: m
            .vector_clock
            .0
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect(),
        deleted: m.deleted,
        deleted_at: m.deleted_at.unwrap_or(0),
        node_id: m.node_id.clone(),
        ..Default::default()
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

    // ── DISK-0043 Step 1: SyncServiceImpl constructs with a MetaDb ──────

    #[tokio::test]
    async fn sync_service_constructs_with_meta_db() {
        let root = tempdir().unwrap();
        let db_dir = tempdir().unwrap();
        let db = disk_core::MetaDb::open(&db_dir.path().join("meta.sqlite"))
            .await
            .unwrap();
        let svc = SyncServiceImpl::new(AuthStore::new(), root.path().to_path_buf())
            .with_meta_db(db, "server-test");
        assert_eq!(svc.server_node_id(), "server-test");
        assert!(svc.meta_db.is_some());
    }

    // ── DISK-0043 Step 2 & 3: delta_upload commits bytes to sync_root + MetaDb ──
    // Unit tests for delta_upload use a real gRPC server (same pattern as
    // two_node_round_trip.rs) because the handler requires Streaming<T>.
    // See crates/disk-server/tests/delta_upload_commit.rs for those tests.

    // ── DISK-0043 Step 4: exchange_state returns real reconcile ─────────

    /// Server has a file; client sends empty state → to_download contains the file.
    #[tokio::test]
    async fn exchange_state_server_file_appears_in_to_download() {
        let root = tempdir().unwrap();
        std::fs::create_dir_all(root.path()).unwrap();
        let db_dir = tempdir().unwrap();
        let db = disk_core::MetaDb::open(&db_dir.path().join("meta.sqlite"))
            .await
            .unwrap();

        // Seed a file into MetaDb.
        let meta = disk_core::types::FileMeta {
            path: std::path::PathBuf::from("wiki/page.md"),
            content_hash: [0xAB; 32],
            size: 100,
            mtime_ns: 1_700_000_000_000_000_000,
            inode: None,
            vector_clock: disk_core::VectorClock::new(),
            deleted: false,
            deleted_at: None,
            node_id: "server".into(),
        };
        db.upsert_file(&meta).await.unwrap();

        let store = AuthStore::new();
        let key = store.register_node("es-node", "N", "linux").unwrap();
        let (token, _) = store.authenticate("es-node", key.as_str()).unwrap();

        let svc = SyncServiceImpl::new(store, root.path().to_path_buf()).with_meta_db(db, "server");

        // Client sends empty file list.
        let mut req = Request::new(SyncStateRequest {
            node_id: "es-node".into(),
            session_token: token.as_str().to_string(),
            files: vec![],
            node_clock: std::collections::HashMap::new(),
            ..Default::default()
        });
        req.metadata_mut().insert(
            "authorization",
            format!("Bearer {}", token.as_str()).parse().unwrap(),
        );

        let resp = svc.exchange_state(req).await.unwrap().into_inner();

        // Server has wiki/page.md; client has nothing → to_download = [wiki/page.md]
        assert_eq!(
            resp.to_download.len(),
            1,
            "client should be told to download server's file"
        );
        assert_eq!(resp.to_download[0].path, "wiki/page.md");
    }

    /// Client has a file; server has empty state → to_upload contains the file.
    #[tokio::test]
    async fn exchange_state_client_file_appears_in_to_upload() {
        let root = tempdir().unwrap();
        std::fs::create_dir_all(root.path()).unwrap();
        let db_dir = tempdir().unwrap();
        let db = disk_core::MetaDb::open(&db_dir.path().join("meta.sqlite"))
            .await
            .unwrap();

        let store = AuthStore::new();
        let key = store.register_node("eu-node", "N", "linux").unwrap();
        let (token, _) = store.authenticate("eu-node", key.as_str()).unwrap();

        let svc = SyncServiceImpl::new(store, root.path().to_path_buf()).with_meta_db(db, "server");

        // Client sends one file.
        let client_file = FileMetadata {
            path: "notes/hello.md".into(),
            content_hash: [0xCC; 32].to_vec(),
            size: 42,
            mtime_ns: 1_700_000_000_000_000_000,
            ..Default::default()
        };
        let mut req = Request::new(SyncStateRequest {
            node_id: "eu-node".into(),
            session_token: token.as_str().to_string(),
            files: vec![client_file],
            node_clock: std::collections::HashMap::new(),
            ..Default::default()
        });
        req.metadata_mut().insert(
            "authorization",
            format!("Bearer {}", token.as_str()).parse().unwrap(),
        );

        let resp = svc.exchange_state(req).await.unwrap().into_inner();

        // Server has nothing; client has notes/hello.md → to_upload = [notes/hello.md]
        assert_eq!(
            resp.to_upload.len(),
            1,
            "client should be told to upload its file"
        );
        assert_eq!(resp.to_upload[0].path, "notes/hello.md");
    }

    // ── Delete propagation + per-client baseline (V-AC-1, V-AC-2, V-AC-4) ──

    /// Helper: build a fully wired service with MetaDb, register one node, and
    /// return the service + bearer token for that node.
    async fn make_service_with_db(
        node_label: &str,
    ) -> (
        SyncServiceImpl,
        String,
        tempfile::TempDir,
        tempfile::TempDir,
    ) {
        let root = tempdir().unwrap();
        let db_dir = tempdir().unwrap();
        std::fs::create_dir_all(root.path()).unwrap();
        let db = disk_core::MetaDb::open(&db_dir.path().join("meta.sqlite"))
            .await
            .unwrap();
        let store = AuthStore::new();
        let key = store.register_node(node_label, "N", "linux").unwrap();
        let (token, _) = store.authenticate(node_label, key.as_str()).unwrap();
        let svc = SyncServiceImpl::new(store, root.path().to_path_buf()).with_meta_db(db, "server");
        (svc, token.as_str().to_string(), root, db_dir)
    }

    fn auth_req<T>(inner: T, token: &str) -> Request<T> {
        let mut req = Request::new(inner);
        req.metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        req
    }

    /// V-AC-2: FileMeta with deleted=true round-trips through proto conversion
    /// and through node_baselines persistence.
    #[tokio::test]
    async fn proto_filemeta_tombstone_round_trip() {
        let deleted_at_ts: i64 = 1_700_000_777;

        // Proto → FileMeta → proto round-trip.
        let proto_in = FileMetadata {
            path: "vault/gone.md".into(),
            content_hash: [0xDD; 32].to_vec(),
            size: 0,
            mtime_ns: 1_700_000_000_000_000_000,
            deleted: true,
            deleted_at: deleted_at_ts,
            node_id: "client-x".into(),
            ..Default::default()
        };
        let domain = proto_to_file_meta(&proto_in);
        assert!(domain.deleted, "proto→domain: deleted must be true");
        assert_eq!(
            domain.deleted_at,
            Some(deleted_at_ts),
            "proto→domain: deleted_at must survive conversion"
        );

        let proto_out = file_meta_to_proto(&domain);
        assert!(proto_out.deleted, "domain→proto: deleted must be true");
        assert_eq!(
            proto_out.deleted_at, deleted_at_ts,
            "domain→proto: deleted_at must survive conversion"
        );

        // Persist through node_baselines and reload.
        let db_dir = tempdir().unwrap();
        let db = disk_core::MetaDb::open(&db_dir.path().join("meta.sqlite"))
            .await
            .unwrap();
        db.upsert_node_baselines("node-rt", "default", std::slice::from_ref(&domain))
            .await
            .unwrap();
        let loaded = db.load_node_baseline("node-rt", "default").await.unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(
            loaded[0].deleted,
            "loaded baseline: deleted flag must be preserved"
        );
        assert_eq!(
            loaded[0].deleted_at,
            Some(deleted_at_ts),
            "loaded baseline: deleted_at must be preserved"
        );
    }

    /// V-AC-4: exchange_state uses a persistent node baseline as `indexed`
    /// instead of always passing `&[]`.
    ///
    /// Control: server has "wiki/seeded.md", NO baseline for client → server
    /// routes the file to `to_download` (first-sync behaviour, indexed=&[]).
    ///
    /// Assert: after seeding a baseline that includes "wiki/seeded.md" for the
    /// same client, exchange_state (with empty client files) routes "wiki/seeded.md"
    /// to `to_delete` rather than `to_download` — proving the baseline is loaded
    /// and fed to the reconciler.
    #[tokio::test]
    async fn sync_state_uses_persistent_node_baseline() {
        let (svc, token, _root, _db_dir) = make_service_with_db("vac4-node").await;

        // Seed "wiki/seeded.md" in the server's MetaDb.
        let server_meta = disk_core::types::FileMeta {
            path: std::path::PathBuf::from("wiki/seeded.md"),
            content_hash: [0xAA; 32],
            size: 512,
            mtime_ns: 1_700_000_000_000_000_000,
            inode: None,
            vector_clock: disk_core::VectorClock::new(),
            deleted: false,
            deleted_at: None,
            node_id: "server".into(),
        };
        svc.meta_db
            .as_ref()
            .unwrap()
            .upsert_file(&server_meta)
            .await
            .unwrap();

        // Control pass: no baseline → file must appear in to_download.
        let resp_no_baseline = svc
            .exchange_state(auth_req(
                SyncStateRequest {
                    node_id: "vac4-node".into(),
                    session_token: token.clone(),
                    files: vec![],
                    node_clock: std::collections::HashMap::new(),
                    ..Default::default()
                },
                &token,
            ))
            .await
            .unwrap()
            .into_inner();
        assert!(
            resp_no_baseline
                .to_download
                .iter()
                .any(|f| f.path == "wiki/seeded.md"),
            "control: without baseline, server file must appear in to_download"
        );
        assert!(
            resp_no_baseline
                .to_delete
                .iter()
                .all(|f| f.path != "wiki/seeded.md"),
            "control: without baseline, server file must NOT appear in to_delete"
        );

        // Seed the node's baseline with "wiki/seeded.md" — simulates a prior sync pass.
        let baseline_entry = disk_core::types::FileMeta {
            path: std::path::PathBuf::from("wiki/seeded.md"),
            content_hash: [0xAA; 32],
            size: 512,
            mtime_ns: 1_700_000_000_000_000_000,
            inode: None,
            vector_clock: disk_core::VectorClock::new(),
            deleted: false,
            deleted_at: None,
            node_id: "server".into(),
        };
        // require_auth returns the node_label used at register_node time ("vac4-node").
        svc.meta_db
            .as_ref()
            .unwrap()
            .upsert_node_baselines("vac4-node", "default", &[baseline_entry])
            .await
            .unwrap();

        // Now client sends empty file list (simulating the file was deleted on client).
        // With baseline loaded, reconciler emits DeleteLocal → to_delete.
        let resp_with_baseline = svc
            .exchange_state(auth_req(
                SyncStateRequest {
                    node_id: "vac4-node".into(),
                    session_token: token.clone(),
                    files: vec![],
                    node_clock: std::collections::HashMap::new(),
                    ..Default::default()
                },
                &token,
            ))
            .await
            .unwrap()
            .into_inner();
        assert!(
            resp_with_baseline
                .to_delete
                .iter()
                .any(|f| f.path == "wiki/seeded.md"),
            "with baseline: client-deleted file must appear in to_delete"
        );
        assert!(
            resp_with_baseline
                .to_download
                .iter()
                .all(|f| f.path != "wiki/seeded.md"),
            "with baseline: client-deleted file must NOT appear in to_download"
        );
    }

    // ── DISK-0046: second-client delete fan-out ──────────────────────────────

    /// V-AC-3: ActionType::DeleteRemote must push a path into to_delete.
    ///
    /// Triplet: server=tombstone, client=live file, baseline=live file
    /// → reconciler emits DeleteRemote → server must include path in to_delete.
    ///
    /// RED pre-fix (DeleteRemote falls into _ => {} and to_delete stays empty).
    #[tokio::test]
    async fn delete_remote_action_maps_to_client_to_delete() {
        let (svc, token, _root, _db_dir) = make_service_with_db("vac3-node").await;

        // Server holds a tombstone for "doc/gone.md".
        let server_tomb = disk_core::types::FileMeta {
            path: std::path::PathBuf::from("doc/gone.md"),
            content_hash: [0x33; 32],
            size: 100,
            mtime_ns: 1_700_000_000_000_000_000,
            inode: None,
            vector_clock: disk_core::VectorClock::new(),
            deleted: true,
            deleted_at: Some(1_700_000_001),
            node_id: "server".into(),
        };
        let db = svc.meta_db.as_ref().unwrap();
        db.upsert_file(&server_tomb).await.unwrap();

        // Client's baseline records the file as live (it saw it on prior sync).
        let baseline_live = disk_core::types::FileMeta {
            deleted: false,
            deleted_at: None,
            ..server_tomb.clone()
        };
        db.upsert_node_baselines("vac3-node", "default", &[baseline_live])
            .await
            .unwrap();

        // Client still reports the file as live.
        let client_live = FileMetadata {
            path: "doc/gone.md".into(),
            content_hash: [0x33; 32].to_vec(),
            size: 100,
            mtime_ns: 1_700_000_000_000_000_000,
            deleted: false,
            ..Default::default()
        };
        let resp = svc
            .exchange_state(auth_req(
                SyncStateRequest {
                    node_id: "vac3-node".into(),
                    session_token: token.clone(),
                    files: vec![client_live],
                    node_clock: std::collections::HashMap::new(),
                    ..Default::default()
                },
                &token,
            ))
            .await
            .unwrap()
            .into_inner();

        assert!(
            resp.to_delete.iter().any(|f| f.path == "doc/gone.md"),
            "DeleteRemote: path must appear in to_delete"
        );
        assert!(
            resp.to_download.iter().all(|f| f.path != "doc/gone.md"),
            "DeleteRemote: path must NOT appear in to_download"
        );
    }

    /// V-AC-2: after a DeleteLocal pass, the server's authoritative files row
    /// must be tombstoned (deleted=true, deleted_at set).
    ///
    /// Flow: seed server file + client baseline → client sends empty list
    /// (DeleteLocal emitted) → reload server files row → assert deleted=true.
    ///
    /// RED pre-fix (server row stays live; only per-client baseline is updated).
    #[tokio::test]
    async fn sync_state_delete_local_tombstones_server_files_row() {
        let (svc, token, _root, _db_dir) = make_service_with_db("vac2-node").await;

        let file_meta = disk_core::types::FileMeta {
            path: std::path::PathBuf::from("vault/note.md"),
            content_hash: [0x22; 32],
            size: 200,
            mtime_ns: 1_700_000_000_000_000_000,
            inode: None,
            vector_clock: disk_core::VectorClock::new(),
            deleted: false,
            deleted_at: None,
            node_id: "server".into(),
        };
        let db = svc.meta_db.as_ref().unwrap();
        db.upsert_file(&file_meta).await.unwrap();
        db.upsert_node_baselines("vac2-node", "default", &[file_meta])
            .await
            .unwrap();

        // Client sends empty file list → DeleteLocal → tombstone should be written.
        svc.exchange_state(auth_req(
            SyncStateRequest {
                node_id: "vac2-node".into(),
                session_token: token.clone(),
                files: vec![],
                node_clock: std::collections::HashMap::new(),
                ..Default::default()
            },
            &token,
        ))
        .await
        .unwrap();

        // Reload the server's authoritative files row.
        let db = svc.meta_db.as_ref().unwrap();
        let server_files = db.list_all_files().await.unwrap();
        let row = server_files
            .iter()
            .find(|m| m.path.to_string_lossy() == "vault/note.md")
            .expect("server row must still exist after delete");

        assert!(
            row.deleted,
            "server files row must be tombstoned (deleted=true)"
        );
        assert!(
            row.deleted_at.is_some(),
            "server files row must have deleted_at set"
        );
    }

    /// V-AC-1: two-client delete fan-out.
    ///
    /// Flow: register two nodes (A, B); A and B both sync a file;
    /// A sends empty list (A deletes → server tombstones authoritative row);
    /// B syncs → B must receive path in to_delete.
    ///
    /// RED pre-fix (server row not tombstoned; B gets to_download instead).
    #[tokio::test]
    async fn sync_state_second_client_receives_delete_fan_out() {
        let root = tempfile::tempdir().unwrap();
        let db_dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path()).unwrap();
        let db = disk_core::MetaDb::open(&db_dir.path().join("meta.sqlite"))
            .await
            .unwrap();
        let store = AuthStore::new();

        // Register node A.
        let key_a = store.register_node("fan-a", "N", "linux").unwrap();
        let (tok_a, _) = store.authenticate("fan-a", key_a.as_str()).unwrap();
        let tok_a = tok_a.as_str().to_string();

        // Register node B on the SAME service (shared store + db).
        let key_b = store.register_node("fan-b", "N", "linux").unwrap();
        let (tok_b, _) = store.authenticate("fan-b", key_b.as_str()).unwrap();
        let tok_b = tok_b.as_str().to_string();

        let svc = SyncServiceImpl::new(store, root.path().to_path_buf()).with_meta_db(db, "server");

        let shared_file = disk_core::types::FileMeta {
            path: std::path::PathBuf::from("shared/page.md"),
            content_hash: [0x55; 32],
            size: 300,
            mtime_ns: 1_700_000_000_000_000_000,
            inode: None,
            vector_clock: disk_core::VectorClock::new(),
            deleted: false,
            deleted_at: None,
            node_id: "server".into(),
        };

        let db_ref = svc.meta_db.as_ref().unwrap();
        // Seed server authoritative row + baselines for both A and B.
        db_ref.upsert_file(&shared_file).await.unwrap();
        db_ref
            .upsert_node_baselines("fan-a", "default", std::slice::from_ref(&shared_file))
            .await
            .unwrap();
        db_ref
            .upsert_node_baselines("fan-b", "default", std::slice::from_ref(&shared_file))
            .await
            .unwrap();

        // A deletes: sends empty file list → server should tombstone authoritative row.
        svc.exchange_state(auth_req(
            SyncStateRequest {
                node_id: "fan-a".into(),
                session_token: tok_a.clone(),
                files: vec![],
                node_clock: std::collections::HashMap::new(),
                ..Default::default()
            },
            &tok_a,
        ))
        .await
        .unwrap();

        // B syncs: still reports the file as live.
        let b_live = FileMetadata {
            path: "shared/page.md".into(),
            content_hash: [0x55; 32].to_vec(),
            size: 300,
            mtime_ns: 1_700_000_000_000_000_000,
            deleted: false,
            ..Default::default()
        };
        let resp_b = svc
            .exchange_state(auth_req(
                SyncStateRequest {
                    node_id: "fan-b".into(),
                    session_token: tok_b.clone(),
                    files: vec![b_live],
                    node_clock: std::collections::HashMap::new(),
                    ..Default::default()
                },
                &tok_b,
            ))
            .await
            .unwrap()
            .into_inner();

        assert!(
            resp_b.to_delete.iter().any(|f| f.path == "shared/page.md"),
            "second client must receive the deleted file in to_delete"
        );
        assert!(
            resp_b
                .to_download
                .iter()
                .all(|f| f.path != "shared/page.md"),
            "second client must NOT receive the file in to_download"
        );
    }

    /// V-AC-5: after client B ACKs delete (sends empty state), a subsequent
    /// sync from B must not resurrect the file (Skip, no to_download).
    #[tokio::test]
    async fn sync_state_deleted_file_not_resurrected_after_ack() {
        let root = tempfile::tempdir().unwrap();
        let db_dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path()).unwrap();
        let db = disk_core::MetaDb::open(&db_dir.path().join("meta.sqlite"))
            .await
            .unwrap();
        let store = AuthStore::new();

        let key = store.register_node("ack-node", "N", "linux").unwrap();
        let (tok, _) = store.authenticate("ack-node", key.as_str()).unwrap();
        let tok = tok.as_str().to_string();

        let svc = SyncServiceImpl::new(store, root.path().to_path_buf()).with_meta_db(db, "server");

        let file_meta = disk_core::types::FileMeta {
            path: std::path::PathBuf::from("notes/to-delete.md"),
            content_hash: [0x77; 32],
            size: 50,
            mtime_ns: 1_700_000_000_000_000_000,
            inode: None,
            vector_clock: disk_core::VectorClock::new(),
            deleted: false,
            deleted_at: None,
            node_id: "server".into(),
        };
        let db_ref = svc.meta_db.as_ref().unwrap();
        // Server tombstone already in place (simulates fan-out already applied).
        let tomb = disk_core::types::FileMeta {
            deleted: true,
            deleted_at: Some(1_700_000_999),
            ..file_meta.clone()
        };
        db_ref.upsert_file(&tomb).await.unwrap();
        // B had a live baseline before receiving the delete instruction.
        db_ref
            .upsert_node_baselines("ack-node", "default", &[file_meta])
            .await
            .unwrap();

        // First sync: B still has the file → receives DeleteRemote (to_delete).
        let b_live = FileMetadata {
            path: "notes/to-delete.md".into(),
            content_hash: [0x77; 32].to_vec(),
            size: 50,
            mtime_ns: 1_700_000_000_000_000_000,
            ..Default::default()
        };
        let resp1 = svc
            .exchange_state(auth_req(
                SyncStateRequest {
                    node_id: "ack-node".into(),
                    session_token: tok.clone(),
                    files: vec![b_live],
                    node_clock: std::collections::HashMap::new(),
                    ..Default::default()
                },
                &tok,
            ))
            .await
            .unwrap()
            .into_inner();
        assert!(
            resp1
                .to_delete
                .iter()
                .any(|f| f.path == "notes/to-delete.md"),
            "first sync: file must appear in to_delete"
        );

        // ACK: B sends empty file list (it applied the delete).
        let resp2 = svc
            .exchange_state(auth_req(
                SyncStateRequest {
                    node_id: "ack-node".into(),
                    session_token: tok.clone(),
                    files: vec![],
                    node_clock: std::collections::HashMap::new(),
                    ..Default::default()
                },
                &tok,
            ))
            .await
            .unwrap()
            .into_inner();
        // No resurrection: file must not appear in either to_download or to_delete.
        assert!(
            resp2
                .to_download
                .iter()
                .all(|f| f.path != "notes/to-delete.md"),
            "ack pass: file must NOT appear in to_download (no resurrection)"
        );
        assert!(
            resp2
                .to_delete
                .iter()
                .all(|f| f.path != "notes/to-delete.md"),
            "ack pass: file must NOT appear in to_delete again"
        );
    }

    /// V-AC-1: a file synced client→server, then omitted from the next sync
    /// request (simulating client deletion), must appear in to_delete and NOT
    /// in to_download.
    #[tokio::test]
    async fn sync_state_deleted_client_file_marks_to_delete() {
        let (svc, token, _root, _db_dir) = make_service_with_db("vac1-node").await;

        // Simulate: file was previously synced — seed both server MetaDb and
        // the client's baseline (as exchange_state writeback would have done).
        let synced_meta = disk_core::types::FileMeta {
            path: std::path::PathBuf::from("docs/synced.md"),
            content_hash: [0x11; 32],
            size: 256,
            mtime_ns: 1_700_000_000_000_000_000,
            inode: None,
            vector_clock: disk_core::VectorClock::new(),
            deleted: false,
            deleted_at: None,
            node_id: "server".into(),
        };
        let db = svc.meta_db.as_ref().unwrap();
        db.upsert_file(&synced_meta).await.unwrap();
        db.upsert_node_baselines("vac1-node", "default", &[synced_meta])
            .await
            .unwrap();

        // Second sync: client sends empty file list (file was deleted on client).
        let resp = svc
            .exchange_state(auth_req(
                SyncStateRequest {
                    node_id: "vac1-node".into(),
                    session_token: token.clone(),
                    files: vec![],
                    node_clock: std::collections::HashMap::new(),
                    ..Default::default()
                },
                &token,
            ))
            .await
            .unwrap()
            .into_inner();

        assert!(
            resp.to_delete.iter().any(|f| f.path == "docs/synced.md"),
            "client-deleted synced file must appear in to_delete"
        );
        assert!(
            resp.to_download.iter().all(|f| f.path != "docs/synced.md"),
            "client-deleted synced file must NOT appear in to_download"
        );
    }

    // ── DISK-0047: three-client recreate-after-delete ────────────────────────

    /// V-AC-5: full delete→recreate→lagging-C path returns Ok (no Inconsistent/500).
    ///
    /// Setup:
    /// - Server has "data/page.md" (recreated, hash 0x99).
    /// - C's baseline is a tombstone for "data/page.md" (A deleted it earlier,
    ///   fan-out wrote a tomb baseline for C).
    /// - C still reports "data/page.md" as live (its pre-delete copy, hash 0xCC).
    ///
    /// Reconciler triple: (l=present/server-recreate, r=present/C-old, i=tomb).
    /// Expected: exchange_state returns Ok, file appears in to_upload (Download arm
    /// → client delivers its conflicting copy), NOT as an Inconsistent/500 error.
    #[tokio::test]
    async fn sync_state_three_client_recreate_with_lagging_baseline() {
        let root = tempfile::tempdir().unwrap();
        let db_dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path()).unwrap();
        let db = disk_core::MetaDb::open(&db_dir.path().join("meta.sqlite"))
            .await
            .unwrap();
        let store = AuthStore::new();

        let key_c = store.register_node("rec-c", "N", "linux").unwrap();
        let (tok_c, _) = store.authenticate("rec-c", key_c.as_str()).unwrap();
        let tok_c = tok_c.as_str().to_string();

        let svc = SyncServiceImpl::new(store, root.path().to_path_buf()).with_meta_db(db, "server");
        let db_ref = svc.meta_db.as_ref().unwrap();

        // Server holds the recreated file (hash 0x99).
        let server_recreated = disk_core::types::FileMeta {
            path: std::path::PathBuf::from("data/page.md"),
            content_hash: [0x99; 32],
            size: 400,
            mtime_ns: 1_700_000_002_000_000_000,
            inode: None,
            vector_clock: disk_core::VectorClock::new(),
            deleted: false,
            deleted_at: None,
            node_id: "server".into(),
        };
        db_ref.upsert_file(&server_recreated).await.unwrap();

        // C's baseline is a tombstone — fan-out from A's delete wrote this.
        let c_baseline_tomb = disk_core::types::FileMeta {
            path: std::path::PathBuf::from("data/page.md"),
            content_hash: [0xCC; 32],
            size: 300,
            mtime_ns: 1_700_000_000_000_000_000,
            inode: None,
            vector_clock: disk_core::VectorClock::new(),
            deleted: true,
            deleted_at: Some(1_700_000_001),
            node_id: "server".into(),
        };
        db_ref
            .upsert_node_baselines("rec-c", "default", &[c_baseline_tomb])
            .await
            .unwrap();

        // C reports "data/page.md" as live (its pre-delete copy, hash 0xCC).
        let c_live = FileMetadata {
            path: "data/page.md".into(),
            content_hash: [0xCC; 32].to_vec(),
            size: 300,
            mtime_ns: 1_700_000_000_000_000_000,
            deleted: false,
            ..Default::default()
        };

        // The call must NOT return an error (was previously Inconsistent → HTTP 500).
        let resp = svc
            .exchange_state(auth_req(
                SyncStateRequest {
                    node_id: "rec-c".into(),
                    session_token: tok_c.clone(),
                    files: vec![c_live],
                    node_clock: std::collections::HashMap::new(),
                    ..Default::default()
                },
                &tok_c,
            ))
            .await
            .expect("exchange_state must return Ok for (P,P,T) triple — not Inconsistent/500")
            .into_inner();

        // Download action → to_upload (client delivers conflicting copy); not to_download.
        assert!(
            resp.to_upload.iter().any(|f| f.path == "data/page.md"),
            "three-client recreate: lagging C's copy must appear in to_upload (conflict resolution)"
        );
        assert!(
            resp.to_download.iter().all(|f| f.path != "data/page.md"),
            "three-client recreate: path must NOT appear in to_download"
        );
    }

    /// V-AC-6: divergent three-client recreate preserves C's bytes (no silent data loss).
    ///
    /// In the divergent case (C's pre-delete hash != server's recreated hash), the
    /// reconciler emits Download + ConflictKind::ModifiedDeleted with local_hash = C's
    /// original bytes. This test verifies that C's content is delivered to the server
    /// (to_upload) rather than silently discarded, satisfying the no-silent-data-loss
    /// requirement. The ConflictReport in the SyncAction confirms which bytes were
    /// preserved at the reconciler level (verified via a direct reconciler call).
    #[tokio::test]
    async fn sync_state_three_client_recreate_no_silent_data_loss() {
        let root = tempfile::tempdir().unwrap();
        let db_dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path()).unwrap();
        let db = disk_core::MetaDb::open(&db_dir.path().join("meta.sqlite"))
            .await
            .unwrap();
        let store = AuthStore::new();

        let key_c = store.register_node("loss-c", "N", "linux").unwrap();
        let (tok_c, _) = store.authenticate("loss-c", key_c.as_str()).unwrap();
        let tok_c = tok_c.as_str().to_string();

        let svc = SyncServiceImpl::new(store, root.path().to_path_buf()).with_meta_db(db, "server");
        let db_ref = svc.meta_db.as_ref().unwrap();

        // Server: recreated file with hash 0xBB (different from C's 0xDD).
        let server_recreated = disk_core::types::FileMeta {
            path: std::path::PathBuf::from("vault/note.md"),
            content_hash: [0xBB; 32],
            size: 512,
            mtime_ns: 1_700_000_002_000_000_000,
            inode: None,
            vector_clock: disk_core::VectorClock::new(),
            deleted: false,
            deleted_at: None,
            node_id: "server".into(),
        };
        db_ref.upsert_file(&server_recreated).await.unwrap();

        // C's baseline: tombstone (from A's delete fan-out).
        let c_tomb_baseline = disk_core::types::FileMeta {
            path: std::path::PathBuf::from("vault/note.md"),
            content_hash: [0xDD; 32],
            size: 200,
            mtime_ns: 1_700_000_000_000_000_000,
            inode: None,
            vector_clock: disk_core::VectorClock::new(),
            deleted: true,
            deleted_at: Some(1_700_000_001),
            node_id: "server".into(),
        };
        db_ref
            .upsert_node_baselines("loss-c", "default", &[c_tomb_baseline])
            .await
            .unwrap();

        // C reports "vault/note.md" as live with hash 0xDD (its pre-delete copy).
        let c_live = FileMetadata {
            path: "vault/note.md".into(),
            content_hash: [0xDD; 32].to_vec(),
            size: 200,
            mtime_ns: 1_700_000_000_000_000_000,
            deleted: false,
            ..Default::default()
        };

        // exchange_state must return Ok and route C's copy to to_upload (not discard it).
        let resp = svc
            .exchange_state(auth_req(
                SyncStateRequest {
                    node_id: "loss-c".into(),
                    session_token: tok_c.clone(),
                    files: vec![c_live],
                    node_clock: std::collections::HashMap::new(),
                    ..Default::default()
                },
                &tok_c,
            ))
            .await
            .expect("exchange_state must return Ok — no silent Inconsistent error")
            .into_inner();

        // C's copy must be preserved (routed to to_upload for server to store/conflict-resolve),
        // not silently discarded. to_download must not contain the path (server recreate
        // is not blindly pushed back to C without acknowledging the conflict).
        assert!(
            resp.to_upload.iter().any(|f| f.path == "vault/note.md"),
            "no-silent-data-loss: C's divergent copy must be routed to to_upload, not discarded"
        );
        assert!(
            resp.to_download.iter().all(|f| f.path != "vault/note.md"),
            "no-silent-data-loss: server must not blindly push recreated file to C \
             without acknowledging the conflict"
        );

        // Verify at the reconciler level that ConflictReport captured C's bytes.
        // This is the definitive proof that no silent data loss occurred.
        let engine = disk_core::reconciler::ReconciliationEngine::new("server".into());
        let local_server = vec![disk_core::types::FileMeta {
            path: std::path::PathBuf::from("vault/note.md"),
            content_hash: [0xBB; 32],
            size: 512,
            mtime_ns: 1_700_000_002_000_000_000,
            inode: None,
            vector_clock: disk_core::VectorClock::new(),
            deleted: false,
            deleted_at: None,
            node_id: "server".into(),
        }];
        let remote_client = vec![disk_core::types::FileMeta {
            path: std::path::PathBuf::from("vault/note.md"),
            content_hash: [0xDD; 32],
            size: 200,
            mtime_ns: 1_700_000_000_000_000_000,
            inode: None,
            vector_clock: disk_core::VectorClock::new(),
            deleted: false,
            deleted_at: None,
            node_id: "loss-c".into(),
        }];
        let indexed_tomb = vec![disk_core::types::FileMeta {
            path: std::path::PathBuf::from("vault/note.md"),
            content_hash: [0xDD; 32],
            size: 200,
            mtime_ns: 1_700_000_000_000_000_000,
            inode: None,
            vector_clock: disk_core::VectorClock::new(),
            deleted: true,
            deleted_at: Some(1_700_000_001),
            node_id: "server".into(),
        }];
        let actions = engine
            .reconcile(&local_server, &remote_client, &indexed_tomb)
            .unwrap();
        let action = actions.first().unwrap();
        let conflict = action
            .conflict
            .as_ref()
            .expect("divergent (P,P,T): ConflictReport must be present to prove no data loss");
        assert_eq!(
            conflict.local_hash,
            Some([0xBB; 32]),
            "ConflictReport.local_hash must be server's recreated copy (0xBB)"
        );
        assert_eq!(
            conflict.remote_hash,
            Some([0xDD; 32]),
            "ConflictReport.remote_hash must be C's pre-delete copy (0xDD) — bytes preserved"
        );
    }

    // ── conflict_transport: ConflictFork actions populate SyncStateResponse ──

    /// When the reconciler produces a ConflictFork action, exchange_state must:
    /// 1. Include a non-empty `conflicts` list in the response.
    /// 2. Persist a row to the `conflicts` table (fork_path set).
    /// 3. Set a non-empty `suggested_resolution` on the ConflictReport.
    ///
    /// Setup: server has "shared.md" with hash [0xAA;32]; client sends
    /// "shared.md" with a *different* hash [0xBB;32].  Both sides have the
    /// file in the node baseline with the SAME original hash [0xCC;32], so
    /// from the reconciler's perspective both sides diverged from a common
    /// ancestor → ConflictFork.
    #[tokio::test]
    async fn conflict_transport_fork_populates_response_and_db() {
        let (svc, token, _root, _db_dir) = make_service_with_db("ct-node").await;

        // Server side: seed "shared.md" with hash [0xAA;32].
        let server_vc = {
            let mut vc = disk_core::VectorClock::new();
            vc.advance("server");
            vc.advance("server"); // tick=2
            vc
        };
        let server_file = disk_core::types::FileMeta {
            path: std::path::PathBuf::from("shared.md"),
            content_hash: [0xAA; 32],
            size: 100,
            mtime_ns: 1_700_000_002_000_000_000,
            inode: None,
            vector_clock: server_vc,
            deleted: false,
            deleted_at: None,
            node_id: "server".into(),
        };
        svc.meta_db
            .as_ref()
            .unwrap()
            .upsert_file(&server_file)
            .await
            .unwrap();

        // Baseline for "ct-node": shared.md was at hash [0xCC;32] (common ancestor).
        let base_vc = disk_core::VectorClock::new(); // tick=0 for both
        let baseline_file = disk_core::types::FileMeta {
            path: std::path::PathBuf::from("shared.md"),
            content_hash: [0xCC; 32],
            size: 80,
            mtime_ns: 1_700_000_000_000_000_000,
            inode: None,
            vector_clock: base_vc,
            deleted: false,
            deleted_at: None,
            node_id: "ct-node".into(),
        };
        svc.meta_db
            .as_ref()
            .unwrap()
            .upsert_node_baselines("ct-node", "default", &[baseline_file])
            .await
            .unwrap();

        // Client sends "shared.md" with hash [0xBB;32] and a divergent clock.
        let mut client_vc_map = std::collections::HashMap::new();
        client_vc_map.insert("ct-node".to_string(), 2u64); // tick=2 (diverged)
        let client_file = FileMetadata {
            path: "shared.md".into(),
            content_hash: [0xBB; 32].to_vec(),
            size: 110,
            mtime_ns: 1_700_000_003_000_000_000,
            vector_clock: client_vc_map,
            node_id: "ct-node".into(),
            ..Default::default()
        };

        let req = auth_req(
            SyncStateRequest {
                node_id: "ct-node".into(),
                session_token: token.clone(),
                files: vec![client_file],
                node_clock: std::collections::HashMap::new(),
                ..Default::default()
            },
            &token,
        );

        let resp = svc.exchange_state(req).await.unwrap().into_inner();

        // Assert 1: conflicts list is non-empty.
        assert!(
            !resp.conflicts.is_empty(),
            "conflicts must be populated when ConflictFork action is present"
        );
        let conflict = &resp.conflicts[0];
        assert_eq!(conflict.path, "shared.md");
        assert!(
            !conflict.suggested_resolution.is_empty(),
            "suggested_resolution must be non-empty"
        );

        // Assert 2: conflict row persisted in meta_db with fork_path set.
        let db_conflicts = svc
            .meta_db
            .as_ref()
            .unwrap()
            .list_unresolved_conflicts()
            .await
            .unwrap();
        assert!(
            !db_conflicts.is_empty(),
            "conflict must be persisted in meta_db"
        );
        let db_conflict = db_conflicts
            .iter()
            .find(|c| c.path == "shared.md")
            .expect("conflict row for shared.md must exist");
        assert!(
            db_conflict.fork_path.is_some(),
            "fork_path must be set in the persisted conflict record"
        );
        assert!(
            !db_conflict.fork_path.as_ref().unwrap().is_empty(),
            "fork_path must be non-empty"
        );
    }
}
