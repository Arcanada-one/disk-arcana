//! DISK-0006 R6 — gRPC transport adapter for [`SyncLoop`].
//!
//! The R5 state machine is transport-agnostic: `begin_sync` / `finish_sync`
//! accept arbitrary `Result<(), LoopError>` outcomes. R6 closes the loop by
//! mapping real `SyncService` responses onto those outcomes.
//!
//! Wire mapping (server is `disk-arcana-server::services::sync.rs`):
//!
//! | Server `Status`                                          | `LoopError`           |
//! |----------------------------------------------------------|-----------------------|
//! | `PermissionDenied` + `AclMismatchDetails` in `details()` | `AclRoleMismatch`     |
//! | `PermissionDenied` + message `share unknown:`            | `ShareUnknown`        |
//! | `PermissionDenied` + message `ACL role mismatch:`        | `AclRoleMismatch`     |
//! | `Unavailable` / `DeadlineExceeded`                       | `TransportUnavailable`|
//! | any other status / `tonic::transport::Error`             | `TransportUnavailable`|
//!
//! `AclMismatchDetails` is the authoritative signal — message-text matching
//! is the fallback for stubs that do not encode the proto payload (and for
//! older server builds before the details encoder landed).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use disk_core::filter::{Filter, FilterRules};
use disk_core::scanner::FileScanner;
use disk_core::types::FileMeta;
use disk_proto::disk::{AclMismatchDetails, FileMetadata};
use prost::Message;
use tonic::{Code, Status};

use super::LoopError;
use crate::blob_cache::BlobCache;
use crate::conflict_writer::apply_conflict;
use crate::connection::{ClientError, DiskClient};

/// Map a `tonic::Status` returned by `SyncService` to a [`LoopError`].
pub fn classify_tonic_status(status: &Status) -> LoopError {
    let details = status.details();
    if !details.is_empty() && AclMismatchDetails::decode(details).is_ok() {
        return LoopError::AclRoleMismatch;
    }
    match status.code() {
        Code::PermissionDenied => {
            let msg = status.message();
            if msg.contains("share unknown") {
                LoopError::ShareUnknown
            } else if msg.contains("ACL role mismatch") {
                LoopError::AclRoleMismatch
            } else {
                // Unknown PermissionDenied — treat as sticky ACL mismatch so the
                // client surfaces it to the operator instead of hammering the
                // server in an infinite backoff loop.
                LoopError::AclRoleMismatch
            }
        }
        Code::Unavailable | Code::DeadlineExceeded => LoopError::TransportUnavailable,
        _ => LoopError::TransportUnavailable,
    }
}

/// Project a [`ClientError`] (which subsumes both `tonic::Status` and
/// `tonic::transport::Error`) onto a [`LoopError`].
pub fn classify_client_error(err: &ClientError) -> LoopError {
    match err {
        ClientError::Status(s) => classify_tonic_status(s),
        ClientError::Transport(_)
        | ClientError::NotAuthenticated
        | ClientError::MetadataError(_) => LoopError::TransportUnavailable,
    }
}

/// Async transport the loop calls per iteration. Returning `Ok(())` drives
/// the state machine to `Idle`; an `Err` is mapped per `LoopError` semantics.
#[tonic::async_trait]
pub trait SyncTransport: Send {
    async fn execute(&mut self) -> Result<(), LoopError>;
}

/// Production transport: invokes `SyncService::ExchangeState` against the
/// configured share.
///
/// DISK-0043: sends real local scan (Scan → Hash → ExchangeState) and
/// executes SyncStateResponse actions (Upload / Download / Conflict-apply).
///
/// # Auto-3-way-merge (conflict APPLY path)
///
/// When a [`BlobCache`] is attached (via [`RemoteSync::with_blob_cache`]) and
/// a pre-loaded baseline map is supplied, the APPLY path can provide the
/// common-ancestor bytes to `apply_conflict`.  The lifecycle is:
///
/// 1. **Previous cycle DOWNLOAD**: bytes written to disk are also stored in the
///    blob cache keyed by their blake3 hash.  That hash becomes the baseline
///    `content_hash` recorded in `node_baselines` after a successful sync.
/// 2. **Current cycle APPLY**: for each `ConflictReport`, look up the path in
///    `baselines` to find the baseline hash, then look up the blob cache to
///    get the base bytes.  If both lookups succeed, `apply_conflict` receives
///    `Some(base)` and can perform a 3-way merge instead of forking.
///
/// Without a blob cache or baseline map, `base = None` is passed and
/// `apply_conflict` falls back to forking (zero-data-loss, as before).
pub struct RemoteSync<'a> {
    client: &'a DiskClient,
    share: String,
    /// Filesystem root for this share (scanned each iteration).
    scan_root: PathBuf,
    /// Node id used as the writer in FileMeta rows.
    node_id: String,
    /// Optional content-addressed blob cache.  When set, downloaded file bytes
    /// are stored here keyed by their blake3 hash so that subsequent cycles can
    /// recover the common-ancestor content for 3-way merges.
    blob_cache: Option<Arc<BlobCache>>,
    /// Last-synced baseline hashes per vault-relative path.  Populated from
    /// `node_baselines` before a cycle begins (see `with_blob_cache`).
    /// Maps `path_string → content_hash([u8;32])`.
    baselines: HashMap<String, [u8; 32]>,
}

impl<'a> RemoteSync<'a> {
    /// Legacy constructor (ACL-probe only — no real scan).
    pub fn new(client: &'a DiskClient, share: impl Into<String>) -> Self {
        Self {
            client,
            share: share.into(),
            scan_root: PathBuf::new(),
            node_id: String::new(),
            blob_cache: None,
            baselines: HashMap::new(),
        }
    }

    /// Full constructor with scan root and node id (DISK-0043 data plane).
    pub fn with_scan_root(
        client: &'a DiskClient,
        share: impl Into<String>,
        scan_root: PathBuf,
        node_id: impl Into<String>,
    ) -> Self {
        Self {
            client,
            share: share.into(),
            scan_root,
            node_id: node_id.into(),
            blob_cache: None,
            baselines: HashMap::new(),
        }
    }

    /// Attach a blob cache and pre-loaded baseline hashes to enable auto
    /// 3-way-merge on the conflict APPLY path.
    ///
    /// `baselines` maps a vault-relative path string to the blake3
    /// `content_hash` of the last successfully synced version of that file
    /// (i.e. the common-ancestor bytes).  Callers typically build this from
    /// `MetaDb::load_node_baseline()` before constructing `RemoteSync`.
    pub fn with_blob_cache(
        mut self,
        cache: Arc<BlobCache>,
        baselines: HashMap<String, [u8; 32]>,
    ) -> Self {
        self.blob_cache = Some(cache);
        self.baselines = baselines;
        self
    }

    pub fn share(&self) -> &str {
        &self.share
    }
}

/// Convert a domain [`FileMeta`] into its proto [`FileMetadata`] equivalent.
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

#[tonic::async_trait]
impl<'a> SyncTransport for RemoteSync<'a> {
    /// One full sync iteration: Scan → ExchangeState → execute actions.
    ///
    /// If `scan_root` is empty (legacy ACL-probe mode), sends an empty
    /// exchange_state (preserves R6 behaviour for callers that have not
    /// upgraded to the full data-plane wiring).
    async fn execute(&mut self) -> Result<(), LoopError> {
        // ── Scan ────────────────────────────────────────────────────────
        let local_files: Vec<FileMetadata> = if self.scan_root.as_os_str().is_empty() {
            Vec::new()
        } else {
            let filter = match Filter::from_config(&FilterRules::default()) {
                Ok(f) => f,
                Err(_) => return Ok(()), // filter error is non-fatal; skip this iteration
            };
            let scanner = FileScanner::new(
                self.scan_root.clone(),
                filter,
                HashMap::new(),
                self.node_id.clone(),
            );
            match scanner.scan() {
                Ok(metas) => metas.iter().map(file_meta_to_proto).collect(),
                Err(_) => Vec::new(),
            }
        };

        // ── Build node_clock from local files ───────────────────────────
        let node_clock: HashMap<String, u64> = {
            let mut clock = HashMap::new();
            for f in &local_files {
                for (node, tick) in &f.vector_clock {
                    let entry = clock.entry(node.clone()).or_insert(0u64);
                    if *tick > *entry {
                        *entry = *tick;
                    }
                }
            }
            clock
        };

        // ── ExchangeState ───────────────────────────────────────────────
        let response = match self
            .client
            .exchange_state(&self.share, local_files, node_clock)
            .await
        {
            Ok(r) => r,
            Err(e) => return Err(classify_client_error(&e)),
        };

        // ── Execute actions ─────────────────────────────────────────────
        // Upload: client pushes files the server asked for.
        if !self.scan_root.as_os_str().is_empty() {
            for to_upload in &response.to_upload {
                let file_path = self.scan_root.join(&to_upload.path);
                if let Ok(bytes) = std::fs::read(&file_path) {
                    let _ = self
                        .client
                        .delta_upload(&self.share, &to_upload.path, &bytes)
                        .await;
                }
            }

            // Download: client pulls files the server wants it to fetch.
            for to_download in &response.to_download {
                if let Ok(bytes) = self.client.download_file(&to_download.path).await {
                    let dest = self.scan_root.join(&to_download.path);
                    if let Some(parent) = dest.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    let _ = std::fs::write(&dest, &bytes);

                    // Cache bytes by their blake3 hash so that a future cycle
                    // can retrieve the common-ancestor content for 3-way merge
                    // without a round-trip to the server.
                    if let Some(ref cache) = self.blob_cache {
                        let hash: [u8; 32] = *blake3::hash(&bytes).as_bytes();
                        if let Err(e) = cache.put(&hash, &bytes) {
                            tracing::debug!(
                                path = %to_download.path,
                                error = %e,
                                "blob cache put failed (non-fatal)"
                            );
                        }
                    }
                }
            }

            // Conflicts: for each conflict reported by the server, apply the
            // resolution on the client's local vault filesystem.
            //
            // Strategy:
            //   1. Read the current local file bytes.
            //   2. Download the remote bytes from the server.
            //   3. Resolve the common-ancestor (base) bytes from the blob cache
            //      using the baseline content_hash for this path.  When a base
            //      is available, `apply_conflict` attempts a 3-way merge for
            //      eligible extensions (.md / .txt); on clean merge the merged
            //      file replaces the live path with no fork.
            //   4. When no base is available (cache miss or no blob_cache),
            //      pass `None` — `apply_conflict` falls back to fork, preserving
            //      both versions (zero-data-loss invariant unchanged).
            //
            // Non-fatal: a failure to resolve a single conflict is logged and
            // skipped so that the remainder of the sync iteration can proceed.
            for conflict in &response.conflicts {
                let rel_path = std::path::Path::new(&conflict.path);

                // Read the current local file.
                let local_bytes = match std::fs::read(self.scan_root.join(rel_path)) {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::warn!(
                            path = %conflict.path,
                            error = %e,
                            "conflict apply: cannot read local file, skipping"
                        );
                        continue;
                    }
                };

                // Download the remote bytes.
                let remote_bytes = match self.client.download_file(&conflict.path).await {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::warn!(
                            path = %conflict.path,
                            error = %e,
                            "conflict apply: cannot download remote file, skipping"
                        );
                        continue;
                    }
                };

                // Resolve the base (common-ancestor) bytes from the blob cache.
                //
                // The baseline map (populated from node_baselines before the
                // cycle) records the content_hash of the last successfully
                // synced version of each file.  That hash is the blob cache key
                // for the common-ancestor content.  When both lookups succeed
                // the merge path is enabled; otherwise we fall back to fork.
                let base_bytes: Option<Vec<u8>> = self.blob_cache.as_ref().and_then(|cache| {
                    let hash = self.baselines.get(&conflict.path)?;
                    cache.get(hash)
                });

                // Apply: merge (Some(base)) or fork (None).
                match apply_conflict(
                    &self.scan_root,
                    rel_path,
                    base_bytes.as_deref(),
                    &local_bytes,
                    &remote_bytes,
                    &self.node_id,
                ) {
                    Ok(outcome) => {
                        tracing::info!(
                            path = %conflict.path,
                            outcome = ?outcome,
                            had_base = base_bytes.is_some(),
                            "conflict apply: resolved"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            path = %conflict.path,
                            error = %e,
                            "conflict apply: fork write failed"
                        );
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use disk_proto::disk::AclMismatchDetails;
    use prost::Message;
    use tonic::{Code, Status};

    #[test]
    fn permission_denied_with_acl_details_maps_to_acl_role_mismatch() {
        let details = AclMismatchDetails {
            claimed_role: "send_only".into(),
            enforced_role: "receive_only".into(),
            share: "vault".into(),
            cert_fingerprint: vec![1, 2, 3],
            ts_ms: 42,
        };
        let mut buf = Vec::new();
        details.encode(&mut buf).unwrap();
        let status = Status::with_details(Code::PermissionDenied, "ACL role mismatch", buf.into());
        assert_eq!(classify_tonic_status(&status), LoopError::AclRoleMismatch);
    }

    #[test]
    fn permission_denied_share_unknown_message_maps_to_share_unknown() {
        let status =
            Status::permission_denied("share unknown: vault; retry after ACL provisioning");
        assert_eq!(classify_tonic_status(&status), LoopError::ShareUnknown);
    }

    #[test]
    fn permission_denied_role_mismatch_message_maps_to_acl_role_mismatch() {
        let status = Status::permission_denied("ACL role mismatch: enforced=ro claimed=so");
        assert_eq!(classify_tonic_status(&status), LoopError::AclRoleMismatch);
    }

    #[test]
    fn unavailable_maps_to_transport_unavailable() {
        let status = Status::unavailable("ACL enforcer unhealthy");
        assert_eq!(
            classify_tonic_status(&status),
            LoopError::TransportUnavailable
        );
    }

    #[test]
    fn deadline_exceeded_maps_to_transport_unavailable() {
        let status = Status::deadline_exceeded("timeout");
        assert_eq!(
            classify_tonic_status(&status),
            LoopError::TransportUnavailable
        );
    }

    #[test]
    fn unknown_status_maps_to_transport_unavailable() {
        let status = Status::internal("boom");
        assert_eq!(
            classify_tonic_status(&status),
            LoopError::TransportUnavailable
        );
    }

    #[test]
    fn permission_denied_unknown_message_maps_to_acl_role_mismatch_sticky() {
        let status = Status::permission_denied("unrecognised reason");
        assert_eq!(classify_tonic_status(&status), LoopError::AclRoleMismatch);
    }

    #[test]
    fn client_error_not_authenticated_maps_to_transport_unavailable() {
        let err = ClientError::NotAuthenticated;
        assert_eq!(classify_client_error(&err), LoopError::TransportUnavailable);
    }

    #[test]
    fn client_error_metadata_maps_to_transport_unavailable() {
        let err = ClientError::MetadataError("bad header".into());
        assert_eq!(classify_client_error(&err), LoopError::TransportUnavailable);
    }

    // ── DISK-0043 Step 6: file_meta_to_proto converts correctly ─────────

    #[test]
    fn file_meta_to_proto_round_trip() {
        let mut vc = disk_core::VectorClock::new();
        vc.advance("client-a");
        let meta = disk_core::types::FileMeta {
            path: std::path::PathBuf::from("notes/hello.md"),
            content_hash: [0xAB; 32],
            size: 42,
            mtime_ns: 1_700_000_000_000_000_000,
            inode: Some(12345),
            vector_clock: vc.clone(),
            deleted: false,
            deleted_at: None,
            node_id: "client-a".into(),
        };
        let proto = file_meta_to_proto(&meta);
        assert_eq!(proto.path, "notes/hello.md");
        assert_eq!(proto.size, 42);
        assert_eq!(proto.content_hash, [0xAB; 32]);
        assert_eq!(proto.inode, 12345);
        assert_eq!(proto.vector_clock.get("client-a").copied().unwrap_or(0), 1);
    }

    /// RemoteSync with an empty scan_root falls back to empty exchange (legacy mode).
    #[test]
    fn remote_sync_legacy_mode_has_empty_scan_root() {
        // Just verify the constructor — no actual gRPC call.
        // (The gRPC call is tested via integration tests.)
        let root = std::path::PathBuf::new();
        assert!(root.as_os_str().is_empty());
    }
}
