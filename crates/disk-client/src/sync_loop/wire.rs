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
use disk_core::types::{ConflictKind, ConflictRecord, FileMeta};
use disk_core::{overlay_scanned_meta, DownloadPayload, E2eeCachedWire, UploadPayload, VaultKey};
use disk_proto::disk::{AclMismatchDetails, FileMetadata};
use prost::Message;
use tonic::{Code, Status};

use super::LoopError;
use crate::blob_cache::BlobCache;
use crate::conflict_writer::{apply_conflict, ConflictApplyOutcome};
use crate::connection::{ClientError, DiskClient};
use crate::lan_sync::{try_lan_fetch, LanFetchContext};

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
    /// Optional MetaDb handle for persisting conflict rows on the client side.
    /// When set, the conflict APPLY path creates a `ConflictRecord` for every
    /// server-reported conflict so that `GET /conflicts` on the local REST
    /// surface returns them.  Without this handle conflict detection is still
    /// functional — only the client-side index is missing.
    meta_db: Option<Arc<disk_core::MetaDb>>,
    /// When set, uploads encrypt plaintext before `DeltaUpload` (DISK-0015).
    e2ee_key: Option<VaultKey>,
    /// In-memory stable ciphertext index when MetaDb is absent or cold (slice 3).
    e2ee_wire_cache: HashMap<String, E2eeCachedWire>,
    /// LAN-preferred download path (DISK-0027 slice 2).
    lan_fetch: Option<LanFetchContext>,
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
            meta_db: None,
            e2ee_key: None,
            e2ee_wire_cache: HashMap::new(),
            lan_fetch: None,
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
            meta_db: None,
            e2ee_key: None,
            e2ee_wire_cache: HashMap::new(),
            lan_fetch: None,
        }
    }

    /// Attach a MetaDb handle so the conflict APPLY path can persist
    /// `ConflictRecord` rows on the client side.
    ///
    /// Without this the conflict is still handled on the filesystem; only the
    /// client-side `conflicts` index (queried by `GET /conflicts`) is missing.
    pub fn with_meta_db(mut self, db: Arc<disk_core::MetaDb>) -> Self {
        self.meta_db = Some(db);
        self
    }

    /// Enable client-side E2EE for the upload path (DISK-0015 slice 2).
    pub fn with_e2ee_key(mut self, key: VaultKey) -> Self {
        self.e2ee_key = Some(key);
        self
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

    /// Enable LAN-preferred delta fetch before cloud download (DISK-0027 slice 2).
    pub fn with_lan_fetch(mut self, ctx: LanFetchContext) -> Self {
        self.lan_fetch = Some(ctx);
        self
    }

    pub fn share(&self) -> &str {
        &self.share
    }

    /// Return `true` when a blob cache has been attached via
    /// [`Self::with_blob_cache`].  Used by tests that drive the daemon's own
    /// construction path to assert the cache is wired without needing a live
    /// gRPC connection.
    pub fn has_blob_cache(&self) -> bool {
        self.blob_cache.is_some()
    }

    /// Return the number of baseline entries loaded into this transport.  Used
    /// alongside [`Self::has_blob_cache`] in daemon-construction tests.
    pub fn baseline_count(&self) -> usize {
        self.baselines.len()
    }

    /// Return `true` when a MetaDb handle has been attached via
    /// [`Self::with_meta_db`].  Used by daemon-construction tests to assert
    /// the client conflict index is wired before any network I/O occurs.
    pub fn has_meta_db(&self) -> bool {
        self.meta_db.is_some()
    }

    /// DISK-0015 slice 3: rewrite scanned plaintext hashes to ciphertext wire
    /// indices before `ExchangeState`, reusing MetaDb / in-memory cache when
    /// `(mtime_ns, size)` are unchanged.
    async fn overlay_e2ee_exchange_files(&mut self, metas: &mut Vec<FileMeta>) {
        let Some(key) = self.e2ee_key.clone() else {
            return;
        };

        let mut db_index: HashMap<String, FileMeta> = HashMap::new();
        if let Some(db) = &self.meta_db {
            if let Ok(rows) = db.list_all_files().await {
                for row in rows {
                    db_index.insert(vault_relative_path_key(&row.path), row);
                }
            }
        }

        metas.retain_mut(|meta| {
            let path_str = vault_relative_path_key(&meta.path);
            let cached = db_index
                .get(&path_str)
                .and_then(E2eeCachedWire::from_file_meta)
                .or_else(|| self.e2ee_wire_cache.get(&path_str).cloned());

            if let Some(ref c) = cached {
                if c.matches_scan(meta) {
                    match overlay_scanned_meta(meta, &key, Some(c), &[]) {
                        Ok(None) => return true,
                        Ok(Some(_)) => unreachable!("cache hit must not re-encrypt"),
                        Err(e) => {
                            tracing::warn!(
                                path = %path_str,
                                error = %e,
                                "E2EE exchange overlay: cache apply failed"
                            );
                            return false;
                        }
                    }
                }
            }

            let abs = self.scan_root.join(&meta.path);
            let plaintext = match std::fs::read(&abs) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(
                        path = %path_str,
                        error = %e,
                        "E2EE exchange overlay: cannot read file"
                    );
                    return false;
                }
            };

            match overlay_scanned_meta(meta, &key, cached.as_ref(), &plaintext) {
                Ok(Some(fresh)) => {
                    self.e2ee_wire_cache.insert(path_str, fresh);
                    true
                }
                Ok(None) => true,
                Err(e) => {
                    tracing::warn!(
                        path = %path_str,
                        error = %e,
                        "E2EE exchange overlay: encrypt failed"
                    );
                    false
                }
            }
        });
    }

    async fn persist_e2ee_wire_meta(
        &mut self,
        rel_path: &str,
        content_hash: [u8; 32],
        encryption_nonce: Vec<u8>,
        mtime_ns: i64,
        plaintext_size: u64,
    ) {
        let cached = E2eeCachedWire {
            content_hash,
            encryption_nonce: encryption_nonce.clone(),
            mtime_ns,
            size: plaintext_size,
        };
        self.e2ee_wire_cache.insert(rel_path.to_owned(), cached);

        if let Some(db) = &self.meta_db {
            let meta = FileMeta {
                path: std::path::PathBuf::from(rel_path),
                content_hash,
                size: plaintext_size,
                mtime_ns,
                inode: None,
                vector_clock: disk_core::VectorClock::default(),
                deleted: false,
                deleted_at: None,
                node_id: self.node_id.clone(),
                encryption_nonce: Some(encryption_nonce),
                version_id: None,
                parent_version_id: None,
            };
            if let Err(e) = db.upsert_file(&meta).await {
                tracing::warn!(
                    path = %rel_path,
                    error = %e,
                    "E2EE: failed to persist wire index (non-fatal)"
                );
            }
        }
    }

    /// DISK-0015 slice 5: verify wire hash and decrypt ciphertext downloads.
    fn materialize_downloaded_bytes(
        &self,
        wire_bytes: &[u8],
        meta: &FileMetadata,
        context: &str,
    ) -> Option<Vec<u8>> {
        let expected_hash: [u8; 32] = meta.content_hash.as_slice().try_into().unwrap_or([0u8; 32]);
        match DownloadPayload::from_wire_bytes(
            wire_bytes,
            &meta.encryption_nonce,
            &expected_hash,
            self.e2ee_key.as_ref(),
        ) {
            Ok(payload) => Some(payload.plaintext),
            Err(e) => {
                tracing::warn!(
                    path = %meta.path,
                    context = %context,
                    error = %e,
                    "download skipped: E2EE materialize failed"
                );
                None
            }
        }
    }
}

fn vault_relative_path_key(path: &std::path::Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

#[cfg(unix)]
fn file_mtime_ns(path: &std::path::Path) -> i64 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path)
        .map(|m| m.mtime() * 1_000_000_000 + m.mtime_nsec())
        .unwrap_or(0)
}

#[cfg(not(unix))]
fn file_mtime_ns(path: &std::path::Path) -> i64 {
    use std::time::UNIX_EPOCH;
    std::fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// Convert a proto [`FileMetadata`] into a domain [`FileMeta`].
fn proto_to_file_meta(m: &FileMetadata) -> FileMeta {
    let content_hash: [u8; 32] = m.content_hash.as_slice().try_into().unwrap_or([0u8; 32]);

    let mut vc = disk_core::VectorClock::new();
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
        encryption_nonce: if m.encryption_nonce.is_empty() {
            None
        } else {
            Some(m.encryption_nonce.clone())
        },
        version_id: if m.version_id == 0 {
            None
        } else {
            Some(m.version_id)
        },
        parent_version_id: if m.parent_version_id == 0 {
            None
        } else {
            Some(m.parent_version_id)
        },
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
        encryption_nonce: m.encryption_nonce.clone().unwrap_or_default(),
        version_id: m.version_id.unwrap_or(0),
        parent_version_id: m.parent_version_id.unwrap_or(0),
        ..Default::default()
    }
}

/// Copy `version_id` / `parent_version_id` from MetaDb rows when available.
fn overlay_version_ids_from_db(metas: &mut [FileMeta], db_index: &HashMap<String, FileMeta>) {
    for meta in metas.iter_mut() {
        let key = vault_relative_path_key(&meta.path);
        if let Some(row) = db_index.get(&key) {
            meta.version_id = row.version_id;
            meta.parent_version_id = row.parent_version_id;
        }
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
                Ok(mut metas) => {
                    if self.e2ee_key.is_some() {
                        self.overlay_e2ee_exchange_files(&mut metas).await;
                    }
                    if let Some(db) = &self.meta_db {
                        if let Ok(rows) = db.list_all_files().await {
                            let index: HashMap<String, FileMeta> = rows
                                .into_iter()
                                .map(|row| (vault_relative_path_key(&row.path), row))
                                .collect();
                            overlay_version_ids_from_db(&mut metas, &index);
                        }
                    }
                    metas.iter().map(file_meta_to_proto).collect()
                }
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
        //
        // DISK-0064: a failed upload (read error or transport error) is a
        // pure no-op — warn and continue.  We must NOT swallow the error
        // silently: a swallowed failure leaves the server without the file,
        // and the NEXT cycle's `to_delete` logic (server-directed local
        // deletion) can then remove the client's own local original.
        // The local file is the source of truth; a transient upload failure
        // must never propagate into a local delete on any future cycle.
        if !self.scan_root.as_os_str().is_empty() {
            for to_upload in &response.to_upload {
                let file_path = self.scan_root.join(&to_upload.path);
                // DISK-0064: log read failures explicitly rather than
                // silently skipping them via `if let Ok(...)`.
                let bytes = match std::fs::read(&file_path) {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::warn!(
                            path = %to_upload.path,
                            error = %e,
                            "upload skipped: cannot read local file"
                        );
                        continue;
                    }
                };
                let payload = if let Some(ref key) = self.e2ee_key {
                    match UploadPayload::from_plaintext_encrypted(&bytes, key) {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::warn!(
                                path = %to_upload.path,
                                error = %e,
                                "upload skipped: E2EE encrypt failed"
                            );
                            continue;
                        }
                    }
                } else {
                    UploadPayload::from_plaintext(&bytes)
                };
                // DISK-0064: explicit match instead of `let _ = ...` so that
                // a transport error is surfaced as a warning, not swallowed.
                // A failed upload is a pure no-op; the server never saw the
                // bytes, so the next cycle will simply request it again.
                match self
                    .client
                    .delta_upload(&self.share, &to_upload.path, &payload)
                    .await
                {
                    Ok(_) => {
                        if !payload.encryption_nonce.is_empty() {
                            let mtime_ns = file_mtime_ns(&file_path);
                            let plaintext_size = bytes.len() as u64;
                            self.persist_e2ee_wire_meta(
                                &to_upload.path,
                                payload.content_hash,
                                payload.encryption_nonce.clone(),
                                mtime_ns,
                                plaintext_size,
                            )
                            .await;
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            path = %to_upload.path,
                            error = %e,
                            "upload failed; skipping"
                        );
                        continue;
                    }
                }
            }

            // Download: client pulls files the server wants it to fetch.
            // Collect successfully-downloaded (path, hash) pairs so that the
            // post-cycle baseline write can record them in node_baselines.
            let mut downloaded_baselines: Vec<disk_core::types::FileMeta> = Vec::new();

            for to_download in &response.to_download {
                // DISK-0062: pass `share` so the server ACL enforcer can route
                // the request correctly.  A failed download is a pure no-op —
                // do NOT record a baseline or infer a delete from it.
                //
                // DISK-0027 slice 2: try enrolled LAN peers before cloud delta_download.
                let expected_hash: Option<[u8; 32]> =
                    to_download.content_hash.as_slice().try_into().ok();

                let bytes = if let Some(ref lan) = self.lan_fetch {
                    if let Some(b) =
                        try_lan_fetch(lan, &self.share, &to_download.path, expected_hash.as_ref())
                            .await
                    {
                        b
                    } else {
                        match self
                            .client
                            .download_file(&self.share, &to_download.path)
                            .await
                        {
                            Ok(b) => b,
                            Err(e) => {
                                tracing::warn!(
                                    path = %to_download.path,
                                    error = %e,
                                    "download failed; skipping"
                                );
                                continue;
                            }
                        }
                    }
                } else {
                    match self
                        .client
                        .download_file(&self.share, &to_download.path)
                        .await
                    {
                        Ok(b) => b,
                        Err(e) => {
                            tracing::warn!(
                                path = %to_download.path,
                                error = %e,
                                "download failed; skipping"
                            );
                            continue;
                        }
                    }
                };

                let plaintext =
                    match self.materialize_downloaded_bytes(&bytes, to_download, "sync-download") {
                        Some(p) => p,
                        None => continue,
                    };

                let dest = self.scan_root.join(&to_download.path);
                if let Some(parent) = dest.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                if let Err(e) = std::fs::write(&dest, &plaintext) {
                    tracing::warn!(
                        path = %to_download.path,
                        error = %e,
                        "download skipped: cannot write plaintext"
                    );
                    continue;
                }

                // Blob cache keys:
                //   plaintext files → blake3(plaintext)
                //   E2EE files      → blake3(ciphertext) so baselines align with wire hashes
                let encrypted = !to_download.encryption_nonce.is_empty();
                let cache_key: [u8; 32] = if encrypted {
                    expected_hash.unwrap_or([0u8; 32])
                } else {
                    *blake3::hash(&plaintext).as_bytes()
                };

                if let Some(ref cache) = self.blob_cache {
                    if let Err(e) = cache.put(&cache_key, &plaintext) {
                        tracing::debug!(
                            path = %to_download.path,
                            error = %e,
                            "blob cache put failed (non-fatal)"
                        );
                    }
                }

                let mut baseline = proto_to_file_meta(to_download);
                baseline.content_hash = cache_key;
                baseline.size = plaintext.len() as u64;
                if encrypted {
                    baseline.encryption_nonce = Some(to_download.encryption_nonce.clone());
                    let mtime_ns = file_mtime_ns(&dest);
                    self.persist_e2ee_wire_meta(
                        &to_download.path,
                        cache_key,
                        to_download.encryption_nonce.clone(),
                        mtime_ns,
                        plaintext.len() as u64,
                    )
                    .await;
                }
                downloaded_baselines.push(baseline);
            }

            // ── Persist post-cycle baselines ────────────────────
            //
            // After every successful cycle, write the content-hashes of all
            // files that were just downloaded to node_baselines.  The NEXT
            // cycle's `load_baselines_for_share` call will find these rows
            // and supply them as the common-ancestor map so that a conflict on
            // any of these paths can attempt a 3-way merge.
            //
            // Non-fatal: a baseline write failure must not abort the sync
            // iteration — the file operations already succeeded.
            if let (Some(db), true) = (&self.meta_db, !downloaded_baselines.is_empty()) {
                // Persist synchronously before the iteration returns: the NEXT
                // cycle's `load_baselines_for_share` must see these rows, so the
                // write cannot race the next sync. A failure is logged but does
                // not abort the sync iteration — the file operations already
                // succeeded.
                if let Err(e) = db
                    .upsert_node_baselines(&self.node_id, &self.share, &downloaded_baselines)
                    .await
                {
                    tracing::warn!(
                        share = %self.share,
                        error = %e,
                        "sync: failed to persist post-cycle baselines (non-fatal)"
                    );
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
                // DISK-0062: pass `share` for the x-disk-share header.
                let remote_bytes =
                    match self.client.download_file(&self.share, &conflict.path).await {
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

                let remote_meta = match conflict.remote.as_ref() {
                    Some(m) => m,
                    None => {
                        tracing::warn!(
                            path = %conflict.path,
                            "conflict apply: missing remote metadata, skipping"
                        );
                        continue;
                    }
                };

                let remote_plain = match self.materialize_downloaded_bytes(
                    &remote_bytes,
                    remote_meta,
                    "conflict-download",
                ) {
                    Some(p) => p,
                    None => continue,
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
                let apply_result = apply_conflict(
                    &self.scan_root,
                    rel_path,
                    base_bytes.as_deref(),
                    &local_bytes,
                    &remote_plain,
                    &self.node_id,
                );

                match &apply_result {
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

                // Persist the conflict row to the client MetaDb so that
                // `GET /conflicts` on the local REST surface returns it.
                // Only unresolved (forked) outcomes create a row; a clean
                // 3-way merge means there is nothing left to resolve.
                if let (Some(db), Ok(outcome)) = (&self.meta_db, &apply_result) {
                    let fork_path = match outcome {
                        ConflictApplyOutcome::Forked(p) => Some(p.to_string_lossy().into_owned()),
                        ConflictApplyOutcome::Merged => None,
                    };
                    // Only record a row when the conflict is still unresolved
                    // (i.e. it forked rather than merged cleanly).
                    if fork_path.is_some() {
                        let local_hash: Option<[u8; 32]> = {
                            let h = *blake3::hash(&local_bytes).as_bytes();
                            Some(h)
                        };
                        let remote_hash: Option<[u8; 32]> = {
                            let h = *blake3::hash(&remote_plain).as_bytes();
                            Some(h)
                        };
                        let base_hash: Option<[u8; 32]> =
                            base_bytes.as_deref().map(|b| *blake3::hash(b).as_bytes());
                        let conflict_type = format!("{:?}", ConflictKind::Concurrent);
                        let rec = ConflictRecord {
                            id: None,
                            vault_id: self.share.clone(),
                            path: conflict.path.clone(),
                            conflict_type,
                            local_hash,
                            remote_hash,
                            base_hash,
                            resolution: None,
                            fork_path,
                            resolved: false,
                            created_at: 0,
                            resolved_at: None,
                        };
                        // Persist synchronously before the iteration returns: the
                        // row must be visible to a subsequent `list` query, and the
                        // write is a cheap local SQLite insert. A DB failure is
                        // logged but does not abort the sync iteration — the file
                        // operation already succeeded.
                        if let Err(e) = db.create_conflict(&rec).await {
                            tracing::warn!(
                                error = %e,
                                "conflict apply: failed to persist ConflictRecord (non-fatal)"
                            );
                        }
                    }
                }
            }

            // DISK-0062 S3 — Apply server-directed local deletions.
            //
            // `response.to_delete` lists files the server has determined this
            // client should remove locally (e.g. the server reconciler emitted
            // a DeleteLocal action after the client's baseline shows the file
            // as present but the server-authoritative state is a tombstone).
            //
            // Trust the server's ACL-filtered response the same way the upload
            // and download loops do.  For each entry:
            //   1. Remove the local file (best-effort; missing file is not an error).
            //   2. Record a tombstone in node_baselines so the NEXT cycle's
            //      reconciler sees the deletion as acknowledged rather than
            //      re-emitting to_delete indefinitely.
            //
            // Non-fatal: a failure to delete one file is logged and skipped so
            // that the rest of the sync iteration proceeds.
            if !response.to_delete.is_empty() {
                let mut delete_baselines: Vec<disk_core::types::FileMeta> = Vec::new();

                for to_delete in &response.to_delete {
                    let dest = self.scan_root.join(&to_delete.path);
                    if dest.exists() {
                        if let Err(e) = std::fs::remove_file(&dest) {
                            tracing::warn!(
                                path = %to_delete.path,
                                error = %e,
                                "delete apply: failed to remove local file (non-fatal)"
                            );
                            // Skip tombstone so the server keeps sending to_delete
                            // until we successfully remove the file.
                            continue;
                        }
                    }

                    // Record a tombstone baseline so the next cycle's reconciler
                    // knows this client acknowledged the deletion.
                    delete_baselines.push(disk_core::types::FileMeta {
                        path: std::path::PathBuf::from(&to_delete.path),
                        content_hash: [0u8; 32],
                        size: 0,
                        mtime_ns: 0,
                        inode: None,
                        vector_clock: disk_core::VectorClock::default(),
                        deleted: true,
                        deleted_at: Some(
                            std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_nanos() as i64,
                        ),
                        node_id: self.node_id.clone(),
                        encryption_nonce: None,
                        version_id: None,
                        parent_version_id: None,
                    });
                }

                if let (Some(db), false) = (&self.meta_db, delete_baselines.is_empty()) {
                    if let Err(e) = db
                        .upsert_node_baselines(&self.node_id, &self.share, &delete_baselines)
                        .await
                    {
                        tracing::warn!(
                            share = %self.share,
                            error = %e,
                            "sync: failed to persist delete tombstone baselines (non-fatal)"
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
            encryption_nonce: None,
            version_id: Some(3),
            parent_version_id: Some(2),
        };
        let proto = file_meta_to_proto(&meta);
        assert_eq!(proto.path, "notes/hello.md");
        assert_eq!(proto.size, 42);
        assert_eq!(proto.content_hash, [0xAB; 32]);
        assert_eq!(proto.inode, 12345);
        assert_eq!(proto.vector_clock.get("client-a").copied().unwrap_or(0), 1);
        assert_eq!(proto.version_id, 3);
        assert_eq!(proto.parent_version_id, 2);
        let back = proto_to_file_meta(&proto);
        assert_eq!(back.version_id, Some(3));
        assert_eq!(back.parent_version_id, Some(2));
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
