//! Cycle-level integration tests for auto-3-way-merge in the sync APPLY path.
//!
//! These tests drive `RemoteSync::execute()` — the FULL wire.rs APPLY path
//! that consumes `response.conflicts` — rather than calling `apply_conflict`
//! directly.  A real in-process gRPC stub returns a `SyncStateResponse` with a
//! populated `conflicts` list; the `DeltaDownload` RPC serves the remote bytes.
//!
//! The blob cache and baseline map are pre-seeded so the APPLY path can resolve
//! the common-ancestor bytes and pass `Some(base)` to `apply_conflict`.
//!
//! Tests:
//!   - `cycle_auto_merges_non_overlap_with_baseline`: non-overlapping `.md`
//!     edits with a base in the cache → file merged in-place, NO fork created.
//!   - `cycle_forks_when_overlap_despite_baseline`: overlapping edits →
//!     even with a base the merge is conflicted → fork written, original
//!     untouched (zero-data-loss invariant).
//!   - `cycle_forks_when_no_baseline`: no base in cache → fork written,
//!     original untouched (regression guard: previous behaviour preserved).

#![cfg(unix)]

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use disk_client::{BlobCache, ClientConfig, DiskClient, RemoteSync, SyncTransport};
use disk_proto::disk::{
    sync_service_server::{SyncService, SyncServiceServer},
    ConflictReport, DeltaChunk, DeltaDownloadRequest, DeltaUploadRequest, DeltaUploadResponse,
    FileMetadata, SyncStateAck, SyncStateRequest, SyncStateResponse,
};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use tokio::net::TcpListener;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{
    transport::{Identity, Server, ServerTlsConfig},
    Request, Response, Status, Streaming,
};

const SESSION_TOKEN: &str = "cycle-test-token";
const NODE_ID: &str = "cycle-test-node";
const SHARE_NAME: &str = "vault";
const CONFLICT_PATH: &str = "docs/notes.md";

// ---------------------------------------------------------------------------
// Stub server
// ---------------------------------------------------------------------------

/// The remote bytes the stub will serve via `DeltaDownload`.
struct StubConflict {
    conflict_path: &'static str,
    remote_bytes: Vec<u8>,
}

struct StubSyncServer {
    conflict: StubConflict,
}

#[tonic::async_trait]
impl SyncService for StubSyncServer {
    type SyncStateStream = ReceiverStream<Result<SyncStateAck, Status>>;
    type DeltaDownloadStream = ReceiverStream<Result<DeltaChunk, Status>>;

    async fn exchange_state(
        &self,
        _req: Request<SyncStateRequest>,
    ) -> Result<Response<SyncStateResponse>, Status> {
        // Return a single ConflictReport for the test path.
        let report = ConflictReport {
            path: self.conflict.conflict_path.to_owned(),
            local: Some(FileMetadata {
                path: self.conflict.conflict_path.to_owned(),
                ..Default::default()
            }),
            remote: Some(FileMetadata {
                path: self.conflict.conflict_path.to_owned(),
                ..Default::default()
            }),
            suggested_resolution: "merge".to_owned(),
        };
        Ok(Response::new(SyncStateResponse {
            conflicts: vec![report],
            ..Default::default()
        }))
    }

    async fn upload_delta(
        &self,
        _req: Request<DeltaUploadRequest>,
    ) -> Result<Response<DeltaUploadResponse>, Status> {
        Err(Status::unimplemented("stub"))
    }

    async fn sync_state(
        &self,
        _req: Request<Streaming<SyncStateRequest>>,
    ) -> Result<Response<Self::SyncStateStream>, Status> {
        Err(Status::unimplemented("stub"))
    }

    async fn delta_upload(
        &self,
        _req: Request<Streaming<DeltaUploadRequest>>,
    ) -> Result<Response<DeltaUploadResponse>, Status> {
        Err(Status::unimplemented("stub"))
    }

    async fn delta_download(
        &self,
        _req: Request<DeltaDownloadRequest>,
    ) -> Result<Response<Self::DeltaDownloadStream>, Status> {
        // Return the remote bytes as a single chunk.
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let chunk = DeltaChunk {
            data: self.conflict.remote_bytes.clone(),
            offset: 0,
            weak_checksum: 0,
            strong_hash: vec![],
        };
        let _ = tx.send(Ok(chunk)).await;
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

struct Fixture {
    server_url: String,
    ca_pem: Vec<u8>,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

async fn spawn_stub(remote_bytes: Vec<u8>) -> Fixture {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind 0");
    let port = listener.local_addr().expect("local_addr").port();

    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    let ca_pem = cert_pem.clone().into_bytes();

    let identity = Identity::from_pem(&cert_pem, &key_pem);
    let tls = ServerTlsConfig::new().identity(identity);

    let svc = StubSyncServer {
        conflict: StubConflict {
            conflict_path: CONFLICT_PATH,
            remote_bytes,
        },
    };

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);

    tokio::spawn(async move {
        Server::builder()
            .tls_config(tls)
            .expect("apply tls")
            .add_service(SyncServiceServer::new(svc))
            .serve_with_incoming_shutdown(incoming, async {
                let _ = rx.await;
            })
            .await
            .expect("server terminated");
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    Fixture {
        server_url: format!("https://localhost:{port}"),
        ca_pem,
        _shutdown: tx,
    }
}

async fn connect(fx: &Fixture) -> DiskClient {
    let client = DiskClient::connect(ClientConfig {
        endpoint: fx.server_url.clone(),
        tls_ca_cert_pem: Some(fx.ca_pem.clone()),
        node_id: NODE_ID.into(),
        api_key: None,
    })
    .await
    .expect("connect");
    client.set_session_token(SESSION_TOKEN.into()).await;
    client
}

// ---------------------------------------------------------------------------
// Helper: count files in a directory (non-recursive)
// ---------------------------------------------------------------------------

fn file_count_in(dir: &Path) -> usize {
    std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .count()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Primary cycle-level proof: when a non-overlapping `.md` conflict has a
/// base present in the blob cache (seeded from node_baselines), the APPLY
/// path produces a MERGED live file with BOTH edits and creates NO fork.
#[tokio::test]
async fn cycle_auto_merges_non_overlap_with_baseline() {
    // The three versions of the conflicting file.
    let base: &[u8] = b"line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9\n";
    let local_edit: &[u8] =
        b"EDITED_BY_LOCAL\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9\n";
    let remote_edit: &[u8] =
        b"line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nEDITED_BY_REMOTE\n";

    // Compute the blake3 hash of the BASE content — this is what node_baselines
    // would store after a successful sync in a prior cycle.
    let base_hash: [u8; 32] = *blake3::hash(base).as_bytes();

    // Spin up the stub server that will return `remote_edit` via DeltaDownload.
    let fx = spawn_stub(remote_edit.to_vec()).await;
    let client = connect(&fx).await;

    // Set up the scan root with the LOCAL-edited version of the file.
    let vault_dir = tempfile::tempdir().unwrap();
    let docs_dir = vault_dir.path().join("docs");
    std::fs::create_dir_all(&docs_dir).unwrap();
    std::fs::write(docs_dir.join("notes.md"), local_edit).unwrap();

    // Blob cache — pre-seed with the BASE bytes so the APPLY path can find them.
    let cache_dir = tempfile::tempdir().unwrap();
    let blob_cache = Arc::new(BlobCache::new(cache_dir.path()));
    blob_cache
        .put(&base_hash, base)
        .expect("blob cache seeding must succeed");

    // Baseline map: CONFLICT_PATH → base_hash (simulates what MetaDb::load_node_baseline
    // would return after a prior successful sync cycle stored the base bytes).
    let mut baselines: HashMap<String, [u8; 32]> = HashMap::new();
    baselines.insert(CONFLICT_PATH.to_owned(), base_hash);

    // Build RemoteSync with the blob cache and baselines attached.
    let mut transport =
        RemoteSync::with_scan_root(&client, SHARE_NAME, vault_dir.path().to_path_buf(), NODE_ID)
            .with_blob_cache(blob_cache, baselines);

    // Execute one sync cycle — this is the full wire.rs APPLY path.
    transport.execute().await.expect("execute must succeed");

    // Assert 1: the live file contains BOTH edits (merged in-place).
    let live_bytes = std::fs::read(vault_dir.path().join(CONFLICT_PATH)).unwrap();
    let live_str = std::str::from_utf8(&live_bytes).unwrap();
    assert!(
        live_str.contains("EDITED_BY_LOCAL"),
        "merged file must contain local edit; got:\n{live_str}"
    );
    assert!(
        live_str.contains("EDITED_BY_REMOTE"),
        "merged file must contain remote edit; got:\n{live_str}"
    );

    // Assert 2: no conflict markers — it was a clean merge.
    assert!(
        !live_str.contains('<'),
        "clean merge must not contain conflict markers; got:\n{live_str}"
    );

    // Assert 3: NO fork file was created — only the original merged file exists.
    let fork_count = file_count_in(&docs_dir) - 1; // subtract the original
    assert_eq!(
        fork_count, 0,
        "no fork file must be created for a clean auto-merge; \
         found extra file(s) in {docs_dir:?}"
    );
}

/// Zero-data-loss guard: when local and remote edits overlap, the cycle MUST
/// fork the remote bytes even when a base is available.  The local file is
/// left untouched.
#[tokio::test]
async fn cycle_forks_when_overlap_despite_baseline() {
    // Both sides edit line 5 — overlap → conflicted → fork.
    let base: &[u8] = b"line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9\n";
    let local_edit: &[u8] =
        b"line1\nline2\nline3\nline4\nLOCAL_EDIT_LINE5\nline6\nline7\nline8\nline9\n";
    let remote_edit: &[u8] =
        b"line1\nline2\nline3\nline4\nREMOTE_EDIT_LINE5\nline6\nline7\nline8\nline9\n";

    let base_hash: [u8; 32] = *blake3::hash(base).as_bytes();

    let fx = spawn_stub(remote_edit.to_vec()).await;
    let client = connect(&fx).await;

    let vault_dir = tempfile::tempdir().unwrap();
    let docs_dir = vault_dir.path().join("docs");
    std::fs::create_dir_all(&docs_dir).unwrap();
    std::fs::write(docs_dir.join("notes.md"), local_edit).unwrap();

    let cache_dir = tempfile::tempdir().unwrap();
    let blob_cache = Arc::new(BlobCache::new(cache_dir.path()));
    blob_cache.put(&base_hash, base).expect("seed");

    let mut baselines: HashMap<String, [u8; 32]> = HashMap::new();
    baselines.insert(CONFLICT_PATH.to_owned(), base_hash);

    let mut transport =
        RemoteSync::with_scan_root(&client, SHARE_NAME, vault_dir.path().to_path_buf(), NODE_ID)
            .with_blob_cache(blob_cache, baselines);

    transport.execute().await.expect("execute must succeed");

    // Assert 1: the local file is UNTOUCHED (zero-data-loss).
    let live_bytes = std::fs::read(vault_dir.path().join(CONFLICT_PATH)).unwrap();
    assert_eq!(
        live_bytes, local_edit,
        "overlapping conflict must leave the local file untouched"
    );

    // Assert 2: a fork was created with the remote bytes.
    let entries: Vec<_> = std::fs::read_dir(&docs_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert_eq!(
        entries.len(),
        2,
        "exactly one fork file must be created for an overlapping conflict; \
         found {entries:?}"
    );
    // The fork must contain the remote bytes.
    let fork_entry = entries
        .iter()
        .find(|e| e.file_name().to_string_lossy().contains("sync-conflict-"))
        .expect("fork filename must contain 'sync-conflict-'");
    let fork_bytes = std::fs::read(fork_entry.path()).unwrap();
    assert_eq!(
        fork_bytes, remote_edit,
        "fork must contain the remote bytes"
    );
}

// ---------------------------------------------------------------------------
// conflict row is persisted to client MetaDb during APPLY
// ---------------------------------------------------------------------------

/// Daemon-faithful test: drive `RemoteSync::execute()` against the
/// gRPC stub with a MetaDb handle attached; assert that a `ConflictRecord` row
/// appears in the client DB after the APPLY phase completes.
///
/// This test does NOT hand-seed the DB.  The row must be created by the APPLY
/// path itself.
#[tokio::test]
#[cfg(unix)]
async fn conflict_apply_persists_row_to_client_meta_db() {
    let local_content: &[u8] = b"line1\nline2\nline3\n";
    let remote_content: &[u8] = b"line1\nLINE2_REMOTE\nline3\n";

    let fx = spawn_stub(remote_content.to_vec()).await;
    let client = connect(&fx).await;

    let vault_dir = tempfile::tempdir().unwrap();
    let docs_dir = vault_dir.path().join("docs");
    std::fs::create_dir_all(&docs_dir).unwrap();
    std::fs::write(docs_dir.join("notes.md"), local_content).unwrap();

    let cache_dir = tempfile::tempdir().unwrap();
    let blob_cache = Arc::new(BlobCache::new(cache_dir.path()));

    // Open a REAL MetaDb — no hand-seeding.
    let db_dir = tempfile::tempdir().unwrap();
    let db = disk_core::MetaDb::open(&db_dir.path().join("meta.db"))
        .await
        .expect("open MetaDb");
    let db = Arc::new(db);

    // Build transport with MetaDb attached (the client-side persist path).
    let mut transport =
        RemoteSync::with_scan_root(&client, SHARE_NAME, vault_dir.path().to_path_buf(), NODE_ID)
            .with_blob_cache(blob_cache, HashMap::new())
            .with_meta_db(Arc::clone(&db));

    // Execute — the APPLY path must create a ConflictRecord in the DB.
    transport.execute().await.expect("execute must succeed");

    // Wait briefly for the fire-and-forget spawn to complete.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Assert: the DB now contains an unresolved conflict row for CONFLICT_PATH.
    let rows = db
        .list_unresolved_conflicts()
        .await
        .expect("list_unresolved_conflicts must succeed");

    assert_eq!(
        rows.len(),
        1,
        "APPLY path must persist one ConflictRecord; found {} rows (expected 1). \
         This proves the client conflict index is populated without hand-seeding.",
        rows.len()
    );
    assert_eq!(
        rows[0].path, CONFLICT_PATH,
        "conflict row path must match the applied conflict path"
    );
    assert!(
        !rows[0].resolved,
        "conflict row must be unresolved after the APPLY phase"
    );
    assert!(
        rows[0].fork_path.is_some(),
        "conflict row must record the fork path"
    );
}

// ---------------------------------------------------------------------------
// two-cycle test — no hand-seeding of baselines
// ---------------------------------------------------------------------------

/// Two-phase stub server: serves a download in phase 1, a conflict in phase 2.
/// Phase transitions are driven by the test via an `Arc<Mutex<u32>>` counter.
struct TwoCycleStub {
    /// Download bytes for phase 1.
    download_bytes: Vec<u8>,
    /// Local bytes for the conflict assertion (phase 2 download via DeltaDownload).
    remote_bytes: Vec<u8>,
    /// Call counter — even = phase 1 (download), odd = phase 2 (conflict).
    call_count: Arc<std::sync::Mutex<u32>>,
}

#[tonic::async_trait]
impl SyncService for TwoCycleStub {
    type SyncStateStream = ReceiverStream<Result<SyncStateAck, Status>>;
    type DeltaDownloadStream = ReceiverStream<Result<DeltaChunk, Status>>;

    async fn exchange_state(
        &self,
        _req: Request<SyncStateRequest>,
    ) -> Result<Response<SyncStateResponse>, Status> {
        let mut count = self.call_count.lock().unwrap();
        let phase = *count;
        *count += 1;
        drop(count);

        if phase == 0 {
            // Phase 1: return a download action so the client fetches the
            // base content and persists it to the blob cache + node_baselines.
            let entry = disk_proto::disk::FileMetadata {
                path: CONFLICT_PATH.to_owned(),
                ..Default::default()
            };
            Ok(Response::new(SyncStateResponse {
                to_download: vec![entry],
                ..Default::default()
            }))
        } else {
            // Phase 2: return a conflict for the same path.
            let report = ConflictReport {
                path: CONFLICT_PATH.to_owned(),
                local: Some(FileMetadata {
                    path: CONFLICT_PATH.to_owned(),
                    ..Default::default()
                }),
                remote: Some(FileMetadata {
                    path: CONFLICT_PATH.to_owned(),
                    ..Default::default()
                }),
                suggested_resolution: "merge".to_owned(),
            };
            Ok(Response::new(SyncStateResponse {
                conflicts: vec![report],
                ..Default::default()
            }))
        }
    }

    async fn upload_delta(
        &self,
        _req: Request<DeltaUploadRequest>,
    ) -> Result<Response<DeltaUploadResponse>, Status> {
        Err(Status::unimplemented("stub"))
    }

    async fn sync_state(
        &self,
        _req: Request<Streaming<SyncStateRequest>>,
    ) -> Result<Response<Self::SyncStateStream>, Status> {
        Err(Status::unimplemented("stub"))
    }

    async fn delta_upload(
        &self,
        _req: Request<Streaming<DeltaUploadRequest>>,
    ) -> Result<Response<DeltaUploadResponse>, Status> {
        Err(Status::unimplemented("stub"))
    }

    async fn delta_download(
        &self,
        req: Request<DeltaDownloadRequest>,
    ) -> Result<Response<Self::DeltaDownloadStream>, Status> {
        // Phase 1 downloads the base; phase 2 downloads the remote conflict bytes.
        // We distinguish by the call_count but both use DeltaDownload — just serve
        // the correct bytes.  The stub serves `download_bytes` for the first call
        // and `remote_bytes` for subsequent calls.
        let _path = req.into_inner().path;
        let count = *self.call_count.lock().unwrap();
        let bytes = if count <= 1 {
            self.download_bytes.clone()
        } else {
            self.remote_bytes.clone()
        };

        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let chunk = DeltaChunk {
            data: bytes,
            offset: 0,
            weak_checksum: 0,
            strong_hash: vec![],
        };
        let _ = tx.send(Ok(chunk)).await;
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

async fn spawn_two_cycle_stub(
    download_bytes: Vec<u8>,
    remote_bytes: Vec<u8>,
    call_count: Arc<std::sync::Mutex<u32>>,
) -> Fixture {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind 0");
    let port = listener.local_addr().expect("local_addr").port();

    let CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    let ca_pem = cert_pem.clone().into_bytes();

    let identity = Identity::from_pem(&cert_pem, &key_pem);
    let tls = ServerTlsConfig::new().identity(identity);

    let svc = TwoCycleStub {
        download_bytes,
        remote_bytes,
        call_count,
    };

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);

    tokio::spawn(async move {
        Server::builder()
            .tls_config(tls)
            .expect("apply tls")
            .add_service(SyncServiceServer::new(svc))
            .serve_with_incoming_shutdown(incoming, async {
                let _ = rx.await;
            })
            .await
            .expect("server terminated");
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    Fixture {
        server_url: format!("https://localhost:{port}"),
        ca_pem,
        _shutdown: tx,
    }
}

/// TRUE two-cycle test: no hand-seeding of baselines or blob cache.
///
/// Cycle 1: the daemon downloads the common-ancestor (base) file content from
///   the stub and writes it to disk AND persists a baseline row via
///   `upsert_node_baselines` (the client baseline-persist path).
///
/// Cycle 2: the stub reports a conflict on the same path.  The APPLY path
///   loads the baseline from the DB (populated in cycle 1), retrieves the base
///   bytes from the blob cache, and attempts a 3-way merge.  Because the local
///   and remote edits are on different lines (non-overlapping), the merge is
///   clean: the live file contains BOTH edits and NO fork is created.
///
/// This test proves the headline feature works end-to-end in the daemon's own
/// assembly without any manual DB or cache seeding.
#[tokio::test]
#[cfg(unix)]
async fn two_cycle_no_hand_seed_auto_merges_non_overlap() {
    // Base content: what the daemon downloads in cycle 1.
    let base: &[u8] = b"line1\nline2\nline3\nline4\nline5\n";

    // After cycle 1 the client holds `base` locally.
    // In cycle 2:
    //   - local: the user edited line 1 (client-side modification).
    //   - remote: the server's version has line 5 edited.
    // Non-overlapping edits → clean 3-way merge.
    let local_after_download: &[u8] = b"LOCAL_EDIT\nline2\nline3\nline4\nline5\n";
    let remote_edit: &[u8] = b"line1\nline2\nline3\nline4\nREMOTE_EDIT\n";

    let call_count = Arc::new(std::sync::Mutex::new(0u32));
    let fx =
        spawn_two_cycle_stub(base.to_vec(), remote_edit.to_vec(), Arc::clone(&call_count)).await;

    let client = connect(&fx).await;

    // Open a real MetaDb and BlobCache — no hand-seeding of either.
    let db_dir = tempfile::tempdir().unwrap();
    let db = Arc::new(
        disk_core::MetaDb::open(&db_dir.path().join("meta.db"))
            .await
            .expect("open MetaDb"),
    );
    let cache_dir = tempfile::tempdir().unwrap();
    let blob_cache = Arc::new(BlobCache::new(cache_dir.path()));

    // Set up the vault directory with the local-edited version (as if the user
    // opened and edited the file after the daemon downloaded it in cycle 1).
    let vault_dir = tempfile::tempdir().unwrap();
    let docs_dir = vault_dir.path().join("docs");
    std::fs::create_dir_all(&docs_dir).unwrap();
    // Cycle 1 will overwrite this with `base`; we pre-create the file so the
    // directory exists for `write`.
    std::fs::write(vault_dir.path().join(CONFLICT_PATH), b"placeholder").unwrap();

    // ── Cycle 1: download base ──────────────────────────────────────────────
    //
    // Build the transport with MetaDb + BlobCache attached exactly as the
    // daemon's run_start + build_remote_sync_for_share does.
    {
        let mut transport = RemoteSync::with_scan_root(
            &client,
            SHARE_NAME,
            vault_dir.path().to_path_buf(),
            NODE_ID,
        )
        .with_blob_cache(Arc::clone(&blob_cache), HashMap::new())
        .with_meta_db(Arc::clone(&db));

        transport.execute().await.expect("cycle 1 must succeed");

        // Wait for the fire-and-forget baseline write to complete.
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    // After cycle 1: the file on disk must hold the downloaded base content.
    let on_disk_after_c1 =
        std::fs::read(vault_dir.path().join(CONFLICT_PATH)).expect("file must exist after c1");
    assert_eq!(
        on_disk_after_c1, base,
        "after cycle 1 the local file must hold the downloaded base content"
    );

    // Simulate the user editing line 1 after cycle 1 completes.
    std::fs::write(vault_dir.path().join(CONFLICT_PATH), local_after_download).unwrap();

    // Assert: the baseline was persisted to the DB by cycle 1.
    let baseline_rows = db
        .load_node_baseline(NODE_ID, SHARE_NAME)
        .await
        .expect("load_node_baseline must succeed");
    assert_eq!(
        baseline_rows.len(),
        1,
        "cycle 1 must have persisted a baseline row to node_baselines; \
         found {} rows — client baseline-persist may not be wired",
        baseline_rows.len()
    );

    // ── Cycle 2: conflict arrives; 3-way merge expected ─────────────────────
    //
    // Load baselines from the DB (as the daemon's per-iteration call does).
    // This is the production path — no hand-seeding.
    let baselines_for_c2 = baseline_rows
        .into_iter()
        .filter(|e| !e.deleted)
        .map(|e| (e.path.to_string_lossy().into_owned(), e.content_hash))
        .collect::<HashMap<String, [u8; 32]>>();

    assert_eq!(
        baselines_for_c2.len(),
        1,
        "baselines loaded from the DB must contain exactly one entry"
    );

    {
        let mut transport = RemoteSync::with_scan_root(
            &client,
            SHARE_NAME,
            vault_dir.path().to_path_buf(),
            NODE_ID,
        )
        .with_blob_cache(Arc::clone(&blob_cache), baselines_for_c2)
        .with_meta_db(Arc::clone(&db));

        transport.execute().await.expect("cycle 2 must succeed");

        // Wait briefly for the fire-and-forget DB writes.
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    // Assert 1: the live file contains BOTH edits (3-way merge succeeded).
    let live_bytes = std::fs::read(vault_dir.path().join(CONFLICT_PATH))
        .expect("live file must exist after cycle 2");
    let live_str = std::str::from_utf8(&live_bytes).unwrap();

    assert!(
        live_str.contains("LOCAL_EDIT"),
        "two_cycle_no_hand_seed: merged file must contain the local edit; got:\n{live_str}"
    );
    assert!(
        live_str.contains("REMOTE_EDIT"),
        "two_cycle_no_hand_seed: merged file must contain the remote edit; got:\n{live_str}"
    );

    // Assert 2: NO fork file created — it was a clean merge.
    let fork_count = file_count_in(&docs_dir).saturating_sub(1);
    assert_eq!(
        fork_count, 0,
        "two_cycle_no_hand_seed: clean 3-way merge must not create a fork; \
         found {fork_count} extra file(s) in {docs_dir:?}"
    );
}

/// Regression guard: when there is NO base in the cache (first-sync scenario
/// or cache eviction), the cycle must still fork rather than crashing or
/// silently discarding data.
#[tokio::test]
async fn cycle_forks_when_no_baseline() {
    let local_edit: &[u8] = b"# Notes\n\nLocal version.\n";
    let remote_edit: &[u8] = b"# Notes\n\nRemote version.\n";

    let fx = spawn_stub(remote_edit.to_vec()).await;
    let client = connect(&fx).await;

    let vault_dir = tempfile::tempdir().unwrap();
    let docs_dir = vault_dir.path().join("docs");
    std::fs::create_dir_all(&docs_dir).unwrap();
    std::fs::write(docs_dir.join("notes.md"), local_edit).unwrap();

    // No blob cache attached — base will be None.
    let mut transport =
        RemoteSync::with_scan_root(&client, SHARE_NAME, vault_dir.path().to_path_buf(), NODE_ID);

    transport.execute().await.expect("execute must succeed");

    // Assert: local file untouched AND fork created.
    let live_bytes = std::fs::read(vault_dir.path().join(CONFLICT_PATH)).unwrap();
    assert_eq!(
        live_bytes, local_edit,
        "without a base, the local file must remain untouched"
    );
    let entry_count = file_count_in(&docs_dir);
    assert_eq!(
        entry_count, 2,
        "without a base, a fork must be created; found {entry_count} file(s)"
    );
}
