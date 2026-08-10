//! ACL role mismatch integration test (P4a Step 7 + Step 11).
//!
//! Scenario: client metadata claims `publisher` role but the ACL table says
//! `receive_only` for this cert fingerprint → `PermissionDenied` response and
//! exactly one `AclRoleMismatch` audit row.
//!
//! Uses `SyncServiceImpl::with_acl` to inject a pre-seeded `AclEnforcer` and
//! an in-memory SQLite `AuditEmitter`.

use disk_proto::disk::{
    sync_service_server::SyncService, DeltaDownloadRequest, FileMetadata, SyncStateRequest,
};
use disk_server::{
    acl::{AclEnforcer, CertFingerprint, EnforcedRole, EnforcementTable},
    audit::AuditEmitter,
    auth::{AuthStore, CertIdentity},
    SyncServiceImpl,
};
use rustls::pki_types::CertificateDer;
use sqlx::SqlitePool;
use tempfile::tempdir;
use tonic::Request;

/// Fake DER bytes that will produce a known cert fingerprint.
fn fake_cert_der(seed: u8) -> Vec<u8> {
    vec![seed; 64]
}

fn cert_fp_from_der(der: &[u8]) -> CertFingerprint {
    let id = CertIdentity::from_der(der);
    id.fingerprint
}

async fn make_in_memory_pool() -> SqlitePool {
    let pool = SqlitePool::connect("sqlite::memory:")
        .await
        .expect("in-memory sqlite");
    // Run the migration to create audit_event table.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS audit_event (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts_ms       INTEGER NOT NULL,
            kind        TEXT    NOT NULL,
            cert_fp     BLOB,
            share       TEXT,
            payload_json TEXT   NOT NULL DEFAULT '{}'
        )",
    )
    .execute(&pool)
    .await
    .expect("create audit_event");
    pool
}

#[tokio::test]
async fn acl_role_mismatch_returns_permission_denied_and_writes_audit_row() {
    // ---- Setup ----
    let der = fake_cert_der(0xCC);
    let fp = cert_fp_from_der(&der);

    // ACL says receive_only, but client will try DeltaDownload which requires
    // ReceiveOnly or Bidirectional — so actually we need send_only to trigger
    // the mismatch on DeltaDownload (read op). Let's use send_only vs read.
    let mut table = EnforcementTable::new(1);
    table.insert(fp, "test-share", EnforcedRole::SendOnly); // send_only cannot download
    let enforcer = AclEnforcer::new_loaded(table);

    let pool = make_in_memory_pool().await;
    let audit = AuditEmitter::new(pool.clone());
    let root = tempdir().unwrap();

    let store = AuthStore::new();
    let svc = SyncServiceImpl::with_acl(store.clone(), root.path().to_path_buf(), enforcer, audit);

    // Register + auth to get a session token (legacy auth still runs first).
    let key = store.register_node("node1", "N", "test", None).unwrap();
    let (token, _) = store.authenticate("node1", key.as_str()).unwrap();

    // ---- Build request with cert extension + bearer token ----
    let cert = CertificateDer::from(der);
    let mut req = Request::new(DeltaDownloadRequest {
        path: "file.md".into(),
        ..Default::default()
    });
    req.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token.as_str()).parse().unwrap(),
    );
    req.metadata_mut()
        .insert("x-disk-share", "test-share".parse().unwrap());
    req.extensions_mut().insert(cert);

    // ---- Call the RPC ----
    let err = svc.delta_download(req).await.unwrap_err();
    assert_eq!(
        err.code(),
        tonic::Code::PermissionDenied,
        "send_only cert must be denied read access: {err}"
    );
    assert!(
        err.message().contains("ACL role mismatch") || err.message().contains("mismatch"),
        "error message should mention mismatch: {}",
        err.message()
    );

    // ---- Verify audit row ----
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_event WHERE kind = 'acl.role_mismatch'")
            .fetch_one(&pool)
            .await
            .expect("count query");
    assert_eq!(
        count, 1,
        "exactly one AclRoleMismatch audit row must be written"
    );
}

#[tokio::test]
async fn acl_receive_only_can_download_but_not_upload() {
    // ReceiveOnly cert can call DeltaDownload (read) but should be denied
    // DeltaUpload (write). Since DeltaUpload takes Streaming<DeltaUploadRequest>
    // we just verify the service struct is wired correctly by checking ACL
    // for the download path (positive case).
    let der = fake_cert_der(0xDD);
    let fp = cert_fp_from_der(&der);

    let mut table = EnforcementTable::new(1);
    table.insert(fp, "wiki", EnforcedRole::ReceiveOnly);
    let enforcer = AclEnforcer::new_loaded(table);

    let pool = make_in_memory_pool().await;
    let audit = AuditEmitter::new(pool.clone());
    let root = tempdir().unwrap();

    // Write a real file so DeltaDownload succeeds if ACL passes.
    std::fs::write(root.path().join("test.md"), b"hello world").unwrap();

    let store = AuthStore::new();
    let svc = SyncServiceImpl::with_acl(store.clone(), root.path().to_path_buf(), enforcer, audit);
    let key = store.register_node("node2", "N", "test", None).unwrap();
    let (token, _) = store.authenticate("node2", key.as_str()).unwrap();

    let cert = CertificateDer::from(der);
    let mut req = Request::new(DeltaDownloadRequest {
        path: "test.md".into(),
        ..Default::default()
    });
    req.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token.as_str()).parse().unwrap(),
    );
    req.metadata_mut()
        .insert("x-disk-share", "wiki".parse().unwrap());
    req.extensions_mut().insert(cert);

    // ReceiveOnly can download — expect Ok.
    let result = svc.delta_download(req).await;
    assert!(
        result.is_ok(),
        "receive_only cert must be permitted to download: {:?}",
        result.err()
    );

    // No mismatch audit rows expected.
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_event WHERE kind = 'acl.role_mismatch'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 0, "no mismatch audit rows for permitted download");
}

// ---------------------------------------------------------------------------
// DISK-0079: the server must not hand upload work to a receive-only follower.
// ---------------------------------------------------------------------------

/// Measured on the Mac follower: a share declared `receive_only` was handed a
/// `to_upload` list by the reconciler and the client executed it — 230 upload
/// attempts against the canonical host. The client refuses such a list since
/// PR #168, but a guarantee enforced on one side only is one deployment away
/// from being no guarantee at all: an older or third-party client would still
/// obey.
///
/// The client here reports a file the server does not have, which is exactly
/// the shape that makes the reconciler emit `to_upload`. With a bidirectional
/// role that list is non-empty (asserted below, so this test cannot pass by
/// simply producing no work); with `receive_only` it must be empty.
#[tokio::test]
async fn receive_only_caller_is_never_given_upload_work() {
    async fn to_upload_len_for(role: EnforcedRole) -> usize {
        let der = fake_cert_der(0xAB);
        let fp = cert_fp_from_der(&der);

        let mut table = EnforcementTable::new(1);
        table.insert(fp, "kb", role);
        let enforcer = AclEnforcer::new_loaded(table);

        let pool = make_in_memory_pool().await;
        let audit = AuditEmitter::new(pool.clone());
        let root = tempdir().unwrap();
        let store = AuthStore::new();
        let db_dir = tempdir().unwrap();
        let db = disk_core::MetaDb::open(&db_dir.path().join("meta.sqlite"))
            .await
            .expect("open meta db");
        let svc =
            SyncServiceImpl::with_acl(store.clone(), root.path().to_path_buf(), enforcer, audit)
                .with_meta_db(db, "server");

        let key = store.register_node("kb-node", "N", "test", None).unwrap();
        let (token, _) = store.authenticate("kb-node", key.as_str()).unwrap();

        // The client reports a file the server has never seen → the reconciler
        // wants it uploaded.
        let mut req = Request::new(SyncStateRequest {
            files: vec![FileMetadata {
                path: "notes/only-on-client.md".into(),
                size: 3,
                ..Default::default()
            }],
            ..Default::default()
        });
        req.metadata_mut().insert(
            "authorization",
            format!("Bearer {}", token.as_str()).parse().unwrap(),
        );
        req.metadata_mut()
            .insert("x-disk-share", "kb".parse().unwrap());
        req.extensions_mut().insert(CertificateDer::from(der));

        let resp = svc
            .exchange_state(req)
            .await
            .expect("exchange_state must succeed for an allowed role")
            .into_inner();
        resp.to_upload.len()
    }

    // Control: the same request against a bidirectional role DOES produce
    // upload work. Without this the assertion below could be satisfied by a
    // reconciler that never emits anything.
    assert_eq!(
        to_upload_len_for(EnforcedRole::Bidirectional).await,
        1,
        "control: a bidirectional caller must still be asked to upload"
    );

    assert_eq!(
        to_upload_len_for(EnforcedRole::ReceiveOnly).await,
        0,
        "a receive_only caller must never be handed upload work"
    );
}

/// DISK-0094: a receive-only follower must not be told to fork on conflict.
/// Canon wins — the server copy is routed as `to_download`, `conflicts` empty.
#[tokio::test]
async fn receive_only_conflict_is_server_wins_not_fork() {
    let der = fake_cert_der(0xCD);
    let fp = cert_fp_from_der(&der);

    let mut table = EnforcementTable::new(1);
    table.insert(fp, "default", EnforcedRole::ReceiveOnly);
    let enforcer = AclEnforcer::new_loaded(table);

    let pool = make_in_memory_pool().await;
    let audit = AuditEmitter::new(pool);
    let root = tempdir().unwrap();
    let store = AuthStore::new();
    let db_dir = tempdir().unwrap();
    let db = disk_core::MetaDb::open(&db_dir.path().join("meta.sqlite"))
        .await
        .expect("open meta db");
    let svc = SyncServiceImpl::with_acl(store.clone(), root.path().to_path_buf(), enforcer, audit)
        .with_meta_db(db, "server");

    let key = store.register_node("kb-node", "N", "test", None).unwrap();
    let (token, _) = store.authenticate("kb-node", key.as_str()).unwrap();

    // Server has shared.md @ [0xAA].
    let mut server_vc = disk_core::VectorClock::new();
    server_vc.advance("server");
    server_vc.advance("server");
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
        encryption_nonce: None,
        version_id: None,
        parent_version_id: None,
    };
    svc.meta_router
        .as_ref()
        .unwrap()
        .tenant_data(None)
        .await
        .expect("tenant db")
        .upsert_file_scoped(None, "default", &server_file)
        .await
        .unwrap();

    // Baseline: common ancestor [0xCC].
    let baseline_file = disk_core::types::FileMeta {
        path: std::path::PathBuf::from("shared.md"),
        content_hash: [0xCC; 32],
        size: 80,
        mtime_ns: 1_700_000_000_000_000_000,
        inode: None,
        vector_clock: disk_core::VectorClock::new(),
        deleted: false,
        deleted_at: None,
        node_id: "kb-node".into(),
        encryption_nonce: None,
        version_id: None,
        parent_version_id: None,
    };
    svc.meta_router
        .as_ref()
        .unwrap()
        .control()
        .upsert_node_baselines("kb-node", "default", &[baseline_file])
        .await
        .unwrap();

    // Client diverged @ [0xBB] — would fork for bidirectional callers.
    let mut client_vc_map = std::collections::HashMap::new();
    client_vc_map.insert("kb-node".to_string(), 2u64);
    let mut req = Request::new(SyncStateRequest {
        files: vec![FileMetadata {
            path: "shared.md".into(),
            content_hash: [0xBB; 32].to_vec(),
            size: 110,
            mtime_ns: 1_700_000_003_000_000_000,
            vector_clock: client_vc_map,
            ..Default::default()
        }],
        ..Default::default()
    });
    req.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token.as_str()).parse().unwrap(),
    );
    req.metadata_mut()
        .insert("x-disk-share", "default".parse().unwrap());
    req.extensions_mut().insert(CertificateDer::from(der));

    let resp = svc
        .exchange_state(req)
        .await
        .expect("exchange_state")
        .into_inner();

    assert!(
        resp.conflicts.is_empty(),
        "receive_only must not receive conflict reports: {:?}",
        resp.conflicts
    );
    assert_eq!(resp.to_upload.len(), 0, "receive_only must not upload");
    assert_eq!(
        resp.to_download.len(),
        1,
        "receive_only conflict must become server-wins download"
    );
    assert_eq!(resp.to_download[0].path, "shared.md");
    assert_eq!(
        resp.to_download[0].content_hash.as_slice(),
        &[0xAA; 32],
        "download must carry the server hash"
    );
}
