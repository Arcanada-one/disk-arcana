//! Bearer-token enforcement test (V-12, T-mTLS-bypass).
//!
//! Verifies that `SyncService.*` RPCs without a valid bearer token return
//! `Status::unauthenticated`.
//!
//! DISK-0004 Step 9.

use disk_proto::disk::sync_service_server::SyncService;
use disk_proto::disk::{DeltaDownloadRequest, DeltaUploadRequest, SyncStateRequest};
use disk_server::{AuthStore, SyncServiceImpl};
use tempfile::tempdir;
use tonic::Request;

fn make_sync_svc() -> SyncServiceImpl {
    let root = tempdir().unwrap();
    let path = root.path().to_path_buf();
    // Leak tempdir so tests can use the path without teardown.
    std::mem::forget(root);
    SyncServiceImpl::new(AuthStore::new(), path)
}

#[tokio::test]
async fn delta_download_without_auth_unauthenticated() {
    let svc = make_sync_svc();
    let req = Request::new(DeltaDownloadRequest {
        path: "file.md".into(),
        ..Default::default()
    });
    let err = svc.delta_download(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

/// ExchangeState now requires auth (DISK-0043: replaced the unimplemented stub
/// with real reconcile). Without a bearer token → Unauthenticated.
#[tokio::test]
async fn exchange_state_without_auth_unauthenticated() {
    let svc = make_sync_svc();
    let req = Request::new(SyncStateRequest::default());
    let err = svc.exchange_state(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn upload_delta_legacy_unimplemented() {
    let svc = make_sync_svc();
    let req = Request::new(DeltaUploadRequest::default());
    let err = svc.upload_delta(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unimplemented);
}
