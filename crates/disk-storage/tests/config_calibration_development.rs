//! Research-only original-source adapter. Never part of an admission verifier.
use disk_storage::{
    PutOptions, S3BackendConfig, S3StorageBackend, StorageBackend, StorageObjectKey,
};
use std::os::unix::fs::PermissionsExt;

#[tokio::test]
#[ignore = "requires an explicitly owned PERSIST02G development laboratory"]
async fn original_s3_development_action() {
    assert_eq!(std::env::var("PERSIST02G_DEVELOPMENT").as_deref(), Ok("1"));
    let endpoint = std::env::var("DISK_B2_ENDPOINT").expect("owned loopback endpoint");
    let port = endpoint
        .strip_prefix("http://127.0.0.1:")
        .expect("numeric loopback only")
        .parse::<u16>()
        .expect("port only, no path/query/fragment");
    assert_ne!(port, 0);
    let root =
        std::path::PathBuf::from(std::env::var("PERSIST02G_CASE_ROOT").expect("owned case root"));
    assert!(root.is_absolute());
    let metadata = std::fs::symlink_metadata(&root).expect("existing owned root");
    assert!(metadata.is_dir() && !metadata.file_type().is_symlink());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    let scratch = tempfile::tempdir_in(root).expect("case-owned SQLite directory");
    let config = S3BackendConfig::backblaze_from_env().expect("original B2 constructor");
    println!(
        "PERSIST02G_READER {}",
        serde_json::json!({"region": config.region, "force_path_style": config.force_path_style})
    );
    let backend = S3StorageBackend::open(config, scratch.path().join("metadata.sqlite"))
        .await
        .expect("original backend open");
    let key = StorageObjectKey::new("development/fixture.txt").expect("synthetic object key");
    let bytes = b"persist02g-synthetic-object\n";
    backend
        .put(&key, bytes, PutOptions::default())
        .await
        .expect("original backend PUT completes");
    let received = backend
        .get(&key)
        .await
        .expect("original backend GET completes");
    assert_eq!(received, bytes);
    println!("PERSIST02G_ACTION_COMPLETE");
}
