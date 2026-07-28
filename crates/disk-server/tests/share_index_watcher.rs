//! Integration test: DISK_SHARE_ROOTS local write → MetaDb row (POST-R13).

use std::path::PathBuf;
use std::time::Duration;

use disk_core::meta_db::MetaDb;
use disk_server::spawn_share_index_watcher;
use tempfile::tempdir;
use tokio::time::sleep;

#[tokio::test]
async fn share_index_watcher_upserts_on_local_write() {
    let dir = tempdir().unwrap();
    let share_root = dir.path().join("hermes-artefacts");
    std::fs::create_dir_all(&share_root).unwrap();

    let db_path = dir.path().join("meta.sqlite");
    let meta_db = MetaDb::open(&db_path).await.unwrap();

    let mut roots = std::collections::HashMap::new();
    roots.insert("hermes-artefacts".to_string(), share_root.clone());

    let _handle =
        spawn_share_index_watcher(roots, meta_db.clone(), "server").expect("watcher must spawn");

    // Arm notify before writing.
    sleep(Duration::from_millis(200)).await;

    let target = share_root.join("probe.txt");
    std::fs::write(&target, b"disk-share-index-probe").unwrap();

    let rel = "probe.txt";
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(Some(row)) = meta_db.get_file_scoped(None, "hermes-artefacts", rel).await {
            if !row.deleted && row.size == 22 {
                return;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }

    panic!("MetaDb row for {rel} not indexed within deadline");
}

#[tokio::test]
async fn share_index_watcher_tombstones_on_delete() {
    let dir = tempdir().unwrap();
    let share_root = dir.path().join("hermes-artefacts");
    std::fs::create_dir_all(&share_root).unwrap();
    let file = share_root.join("gone.txt");
    std::fs::write(&file, b"x").unwrap();

    let db_path = dir.path().join("meta.sqlite");
    let meta_db = MetaDb::open(&db_path).await.unwrap();
    meta_db
        .upsert_file_scoped(
            None,
            "hermes-artefacts",
            &disk_core::types::FileMeta {
                path: PathBuf::from("gone.txt"),
                content_hash: *blake3::hash(b"x").as_bytes(),
                size: 1,
                mtime_ns: 0,
                inode: None,
                vector_clock: Default::default(),
                deleted: false,
                deleted_at: None,
                node_id: "server".into(),
                encryption_nonce: None,
                version_id: None,
                parent_version_id: None,
            },
        )
        .await
        .unwrap();

    let mut roots = std::collections::HashMap::new();
    roots.insert("hermes-artefacts".to_string(), share_root.clone());
    let _handle = spawn_share_index_watcher(roots, meta_db.clone(), "server").unwrap();

    sleep(Duration::from_millis(200)).await;

    std::fs::remove_file(&file).unwrap();

    let rel = "gone.txt";
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(Some(row)) = meta_db.get_file_scoped(None, "hermes-artefacts", rel).await {
            if row.deleted {
                return;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }

    panic!("MetaDb tombstone for {rel} not written within deadline");
}
