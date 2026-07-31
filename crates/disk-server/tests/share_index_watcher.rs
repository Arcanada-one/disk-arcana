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

    let _handle = spawn_share_index_watcher(roots, meta_db.clone(), "server")
        .expect("watcher startup must succeed")
        .expect("configured watcher must spawn");

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
    let _handle = spawn_share_index_watcher(roots, meta_db.clone(), "server")
        .expect("watcher startup must succeed")
        .expect("configured watcher must spawn");

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

#[tokio::test]
async fn share_index_configured_missing_root_is_fail_closed() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("meta.sqlite");
    let meta_db = MetaDb::open(&db_path).await.unwrap();

    let mut roots = std::collections::HashMap::new();
    roots.insert(
        "missing-share".to_string(),
        dir.path().join("does-not-exist"),
    );

    let result = spawn_share_index_watcher(roots, meta_db, "server");
    let error = match result {
        Ok(_) => panic!("configured missing root must fail startup"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("configured share roots are unavailable"),
        "unexpected error: {error}"
    );
}

/// Rename within a single vault: the vanished old path must be tombstoned,
/// the new path must be upserted to the same vault, and the content must
/// match the original file.
#[tokio::test]
async fn share_index_watcher_rename_within_vault_tombstones_old_and_upserts_new() {
    let dir = tempdir().unwrap();
    let share_root = dir.path().join("vault");
    std::fs::create_dir_all(&share_root).unwrap();

    let old_path = share_root.join("old-name.txt");
    let original_content = b"rename-me";
    std::fs::write(&old_path, original_content).unwrap();
    let original_hash = *blake3::hash(original_content).as_bytes();

    let db_path = dir.path().join("meta.sqlite");
    let meta_db = MetaDb::open(&db_path).await.unwrap();

    // Seed the old path so we can verify the tombstone after rename.
    meta_db
        .upsert_file_scoped(
            None,
            "vault",
            &disk_core::types::FileMeta {
                path: PathBuf::from("old-name.txt"),
                content_hash: original_hash,
                size: original_content.len() as u64,
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
    roots.insert("vault".to_string(), share_root.clone());
    let _handle = spawn_share_index_watcher(roots, meta_db.clone(), "server")
        .expect("watcher startup must succeed")
        .expect("configured watcher must spawn");

    // Arm notify before mutating.
    sleep(Duration::from_millis(300)).await;

    // Rename the file within the same vault.
    let new_path = share_root.join("new-name.txt");
    std::fs::rename(&old_path, &new_path).unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    let (mut old_tombstoned, mut new_upserted) = (false, false);
    while tokio::time::Instant::now() < deadline && !(old_tombstoned && new_upserted) {
        if !old_tombstoned {
            if let Ok(Some(row)) = meta_db.get_file_scoped(None, "vault", "old-name.txt").await {
                if row.deleted {
                    old_tombstoned = true;
                }
            }
        }
        if !new_upserted {
            if let Ok(Some(row)) = meta_db.get_file_scoped(None, "vault", "new-name.txt").await {
                if !row.deleted && row.size == original_content.len() as u64 {
                    new_upserted = true;
                }
            }
        }
        sleep(Duration::from_millis(100)).await;
    }

    assert!(
        old_tombstoned,
        "old path must be tombstoned after within-vault rename"
    );
    assert!(
        new_upserted,
        "new path must be upserted after within-vault rename"
    );

    // The new row must carry the original file's content hash.
    let new_row = meta_db
        .get_file_scoped(None, "vault", "new-name.txt")
        .await
        .unwrap()
        .expect("new path must have a MetaDb row");
    assert!(!new_row.deleted);
    assert_eq!(new_row.content_hash, original_hash);
    assert_eq!(new_row.size, original_content.len() as u64);
}

/// Cross-vault move: a file moved from vault A to vault B must be tombstoned
/// under vault A and upserted under vault B — no cross-vault path leakage,
/// and no file owned by one vault appears under the other.
#[tokio::test]
async fn share_index_watcher_cross_vault_move_tombstones_source_and_upserts_dest() {
    let dir = tempdir().unwrap();

    let root_a = dir.path().join("vault-a");
    std::fs::create_dir_all(&root_a).unwrap();
    let root_b = dir.path().join("vault-b");
    std::fs::create_dir_all(&root_b).unwrap();

    let file_a = root_a.join("move-me.txt");
    let content = b"cross-vault-data";
    std::fs::write(&file_a, content).unwrap();
    let content_hash = *blake3::hash(content).as_bytes();

    let db_path = dir.path().join("meta.sqlite");
    let meta_db = MetaDb::open(&db_path).await.unwrap();

    // Seed the file under vault A.
    meta_db
        .upsert_file_scoped(
            None,
            "vault-a",
            &disk_core::types::FileMeta {
                path: PathBuf::from("move-me.txt"),
                content_hash,
                size: content.len() as u64,
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
    roots.insert("vault-a".to_string(), root_a.clone());
    roots.insert("vault-b".to_string(), root_b.clone());
    let _handle = spawn_share_index_watcher(roots, meta_db.clone(), "server")
        .expect("watcher startup must succeed")
        .expect("configured watcher must spawn");

    sleep(Duration::from_millis(300)).await;

    // Move the file from vault A to vault B.
    let file_b = root_b.join("moved-here.txt");
    std::fs::rename(&file_a, &file_b).unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let (mut a_tombstoned, mut b_upserted) = (false, false);
    while tokio::time::Instant::now() < deadline && !(a_tombstoned && b_upserted) {
        if !a_tombstoned {
            if let Ok(Some(row)) = meta_db
                .get_file_scoped(None, "vault-a", "move-me.txt")
                .await
            {
                if row.deleted {
                    a_tombstoned = true;
                }
            }
        }
        if !b_upserted {
            if let Ok(Some(row)) = meta_db
                .get_file_scoped(None, "vault-b", "moved-here.txt")
                .await
            {
                if !row.deleted && row.size == content.len() as u64 {
                    b_upserted = true;
                }
            }
        }
        sleep(Duration::from_millis(100)).await;
    }

    assert!(
        a_tombstoned,
        "source path must be tombstoned in vault A after cross-vault move"
    );
    assert!(
        b_upserted,
        "destination path must be upserted in vault B after cross-vault move"
    );

    // Destination row must carry the original content.
    let b_row = meta_db
        .get_file_scoped(None, "vault-b", "moved-here.txt")
        .await
        .unwrap()
        .expect("dest path must have a MetaDb row");
    assert!(!b_row.deleted);
    assert_eq!(b_row.content_hash, content_hash);
    assert_eq!(b_row.size, content.len() as u64);

    // ── No cross-vault misattribution ──
    // The source path must not appear live under vault B.
    assert!(
        meta_db
            .get_file_scoped(None, "vault-b", "move-me.txt")
            .await
            .unwrap()
            .map_or(true, |r| r.deleted),
        "source path must not be live under vault B"
    );
    // The dest path must not appear under vault A.
    assert!(
        meta_db
            .get_file_scoped(None, "vault-a", "moved-here.txt")
            .await
            .unwrap()
            .is_none(),
        "dest path must not appear under vault A"
    );
}
