#![allow(clippy::cmp_owned)]
//! Lifecycle / CRUD coverage for `MetaDb` files / tombstones / conflicts.

use std::path::PathBuf;

use disk_core::{ConflictRecord, FileMeta, MetaDb, Tombstone, VectorClock, DEFAULT_TTL_SECS};
use tempfile::tempdir;

fn meta(path: &str, hash_byte: u8, size: u64) -> FileMeta {
    FileMeta {
        path: PathBuf::from(path),
        content_hash: [hash_byte; 32],
        size,
        mtime_ns: 1_000_000,
        inode: Some(42),
        vector_clock: VectorClock::new(),
        deleted: false,
        deleted_at: None,
        node_id: "node-A".into(),
    }
}

async fn fresh_db() -> MetaDb {
    let dir = tempdir().unwrap();
    let path = dir.path().join("meta.sqlite");
    let db = MetaDb::open(&path).await.expect("open");
    std::mem::forget(dir); // keep tempdir alive for the duration of the test
    db
}

#[tokio::test]
async fn upsert_then_get_round_trip() {
    let db = fresh_db().await;
    let m = meta("notes/a.md", 0x11, 12);
    db.upsert_file(&m).await.unwrap();
    let got = db.get_file("notes/a.md").await.unwrap().unwrap();
    assert_eq!(got.content_hash, [0x11; 32]);
    assert_eq!(got.size, 12);
    assert_eq!(got.path, PathBuf::from("notes/a.md"));
}

#[tokio::test]
async fn upsert_overwrites_existing() {
    let db = fresh_db().await;
    db.upsert_file(&meta("a.md", 0x01, 10)).await.unwrap();
    db.upsert_file(&meta("a.md", 0x02, 20)).await.unwrap();
    let got = db.get_file("a.md").await.unwrap().unwrap();
    assert_eq!(got.content_hash, [0x02; 32]);
    assert_eq!(got.size, 20);
}

#[tokio::test]
async fn delete_file_removes_row() {
    let db = fresh_db().await;
    db.upsert_file(&meta("a.md", 0x01, 1)).await.unwrap();
    db.delete_file("a.md").await.unwrap();
    assert!(db.get_file("a.md").await.unwrap().is_none());
}

#[tokio::test]
async fn list_all_files_returns_inserted_rows_sorted() {
    let db = fresh_db().await;
    db.upsert_file(&meta("z.md", 0x09, 1)).await.unwrap();
    db.upsert_file(&meta("a.md", 0x01, 1)).await.unwrap();
    db.upsert_file(&meta("m.md", 0x05, 1)).await.unwrap();
    let all = db.list_all_files().await.unwrap();
    let paths: Vec<_> = all.iter().map(|m| m.path.display().to_string()).collect();
    assert_eq!(paths, vec!["a.md", "m.md", "z.md"]);
}

#[tokio::test]
async fn create_and_get_tombstone() {
    let db = fresh_db().await;
    let t = Tombstone::new(
        "trash/x.md".into(),
        [0xAB; 32],
        "node-A".into(),
        1_000_000,
        DEFAULT_TTL_SECS,
    );
    db.create_tombstone(&t).await.unwrap();
    let got = db.get_tombstone("trash/x.md").await.unwrap().unwrap();
    assert_eq!(got.last_hash, [0xAB; 32]);
    assert_eq!(got.deleted_by, "node-A");
    assert!(got.ttl_expires > got.deleted_at);
}

#[tokio::test]
async fn list_active_tombstones_filters_by_now() {
    let db = fresh_db().await;
    let active = Tombstone::new("a.md".into(), [0x01; 32], "n".into(), 0, 100);
    let stale = Tombstone::new("b.md".into(), [0x02; 32], "n".into(), 0, 10);
    db.create_tombstone(&active).await.unwrap();
    db.create_tombstone(&stale).await.unwrap();

    let listed = db.list_active_tombstones(50).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].path, "a.md");
}

#[tokio::test]
async fn delete_tombstone_removes_row() {
    let db = fresh_db().await;
    let t = Tombstone::new("a.md".into(), [0; 32], "n".into(), 0, 100);
    db.create_tombstone(&t).await.unwrap();
    db.delete_tombstone("a.md").await.unwrap();
    assert!(db.get_tombstone("a.md").await.unwrap().is_none());
}

#[tokio::test]
async fn create_and_list_conflicts() {
    let db = fresh_db().await;
    let c = ConflictRecord {
        id: None,
        vault_id: "default".into(),
        path: "a.md".into(),
        conflict_type: "concurrent".into(),
        local_hash: Some([0x01; 32]),
        remote_hash: Some([0x02; 32]),
        base_hash: None,
        resolution: None,
        fork_path: None,
        resolved: false,
        created_at: 0,
        resolved_at: None,
    };
    let id = db.create_conflict(&c).await.unwrap();
    assert!(id > 0);
    let listed = db.list_unresolved_conflicts().await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].path, "a.md");
    assert!(!listed[0].resolved);
}

#[tokio::test]
async fn vector_clock_round_trips_through_db() {
    let db = fresh_db().await;
    let mut vc = VectorClock::new();
    vc.advance("n1");
    vc.advance("n2");
    vc.advance("n2");
    let mut m = meta("vc.md", 0xCC, 5);
    m.vector_clock = vc.clone();
    db.upsert_file(&m).await.unwrap();
    let got = db.get_file("vc.md").await.unwrap().unwrap();
    assert_eq!(got.vector_clock, vc);
}
