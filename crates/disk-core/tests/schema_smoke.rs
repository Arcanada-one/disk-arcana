use disk_core::MetaDb;
use sqlx::Row;
use tempfile::tempdir;

#[tokio::test]
async fn migrations_apply_and_files_table_has_forward_compat_columns() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("disk-meta.sqlite");
    let db = MetaDb::open(&db_path).await.expect("open");

    let rows = sqlx::query("PRAGMA table_info(files)")
        .fetch_all(db.pool())
        .await
        .expect("table_info");
    let columns: Vec<String> = rows.iter().map(|r| r.get::<String, _>("name")).collect();

    for required in [
        "id",
        "tenant_id",
        "vault_id",
        "user_id",
        "path",
        "content_hash",
        "size",
        "mtime_ns",
        "inode",
        "vector_clock",
        "sync_state",
        "last_synced",
        "version_id",
        "parent_version_id",
        "encryption_nonce",
        "created_at",
        "updated_at",
    ] {
        assert!(
            columns.iter().any(|c| c == required),
            "missing column `{required}` in files; got {columns:?}"
        );
    }
}

#[tokio::test]
async fn wal_mode_enabled_after_open() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("wal.sqlite");
    let db = MetaDb::open(&db_path).await.expect("open");

    let mode: String = sqlx::query_scalar("PRAGMA journal_mode")
        .fetch_one(db.pool())
        .await
        .expect("query");
    assert_eq!(mode.to_lowercase(), "wal");
}

#[tokio::test]
async fn nodes_table_present_after_migration_002() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("nodes.sqlite");
    let db = MetaDb::open(&db_path).await.expect("open");

    let rows = sqlx::query("PRAGMA table_info(nodes)")
        .fetch_all(db.pool())
        .await
        .expect("table_info");
    let columns: Vec<String> = rows.iter().map(|r| r.get::<String, _>("name")).collect();

    assert!(columns.iter().any(|c| c == "node_id"));
    assert!(columns.iter().any(|c| c == "tenant_id"));
}
