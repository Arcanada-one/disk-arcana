use disk_core::MetaDb;
use sqlx::Row;
use tempfile::tempdir;

// ── Migration 005 schema checks ─────────────────────────────────────────────

#[tokio::test]
async fn migration_005_files_has_deleted_columns() {
    let dir = tempdir().expect("tempdir");
    let db = MetaDb::open(&dir.path().join("meta.sqlite"))
        .await
        .expect("open");

    let rows = sqlx::query("PRAGMA table_info(files)")
        .fetch_all(db.pool())
        .await
        .expect("table_info files");
    let columns: Vec<String> = rows.iter().map(|r| r.get::<String, _>("name")).collect();

    assert!(
        columns.iter().any(|c| c == "deleted"),
        "files table must have `deleted` column after migration 005; got {columns:?}"
    );
    assert!(
        columns.iter().any(|c| c == "deleted_at"),
        "files table must have `deleted_at` column after migration 005; got {columns:?}"
    );
}

#[tokio::test]
async fn migration_005_node_baselines_table_exists() {
    let dir = tempdir().expect("tempdir");
    let db = MetaDb::open(&dir.path().join("meta.sqlite"))
        .await
        .expect("open");

    let tables: Vec<String> =
        sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .fetch_all(db.pool())
            .await
            .expect("sqlite_master");

    assert!(
        tables.iter().any(|t| t == "node_baselines"),
        "node_baselines table must exist after migration 005; got {tables:?}"
    );

    let rows = sqlx::query("PRAGMA table_info(node_baselines)")
        .fetch_all(db.pool())
        .await
        .expect("table_info node_baselines");
    let columns: Vec<String> = rows.iter().map(|r| r.get::<String, _>("name")).collect();

    for required in [
        "node_id",
        "vault_id",
        "path",
        "content_hash",
        "deleted",
        "deleted_at",
    ] {
        assert!(
            columns.iter().any(|c| c == required),
            "node_baselines missing column `{required}`; got {columns:?}"
        );
    }
}

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

// DISK-0005 v1.1 — migration 003 introduces ACL / enrollment / publisher tables.
// See PRD-DISK-0001 v1.1 §4.11 and creative-DISK-0005-*.md.

#[tokio::test]
async fn v1_1_acl_enrollment_tables_present_after_migration_003() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("acl.sqlite");
    let db = MetaDb::open(&db_path).await.expect("open");

    let table_rows = sqlx::query("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .fetch_all(db.pool())
        .await
        .expect("sqlite_master");
    let tables: Vec<String> = table_rows
        .iter()
        .map(|r| r.get::<String, _>("name"))
        .collect();

    for required in [
        "acl_meta",
        "audit_event",
        "node_certs",
        "node_shares",
        "pending_enrollments",
        "publisher_counter",
        "publisher_keys",
    ] {
        assert!(
            tables.iter().any(|t| t == required),
            "missing v1.1 table `{required}` after migration 003; got {tables:?}"
        );
    }
}

#[tokio::test]
async fn v1_1_acl_meta_singleton_constraint() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("acl_meta.sqlite");
    let db = MetaDb::open(&db_path).await.expect("open");

    // First insert with id=1 must succeed.
    sqlx::query(
        "INSERT INTO acl_meta (id, version, updated_at, signed_by, file_sha256, loaded_at)
         VALUES (1, 1, 0, 'test', randomblob(32), 0)",
    )
    .execute(db.pool())
    .await
    .expect("first insert");

    // Second insert with id=2 MUST be rejected by CHECK(id=1).
    let second = sqlx::query(
        "INSERT INTO acl_meta (id, version, updated_at, signed_by, file_sha256, loaded_at)
         VALUES (2, 2, 0, 'test', randomblob(32), 0)",
    )
    .execute(db.pool())
    .await;
    assert!(
        second.is_err(),
        "acl_meta should enforce singleton via CHECK(id=1)"
    );
}

#[tokio::test]
async fn v1_1_node_shares_role_check_constraint() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("roles.sqlite");
    let db = MetaDb::open(&db_path).await.expect("open");

    // Seed a node + cert so node_shares FK is satisfied.
    sqlx::query(
        "INSERT INTO nodes (node_id, api_key_hash, registered_at)
         VALUES ('test-node', randomblob(32), 0)",
    )
    .execute(db.pool())
    .await
    .expect("seed node");

    let node_pk: i64 = sqlx::query_scalar("SELECT id FROM nodes WHERE node_id = 'test-node'")
        .fetch_one(db.pool())
        .await
        .expect("node id");

    sqlx::query(
        "INSERT INTO node_certs (cert_fingerprint, node_id, enrolled_at, expires_at)
         VALUES (randomblob(32), ?1, 0, 0)",
    )
    .bind(node_pk)
    .execute(db.pool())
    .await
    .expect("seed cert");

    let fp: Vec<u8> = sqlx::query_scalar("SELECT cert_fingerprint FROM node_certs LIMIT 1")
        .fetch_one(db.pool())
        .await
        .expect("fp");

    // Each of the four documented roles must be accepted.
    for role in ["bidirectional", "receive_only", "send_only", "publisher"] {
        let res = sqlx::query(
            "INSERT INTO node_shares (cert_fingerprint, share_name, enforced_role, updated_at)
             VALUES (?1, ?2, ?3, 0)",
        )
        .bind(&fp)
        .bind(format!("share-{role}"))
        .bind(role)
        .execute(db.pool())
        .await;
        assert!(res.is_ok(), "role `{role}` should be accepted");
    }

    // An invalid role string MUST be rejected by the CHECK constraint.
    let bogus = sqlx::query(
        "INSERT INTO node_shares (cert_fingerprint, share_name, enforced_role, updated_at)
         VALUES (?1, 'bogus-share', 'arbitrary', 0)",
    )
    .bind(&fp)
    .execute(db.pool())
    .await;
    assert!(
        bogus.is_err(),
        "node_shares.enforced_role must reject values outside the documented enum"
    );
}

#[tokio::test]
async fn migration_006_tenant_billing_table_exists() {
    let dir = tempdir().expect("tempdir");
    let db = MetaDb::open(&dir.path().join("billing-schema.sqlite"))
        .await
        .expect("open");

    let tables: Vec<String> =
        sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .fetch_all(db.pool())
            .await
            .expect("sqlite_master");

    assert!(
        tables.iter().any(|t| t == "tenant_billing"),
        "tenant_billing table must exist after migration 006; got {tables:?}"
    );
}

#[tokio::test]
async fn migration_007_tenant_vaults_table_exists() {
    let dir = tempdir().expect("tempdir");
    let db = MetaDb::open(&dir.path().join("vaults-schema.sqlite"))
        .await
        .expect("open");

    let tables: Vec<String> =
        sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .fetch_all(db.pool())
            .await
            .expect("sqlite_master");

    assert!(
        tables.iter().any(|t| t == "tenant_vaults"),
        "tenant_vaults table must exist after migration 007; got {tables:?}"
    );
}

#[tokio::test]
async fn migration_008_pending_enrollments_tenant_column() {
    let dir = tempdir().expect("tempdir");
    let db = MetaDb::open(&dir.path().join("enroll-tenant-schema.sqlite"))
        .await
        .expect("open");

    let names: Vec<String> = sqlx::query_as::<_, (i64, String, String, i64, Option<String>, i64)>(
        "PRAGMA table_info(pending_enrollments)",
    )
    .fetch_all(db.pool())
    .await
    .expect("table_info")
    .into_iter()
    .map(|row| row.1)
    .collect();

    assert!(
        names.iter().any(|c| c == "tenant_id"),
        "pending_enrollments.tenant_id must exist after migration 008; got {names:?}"
    );
}

#[tokio::test]
async fn migration_009_node_baselines_tenant_index() {
    let dir = tempdir().expect("tempdir");
    let db = MetaDb::open(&dir.path().join("baseline-index-schema.sqlite"))
        .await
        .expect("open");

    let indexes: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='node_baselines'",
    )
    .fetch_all(db.pool())
    .await
    .expect("sqlite_master indexes");

    assert!(
        indexes
            .iter()
            .any(|n| n == "idx_node_baselines_tenant_scope"),
        "idx_node_baselines_tenant_scope must exist after migration 009; got {indexes:?}"
    );
}

#[tokio::test]
async fn migration_011_user_accounts_table_exists() {
    let dir = tempdir().expect("tempdir");
    let db = MetaDb::open(&dir.path().join("user-accounts-schema.sqlite"))
        .await
        .expect("open");

    let tables: Vec<String> =
        sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .fetch_all(db.pool())
            .await
            .expect("sqlite_master");

    assert!(
        tables.iter().any(|t| t == "user_accounts"),
        "user_accounts table must exist after migration 011; got {tables:?}"
    );
}

#[tokio::test]
async fn migration_012_user_accounts_oauth_columns_exist() {
    let dir = tempdir().expect("tempdir");
    let db = MetaDb::open(&dir.path().join("user-accounts-oauth-schema.sqlite"))
        .await
        .expect("open");

    let rows = sqlx::query("PRAGMA table_info(user_accounts)")
        .fetch_all(db.pool())
        .await
        .expect("table_info user_accounts");
    let columns: Vec<String> = rows.iter().map(|r| r.get::<String, _>("name")).collect();

    for required in ["oauth_provider", "oauth_subject"] {
        assert!(
            columns.iter().any(|c| c == required),
            "user_accounts missing column `{required}` after migration 012; got {columns:?}"
        );
    }
}
