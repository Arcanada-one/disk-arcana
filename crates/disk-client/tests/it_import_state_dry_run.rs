//! DISK-0006 R8 — `disk import-state --dry-run` produces a plan without
//! writing any MetaDb rows.
//!
//! Plan §Test Plan row `it_import_state.rs` covers the dry-run contract:
//! the report MUST list every file the operator would seed but MUST NOT
//! open a write transaction. The test wires a fresh MetaDb, populates a
//! deterministic two-file fixture, runs dry-run, asserts both the report
//! shape (entries + byte accounting) and the DB shape (zero rows). A
//! follow-up live run on the same DB then confirms idempotence: dry-run
//! is a true preview, not a side-effect.

#![cfg(unix)]

use std::fs;
use std::path::PathBuf;

use disk_client::{import_state, ImportEntry};
use disk_core::MetaDb;
use tempfile::tempdir;

#[tokio::test]
async fn dry_run_lists_entries_and_writes_zero_rows() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("meta.db");
    let db = MetaDb::open(&db_path).await.unwrap();

    let share = dir.path().join("share");
    fs::create_dir(&share).unwrap();
    fs::write(share.join("alpha.txt"), b"alpha-bytes").unwrap(); // 11
    let nested = share.join("nested");
    fs::create_dir(&nested).unwrap();
    fs::write(nested.join("beta.bin"), b"beta-payload-1234").unwrap(); // 17

    let report = import_state(&share, "node-r8", &db, true)
        .await
        .expect("import_state dry_run");

    assert!(report.dry_run);
    assert_eq!(report.files_seen, 2);
    assert_eq!(
        report.files_imported, 0,
        "dry_run MUST NOT bump files_imported"
    );
    assert_eq!(report.bytes_total, 11 + 17);
    assert_eq!(report.entries.len(), 2);

    let mut paths: Vec<PathBuf> = report
        .entries
        .iter()
        .map(|e: &ImportEntry| e.relative_path.clone())
        .collect();
    paths.sort();
    assert_eq!(
        paths,
        vec![PathBuf::from("alpha.txt"), PathBuf::from("nested/beta.bin")]
    );

    // Every reported entry must hold a non-zero blake3 hash.
    for e in &report.entries {
        assert_ne!(e.content_hash, [0u8; 32], "blake3 hash must be populated");
    }

    let rows = db.list_all_files().await.unwrap();
    assert!(
        rows.is_empty(),
        "dry_run must leave MetaDb untouched; got {} rows",
        rows.len()
    );

    // Idempotence: a follow-up live run on the same DB must succeed and
    // produce exactly 2 rows — proving the dry-run did not poison state.
    let live = import_state(&share, "node-r8", &db, false)
        .await
        .expect("live import_state");
    assert_eq!(live.files_imported, 2);
    let after = db.list_all_files().await.unwrap();
    assert_eq!(after.len(), 2);
}
