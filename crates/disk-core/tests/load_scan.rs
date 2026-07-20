//! Load-style scanner test (DISK-0012). Ignored in default `cargo test` runs.

use std::time::Instant;

use disk_core::filter::{Filter, FilterRules};
use disk_core::scanner::scan_root;
use tempfile::TempDir;

#[test]
#[ignore = "load test — run scripts/load-test-scanner-smoke.sh"]
fn load_scan_1000_markdown_files() {
    let dir = TempDir::new().expect("tempdir");
    let notes = dir.path().join("notes");
    std::fs::create_dir_all(&notes).expect("mkdir");
    for i in 0..1000 {
        std::fs::write(notes.join(format!("note_{i:04}.md")), b"# load\n")
            .expect("write");
    }
    let filter = Filter::from_config(&FilterRules::default()).expect("filter");
    let started = Instant::now();
    let metas = scan_root(dir.path(), filter, "load-test".into()).expect("scan");
    let elapsed = started.elapsed();
    assert_eq!(metas.len(), 1000);
    eprintln!(
        "load_scan_1000: {} files in {:?} ({:.1} files/s)",
        metas.len(),
        elapsed,
        metas.len() as f64 / elapsed.as_secs_f64()
    );
    assert!(
        elapsed.as_secs() < 120,
        "1000-file scan should finish within 120s on DEVS, took {:?}",
        elapsed
    );
}
