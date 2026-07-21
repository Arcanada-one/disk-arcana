//! Load-style scanner harness (DISK-0012 / G3 T6.2 scaffold).
//!
//! Ignored in default `cargo test` runs — invoke via `scripts/load-test-*.sh`.

use std::path::Path;
use std::time::{Duration, Instant};

use disk_core::filter::{Filter, FilterRules};
use disk_core::scanner::scan_root;
use tempfile::TempDir;

const FILE_BODY: &[u8] = b"# load\n";

fn seed_markdown_files(root: &Path, count: usize) {
    let notes = root.join("notes");
    std::fs::create_dir_all(&notes).expect("mkdir notes");
    for i in 0..count {
        std::fs::write(notes.join(format!("note_{i:05}.md")), FILE_BODY).expect("write note");
    }
}

fn run_scan_load_test(count: usize, max_elapsed: Duration) {
    let dir = TempDir::new().expect("tempdir");
    seed_markdown_files(dir.path(), count);
    let filter = Filter::from_config(&FilterRules::default()).expect("filter");
    let started = Instant::now();
    let metas = scan_root(dir.path(), filter, "load-test".into()).expect("scan");
    let elapsed = started.elapsed();
    assert_eq!(metas.len(), count);
    eprintln!(
        "load_scan_{count}: {count} files in {elapsed:?} ({rate:.1} files/s)",
        count = count,
        elapsed = elapsed,
        rate = count as f64 / elapsed.as_secs_f64().max(1e-9)
    );
    assert!(
        elapsed <= max_elapsed,
        "{count}-file scan should finish within {max_elapsed:?} on DEVS, took {elapsed:?}"
    );
}

#[test]
#[ignore = "load test — run scripts/load-test-scanner-smoke.sh"]
fn load_scan_1000_markdown_files() {
    run_scan_load_test(1_000, Duration::from_secs(120));
}

#[test]
#[ignore = "load test — run scripts/load-test-scanner-10k.sh"]
fn load_scan_10000_markdown_files() {
    run_scan_load_test(10_000, Duration::from_secs(600));
}
