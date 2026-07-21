//! Fuzz `ReconciliationEngine::reconcile` — adversarial `FileMeta` slices must
//! yield `Result`, never panic.

#![no_main]

use std::path::PathBuf;

use arbitrary::Arbitrary;
use disk_core::reconciler::ReconciliationEngine;
use disk_core::types::FileMeta;
use disk_core::vector_clock::VectorClock;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FuzzClockEntry {
    node: String,
    counter: u64,
}

#[derive(Arbitrary, Debug)]
struct FuzzFileMeta {
    path: String,
    content_hash: [u8; 32],
    size: u64,
    mtime_ns: i64,
    inode: Option<u64>,
    deleted: bool,
    deleted_at: Option<i64>,
    node_id: String,
    clock: Vec<FuzzClockEntry>,
}

fn to_meta(f: FuzzFileMeta) -> Option<FileMeta> {
    if f.path.is_empty() || f.path.contains('\0') {
        return None;
    }
    let mut vector_clock = VectorClock::new();
    for e in f.clock {
        if e.node.is_empty() {
            continue;
        }
        vector_clock.0.insert(e.node, e.counter);
    }
    Some(FileMeta {
        path: PathBuf::from(f.path),
        content_hash: f.content_hash,
        size: f.size,
        mtime_ns: f.mtime_ns,
        inode: f.inode,
        vector_clock,
        deleted: f.deleted,
        deleted_at: f.deleted_at,
        node_id: if f.node_id.is_empty() {
            "fuzz".into()
        } else {
            f.node_id
        },
        encryption_nonce: None,
    version_id: None,
    parent_version_id: None,
    })
}

fn collect(input: Vec<FuzzFileMeta>) -> Vec<FileMeta> {
    input.into_iter().filter_map(to_meta).collect()
}

fuzz_target!(|input: (Vec<FuzzFileMeta>, Vec<FuzzFileMeta>, Vec<FuzzFileMeta>)| {
    let engine = ReconciliationEngine::new("fuzz-node".into());
    let local = collect(input.0);
    let remote = collect(input.1);
    let indexed = collect(input.2);
    let _ = engine.reconcile(&local, &remote, &indexed);
});
