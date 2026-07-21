//! Criterion benchmarks for DISK-0012 hardening (hash, delta, reconcile).

use std::io::Cursor;
use std::path::PathBuf;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use disk_core::delta::strong::hash as blake3_hash;
use disk_core::delta::{apply_plan, build_plan_with_data, chunks};
use disk_core::filter::{Filter, FilterRules};
use disk_core::reconciler::ReconciliationEngine;
use disk_core::scanner::scan_root;
use disk_core::types::FileMeta;
use disk_core::vector_clock::VectorClock;

fn bench_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("blake3_hash");
    for size_kb in [64, 1024] {
        let data = vec![0xABu8; size_kb * 1024];
        group.bench_with_input(BenchmarkId::from_parameter(size_kb), &data, |b, data| {
            b.iter(|| black_box(blake3_hash(data)));
        });
    }
    group.finish();
}

fn bench_delta_roundtrip(c: &mut Criterion) {
    let mut base = vec![0u8; 256 * 1024];
    for (i, b) in base.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    let mut client = base.clone();
    client[4096..4106].copy_from_slice(b"EDITED!!!!");

    let client_chunks: Vec<_> = chunks(Cursor::new(&client)).map(|r| r.unwrap()).collect();
    let plan = build_plan_with_data(&client_chunks, &base);

    c.bench_function("delta_build_plan_256k", |b| {
        b.iter(|| black_box(build_plan_with_data(&client_chunks, &base)));
    });
    c.bench_function("delta_apply_plan_256k", |b| {
        b.iter(|| black_box(apply_plan(&base, &plan).unwrap()));
    });
}

fn make_meta(i: usize, deleted: bool) -> FileMeta {
    FileMeta {
        path: PathBuf::from(format!("notes/file_{i:04}.md")),
        content_hash: [i as u8; 32],
        size: 128,
        mtime_ns: i as i64,
        inode: Some(i as u64),
        vector_clock: VectorClock::new(),
        deleted,
        deleted_at: None,
        node_id: "bench".into(),
        encryption_nonce: None,
        version_id: None,
        parent_version_id: None,
    }
}

fn bench_reconcile(c: &mut Criterion) {
    let engine = ReconciliationEngine::new("bench-node".into());
    let local: Vec<FileMeta> = (0..200).map(|i| make_meta(i, false)).collect();
    let remote: Vec<FileMeta> = (0..200).map(|i| make_meta(i, i % 17 == 0)).collect();
    let indexed = local.clone();

    c.bench_function("reconcile_200_paths", |b| {
        b.iter(|| black_box(engine.reconcile(&local, &remote, &indexed).unwrap()));
    });
}

fn bench_scan(c: &mut Criterion) {
    let dir = tempfile::tempdir().expect("tempdir");
    let notes = dir.path().join("notes");
    std::fs::create_dir_all(&notes).expect("mkdir");
    for i in 0..500 {
        std::fs::write(notes.join(format!("f_{i:04}.md")), b"# bench\n").expect("write");
    }
    let filter = Filter::from_config(&FilterRules::default()).expect("filter");

    c.bench_function("scan_root_500_md", |b| {
        b.iter(|| black_box(scan_root(dir.path(), filter.clone(), "bench".into()).expect("scan")));
    });
}

criterion_group!(
    benches,
    bench_hash,
    bench_delta_roundtrip,
    bench_reconcile,
    bench_scan
);
criterion_main!(benches);
