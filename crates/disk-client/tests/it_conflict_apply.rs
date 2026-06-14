//! Integration tests proving the conflict-resolution APPLY layer writes real
//! files to disk — closing the dead-code gap identified by QA.
//!
//! These tests exercise `apply_conflict` (the production entry point wired
//! into the sync-loop and the REST handler) against a real `tempdir`, so
//! they validate the zero-data-loss invariant end-to-end without a running
//! gRPC server.
//!
//! Test names chosen for discoverability:
//!   - `conflict_apply_writes_fork_on_disk`
//!   - `auto_three_way_merges_non_overlap`

use std::fs;
use std::path::Path;

use disk_client::{apply_conflict, ConflictApplyOutcome};

const NODE_ID: &str = "deadbeef-node-id-8chars";

/// Gap-1 proof: when a conflict fork is applied (no base → refuse → fork),
/// the fork file lands on disk AND the original local file is untouched.
///
/// This is the canonical integration test referenced in the QA report:
/// `conflict_apply_writes_fork_on_disk`.
#[test]
fn conflict_apply_writes_fork_on_disk() {
    let dir = tempfile::tempdir().unwrap();
    let base_dir = dir.path();

    // Arrange: write the local version to disk.
    let rel = Path::new("notes/journal.md");
    let local_content = b"# My Journal\n\nLocal edits here.\n";
    let remote_content = b"# My Journal\n\nRemote edits here.\n";

    let local_abs = base_dir.join(rel);
    fs::create_dir_all(local_abs.parent().unwrap()).unwrap();
    fs::write(&local_abs, local_content).unwrap();

    // Act: apply the conflict (no base → three_way_merge refuses → fork).
    let outcome = apply_conflict(
        base_dir,
        rel,
        None, // no base → Refused(NoBase) → fork path
        local_content,
        remote_content,
        NODE_ID,
    )
    .expect("apply_conflict must succeed");

    // Assert 1: outcome is a fork (not a merge, since no base was provided).
    let fork_rel = match outcome {
        ConflictApplyOutcome::Forked(p) => p,
        ConflictApplyOutcome::Merged => {
            panic!("expected Forked outcome when no base is provided, got Merged")
        }
    };

    // Assert 2: the fork file exists on disk with the remote bytes.
    let fork_abs = base_dir.join(&fork_rel);
    assert!(
        fork_abs.exists(),
        "fork file must exist on disk: {}",
        fork_abs.display()
    );
    let fork_bytes = fs::read(&fork_abs).unwrap();
    assert_eq!(
        fork_bytes, remote_content,
        "fork file must contain the remote (losing) bytes"
    );

    // Assert 3: the original local file is UNTOUCHED (zero-data-loss).
    let local_after = fs::read(&local_abs).unwrap();
    assert_eq!(
        local_after, local_content,
        "original local file must be untouched after fork"
    );

    // Assert 4: fork filename contains the sync-conflict sentinel.
    let fork_name = fork_abs.file_name().unwrap().to_str().unwrap();
    assert!(
        fork_name.contains("sync-conflict-"),
        "fork filename must contain 'sync-conflict-' sentinel: {fork_name}"
    );

    // Assert 5: fork is inside the same directory as the original.
    assert!(
        fork_rel.starts_with("notes"),
        "fork must be co-located with the original: {}",
        fork_rel.display()
    );
}

/// Gap-2 proof: for a `.md` file with a known base, non-overlapping edits
/// by local and remote are merged clean, the merged file lands on disk, and
/// no fork is created.
///
/// This is the integration test for the auto-3-way-merge path:
/// `auto_three_way_merges_non_overlap`.
#[test]
fn auto_three_way_merges_non_overlap() {
    let dir = tempfile::tempdir().unwrap();
    let base_dir = dir.path();

    let rel = Path::new("docs/readme.md");

    // Common ancestor: 9 lines so that edits on line 1 and line 9 don't overlap.
    let base = b"line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9\n";
    // Local edited line 1 only.
    let local = b"EDITED_BY_LOCAL\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9\n";
    // Remote edited line 9 only.
    let remote = b"line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nEDITED_BY_REMOTE\n";

    // Write the local version to disk (what the apply phase would find).
    let local_abs = base_dir.join(rel);
    fs::create_dir_all(local_abs.parent().unwrap()).unwrap();
    fs::write(&local_abs, local).unwrap();

    // Act: apply conflict with the known base → should merge cleanly.
    let outcome = apply_conflict(base_dir, rel, Some(base), local, remote, NODE_ID)
        .expect("apply_conflict must succeed");

    // Assert 1: outcome is a merge (not a fork).
    match outcome {
        ConflictApplyOutcome::Merged => {}
        ConflictApplyOutcome::Forked(p) => {
            panic!("expected Merged outcome for non-overlapping edits, got Forked({p:?})")
        }
    }

    // Assert 2: the live file now contains BOTH edits.
    let merged_bytes = fs::read(&local_abs).unwrap();
    let merged_str = std::str::from_utf8(&merged_bytes).unwrap();
    assert!(
        merged_str.contains("EDITED_BY_LOCAL"),
        "merged file must contain local edit: {merged_str}"
    );
    assert!(
        merged_str.contains("EDITED_BY_REMOTE"),
        "merged file must contain remote edit: {merged_str}"
    );

    // Assert 3: no conflict markers — it was a clean merge.
    assert!(
        !merged_str.contains('<'),
        "clean merge must not contain conflict markers: {merged_str}"
    );

    // Assert 4: no fork file was created (directory contains only the original).
    let entries: Vec<_> = fs::read_dir(base_dir.join("docs"))
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "no fork file should be created for a clean merge; found: {:?}",
        entries.iter().map(|e| e.file_name()).collect::<Vec<_>>()
    );
}
