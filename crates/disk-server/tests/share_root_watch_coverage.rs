//! DISK-0070: a share served through the `sync_root` fallback must be
//! recognised as unwatched.
//!
//! `SyncService::root_for` resolves any share absent from `DISK_SHARE_ROOTS`
//! to `DISK_SYNC_ROOT`, so such a share reads correctly. The `share_index`
//! watcher, however, is armed only over declared roots — the share is then
//! never indexed and clients pull nothing, while the server health endpoint
//! and the client status both keep reporting success. That combination is what
//! silently unserved `datarim-kb` on arcana-agents.
//!
//! These tests pin the detection predicate the server logs on, so a future
//! change cannot quietly restore the silent-gap behaviour.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use disk_server::sync_root_is_unwatched;

fn roots(pairs: &[(&str, &str)]) -> HashMap<String, PathBuf> {
    pairs
        .iter()
        .map(|(share, path)| ((*share).to_string(), PathBuf::from(*path)))
        .collect()
}

/// The exact production misconfiguration: only the secondary share is declared,
/// so the share living at `sync_root` is served but unwatched.
#[test]
fn secondary_share_only_leaves_sync_root_unwatched() {
    let declared = roots(&[(
        "hermes-artefacts",
        "/var/lib/disk-arcana/shares/hermes-artefacts",
    )]);
    assert!(
        sync_root_is_unwatched(&declared, Path::new("/home/dev/arcanada/datarim")),
        "a share served via the sync_root fallback must be reported as unwatched"
    );
}

/// Declaring every served share — including the one at `sync_root` — closes it.
#[test]
fn declaring_sync_root_share_closes_the_gap() {
    let declared = roots(&[
        ("datarim-kb", "/home/dev/arcanada/datarim"),
        (
            "hermes-artefacts",
            "/var/lib/disk-arcana/shares/hermes-artefacts",
        ),
    ]);
    assert!(
        !sync_root_is_unwatched(&declared, Path::new("/home/dev/arcanada/datarim")),
        "sync_root is covered by a declared root, so nothing should be reported"
    );
}

/// An empty map means the watcher never spawns at all, so the gap is real.
/// Guards against treating "nothing declared" as "nothing to warn about".
#[test]
fn empty_share_roots_is_unwatched() {
    assert!(
        sync_root_is_unwatched(&HashMap::new(), Path::new("/var/lib/disk-arcana/sync")),
        "with no declared roots the sync_root share cannot be watched"
    );
}

/// The share name is irrelevant — coverage is decided by the path. Clients
/// choose their own share names (the Mac declares `datarim-kb`), so matching
/// on a hardcoded name would be wrong.
#[test]
fn coverage_is_decided_by_path_not_share_name() {
    let declared = roots(&[("some-other-name", "/var/lib/disk-arcana/sync")]);
    assert!(
        !sync_root_is_unwatched(&declared, Path::new("/var/lib/disk-arcana/sync")),
        "any declared root pointing at sync_root provides the watcher"
    );
}
