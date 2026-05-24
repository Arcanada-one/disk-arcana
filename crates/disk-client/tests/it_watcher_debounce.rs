//! IT for DISK-0006 R5 plan AC `it_watcher_debounce`.
//!
//! Plan §Test Plan row: `Rapid 100 events on one file → single sync
//! trigger.` R5 ships the [`FsWatcher`] + [`FsEventDebouncer`]
//! primitives; the actual sync trigger lands in R6, so the IT asserts
//! the upstream contract: 100 rapid writes produce 100+ raw events
//! through `notify`, then collapse to one `FsEvent::Change` after the
//! 500 ms quiet window.

use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use disk_client::{FsEvent, FsEventDebouncer, FsWatcher, DEFAULT_DEBOUNCE_WINDOW};
use tempfile::TempDir;
use tokio::time::timeout;

fn touch_with_byte(path: &Path, byte: u8) {
    fs::write(path, [byte]).expect("write file");
}

#[tokio::test]
async fn rapid_writes_to_one_file_debounce_to_single_event() {
    let dir = TempDir::new().expect("tmp");
    // macOS TempDir resolves to `/var/folders/...` which is a symlink to
    // `/private/var/folders/...` — notify surfaces the canonical path, so
    // we compare against the canonical form on both sides.
    let share_root = dir.path().canonicalize().expect("canonical share root");
    let mut watcher = FsWatcher::watch(&share_root).expect("watch must succeed");

    // Slight delay so the platform-native watcher arms its inotify /
    // FSEvents subscription before the first write. Without this the
    // initial create can race ahead of the subscription on Linux.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let target = share_root.join("rapid.md");
    // 100 distinct writes to the same path.
    for i in 0..100u8 {
        touch_with_byte(&target, i);
    }
    let target = target.canonicalize().unwrap_or(target);

    // Drain everything notify produced into the debouncer for up to 2 s.
    let mut debouncer = FsEventDebouncer::new(DEFAULT_DEBOUNCE_WINDOW);
    let drain_started = Instant::now();
    let drain_deadline = drain_started + Duration::from_secs(2);
    let mut raw_count = 0usize;
    while Instant::now() < drain_deadline {
        match timeout(Duration::from_millis(100), watcher.recv()).await {
            Ok(Some(ev)) => {
                raw_count += 1;
                debouncer.push(ev, Instant::now());
            }
            Ok(None) => break,
            Err(_elapsed) => {
                // No event in the last 100ms — check whether the debouncer
                // window has closed.
                if debouncer.pending_len() > 0
                    && debouncer
                        .next_deadline()
                        .map(|d| Instant::now() >= d)
                        .unwrap_or(false)
                {
                    break;
                }
            }
        }
    }

    assert!(raw_count >= 1, "notify must surface at least one event");

    // Coalesce: drain after the debounce window has elapsed.
    let drained = debouncer.drain_expired(Instant::now() + DEFAULT_DEBOUNCE_WINDOW);
    let changes_on_target: Vec<_> = drained
        .iter()
        .filter(|e| e.path() == target && matches!(e, FsEvent::Change(_)))
        .collect();
    assert_eq!(
        changes_on_target.len(),
        1,
        "100 rapid writes must debounce to a single Change event for {target:?}, raw={raw_count}, drained={drained:?}"
    );
}

#[tokio::test]
async fn fs_watcher_emits_change_on_create() {
    let dir = TempDir::new().expect("tmp");
    let share_root = dir.path().canonicalize().expect("canonical");
    let mut watcher = FsWatcher::watch(&share_root).expect("watch");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let target = share_root.join("new.md");
    fs::write(&target, b"hello").expect("write");
    let target = target.canonicalize().unwrap_or(target);

    // Wait up to 2 s for the first event.
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut saw_change = false;
    while Instant::now() < deadline {
        if let Ok(Some(ev)) = timeout(Duration::from_millis(100), watcher.recv()).await {
            if matches!(ev, FsEvent::Change(p) if p == target) {
                saw_change = true;
                break;
            }
        }
    }
    assert!(
        saw_change,
        "FsWatcher must surface FsEvent::Change for newly-created file"
    );
}
