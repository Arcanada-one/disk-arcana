//! Filesystem watcher + 500 ms debouncer (DISK-0006 R5 skeleton).
//!
//! Plan §FsWatcher + sync-loop state machine:
//! - Created / Modified → `FsEvent::Change(path)`.
//! - Deleted → `FsEvent::Delete(path)`.
//! - 500 ms debounce window collapses duplicate events on the same path.
//! - Rename modes: `From` → `Delete(old)`, `To` → `Change(new)`, and
//!   `Both` → `Delete(old)` + `Change(new)`; the old path is never
//!   silently dropped.
//!
//! The debouncer is intentionally a pure-data struct (no `tokio`,
//! no I/O, no time source dependency) so it can be exhaustively
//! unit-tested with explicit clocks. The `FsWatcher` prefers the
//! `notify` crate's native watcher and falls back to `PollWatcher` when the
//! native constructor or `watch()` call fails. Events are translated into
//! [`FsEvent`] and forwarded through a tokio mpsc channel.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use thiserror::Error;
use tokio::sync::mpsc;

pub const DEFAULT_DEBOUNCE_WINDOW: Duration = Duration::from_millis(500);
const FALLBACK_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Coalesced filesystem event surfaced by [`FsWatcher`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsEvent {
    /// A file was created, modified, or arrived through a rename.
    Change(PathBuf),
    /// A file was deleted (or moved out of the watched share).
    Delete(PathBuf),
}

impl FsEvent {
    /// Path the event refers to.
    pub fn path(&self) -> &Path {
        match self {
            FsEvent::Change(p) | FsEvent::Delete(p) => p,
        }
    }
}

/// Errors returned by watcher construction / event consumption.
#[derive(Debug, Error)]
pub enum WatcherError {
    #[error("notify backend: {0}")]
    Notify(#[from] notify::Error),

    #[error("share root {0} does not exist")]
    MissingShareRoot(PathBuf),

    #[error("native notify backend failed: {native}; polling fallback failed: {poll}")]
    AllBackendsFailed { native: String, poll: String },
}

// ---------------------------------------------------------------------------
// FsEventDebouncer — pure-data coalescer
// ---------------------------------------------------------------------------

/// Per-path coalescing buffer.
///
/// Push raw events as they arrive; call [`drain_expired`](Self::drain_expired)
/// when the time crosses [`next_deadline`](Self::next_deadline). Each path
/// holds at most one pending event; later events on the same path
/// override earlier ones with the documented merge rule.
///
/// Merge rule (plan §FsWatcher state machine + ai-quality #6 corner cases):
/// - `Change` then `Change` → `Change` (no-op coalesce).
/// - `Change` then `Delete` → `Delete` (final state wins — file gone).
/// - `Delete` then `Change` → `Change` (file came back, re-sync needed).
/// - `Delete` then `Delete` → `Delete`.
pub struct FsEventDebouncer {
    window: Duration,
    /// BTreeMap keeps deterministic iteration order — fixes drain ordering
    /// regardless of underlying hasher (HashMap nondeterminism would make
    /// the ordering UT flaky).
    pending: BTreeMap<PathBuf, PendingEntry>,
}

struct PendingEntry {
    event: FsEvent,
    /// First time the entry was pushed; resets to current `now` on every
    /// subsequent push for the same path so a steady stream of events
    /// keeps the debounce window alive.
    deadline: Instant,
}

impl FsEventDebouncer {
    /// Construct with the supplied debounce window.
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            pending: BTreeMap::new(),
        }
    }

    /// Default 500 ms window per plan §FsWatcher.
    pub fn with_default_window() -> Self {
        Self::new(DEFAULT_DEBOUNCE_WINDOW)
    }

    /// Number of paths currently in the buffer.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Earliest deadline across pending entries — drives the wakeup timer.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.pending.values().map(|e| e.deadline).min()
    }

    /// Push a raw event observed at `now`. Coalesces with any prior
    /// pending entry on the same path.
    pub fn push(&mut self, event: FsEvent, now: Instant) {
        let path = event.path().to_path_buf();
        let deadline = now + self.window;
        match self.pending.get_mut(&path) {
            Some(slot) => {
                slot.event = merge(slot.event.clone(), event);
                slot.deadline = deadline;
            }
            None => {
                self.pending.insert(path, PendingEntry { event, deadline });
            }
        }
    }

    /// Drain entries whose deadline is `<= now`. Returns them in
    /// path order (BTreeMap iteration).
    pub fn drain_expired(&mut self, now: Instant) -> Vec<FsEvent> {
        let expired_keys: Vec<PathBuf> = self
            .pending
            .iter()
            .filter(|(_, v)| v.deadline <= now)
            .map(|(k, _)| k.clone())
            .collect();
        expired_keys
            .into_iter()
            .map(|k| self.pending.remove(&k).expect("present").event)
            .collect()
    }

    /// Flush every pending entry regardless of deadline. Useful on
    /// shutdown or for tests that want to inspect everything in flight.
    pub fn drain_all(&mut self) -> Vec<FsEvent> {
        let out: Vec<FsEvent> = self.pending.values().map(|e| e.event.clone()).collect();
        self.pending.clear();
        out
    }
}

fn merge(prior: FsEvent, next: FsEvent) -> FsEvent {
    // `next` wins on Change/Delete transitions because it reflects the
    // most recent observed state.
    match (prior, next) {
        (FsEvent::Change(_), e @ FsEvent::Change(_)) => e,
        (FsEvent::Change(_), e @ FsEvent::Delete(_)) => e,
        (FsEvent::Delete(_), e @ FsEvent::Change(_)) => e,
        (FsEvent::Delete(_), e @ FsEvent::Delete(_)) => e,
    }
}

/// Translate a single `notify::Event` into one or more [`FsEvent`]s.
/// Public to support direct unit tests of the mapping logic without
/// spinning up a real `RecommendedWatcher`.
pub fn translate_notify_event(ev: &notify::Event) -> Vec<FsEvent> {
    use notify::event::{EventKind, ModifyKind, RemoveKind, RenameMode};
    let mut out = Vec::with_capacity(ev.paths.len());
    let kind = ev.kind;
    for (i, p) in ev.paths.iter().enumerate() {
        let mapped = match kind {
            EventKind::Create(_) => Some(FsEvent::Change(p.clone())),
            EventKind::Modify(ModifyKind::Name(RenameMode::From)) => {
                Some(FsEvent::Delete(p.clone()))
            }
            EventKind::Modify(ModifyKind::Name(RenameMode::Both)) => {
                if i == 0 {
                    // From path — file no longer exists at the old location.
                    Some(FsEvent::Delete(p.clone()))
                } else {
                    // To path — file now exists at the new location.
                    Some(FsEvent::Change(p.clone()))
                }
            }
            EventKind::Modify(_) => Some(FsEvent::Change(p.clone())),
            EventKind::Remove(RemoveKind::File)
            | EventKind::Remove(RemoveKind::Folder)
            | EventKind::Remove(RemoveKind::Any)
            | EventKind::Remove(RemoveKind::Other) => Some(FsEvent::Delete(p.clone())),
            EventKind::Any | EventKind::Access(_) | EventKind::Other => None,
        };
        if let Some(e) = mapped {
            out.push(e);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// FsWatcher — notify backend wrapper
// ---------------------------------------------------------------------------

/// Per-share filesystem watcher.
///
/// Holds the live native or polling watcher for its lifetime; dropping the
/// watcher stops the notify thread. Events are forwarded to a tokio mpsc
/// channel so consumers can integrate via `.recv().await`.
pub struct FsWatcher {
    _watcher: Box<dyn notify::Watcher + Send>,
    rx: mpsc::UnboundedReceiver<FsEvent>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WatcherBackend {
    Native,
    Poll,
}

struct WatcherSelection<T> {
    backend: WatcherBackend,
    watcher: T,
    native_failure: Option<String>,
}

fn native_or_poll<T, Native, Poll>(
    native: Native,
    poll: Poll,
) -> Result<WatcherSelection<T>, WatcherError>
where
    Native: FnOnce() -> notify::Result<T>,
    Poll: FnOnce() -> notify::Result<T>,
{
    match native() {
        Ok(watcher) => Ok(WatcherSelection {
            backend: WatcherBackend::Native,
            watcher,
            native_failure: None,
        }),
        Err(native_error) => match poll() {
            Ok(watcher) => Ok(WatcherSelection {
                backend: WatcherBackend::Poll,
                watcher,
                native_failure: Some(native_error.to_string()),
            }),
            Err(poll_error) => Err(WatcherError::AllBackendsFailed {
                native: native_error.to_string(),
                poll: poll_error.to_string(),
            }),
        },
    }
}

fn event_handler(
    tx: mpsc::UnboundedSender<FsEvent>,
) -> impl FnMut(notify::Result<notify::Event>) + Send + 'static {
    move |result| match result {
        Ok(event) => {
            for fs_event in translate_notify_event(&event) {
                let _ = tx.send(fs_event);
            }
        }
        Err(error) => tracing::warn!(error = %error, "notify watcher emitted error"),
    }
}

fn fallback_poll_config() -> notify::Config {
    notify::Config::default()
        .with_poll_interval(FALLBACK_POLL_INTERVAL)
        .with_compare_contents(true)
}

impl FsWatcher {
    /// Watch `share_root` recursively. Returns immediately once the
    /// notify thread is up; events arrive through [`recv`](Self::recv).
    pub fn watch(share_root: &Path) -> Result<Self, WatcherError> {
        use notify::{PollWatcher, RecursiveMode, Watcher};
        if !share_root.exists() {
            return Err(WatcherError::MissingShareRoot(share_root.to_path_buf()));
        }
        let (tx, rx) = mpsc::unbounded_channel();
        let native_tx = tx.clone();
        let poll_tx = tx;
        let selected = native_or_poll(
            move || {
                let mut watcher = notify::recommended_watcher(event_handler(native_tx))?;
                watcher.watch(share_root, RecursiveMode::Recursive)?;
                Ok(Box::new(watcher) as Box<dyn Watcher + Send>)
            },
            move || {
                let mut watcher = PollWatcher::new(event_handler(poll_tx), fallback_poll_config())?;
                watcher.watch(share_root, RecursiveMode::Recursive)?;
                Ok(Box::new(watcher) as Box<dyn Watcher + Send>)
            },
        )?;

        if let Some(native_failure) = selected.native_failure {
            tracing::warn!(
                error = %native_failure,
                "native notify watcher failed; polling fallback armed"
            );
        }
        tracing::debug!(backend = ?selected.backend, "filesystem watcher armed");

        Ok(Self {
            _watcher: selected.watcher,
            rx,
        })
    }

    /// Await the next raw event. Returns `None` when the underlying
    /// channel is closed (watcher dropped).
    pub async fn recv(&mut self) -> Option<FsEvent> {
        self.rx.recv().await
    }

    /// Non-blocking poll. Used by the sync-loop scaffolding in
    /// [`crate::sync_loop`] to drain bursts in lockstep with the
    /// debouncer timer.
    pub fn try_recv(&mut self) -> Result<FsEvent, mpsc::error::TryRecvError> {
        self.rx.try_recv()
    }
}

// ---------------------------------------------------------------------------
// Tests — pure-data debouncer + notify-event translation
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn p(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    #[test]
    fn debouncer_coalesces_rapid_changes_to_one() {
        let mut d = FsEventDebouncer::new(Duration::from_millis(500));
        let t0 = Instant::now();
        for _ in 0..100 {
            d.push(FsEvent::Change(p("/a.md")), t0);
        }
        assert_eq!(d.pending_len(), 1);
        let drained = d.drain_expired(t0 + Duration::from_millis(500));
        assert_eq!(drained, vec![FsEvent::Change(p("/a.md"))]);
    }

    #[test]
    fn debouncer_preserves_per_path_distinct_events() {
        let mut d = FsEventDebouncer::with_default_window();
        let t0 = Instant::now();
        d.push(FsEvent::Change(p("/a")), t0);
        d.push(FsEvent::Change(p("/b")), t0);
        d.push(FsEvent::Change(p("/c")), t0);
        assert_eq!(d.pending_len(), 3);
        let drained = d.drain_expired(t0 + Duration::from_millis(500));
        assert_eq!(
            drained,
            vec![
                FsEvent::Change(p("/a")),
                FsEvent::Change(p("/b")),
                FsEvent::Change(p("/c")),
            ]
        );
    }

    #[test]
    fn debouncer_change_then_delete_yields_delete() {
        let mut d = FsEventDebouncer::with_default_window();
        let t0 = Instant::now();
        d.push(FsEvent::Change(p("/a")), t0);
        d.push(FsEvent::Delete(p("/a")), t0 + Duration::from_millis(10));
        let drained = d.drain_expired(t0 + Duration::from_secs(1));
        assert_eq!(drained, vec![FsEvent::Delete(p("/a"))]);
    }

    #[test]
    fn debouncer_delete_then_change_yields_change() {
        let mut d = FsEventDebouncer::with_default_window();
        let t0 = Instant::now();
        d.push(FsEvent::Delete(p("/a")), t0);
        d.push(FsEvent::Change(p("/a")), t0 + Duration::from_millis(10));
        let drained = d.drain_expired(t0 + Duration::from_secs(1));
        assert_eq!(drained, vec![FsEvent::Change(p("/a"))]);
    }

    #[test]
    fn debouncer_drain_respects_deadline() {
        let mut d = FsEventDebouncer::new(Duration::from_millis(500));
        let t0 = Instant::now();
        d.push(FsEvent::Change(p("/a")), t0);
        // 100 ms later — still within window → nothing drained.
        assert!(d.drain_expired(t0 + Duration::from_millis(100)).is_empty());
        // 500 ms later — boundary reached → drained.
        let drained = d.drain_expired(t0 + Duration::from_millis(500));
        assert_eq!(drained.len(), 1);
        assert!(d.drain_expired(t0 + Duration::from_secs(10)).is_empty());
    }

    #[test]
    fn debouncer_continuous_push_postpones_deadline() {
        let mut d = FsEventDebouncer::new(Duration::from_millis(500));
        let t0 = Instant::now();
        d.push(FsEvent::Change(p("/a")), t0);
        // Every 100 ms another event arrives, pushing the deadline forward.
        for i in 1..=5 {
            d.push(
                FsEvent::Change(p("/a")),
                t0 + Duration::from_millis(100 * i),
            );
        }
        // At t0+600 the original window would have elapsed (t0+500) but
        // the last push at t0+500 reset the deadline to t0+1000.
        assert!(d.drain_expired(t0 + Duration::from_millis(600)).is_empty());
        // At t0+1000 we cross the latest deadline.
        let drained = d.drain_expired(t0 + Duration::from_millis(1000));
        assert_eq!(drained.len(), 1);
    }

    #[test]
    fn debouncer_next_deadline_reports_min_across_paths() {
        let mut d = FsEventDebouncer::new(Duration::from_millis(500));
        let t0 = Instant::now();
        d.push(FsEvent::Change(p("/a")), t0);
        d.push(FsEvent::Change(p("/b")), t0 + Duration::from_millis(200));
        let earliest = d.next_deadline().expect("must have one");
        assert_eq!(earliest, t0 + Duration::from_millis(500));
    }

    #[test]
    fn debouncer_drain_all_empties_buffer() {
        let mut d = FsEventDebouncer::with_default_window();
        let t0 = Instant::now();
        d.push(FsEvent::Change(p("/a")), t0);
        d.push(FsEvent::Change(p("/b")), t0);
        let drained = d.drain_all();
        assert_eq!(drained.len(), 2);
        assert_eq!(d.pending_len(), 0);
    }

    #[test]
    fn translate_create_event_yields_change() {
        use notify::event::{CreateKind, EventKind};
        let ev = notify::Event {
            kind: EventKind::Create(CreateKind::File),
            paths: vec![p("/a.md")],
            attrs: Default::default(),
        };
        let out = translate_notify_event(&ev);
        assert_eq!(out, vec![FsEvent::Change(p("/a.md"))]);
    }

    #[test]
    fn translate_remove_event_yields_delete() {
        use notify::event::{EventKind, RemoveKind};
        let ev = notify::Event {
            kind: EventKind::Remove(RemoveKind::File),
            paths: vec![p("/a.md")],
            attrs: Default::default(),
        };
        let out = translate_notify_event(&ev);
        assert_eq!(out, vec![FsEvent::Delete(p("/a.md"))]);
    }

    #[test]
    fn translate_modify_event_yields_change() {
        use notify::event::{EventKind, ModifyKind};
        let ev = notify::Event {
            kind: EventKind::Modify(ModifyKind::Any),
            paths: vec![p("/a.md")],
            attrs: Default::default(),
        };
        let out = translate_notify_event(&ev);
        assert_eq!(out, vec![FsEvent::Change(p("/a.md"))]);
    }

    #[test]
    fn translate_access_event_is_ignored() {
        use notify::event::{AccessKind, EventKind};
        let ev = notify::Event {
            kind: EventKind::Access(AccessKind::Read),
            paths: vec![p("/a.md")],
            attrs: Default::default(),
        };
        let out = translate_notify_event(&ev);
        assert!(out.is_empty());
    }

    // ── Rename-mode mapping ──

    #[test]
    fn translate_rename_from_yields_delete() {
        use notify::event::{EventKind, ModifyKind, RenameMode};
        let ev = notify::Event {
            kind: EventKind::Modify(ModifyKind::Name(RenameMode::From)),
            paths: vec![p("/old-name.txt")],
            attrs: Default::default(),
        };
        let out = translate_notify_event(&ev);
        assert_eq!(out, vec![FsEvent::Delete(p("/old-name.txt"))]);
    }

    #[test]
    fn translate_rename_to_yields_change() {
        use notify::event::{EventKind, ModifyKind, RenameMode};
        let ev = notify::Event {
            kind: EventKind::Modify(ModifyKind::Name(RenameMode::To)),
            paths: vec![p("/new-name.txt")],
            attrs: Default::default(),
        };
        let out = translate_notify_event(&ev);
        assert_eq!(out, vec![FsEvent::Change(p("/new-name.txt"))]);
    }

    #[test]
    fn translate_rename_both_yields_delete_from_and_change_to() {
        use notify::event::{EventKind, ModifyKind, RenameMode};
        let ev = notify::Event {
            kind: EventKind::Modify(ModifyKind::Name(RenameMode::Both)),
            paths: vec![p("/old-name.txt"), p("/new-name.txt")],
            attrs: Default::default(),
        };
        let out = translate_notify_event(&ev);
        assert_eq!(
            out,
            vec![
                FsEvent::Delete(p("/old-name.txt")),
                FsEvent::Change(p("/new-name.txt")),
            ]
        );
    }

    #[test]
    fn fs_watcher_rejects_missing_root() {
        let res = FsWatcher::watch(Path::new("/definitely/not/here/disk-0006-r5"));
        let err = match res {
            Ok(_) => panic!("expected error"),
            Err(e) => e,
        };
        assert!(matches!(err, WatcherError::MissingShareRoot(_)));
    }

    /// Replaces the old Config-only assertion with a real forced `PollWatcher`
    /// test: writes a file, captures its mtime, rewrites with same-length
    /// content and restores the original mtime, then proves a translated
    /// [`FsEvent::Change`] is received through the channel — confirming
    /// `with_compare_contents(true)` detects the content rewrite despite
    /// identical size and mtime.
    #[test]
    fn poll_watcher_detects_same_size_mtime_content_rewrite() {
        use notify::{PollWatcher, RecursiveMode, Watcher};

        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let target = root.join("rewrite.txt");

        // Write initial content and capture its mtime.
        std::fs::write(&target, b"AAAA").unwrap();
        let initial_mtime = std::fs::metadata(&target).unwrap().modified().unwrap();

        let (tx, mut rx) = mpsc::unbounded_channel();
        let config = fallback_poll_config();
        let mut watcher = PollWatcher::new(event_handler(tx), config).unwrap();
        watcher.watch(&root, RecursiveMode::Recursive).unwrap();

        // Let the first poll cycle detect the file.
        std::thread::sleep(Duration::from_millis(150));

        // Drain any initial Create event.
        while rx.try_recv().is_ok() {}

        // Rewrite with same length (4 bytes) so size is unchanged.
        std::fs::write(&target, b"BBBB").unwrap();

        // Restore the original mtime — now size AND mtime are identical.
        std::fs::File::open(&target)
            .unwrap()
            .set_modified(initial_mtime)
            .unwrap();

        // Sanity: size and mtime match pre-rewrite state.
        let meta = std::fs::metadata(&target).unwrap();
        assert_eq!(meta.len(), 4);
        assert_eq!(meta.modified().unwrap(), initial_mtime);

        // PollWatcher with compare_contents must detect the content change.
        let deadline = std::time::Instant::now() + Duration::from_secs(8);
        let mut event_received = false;
        while std::time::Instant::now() < deadline {
            if let Ok(event) = rx.try_recv() {
                if matches!(&event, FsEvent::Change(p) if p == &target) {
                    event_received = true;
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(60));
        }

        assert!(
            event_received,
            "forced PollWatcher with compare_contents must emit FsEvent::Change \
             for same-size, same-mtime content rewrite"
        );

        drop(watcher);
    }

    #[test]
    fn native_success_does_not_construct_poll_fallback() {
        let poll_calls = Cell::new(0);
        let selected = native_or_poll(
            || Ok("native"),
            || {
                poll_calls.set(poll_calls.get() + 1);
                Ok("poll")
            },
        )
        .unwrap();

        assert_eq!(selected.backend, WatcherBackend::Native);
        assert_eq!(selected.watcher, "native");
        assert!(selected.native_failure.is_none());
        assert_eq!(poll_calls.get(), 0);
    }

    #[test]
    fn native_constructor_failure_uses_poll_fallback() {
        let selected = native_or_poll(
            || Err(notify::Error::generic("native constructor failed")),
            || Ok("poll"),
        )
        .unwrap();

        assert_eq!(selected.backend, WatcherBackend::Poll);
        assert_eq!(selected.watcher, "poll");
        assert!(selected
            .native_failure
            .as_deref()
            .is_some_and(|message| message.contains("constructor")));
    }

    #[test]
    fn native_watch_failure_uses_poll_fallback() {
        let selected = native_or_poll(
            || Err(notify::Error::generic("native watch failed")),
            || Ok("poll"),
        )
        .unwrap();

        assert_eq!(selected.backend, WatcherBackend::Poll);
        assert_eq!(selected.watcher, "poll");
        assert!(selected
            .native_failure
            .as_deref()
            .is_some_and(|message| message.contains("watch")));
    }

    #[test]
    fn both_watcher_backends_failing_is_fail_closed() {
        let error = native_or_poll::<(), _, _>(
            || Err(notify::Error::generic("native failed")),
            || Err(notify::Error::generic("poll failed")),
        )
        .err()
        .expect("both failures must be returned");

        match error {
            WatcherError::AllBackendsFailed { native, poll } => {
                assert!(native.contains("native failed"));
                assert!(poll.contains("poll failed"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }
}
