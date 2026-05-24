//! Filesystem watcher + 500 ms debouncer (DISK-0006 R5 skeleton).
//!
//! Plan §FsWatcher + sync-loop state machine:
//! - Created / Modified / Renamed → `FsEvent::Change(path)`.
//! - Deleted → `FsEvent::Delete(path)`.
//! - 500 ms debounce window collapses duplicate events on the same path.
//! - Rename pair (from, to) → single `Change(to)` (the `from` path
//!   silently drops; the next state machine cycle will see the new
//!   path and the missing one in its scan).
//!
//! The debouncer is intentionally a pure-data struct (no `tokio`,
//! no I/O, no time source dependency) so it can be exhaustively
//! unit-tested with explicit clocks. The `FsWatcher` wraps the
//! `notify` crate's `RecommendedWatcher`, translates `notify::Event`
//! into [`FsEvent`], and forwards through a tokio mpsc channel.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use thiserror::Error;
use tokio::sync::mpsc;

pub const DEFAULT_DEBOUNCE_WINDOW: Duration = Duration::from_millis(500);

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
    use notify::event::{EventKind, RemoveKind};
    let mut out = Vec::with_capacity(ev.paths.len());
    let kind = ev.kind;
    for p in &ev.paths {
        let mapped = match kind {
            EventKind::Create(_) | EventKind::Modify(_) => Some(FsEvent::Change(p.clone())),
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
/// Holds the live `RecommendedWatcher` for its lifetime; dropping the
/// watcher stops the notify thread. Events are forwarded to a tokio
/// mpsc channel so consumers can integrate via `.recv().await`.
pub struct FsWatcher {
    _watcher: notify::RecommendedWatcher,
    rx: mpsc::UnboundedReceiver<FsEvent>,
}

impl FsWatcher {
    /// Watch `share_root` recursively. Returns immediately once the
    /// notify thread is up; events arrive through [`recv`](Self::recv).
    pub fn watch(share_root: &Path) -> Result<Self, WatcherError> {
        use notify::{RecursiveMode, Watcher};
        if !share_root.exists() {
            return Err(WatcherError::MissingShareRoot(share_root.to_path_buf()));
        }
        let (tx, rx) = mpsc::unbounded_channel();
        let tx_clone = tx.clone();
        let mut watcher: notify::RecommendedWatcher =
            notify::recommended_watcher(move |res: notify::Result<notify::Event>| match res {
                Ok(ev) => {
                    for fs_ev in translate_notify_event(&ev) {
                        let _ = tx_clone.send(fs_ev);
                    }
                }
                Err(e) => tracing::warn!(error = %e, "notify watcher emitted error"),
            })?;
        watcher.watch(share_root, RecursiveMode::Recursive)?;
        Ok(Self {
            _watcher: watcher,
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

    #[test]
    fn fs_watcher_rejects_missing_root() {
        let res = FsWatcher::watch(Path::new("/definitely/not/here/disk-0006-r5"));
        let err = match res {
            Ok(_) => panic!("expected error"),
            Err(e) => e,
        };
        assert!(matches!(err, WatcherError::MissingShareRoot(_)));
    }
}
