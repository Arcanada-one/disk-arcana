//! 3-way merge engine using `diffy`.
//!
//! `three_way_merge(base, local, remote)` returns a [`MergeOutput`] that
//! captures the result in four exhaustive cases:
//!
//! - `Clean`     — all hunks applied without conflict (both versions merged).
//! - `Conflicted` — at least one hunk overlaps; the result contains git-style
//!   `<<<<<<<` / `=======` / `>>>>>>>` conflict markers AND signals that the
//!   caller must fall back to an auto-fork.
//! - `Refused`   — a guard-rail fired before merging was attempted:
//!   - `NoBase`    — no base version available.
//!   - `TooLarge`  — any input exceeds 10 MiB.
//!   - `Binary`    — a NUL byte found in the first 1 024 bytes of any input.
//!   - `NotText`   — input is not valid UTF-8 (cannot be diff'd as text).
//!
//! Guard-rails fire in short-circuit order: `NoBase` → `TooLarge` → `Binary`
//! → `NotText`.  Only after all guards pass is `diffy::merge` invoked.
//!
//! The caller (sync APPLY phase) interprets `Conflicted` and `Refused(_)` as a
//! signal to execute an auto-fork instead of writing a potentially-corrupt
//! merged file.  The zero-data-loss invariant is never violated.

use diffy::MergeOptions;

/// Maximum allowed length (bytes) of any merge input.
pub const SIZE_CAP: usize = 10 * 1024 * 1024; // 10 MiB

/// Number of bytes to scan for NUL bytes (binary detection).
const BINARY_SCAN_LEN: usize = 1024;

/// Result of a 3-way merge operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MergeOutput {
    /// Merge succeeded with no conflicts; `Vec<u8>` is the merged content.
    Clean(Vec<u8>),
    /// Merge succeeded structurally but contains overlapping hunks; the content
    /// includes git-style conflict markers.  The caller MUST fall back to
    /// auto-fork — do not write this content as the resolved file.
    Conflicted(Vec<u8>),
    /// A guard-rail prevented merging.  The caller MUST fall back to auto-fork.
    Refused(RefuseReason),
}

/// Why a merge was refused before `diffy` was invoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefuseReason {
    /// No base version is available; 3-way merge requires all three inputs.
    NoBase,
    /// At least one input exceeds the 10 MiB size cap.
    TooLarge,
    /// A NUL byte was found in the first 1 KiB of at least one input —
    /// the content is likely binary and must not be merged as text.
    Binary,
    /// At least one input is not valid UTF-8 and cannot be text-diff'd.
    NotText,
}

/// Attempt a 3-way merge of `local` and `remote` against a common `base`.
///
/// `base` must be `Some(&[u8])` for the merge to proceed; `None` triggers
/// `Refused(RefuseReason::NoBase)`.
pub fn three_way_merge(base: Option<&[u8]>, local: &[u8], remote: &[u8]) -> MergeOutput {
    // Guard 1: base absent.
    let base = match base {
        Some(b) => b,
        None => return MergeOutput::Refused(RefuseReason::NoBase),
    };

    // Guard 2: size cap.
    if base.len() > SIZE_CAP || local.len() > SIZE_CAP || remote.len() > SIZE_CAP {
        return MergeOutput::Refused(RefuseReason::TooLarge);
    }

    // Guard 3: binary detection (NUL byte in first BINARY_SCAN_LEN bytes).
    if has_nul(base) || has_nul(local) || has_nul(remote) {
        return MergeOutput::Refused(RefuseReason::Binary);
    }

    // Guard 4: UTF-8 check.
    let base_str = match std::str::from_utf8(base) {
        Ok(s) => s,
        Err(_) => return MergeOutput::Refused(RefuseReason::NotText),
    };
    let local_str = match std::str::from_utf8(local) {
        Ok(s) => s,
        Err(_) => return MergeOutput::Refused(RefuseReason::NotText),
    };
    let remote_str = match std::str::from_utf8(remote) {
        Ok(s) => s,
        Err(_) => return MergeOutput::Refused(RefuseReason::NotText),
    };

    // Run diffy 3-way merge with Diff3 conflict style.
    let opts = MergeOptions::new();
    match opts.merge(base_str, local_str, remote_str) {
        Ok(merged) => MergeOutput::Clean(merged.into_bytes()),
        Err(conflicted) => MergeOutput::Conflicted(conflicted.into_bytes()),
    }
}

/// Returns `true` when a NUL byte (`\0`) is found in the first
/// `BINARY_SCAN_LEN` bytes of `data`.
fn has_nul(data: &[u8]) -> bool {
    let scan = &data[..data.len().min(BINARY_SCAN_LEN)];
    scan.contains(&0u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to make a slice from a string.
    fn b(s: &str) -> &[u8] {
        s.as_bytes()
    }

    /// Non-overlapping edits on different lines → Clean merge, both edits present.
    #[test]
    fn three_way_non_overlap_clean() {
        let base = b("line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9\n");
        let local = b("EDITED_LINE1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9\n");
        let remote = b("line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nEDITED_LINE9\n");
        let out = three_way_merge(Some(base), local, remote);
        match out {
            MergeOutput::Clean(merged) => {
                let s = std::str::from_utf8(&merged).unwrap();
                assert!(s.contains("EDITED_LINE1"), "local edit missing: {s}");
                assert!(s.contains("EDITED_LINE9"), "remote edit missing: {s}");
                assert!(!s.contains('<'), "unexpected conflict markers: {s}");
            }
            other => panic!("expected Clean, got {other:?}"),
        }
    }

    /// Overlapping edits on the same line → Conflicted with git-style markers.
    #[test]
    fn three_way_overlap_conflicted() {
        let base = b("line1\nshared line\nline3\n");
        let local = b("line1\nlocal version\nline3\n");
        let remote = b("line1\nremote version\nline3\n");
        let out = three_way_merge(Some(base), local, remote);
        match out {
            MergeOutput::Conflicted(content) => {
                let s = std::str::from_utf8(&content).unwrap();
                assert!(s.contains('<'), "expected conflict markers: {s}");
                assert!(s.contains("local version"), "local content missing: {s}");
                assert!(s.contains("remote version"), "remote content missing: {s}");
            }
            other => panic!("expected Conflicted, got {other:?}"),
        }
    }

    /// Binary content → Refused(Binary).
    #[test]
    fn three_way_binary_refused() {
        let base = b("normal text");
        let local: &[u8] = b"binary\x00content";
        let remote = b("normal text");
        let out = three_way_merge(Some(base), local, remote);
        assert_eq!(out, MergeOutput::Refused(RefuseReason::Binary));
    }

    /// Base is None → Refused(NoBase).
    #[test]
    fn three_way_no_base_refused() {
        let out = three_way_merge(None, b("local"), b("remote"));
        assert_eq!(out, MergeOutput::Refused(RefuseReason::NoBase));
    }

    /// Any input > 10 MiB → Refused(TooLarge).
    #[test]
    fn three_way_too_large_refused() {
        let big = vec![b'x'; SIZE_CAP + 1];
        let small = b("small");
        let out = three_way_merge(Some(small), &big, small);
        assert_eq!(out, MergeOutput::Refused(RefuseReason::TooLarge));
    }

    /// Binary guard fires on remote even when local is clean.
    #[test]
    fn three_way_binary_in_remote_refused() {
        let base = b("text");
        let local = b("text edit");
        let mut remote = b"remote\x00nul".to_vec();
        remote.extend_from_slice(b" text");
        let out = three_way_merge(Some(base), local, &remote);
        assert_eq!(out, MergeOutput::Refused(RefuseReason::Binary));
    }

    /// NUL beyond the first 1024 bytes does NOT trigger Binary guard
    /// (only the first 1 KiB is scanned).
    #[test]
    fn three_way_nul_beyond_scan_window_not_refused() {
        let mut content = vec![b'a'; 1025];
        content[1024] = 0u8; // NUL at byte 1024 — outside scan window
        let _base = content.clone();
        // Make it valid UTF-8 up to 1024, NUL outside window won't trigger binary.
        // Build a content that is valid UTF-8 with NUL only outside scan window.
        // Actually NUL is valid in bytes but not UTF-8, so we'll build ASCII content.
        // For this test: content[0..1024] = 'a', content[1024] = NUL.
        // This will fail UTF-8 check, but the point is binary guard didn't fire.
        // Let's use a content where only position 1024 has NUL:
        let out = three_way_merge(Some(&content), &content, &content);
        // Either NotText (UTF-8 fail) or Clean (if diffy handles it) — but NOT Binary.
        assert_ne!(out, MergeOutput::Refused(RefuseReason::Binary));
    }
}
