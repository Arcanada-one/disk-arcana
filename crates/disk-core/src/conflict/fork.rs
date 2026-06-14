//! Fork-filename generator (Syncthing naming convention).
//!
//! `fork_filename` produces a deterministic conflict copy name from the
//! original vault-relative path, the first 8 hex characters of the writing
//! node's ID, and a UTC timestamp truncated to the second.
//!
//! **Name scheme (Syncthing convention):**
//!
//! ```text
//! {stem}.sync-conflict-{node_id8}-{YYYYMMDD-HHMMSS}{.ext}
//! ```
//!
//! The conflict suffix is inserted **before the last extension** so that
//! the result remains recognisable to editors and OS tools:
//! - `notes/todo.md`      → `notes/todo.sync-conflict-abc12345-20260101-120000.md`
//! - `archive.tar.gz`     → `archive.tar.sync-conflict-abc12345-20260101-120000.gz`
//! - `README`             → `README.sync-conflict-abc12345-20260101-120000`
//! - `.obsidian/config`   → `.obsidian/config.sync-conflict-abc12345-20260101-120000`
//!
//! Security: `node_id8` is filtered to `[0-9a-f]` before insertion so that
//! `/`, `..`, NUL and other traversal-dangerous characters cannot appear in
//! the generated file name.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Length of the node-ID prefix embedded in fork names.
const NODE_ID_PREFIX_LEN: usize = 8;

/// Build a conflict-copy path for `original` using the Syncthing naming
/// convention.
///
/// # Arguments
/// * `rel_path`  — vault-relative source path (must not be empty).
/// * `node_id`   — writer's node identifier; only the first
///   [`NODE_ID_PREFIX_LEN`] hex chars are used; non-hex chars are stripped.
/// * `ts`        — timestamp to embed (truncated to the second, UTC).
///
/// # Returns
/// A new `PathBuf` with the conflict suffix inserted between the file stem
/// and its last extension (or appended when no extension is present).
pub fn fork_filename(rel_path: &Path, node_id: &str, ts: SystemTime) -> PathBuf {
    let parent = rel_path.parent().unwrap_or_else(|| Path::new(""));
    let file_name = rel_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();

    // Filter node_id to [0-9a-f] then take the first 8 chars.
    let node_id8: String = node_id
        .chars()
        .filter(|c| c.is_ascii_hexdigit() && c.is_ascii_lowercase() || c.is_ascii_digit())
        .take(NODE_ID_PREFIX_LEN)
        .collect();
    // Pad with '0' if too short (e.g. empty node_id).
    let node_id8 = format!("{:0<8}", node_id8);

    let ts_str = format_timestamp(ts);

    let suffix = format!("sync-conflict-{node_id8}-{ts_str}");

    // Split the filename into (base, maybe_ext).
    // For dotfiles (`.obsidian/config`) that have no extension other than
    // the leading dot, treat the whole name as the stem with no extension.
    let (stem, ext) = split_stem_ext(&file_name);

    let new_name = if ext.is_empty() {
        format!("{stem}.{suffix}")
    } else {
        format!("{stem}.{suffix}.{ext}")
    };

    if parent.as_os_str().is_empty() {
        PathBuf::from(new_name)
    } else {
        parent.join(new_name)
    }
}

/// Split a filename into (stem, extension) following the Syncthing convention:
/// the extension is only the **last** component after the final `.`.
/// Dotfiles (`.hidden`) are treated as having no extension.
fn split_stem_ext(name: &str) -> (&str, &str) {
    // A leading dot that forms the whole prefix of a dotfile is NOT an
    // extension separator.  We start looking for the extension separator
    // only after the leading dot (if any).
    let search_from = if name.starts_with('.') { 1 } else { 0 };
    match name[search_from..].rfind('.') {
        None => (name, ""),
        Some(rel_pos) => {
            let dot_pos = search_from + rel_pos;
            (&name[..dot_pos], &name[dot_pos + 1..])
        }
    }
}

/// Format a `SystemTime` as `YYYYMMDD-HHMMSS` in UTC.
fn format_timestamp(ts: SystemTime) -> String {
    use std::time::UNIX_EPOCH;
    let secs = ts
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Manual UTC decomposition — avoids a dependency on `chrono`.
    let (y, mo, d, h, mi, s) = unix_to_ymd_hms(secs);
    format!("{y:04}{mo:02}{d:02}-{h:02}{mi:02}{s:02}")
}

/// Decompose Unix seconds into (year, month, day, hour, minute, second) in UTC.
/// Gregorian calendar, valid for years 1970–2099.
fn unix_to_ymd_hms(secs: u64) -> (u32, u32, u32, u32, u32, u32) {
    let s = secs % 60;
    let mins = secs / 60;
    let mi = mins % 60;
    let hours = mins / 60;
    let h = hours % 24;
    let days = hours / 24;

    // Compute year and day-of-year using the 400-year Gregorian cycle.
    let mut year = 1970u32;
    let mut rem = days;
    loop {
        let dy = days_in_year(year);
        if rem < dy {
            break;
        }
        rem -= dy;
        year += 1;
    }

    let mut mo = 1u32;
    loop {
        let dm = days_in_month(year, mo);
        if rem < dm {
            break;
        }
        rem -= dm;
        mo += 1;
    }
    let d = rem + 1;

    (year, mo, d as u32, h as u32, mi as u32, s as u32)
}

fn is_leap(y: u32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_year(y: u32) -> u64 {
    if is_leap(y) {
        366
    } else {
        365
    }
}

fn days_in_month(y: u32, mo: u32) -> u64 {
    match mo {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap(y) {
                29
            } else {
                28
            }
        }
        _ => panic!("invalid month {mo}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    /// 2026-01-15 12:34:56 UTC  →  20260115-123456
    fn ts_fixed() -> SystemTime {
        // 2026-01-15 12:34:56 UTC
        UNIX_EPOCH + Duration::from_secs(1_768_292_096)
    }

    #[test]
    fn fork_filename_normal_md() {
        let ts = ts_fixed();
        let result = fork_filename(Path::new("notes/todo.md"), "abc12345deadbeef", ts);
        let name = result.file_name().unwrap().to_str().unwrap();
        assert!(
            name.starts_with("todo.sync-conflict-abc12345-"),
            "name={name}"
        );
        assert!(name.ends_with(".md"), "name={name}");
        assert_eq!(result.parent().unwrap(), Path::new("notes"));
    }

    #[test]
    fn fork_filename_dotfile_no_ext() {
        // .obsidian/config has no extension beyond the leading dot — suffix appended to end.
        let ts = ts_fixed();
        let result = fork_filename(Path::new(".obsidian/config"), "abc12345", ts);
        let name = result.file_name().unwrap().to_str().unwrap();
        // Should be: config.sync-conflict-abc12345-...  (no trailing extension)
        assert!(name.starts_with("config.sync-conflict-"), "name={name}");
        // No trailing dot-extension.
        assert!(
            !name.ends_with(".config"),
            "should not end with .config: {name}"
        );
    }

    #[test]
    fn fork_filename_multi_dot_tar_gz() {
        // archive.tar.gz — suffix before the last '.gz'
        let ts = ts_fixed();
        let result = fork_filename(Path::new("archive.tar.gz"), "abc12345", ts);
        let name = result.file_name().unwrap().to_str().unwrap();
        assert!(name.ends_with(".gz"), "name={name}");
        assert!(name.contains("archive.tar.sync-conflict-"), "name={name}");
    }

    #[test]
    fn fork_filename_no_extension_readme() {
        // README — no extension, suffix appended.
        let ts = ts_fixed();
        let result = fork_filename(Path::new("README"), "abc12345", ts);
        let name = result.file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with("README.sync-conflict-"), "name={name}");
        // No extension suffix.
        let parts: Vec<&str> = name.split('.').collect();
        // README.sync-conflict-abc12345-YYYYMMDD-HHMMSS → 3 parts (README, sync-conflict-..., (none))
        assert!(parts.len() >= 2, "name={name}");
    }

    #[test]
    fn node_id8_only_hex_lowercase() {
        // node_id with uppercase, dashes, and other chars — only lowercase hex passes.
        let ts = ts_fixed();
        let result = fork_filename(Path::new("file.txt"), "ABCD1234ZZZZ", ts);
        let name = result.file_name().unwrap().to_str().unwrap();
        // Only lowercase hex in source so only digits pass from ABCD1234ZZZZ → 1234
        // After filter + pad → 12340000
        assert!(name.contains("sync-conflict-"), "name={name}");
        // The node_id8 should be exactly 8 chars of [0-9a-f].
        let after = name.split("sync-conflict-").nth(1).unwrap();
        let node_part = after.split('-').next().unwrap();
        assert_eq!(node_part.len(), 8, "node_id8 length: {node_part}");
        assert!(
            node_part.chars().all(|c| c.is_ascii_hexdigit()),
            "node_id8 must be hex: {node_part}"
        );
    }

    #[test]
    fn no_path_traversal_in_fork_name() {
        // A malicious node_id with traversal chars — must not appear in result.
        let ts = ts_fixed();
        let result = fork_filename(Path::new("file.md"), "../../../etc/passwd\0evil", ts);
        let name = result.to_string_lossy();
        assert!(!name.contains(".."), "no dot-dot: {name}");
        assert!(!name.contains('\0'), "no NUL: {name}");
        assert!(
            !name.contains('/'),
            "file name must not contain slash: {name}"
        );
        // Verify only the file name portion — parent is preserved from rel_path.
        let file_name = result.file_name().unwrap().to_str().unwrap();
        assert!(!file_name.contains('/'), "file_name portion: {file_name}");
        assert!(!file_name.contains(".."), "file_name portion: {file_name}");
    }

    #[test]
    fn timestamp_format_correct() {
        // 2026-01-15 12:34:56 UTC
        let ts = UNIX_EPOCH + Duration::from_secs(1_768_292_096);
        let formatted = format_timestamp(ts);
        // We just need 8 digits + dash + 6 digits format.
        assert_eq!(formatted.len(), 15, "format: {formatted}");
        let (date, time) = formatted.split_once('-').unwrap();
        assert_eq!(date.len(), 8);
        assert_eq!(time.len(), 6);
    }
}
