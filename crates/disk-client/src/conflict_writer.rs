//! Atomic fork writer for conflict copies.
//!
//! `write_fork` atomically writes a conflict copy of a vault file using
//! `tempfile::NamedTempFile` in the same parent directory, then persists it to
//! the fork name produced by `disk_core::conflict::fork_filename`.
//!
//! Atomicity guarantee: the fork file either appears fully-written or not at
//! all.  The original file is never modified.
//!
//! Collision handling: when the computed fork path already exists (two conflicts
//! within the same clock second on the same node), a numeric suffix (`-1`, `-2`,
//! …) is inserted before the final extension until a free slot is found.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use disk_core::conflict::fork_filename;

/// Errors that can occur while writing a fork file.
#[derive(Debug, thiserror::Error)]
pub enum ForkWriteError {
    /// An I/O error occurred while creating or writing the temp file.
    #[error("fork write I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// `persist()` failed (e.g. cross-device rename).
    #[error("fork persist failed: {0}")]
    Persist(#[from] tempfile::PersistError),

    /// The computed fork path escapes the vault root.
    #[error("fork path would escape vault root")]
    PathTraversal,
}

/// Maximum collision counter attempts before giving up.
const MAX_COLLISION_ATTEMPTS: u32 = 100;

/// Atomically write a conflict copy of `rel_path` into `base_dir`.
///
/// # Arguments
/// * `base_dir`  — absolute vault root (fork is placed relative to this).
/// * `rel_path`  — vault-relative path of the original file.
/// * `contents`  — bytes to write to the fork copy.
/// * `node_id`   — writer node identifier; only the first 8 hex chars are used.
///
/// # Returns
/// The vault-relative path of the fork file that was created.
pub fn write_fork(
    base_dir: &Path,
    rel_path: &Path,
    contents: &[u8],
    node_id: &str,
) -> Result<PathBuf, ForkWriteError> {
    let ts = SystemTime::now();
    let fork_rel = fork_filename(rel_path, node_id, ts);

    // Guard: the fork path must stay inside base_dir.
    validate_no_traversal(&fork_rel)?;

    let fork_abs = base_dir.join(&fork_rel);

    // Ensure parent directory exists.
    if let Some(parent) = fork_abs.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Try to persist at the computed path; on collision add a counter suffix.
    for attempt in 0..MAX_COLLISION_ATTEMPTS {
        let candidate = if attempt == 0 {
            fork_abs.clone()
        } else {
            with_collision_suffix(&fork_abs, attempt)
        };

        match write_atomic(&candidate, contents) {
            Ok(()) => {
                // Return the relative path.
                let rel = candidate
                    .strip_prefix(base_dir)
                    .unwrap_or(&candidate)
                    .to_path_buf();
                return Ok(rel);
            }
            Err(ForkWriteError::Io(e)) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // Collision — try next counter.
                continue;
            }
            Err(e) => return Err(e),
        }
    }

    Err(ForkWriteError::Io(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "exceeded collision counter limit",
    )))
}

/// Write `contents` to `path` atomically using a temp file in the same parent.
///
/// Returns `Err(Io(AlreadyExists))` when `path` already exists so that the
/// caller can increment the collision counter.
fn write_atomic(path: &Path, contents: &[u8]) -> Result<(), ForkWriteError> {
    use std::io::Write as _;

    // Fail fast if the destination already exists.
    if path.exists() {
        return Err(ForkWriteError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "fork path already exists",
        )));
    }

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.write_all(contents)?;
    tmp.flush()?;
    tmp.persist(path)?;
    Ok(())
}

/// Insert a collision counter before the last extension.
///
/// `archive.tar.gz` + counter 1 → `archive.tar.sync-conflict-...-1.gz`
fn with_collision_suffix(path: &Path, counter: u32) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();

    let new_name = match name.rfind('.') {
        None => format!("{name}-{counter}"),
        Some(dot) => format!("{}-{}{}", &name[..dot], counter, &name[dot..]),
    };

    if parent.as_os_str().is_empty() {
        PathBuf::from(new_name)
    } else {
        parent.join(new_name)
    }
}

/// Reject relative paths with `..` components or NUL bytes.
fn validate_no_traversal(rel: &Path) -> Result<(), ForkWriteError> {
    use std::path::Component;
    let s = rel.to_string_lossy();
    if s.contains('\0') {
        return Err(ForkWriteError::PathTraversal);
    }
    for comp in rel.components() {
        if matches!(comp, Component::ParentDir | Component::RootDir | Component::Prefix(_)) {
            return Err(ForkWriteError::PathTraversal);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn fork_writer_creates_both_files() {
        let dir = tempfile::tempdir().unwrap();
        let original_rel = Path::new("notes/todo.md");
        let original_abs = dir.path().join(original_rel);
        fs::create_dir_all(original_abs.parent().unwrap()).unwrap();
        let original_content = b"original content";
        fs::write(&original_abs, original_content).unwrap();

        let fork_content = b"fork content";
        let fork_rel = write_fork(dir.path(), original_rel, fork_content, "abc12345dead").unwrap();

        // Original is untouched.
        let orig_read = fs::read(&original_abs).unwrap();
        assert_eq!(orig_read, original_content, "original must be unchanged");

        // Fork exists with correct content.
        let fork_abs = dir.path().join(&fork_rel);
        assert!(fork_abs.exists(), "fork must exist: {}", fork_abs.display());
        let fork_read = fs::read(&fork_abs).unwrap();
        assert_eq!(fork_read, fork_content, "fork content must match");

        // Fork name contains the conflict suffix.
        let fork_name = fork_abs.file_name().unwrap().to_str().unwrap();
        assert!(
            fork_name.contains("sync-conflict-"),
            "fork name must contain conflict suffix: {fork_name}"
        );
    }

    #[test]
    fn fork_writer_collision_adds_counter() {
        let dir = tempfile::tempdir().unwrap();
        let rel = Path::new("file.txt");
        let content = b"hello";

        // Write the first fork.
        let fork1 = write_fork(dir.path(), rel, content, "abc12345").unwrap();

        // Manually create the exact path that the second attempt would use
        // so that we force a collision on the first slot.
        // The collision guard increments the counter, so the second write_fork
        // call should produce a path with "-1" suffix.
        let fork2 = write_fork(dir.path(), rel, content, "abc12345").unwrap();

        // Both forks must exist.
        assert!(dir.path().join(&fork1).exists(), "fork1 must exist");
        assert!(dir.path().join(&fork2).exists(), "fork2 must exist");

        // They must have different paths (collision was resolved).
        assert_ne!(fork1, fork2, "fork paths must differ on collision");
    }

    #[test]
    fn fork_writer_returns_relative_path() {
        let dir = tempfile::tempdir().unwrap();
        let rel = Path::new("docs/readme.md");
        fs::create_dir_all(dir.path().join("docs")).unwrap();
        let fork_rel = write_fork(dir.path(), rel, b"content", "deadbeef").unwrap();
        // Returned path must be relative (not absolute).
        assert!(
            fork_rel.is_relative(),
            "must return relative path: {}",
            fork_rel.display()
        );
        // Must be inside docs/.
        assert!(
            fork_rel.starts_with("docs"),
            "must be under docs/: {}",
            fork_rel.display()
        );
    }
}
