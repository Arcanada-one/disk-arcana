//! Path-traversal guard for the scanner.
//!
//! [`validate`] rejects malicious or malformed paths before they reach the
//! filesystem walker or the metadata index. The guard treats the configured
//! sync root as canonical truth: any candidate path that, after symlink
//! resolution, lies outside the root is refused.

use std::path::{Component, Path, PathBuf};

use crate::error::PathGuardError;

/// Validate `candidate` against the canonical `root`.
///
/// Returns the canonicalized absolute path on success. The guard rejects:
/// - paths containing NUL bytes,
/// - paths whose components contain `..`,
/// - non-UTF-8 path representations,
/// - paths whose canonical form escapes `root` (including via symlinks).
///
/// `candidate` may be either absolute or relative to `root`.
pub fn validate(candidate: &Path, root: &Path) -> Result<PathBuf, PathGuardError> {
    let bytes = path_to_bytes(candidate);
    if bytes.contains(&0u8) {
        return Err(PathGuardError::NullByte);
    }

    if candidate.to_str().is_none() {
        return Err(PathGuardError::InvalidUtf8);
    }

    if candidate
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(PathGuardError::RelativeWithDotDot);
    }

    let absolute = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        root.join(candidate)
    };

    let canonical_root = root
        .canonicalize()
        .map_err(|_| PathGuardError::OutsideRoot)?;

    let canonical = match absolute.canonicalize() {
        Ok(p) => p,
        Err(_) => {
            // Path may not exist yet (e.g. about-to-be-created file with
            // one or more missing parent directories). Walk up the ancestor
            // chain until we find an existing directory, then re-attach the
            // remaining suffix.
            //
            // This handles both `root/notes/hello.md` (notes/ doesn't exist)
            // and `root/a/b/c/file.md` (a/ through c/ are all new).
            let mut ancestor = absolute.as_path();
            let mut suffix: Vec<_> = Vec::new();
            let canon_ancestor = loop {
                match ancestor.canonicalize() {
                    Ok(p) => break p,
                    Err(_) => {
                        // Push the last component onto the suffix stack and
                        // move up.  If we reach the filesystem root without
                        // finding an existing ancestor, treat it as OutsideRoot.
                        let name = ancestor.file_name().ok_or(PathGuardError::OutsideRoot)?;
                        suffix.push(name.to_os_string());
                        ancestor = ancestor.parent().ok_or(PathGuardError::OutsideRoot)?;
                        if ancestor.as_os_str().is_empty() {
                            return Err(PathGuardError::OutsideRoot);
                        }
                    }
                }
            };
            // Re-attach the suffix (reversed — we pushed most-specific last).
            suffix.reverse();
            suffix.iter().fold(canon_ancestor, |acc, seg| acc.join(seg))
        }
    };

    if !canonical.starts_with(&canonical_root) {
        return Err(PathGuardError::SymlinkOutsideRoot);
    }

    if canonical.as_os_str().len() > path_max() {
        return Err(PathGuardError::PathTooLong);
    }

    Ok(canonical)
}

#[cfg(unix)]
fn path_to_bytes(p: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    p.as_os_str().as_bytes().to_vec()
}

#[cfg(not(unix))]
fn path_to_bytes(p: &Path) -> Vec<u8> {
    p.to_string_lossy().as_bytes().to_vec()
}

/// Effective platform PATH_MAX. Conservative cross-platform choice — POSIX
/// guarantees ≥ 4096; Windows MAX_PATH is 260 but extended paths reach 32 767.
const fn path_max() -> usize {
    4096
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn rejects_dot_dot_segment() {
        let root = tempdir().unwrap();
        let err = validate(Path::new("../etc/passwd"), root.path()).unwrap_err();
        assert_eq!(err, PathGuardError::RelativeWithDotDot);
    }

    #[test]
    fn rejects_nested_dot_dot() {
        let root = tempdir().unwrap();
        let err = validate(Path::new("legit/then/../../escape"), root.path()).unwrap_err();
        assert_eq!(err, PathGuardError::RelativeWithDotDot);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_absolute_outside_root() {
        let root = tempdir().unwrap();
        let err = validate(Path::new("/etc/passwd"), root.path()).unwrap_err();
        assert!(matches!(
            err,
            PathGuardError::OutsideRoot | PathGuardError::SymlinkOutsideRoot
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_null_byte() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let root = tempdir().unwrap();
        let p = PathBuf::from(OsStr::from_bytes(b"legit\0evil"));
        let err = validate(&p, root.path()).unwrap_err();
        assert_eq!(err, PathGuardError::NullByte);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_pointing_outside_root() {
        let root = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let target = outside.path().join("secret.txt");
        fs::write(&target, b"x").unwrap();

        let link = root.path().join("escape");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err = validate(&link, root.path()).unwrap_err();
        assert_eq!(err, PathGuardError::SymlinkOutsideRoot);
    }

    #[test]
    fn accepts_valid_relative_path() {
        let root = tempdir().unwrap();
        fs::create_dir_all(root.path().join("notes")).unwrap();
        fs::write(root.path().join("notes/a.md"), b"x").unwrap();
        let canonical = validate(Path::new("notes/a.md"), root.path()).unwrap();
        assert!(canonical.starts_with(root.path().canonicalize().unwrap()));
    }

    #[test]
    fn accepts_dot_segments_after_canonicalize() {
        let root = tempdir().unwrap();
        fs::create_dir_all(root.path().join("a")).unwrap();
        fs::write(root.path().join("a/b.md"), b"x").unwrap();
        let canonical = validate(Path::new("a/./b.md"), root.path()).unwrap();
        assert!(canonical.ends_with("b.md"));
    }

    #[test]
    fn rejects_extremely_long_path() {
        let root = tempdir().unwrap();
        let huge: PathBuf = std::iter::repeat("verylongsegment").take(400).collect();
        let err = validate(&huge, root.path()).unwrap_err();
        assert!(matches!(
            err,
            PathGuardError::PathTooLong
                | PathGuardError::OutsideRoot
                | PathGuardError::SymlinkOutsideRoot
        ));
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig {
            cases: 32,
            ..proptest::prelude::ProptestConfig::default()
        })]

        #[test]
        fn fuzz_dot_dot_always_rejected(
            prefix in "[a-z]{1,4}(/[a-z]{1,4}){0,3}",
            depth in 1usize..4,
        ) {
            let root = tempdir().unwrap();
            let mut p = PathBuf::from(prefix);
            for _ in 0..depth {
                p = p.join("..");
            }
            p = p.join("escape");
            let err = validate(&p, root.path()).unwrap_err();
            proptest::prop_assert_eq!(err, PathGuardError::RelativeWithDotDot);
        }
    }
}
