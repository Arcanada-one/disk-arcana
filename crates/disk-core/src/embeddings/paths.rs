//! Relative path helpers for `.disk-embeddings/` co-storage layout.

use std::path::{Component, Path, PathBuf};

/// Root directory for embedding sidecars inside a share.
pub const CO_STORAGE_ROOT: &str = ".disk-embeddings";

/// Manifest suffix appended to the mirrored source relative path.
pub const MANIFEST_SUFFIX: &str = ".manifest.json";

/// Raw vector blob suffix appended to the mirrored source relative path.
pub const VECTOR_SUFFIX: &str = ".vec.bin";

/// `true` when `rel` lives under `.disk-embeddings/`.
pub fn is_co_storage_path(rel: &Path) -> bool {
    rel.components().next().is_some_and(
        |c| matches!(c, Component::Normal(seg) if seg.eq_ignore_ascii_case(CO_STORAGE_ROOT)),
    )
}

/// Relative manifest path for a source file, e.g. `notes/a.md` →
/// `.disk-embeddings/notes/a.md.manifest.json`.
pub fn manifest_rel_path(source_rel: &Path) -> PathBuf {
    let mut out = PathBuf::from(CO_STORAGE_ROOT);
    out.push(source_rel);
    let file_name = source_rel
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    out.set_file_name(format!("{}{MANIFEST_SUFFIX}", file_name.to_string_lossy()));
    out
}

/// Relative vector blob path for a source file, e.g. `notes/a.md` →
/// `.disk-embeddings/notes/a.md.vec.bin`.
pub fn vector_blob_rel_path(source_rel: &Path) -> PathBuf {
    let mut out = PathBuf::from(CO_STORAGE_ROOT);
    out.push(source_rel);
    let file_name = source_rel
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    out.set_file_name(format!("{}{VECTOR_SUFFIX}", file_name.to_string_lossy()));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn co_storage_path_detection() {
        assert!(is_co_storage_path(Path::new(
            ".disk-embeddings/notes/a.md.manifest.json"
        )));
        assert!(is_co_storage_path(Path::new(".disk-embeddings/x.vec.bin")));
        assert!(!is_co_storage_path(Path::new("notes/a.md")));
        assert!(!is_co_storage_path(Path::new(".disk-archive/foo")));
    }

    #[test]
    fn manifest_and_vector_paths_mirror_source() {
        let src = Path::new("notes/welcome.md");
        assert_eq!(
            manifest_rel_path(src),
            PathBuf::from(".disk-embeddings/notes/welcome.md.manifest.json")
        );
        assert_eq!(
            vector_blob_rel_path(src),
            PathBuf::from(".disk-embeddings/notes/welcome.md.vec.bin")
        );
    }
}
