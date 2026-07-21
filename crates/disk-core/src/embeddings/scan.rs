//! Share-wide embedding sidecar inventory for operator diagnostics.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

use super::manifest::evaluate_staleness;
use super::paths::is_co_storage_path;
use crate::filter::Filter;
use crate::scanner::hash_file;

/// Default text extensions considered embeddable when scanning a share.
pub const DEFAULT_EMBEDDABLE_EXTENSIONS: &[&str] = &["md", "markdown", "txt"];

/// Per-source sidecar status row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceSidecarStatus {
    pub source_path: PathBuf,
    pub content_hash_hex: String,
    pub staleness: super::manifest::Staleness,
}

/// Aggregated report for `disk embeddings status`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareEmbeddingsReport {
    pub share_name: String,
    pub enabled: bool,
    pub model_id: String,
    pub dimensions: u32,
    pub fresh: usize,
    pub stale: usize,
    pub missing: usize,
    pub co_storage_file_count: usize,
    pub sources: Vec<SourceSidecarStatus>,
}

/// Scan `share_root` for embeddable sources and evaluate sidecar freshness.
pub fn scan_share_embeddings(
    share_name: &str,
    share_root: &Path,
    filter: &Filter,
    enabled: bool,
    model_id: &str,
    dimensions: u32,
    embeddable_extensions: &[&str],
) -> Result<ShareEmbeddingsReport, std::io::Error> {
    let mut sources = Vec::new();
    let mut co_storage_file_count = 0usize;
    let ext_set: HashSet<String> = embeddable_extensions
        .iter()
        .map(|e| e.trim_start_matches('.').to_ascii_lowercase())
        .collect();

    for entry in WalkDir::new(share_root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .flatten()
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let abs = entry.path();
        let rel = match abs.strip_prefix(share_root) {
            Ok(r) => r.to_path_buf(),
            Err(_) => continue,
        };
        if rel.as_os_str().is_empty() {
            continue;
        }
        if filter.is_excluded(&rel) {
            continue;
        }
        if is_co_storage_path(&rel) {
            co_storage_file_count += 1;
            continue;
        }
        if !enabled {
            continue;
        }
        let ext = rel
            .extension()
            .and_then(|e| e.to_str())
            .map(|s| s.to_ascii_lowercase());
        let Some(ext) = ext else {
            continue;
        };
        if !ext_set.contains(&ext) {
            continue;
        }

        let hash_hex = hex::encode(
            hash_file(abs).map_err(|e| std::io::Error::other(e.to_string()))?,
        );
        let staleness = evaluate_staleness(share_root, &rel, &hash_hex, model_id, dimensions);
        sources.push(SourceSidecarStatus {
            source_path: rel,
            content_hash_hex: hash_hex,
            staleness,
        });
    }

    let mut fresh = 0usize;
    let mut stale = 0usize;
    let mut missing = 0usize;
    for row in &sources {
        match row.staleness {
            super::manifest::Staleness::Fresh => fresh += 1,
            super::manifest::Staleness::MissingManifest | super::manifest::Staleness::MissingVector => {
                missing += 1
            }
            _ => stale += 1,
        }
    }

    Ok(ShareEmbeddingsReport {
        share_name: share_name.to_string(),
        enabled,
        model_id: model_id.to_string(),
        dimensions,
        fresh,
        stale,
        missing,
        co_storage_file_count,
        sources,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::embeddings::manifest::SidecarManifest;
    use crate::embeddings::paths::vector_blob_rel_path;
    use crate::filter::{Filter, FilterRules};
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn scan_counts_fresh_and_missing() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        fs::create_dir_all(root.join("notes")).unwrap();
        fs::write(root.join("notes/a.md"), b"one").unwrap();
        fs::write(root.join("notes/b.md"), b"two").unwrap();

        let hash = hex::encode(hash_file(&root.join("notes/a.md")).unwrap());
        let manifest = SidecarManifest::new("notes/a.md", &hash, "bge-m3", 2, 8);
        manifest
            .write_to_share(root, Path::new("notes/a.md"))
            .unwrap();
        let vector_rel = vector_blob_rel_path(Path::new("notes/a.md"));
        fs::create_dir_all(root.join(vector_rel.parent().unwrap())).unwrap();
        fs::write(root.join(vector_rel), vec![0u8; 8]).unwrap();

        let filter = Filter::from_config(&FilterRules::default()).unwrap();
        let report = scan_share_embeddings(
            "wiki",
            root,
            &filter,
            true,
            "bge-m3",
            2,
            DEFAULT_EMBEDDABLE_EXTENSIONS,
        )
        .unwrap();

        assert_eq!(report.fresh, 1);
        assert_eq!(report.missing, 1);
        assert_eq!(report.stale, 0);
        assert!(report.co_storage_file_count >= 2);
    }
}
