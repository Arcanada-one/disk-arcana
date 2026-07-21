//! Post-sync embedding sidecar sweep (DISK-0029 slice 2).

use std::time::Duration;

use disk_core::embeddings::scan::{scan_share_embeddings, DEFAULT_EMBEDDABLE_EXTENSIONS};
use disk_core::embeddings::ShareEmbeddingsReport;
use disk_core::filter::{Filter, FilterRules};
use serde::Serialize;

use crate::config::{EmbeddingsSection, FilterMode, ShareSection};

/// Snapshot exposed on loopback `GET /embeddings/status`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct EmbeddingsStatusSnapshot {
    pub share: String,
    pub enabled: bool,
    pub fresh: usize,
    pub stale: usize,
    pub missing: usize,
    pub co_storage_files: usize,
    pub swept_at_unix: i64,
}

impl From<ShareEmbeddingsReport> for EmbeddingsStatusSnapshot {
    fn from(report: ShareEmbeddingsReport) -> Self {
        Self {
            share: report.share_name,
            enabled: report.enabled,
            fresh: report.fresh,
            stale: report.stale,
            missing: report.missing,
            co_storage_files: report.co_storage_file_count,
            swept_at_unix: unix_now(),
        }
    }
}

/// Run a blocking filesystem sweep for one share.
pub fn sweep_share(
    share: &ShareSection,
    embeddings: &EmbeddingsSection,
) -> std::io::Result<ShareEmbeddingsReport> {
    let filter = share_filter(share).map_err(|e| std::io::Error::other(e.to_string()))?;
    scan_share_embeddings(
        &share.name,
        &share.path,
        &filter,
        embeddings.enabled,
        &embeddings.model_id,
        embeddings.dimensions,
        DEFAULT_EMBEDDABLE_EXTENSIONS,
    )
}

/// Optional server webhook report when stale/missing sidecars exist.
pub async fn report_stale_to_server(
    api_base: &str,
    bearer_token: &str,
    vault_id: &str,
    share: &str,
    report: &ShareEmbeddingsReport,
) -> Result<(), String> {
    if !report.enabled || (report.stale == 0 && report.missing == 0) {
        return Ok(());
    }

    let stale_paths: Vec<serde_json::Value> = report
        .sources
        .iter()
        .filter(|row| !row.staleness.is_fresh())
        .map(|row| {
            serde_json::json!({
                "path": row.source_path.to_string_lossy(),
                "status": row.staleness.label(),
            })
        })
        .collect();

    let body = serde_json::json!({
        "vault_id": vault_id,
        "share": share,
        "fresh": report.fresh,
        "stale": report.stale,
        "missing": report.missing,
        "paths": stale_paths,
    });

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;
    let url = format!("{}/agents/embeddings-stale", api_base.trim_end_matches('/'));
    let resp = client
        .post(&url)
        .bearer_auth(bearer_token)
        .json(&body)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("POST {url} HTTP {}", resp.status()));
    }
    Ok(())
}

pub fn share_filter(share: &ShareSection) -> Result<Filter, disk_core::error::FilterError> {
    let mut rules = FilterRules::default();
    if let Some(f) = &share.filter {
        match f.mode {
            FilterMode::Whitelist => {
                rules.extensions_whitelist = f.extensions.clone();
                rules.ignore_globs.extend(f.include.clone());
            }
            FilterMode::Blacklist => {
                rules.ignore_globs.extend(f.exclude.clone());
            }
        }
    }
    Filter::from_config(&rules)
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use disk_core::embeddings::manifest::SidecarManifest;
    use disk_core::embeddings::paths::vector_blob_rel_path;
    use disk_core::scanner::hash_file;
    use std::fs;
    use std::path::Path;
    use tempfile::TempDir;

    #[test]
    fn sweep_share_reports_missing_when_enabled() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        fs::create_dir_all(root.join("notes")).unwrap();
        fs::write(root.join("notes/a.md"), b"one").unwrap();

        let share = ShareSection {
            name: "wiki".into(),
            path: root.to_path_buf(),
            intended_direction: None,
            filter: None,
            publisher: None,
        };
        let embeddings = EmbeddingsSection {
            enabled: true,
            model_id: "bge-m3".into(),
            dimensions: 4,
        };
        let report = sweep_share(&share, &embeddings).unwrap();
        assert_eq!(report.missing, 1);
        assert_eq!(report.fresh, 0);
    }

    #[test]
    fn snapshot_from_report_carries_counts() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        fs::create_dir_all(root.join("notes")).unwrap();
        fs::write(root.join("notes/a.md"), b"one").unwrap();
        let hash = hex::encode(hash_file(&root.join("notes/a.md")).unwrap());
        let manifest = SidecarManifest::new("notes/a.md", hash, "bge-m3", 4, 8);
        manifest
            .write_to_share(root, Path::new("notes/a.md"))
            .unwrap();
        let vector_rel = vector_blob_rel_path(Path::new("notes/a.md"));
        fs::create_dir_all(root.join(vector_rel.parent().unwrap())).unwrap();
        fs::write(root.join(vector_rel), vec![0u8; 8]).unwrap();

        let share = ShareSection {
            name: "wiki".into(),
            path: root.to_path_buf(),
            intended_direction: None,
            filter: None,
            publisher: None,
        };
        let embeddings = EmbeddingsSection {
            enabled: true,
            model_id: "bge-m3".into(),
            dimensions: 4,
        };
        let report = sweep_share(&share, &embeddings).unwrap();
        let snap = EmbeddingsStatusSnapshot::from(report);
        assert_eq!(snap.fresh, 1);
        assert!(snap.swept_at_unix > 0);
    }
}
