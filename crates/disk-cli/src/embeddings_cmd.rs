//! `disk embeddings` — co-storage sidecar diagnostics (DISK-0029 slice 1).

use std::path::Path;

use anyhow::{bail, Context, Result};
use disk_client::config::{DiskConfig, FilterMode, ShareSection};
use disk_core::embeddings::scan::{scan_share_embeddings, DEFAULT_EMBEDDABLE_EXTENSIONS};
use disk_core::filter::{Filter, FilterRules};

/// `disk embeddings status [--share <name>] [--config <path>]`.
pub fn run_embeddings_status(config_path: &Path, share_name: Option<&str>) -> Result<()> {
    let cfg = DiskConfig::load(config_path)
        .with_context(|| format!("load {}", config_path.display()))?;

    let shares: Vec<_> = match share_name {
        Some(name) => cfg
            .shares
            .iter()
            .filter(|s| s.name == name)
            .collect(),
        None => cfg.shares.iter().collect(),
    };

    if shares.is_empty() {
        if let Some(name) = share_name {
            bail!("share {name:?} not found in {}", config_path.display());
        }
        bail!("no [[share]] blocks in {}", config_path.display());
    }

    for share in shares {
        let filter = share_filter(share)?;
        let report = scan_share_embeddings(
            &share.name,
            &share.path,
            &filter,
            cfg.embeddings.enabled,
            &cfg.embeddings.model_id,
            cfg.embeddings.dimensions,
            DEFAULT_EMBEDDABLE_EXTENSIONS,
        )
        .with_context(|| format!("scan share {}", share.name))?;

        println!("share: {}", report.share_name);
        println!("  embeddings_enabled: {}", report.enabled);
        println!("  model_id: {}", report.model_id);
        println!("  dimensions: {}", report.dimensions);
        println!("  fresh: {}", report.fresh);
        println!("  stale: {}", report.stale);
        println!("  missing: {}", report.missing);
        println!("  co_storage_files: {}", report.co_storage_file_count);

        if report.enabled {
            for row in &report.sources {
                if row.staleness.is_fresh() {
                    continue;
                }
                println!(
                    "  - {} [{}]",
                    row.source_path.display(),
                    row.staleness.label()
                );
            }
        }
        println!();
    }

    Ok(())
}

fn share_filter(share: &ShareSection) -> Result<Filter> {
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
    Filter::from_config(&rules).map_err(|e| anyhow::anyhow!("filter: {e}"))
}
