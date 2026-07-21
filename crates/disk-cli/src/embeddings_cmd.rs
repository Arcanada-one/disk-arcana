//! `disk embeddings` — co-storage sidecar diagnostics and ingest (DISK-0029).

use std::path::Path;

use anyhow::{bail, Context, Result};
use base64::Engine;
use disk_client::config::DiskConfig;
use disk_client::embeddings_sweep::{share_filter, sweep_share};
use disk_core::embeddings::write_sidecar;

/// `disk embeddings status [--share <name>] [--config <path>]`.
pub fn run_embeddings_status(config_path: &Path, share_name: Option<&str>) -> Result<()> {
    let cfg =
        DiskConfig::load(config_path).with_context(|| format!("load {}", config_path.display()))?;

    let shares: Vec<_> = match share_name {
        Some(name) => cfg.shares.iter().filter(|s| s.name == name).collect(),
        None => cfg.shares.iter().collect(),
    };

    if shares.is_empty() {
        if let Some(name) = share_name {
            bail!("share {name:?} not found in {}", config_path.display());
        }
        bail!("no [[share]] blocks in {}", config_path.display());
    }

    for share in shares {
        let _ = share_filter(share).map_err(|e| anyhow::anyhow!("filter: {e}"))?;
        let report = sweep_share(share, &cfg.embeddings)
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

/// Inputs for `disk embeddings write`.
pub struct EmbeddingsWriteParams<'a> {
    pub share: &'a str,
    pub path: &'a str,
    pub vector_file: Option<&'a Path>,
    pub vector_base64: Option<&'a str>,
}

/// `disk embeddings write --share <name> --path <rel> [--vector-file <path>|--vector-base64 <b64>]`.
pub fn run_embeddings_write(config_path: &Path, params: EmbeddingsWriteParams<'_>) -> Result<()> {
    let EmbeddingsWriteParams {
        share,
        path,
        vector_file,
        vector_base64,
    } = params;

    let cfg =
        DiskConfig::load(config_path).with_context(|| format!("load {}", config_path.display()))?;
    if !cfg.embeddings.enabled {
        bail!(
            "embeddings co-storage is disabled in {}; set [embeddings] enabled = true",
            config_path.display()
        );
    }

    let share_cfg = cfg
        .shares
        .iter()
        .find(|s| s.name == share)
        .with_context(|| format!("share {share:?} not found in {}", config_path.display()))?;

    let vector_bytes = match (vector_file, vector_base64) {
        (Some(f), None) => {
            std::fs::read(f).with_context(|| format!("read vector file {}", f.display()))?
        }
        (None, Some(b64)) => base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .context("decode --vector-base64")?,
        (Some(_), Some(_)) => bail!("use only one of --vector-file or --vector-base64"),
        (None, None) => bail!("provide --vector-file or --vector-base64"),
    };

    let result = write_sidecar(
        &share_cfg.path,
        path,
        &vector_bytes,
        &cfg.embeddings.model_id,
        cfg.embeddings.dimensions,
    )
    .map_err(|e| anyhow::anyhow!("write sidecar: {e}"))?;

    println!(
        "write ok: source={} hash={} manifest={} vector={} bytes={}",
        result.source_path,
        result.source_content_hash,
        result.manifest_rel.display(),
        result.vector_rel.display(),
        result.vector_bytes,
    );
    Ok(())
}
