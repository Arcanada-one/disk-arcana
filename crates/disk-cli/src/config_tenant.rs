//! Update `[node].tenant_id` in `disk.toml` (DISK-0030 slice 3).

use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use disk_client::config::DiskConfig;

/// Set or replace `[node].tenant_id` in `disk.toml`, validating before commit.
///
/// Rolls back to the original file content if the updated TOML fails validation.
pub fn set_node_tenant_id(cfg_path: &Path, tenant_id: &str) -> Result<PathBuf> {
    if tenant_id.is_empty() {
        return Err(anyhow!("tenant_id must not be empty"));
    }
    if !cfg_path.exists() {
        return Err(anyhow!(
            "{} does not exist — run `disk enroll` first",
            cfg_path.display()
        ));
    }

    let original =
        fs::read_to_string(cfg_path).with_context(|| format!("read {}", cfg_path.display()))?;

    DiskConfig::from_str(&original).with_context(|| {
        format!(
            "existing {} is invalid; refusing to update tenant_id",
            cfg_path.display()
        )
    })?;

    let updated = patch_node_tenant_id(&original, tenant_id)?;
    fs::write(cfg_path, &updated).with_context(|| format!("write {}", cfg_path.display()))?;

    if let Err(e) = DiskConfig::from_str(&updated) {
        fs::write(cfg_path, &original).with_context(|| {
            format!(
                "rollback failed: could not restore original {}",
                cfg_path.display()
            )
        })?;
        return Err(anyhow!(
            "updated config failed validation; original restored: {e}"
        ));
    }

    Ok(cfg_path.to_path_buf())
}

fn patch_node_tenant_id(raw: &str, tenant_id: &str) -> Result<String> {
    let mut lines: Vec<String> = raw.lines().map(str::to_owned).collect();
    let mut in_node = false;
    let mut tenant_line: Option<usize> = None;
    let mut id_line: Option<usize> = None;

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            if in_node {
                break;
            }
            if trimmed == "[node]" {
                in_node = true;
            }
            continue;
        }
        if !in_node {
            continue;
        }
        if trimmed.starts_with("tenant_id") {
            tenant_line = Some(idx);
        }
        if trimmed.starts_with("id ") || trimmed.starts_with("id=") {
            id_line = Some(idx);
        }
    }

    if !in_node {
        return Err(anyhow!("disk.toml has no [node] section"));
    }

    let assignment = format!("tenant_id = {}", toml_string(tenant_id));
    if let Some(idx) = tenant_line {
        lines[idx] = assignment;
    } else {
        let insert_at = id_line.map(|i| i + 1).unwrap_or(1);
        lines.insert(insert_at, assignment);
    }

    let mut out = lines.join("\n");
    if raw.ends_with('\n') {
        out.push('\n');
    }
    Ok(out)
}

fn toml_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const BASE: &str = r#"
[node]
id = "dev"
[node.default]
intended_direction = "receive_only"

[server]
address = "disk.arcanada.ai:9443"
client_cert = "/etc/disk-arcana/client.crt"
client_key  = "/etc/disk-arcana/client.key"
"#;

    #[test]
    fn inserts_tenant_id_after_node_id() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("disk.toml");
        fs::write(&path, BASE).unwrap();
        set_node_tenant_id(&path, "corp-team").unwrap();
        let cfg = DiskConfig::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(cfg.node.tenant_id.as_deref(), Some("corp-team"));
    }

    #[test]
    fn replaces_existing_tenant_id() {
        let toml = BASE.replace("id = \"dev\"", "id = \"dev\"\ntenant_id = \"old\"");
        let dir = tempdir().unwrap();
        let path = dir.path().join("disk.toml");
        fs::write(&path, &toml).unwrap();
        set_node_tenant_id(&path, "new-tenant").unwrap();
        let cfg = DiskConfig::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(cfg.node.tenant_id.as_deref(), Some("new-tenant"));
        let raw = fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("old"));
    }
}
