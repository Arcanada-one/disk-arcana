//! `disk versions` — list/restore file history via health HTTP API (DISK-0020 slice 3).

use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::Value;

const DEFAULT_API_BASE: &str = "http://127.0.0.1:9446";

fn api_base(override_base: Option<&str>) -> String {
    override_base
        .map(str::to_string)
        .or_else(|| std::env::var("DISK_API_BASE").ok())
        .unwrap_or_else(|| DEFAULT_API_BASE.to_string())
        .trim_end_matches('/')
        .to_string()
}

fn bearer_token(override_token: Option<&str>) -> Result<String> {
    override_token
        .map(str::to_string)
        .or_else(|| std::env::var("DISK_ACCESS_TOKEN").ok())
        .filter(|t| !t.is_empty())
        .context("set --token or DISK_ACCESS_TOKEN (dashboard login JWT)")
}

async fn api_get(api: &str, token: &str, path: &str) -> Result<Value> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;
    let url = format!("{api}{path}");
    let resp = client
        .get(&url)
        .bearer_auth(token)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        let msg = body
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("request failed");
        anyhow::bail!("GET {path} HTTP {status}: {msg}");
    }
    Ok(body)
}

async fn api_post(api: &str, token: &str, path: &str, json_body: Value) -> Result<Value> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;
    let url = format!("{api}{path}");
    let resp = client
        .post(&url)
        .bearer_auth(token)
        .json(&json_body)
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        let msg = body
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("request failed");
        anyhow::bail!("POST {path} HTTP {status}: {msg}");
    }
    Ok(body)
}

fn format_bytes(n: u64) -> String {
    if n < 1024 {
        return format!("{n} B");
    }
    let units = ["KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0usize;
    while v >= 1024.0 && i < units.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.1} {}", units[i])
}

fn format_ts(ts: i64) -> String {
    if ts <= 0 {
        return "—".into();
    }
    // Best-effort UTC display without extra deps.
    format!("unix:{ts}")
}

fn print_version_row(v: &Value, can_restore: bool) {
    let vid = v["version_id"].as_u64().unwrap_or(0);
    let current = v["is_current"].as_bool().unwrap_or(false);
    let blob = v["blob_available"].as_bool().unwrap_or(false);
    let size = v["size"].as_u64().unwrap_or(0);
    let hash = v["content_hash_hex"].as_str().unwrap_or("");
    let hash_short = if hash.len() > 8 {
        format!("{}…", &hash[..8])
    } else {
        hash.to_string()
    };
    let author = v["created_by"].as_str().unwrap_or("—");
    let created = format_ts(v["created_at"].as_i64().unwrap_or(0));
    let tag = if current { " [current]" } else { "" };
    let blob_tag = if !blob { " [blob missing]" } else { "" };
    print!(
        "v{vid:<4}  {created:<14}  {:>10}  {hash_short:<10}  {author:<12}",
        format_bytes(size)
    );
    if can_restore && blob && !current {
        print!("  (restorable)");
    }
    println!("{tag}{blob_tag}");
}

/// `disk versions list --path <path> [--vault default] [--limit N] [--offset N]`.
pub async fn run_versions_list(
    api: Option<&str>,
    token: Option<&str>,
    path: &str,
    vault: &str,
    limit: u32,
    offset: u32,
) -> Result<()> {
    let base = api_base(api);
    let token = bearer_token(token)?;
    let qs = format!(
        "/versions?path={}&vault_id={}&limit={}&offset={}",
        urlencoding(path),
        urlencoding(vault),
        limit,
        offset
    );
    let data = api_get(&base, &token, &qs).await?;

    let plan = data["plan_tier"].as_str().unwrap_or("?");
    let retention = &data["retention"];
    let max_v = retention["max_versions"].as_u64().unwrap_or(0);
    let max_days = retention["max_age_days"].as_u64().unwrap_or(0);
    println!(
        "path: {}  vault: {}  plan: {plan}  retention: {max_v} versions / {max_days} days",
        data["path"].as_str().unwrap_or(path),
        data["vault_id"].as_str().unwrap_or(vault),
    );

    if data["file_deleted"].as_bool().unwrap_or(false) {
        println!("note: file is marked deleted in metadata");
    } else if !data["file_exists"].as_bool().unwrap_or(false) {
        println!("note: no live file row for this path");
    }

    println!(
        "{:<6}  {:<14}  {:>10}  {:<10}  author",
        "ver", "created", "size", "hash"
    );
    println!("{}", "-".repeat(72));

    if let Some(current) = data.get("current").filter(|v| !v.is_null()) {
        print_version_row(current, false);
    }

    if let Some(rows) = data["versions"].as_array() {
        for row in rows {
            print_version_row(row, true);
        }
        if rows.is_empty() && data.get("current").map(|c| c.is_null()).unwrap_or(true) {
            println!("(no versions)");
        }
    }

    if let Some(p) = data.get("pagination") {
        println!(
            "pagination: offset={} limit={} total_historical={} has_more={}",
            p["offset"].as_u64().unwrap_or(0),
            p["limit"].as_u64().unwrap_or(0),
            p["total_historical"].as_u64().unwrap_or(0),
            p["has_more"].as_bool().unwrap_or(false),
        );
    }

    Ok(())
}

/// `disk versions restore --path <path> --version-id <id> [--vault default]`.
pub async fn run_versions_restore(
    api: Option<&str>,
    token: Option<&str>,
    path: &str,
    vault: &str,
    version_id: u64,
) -> Result<()> {
    if version_id == 0 {
        anyhow::bail!("--version-id must be > 0");
    }
    let base = api_base(api);
    let token = bearer_token(token)?;
    let body = serde_json::json!({
        "path": path,
        "vault_id": vault,
        "version_id": version_id,
    });
    let data = api_post(&base, &token, "/versions/restore", body).await?;
    let message = data["message"].as_str().unwrap_or("restore completed");
    println!("{message}");
    if let Some(new_id) = data["new_version_id"].as_u64() {
        println!("new_version_id: {new_id}");
    }
    Ok(())
}

fn urlencoding(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u8),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlencoding_encodes_slashes() {
        assert_eq!(urlencoding("notes/a.md"), "notes%2Fa.md");
    }

    #[test]
    fn api_base_prefers_flag() {
        assert_eq!(
            api_base(Some("https://disk.example")),
            "https://disk.example"
        );
    }
}
