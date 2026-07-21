//! `disk snapshots` — point-in-time vault snapshots via health HTTP API (DISK-0020 slice 4).

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
        .timeout(Duration::from_secs(60))
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
        .timeout(Duration::from_secs(120))
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

fn urlencoding(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u8),
        })
        .collect()
}

/// `disk snapshots create [--vault default] [--label ...]`.
pub async fn run_snapshots_create(
    api: Option<&str>,
    token: Option<&str>,
    vault: &str,
    label: Option<&str>,
) -> Result<()> {
    let base = api_base(api);
    let token = bearer_token(token)?;
    let mut body = serde_json::json!({ "vault_id": vault });
    if let Some(l) = label.filter(|s| !s.is_empty()) {
        body["label"] = serde_json::Value::String(l.to_string());
    }
    let data = api_post(&base, &token, "/snapshots", body).await?;
    let snap = &data["snapshot"];
    println!(
        "created snapshot id={} vault={} files={} bytes={}",
        snap["id"].as_u64().unwrap_or(0),
        snap["vault_id"].as_str().unwrap_or(vault),
        snap["file_count"].as_u64().unwrap_or(0),
        format_bytes(snap["bytes_total"].as_u64().unwrap_or(0)),
    );
    if let Some(l) = snap["label"].as_str() {
        println!("label: {l}");
    }
    Ok(())
}

/// `disk snapshots list [--vault default]`.
pub async fn run_snapshots_list(
    api: Option<&str>,
    token: Option<&str>,
    vault: &str,
    limit: u32,
    offset: u32,
) -> Result<()> {
    let base = api_base(api);
    let token = bearer_token(token)?;
    let path = format!(
        "/snapshots?vault_id={}&limit={}&offset={}",
        urlencoding(vault),
        limit,
        offset
    );
    let data = api_get(&base, &token, &path).await?;
    let rows = data["snapshots"].as_array().cloned().unwrap_or_default();
    if rows.is_empty() {
        println!("no snapshots for vault {vault}");
        return Ok(());
    }
    println!(
        "{:<6}  {:<12}  {:>6}  {:>10}  label",
        "id", "created", "files", "size"
    );
    println!("{}", "-".repeat(64));
    for row in rows {
        println!(
            "{:<6}  {:<12}  {:>6}  {:>10}  {}",
            row["id"].as_u64().unwrap_or(0),
            row["created_at"].as_i64().unwrap_or(0),
            row["file_count"].as_u64().unwrap_or(0),
            format_bytes(row["bytes_total"].as_u64().unwrap_or(0)),
            row["label"].as_str().unwrap_or("—"),
        );
    }
    Ok(())
}

/// `disk snapshots show --id <n> [--vault default]`.
pub async fn run_snapshots_show(
    api: Option<&str>,
    token: Option<&str>,
    vault: &str,
    snapshot_id: u64,
) -> Result<()> {
    let base = api_base(api);
    let token = bearer_token(token)?;
    let path = format!("/snapshots/{snapshot_id}?vault_id={}", urlencoding(vault));
    let data = api_get(&base, &token, &path).await?;
    let snap = &data["snapshot"];
    println!(
        "snapshot {} vault={} files={} bytes={} created={}",
        snap["id"].as_u64().unwrap_or(snapshot_id),
        snap["vault_id"].as_str().unwrap_or(vault),
        snap["file_count"].as_u64().unwrap_or(0),
        format_bytes(snap["bytes_total"].as_u64().unwrap_or(0)),
        snap["created_at"].as_i64().unwrap_or(0),
    );
    if let Some(files) = data["files"].as_array() {
        println!("{:<40}  {:>6}  deleted  blob", "path", "size");
        for f in files {
            println!(
                "{:<40}  {:>6}  {:>7}  {}",
                f["path"].as_str().unwrap_or("?"),
                f["size"].as_u64().unwrap_or(0),
                f["deleted"].as_bool().unwrap_or(false),
                f["blob_available"].as_bool().unwrap_or(false),
            );
        }
    }
    Ok(())
}

/// `disk snapshots restore --id <n> [--vault default]`.
pub async fn run_snapshots_restore(
    api: Option<&str>,
    token: Option<&str>,
    vault: &str,
    snapshot_id: u64,
) -> Result<()> {
    let base = api_base(api);
    let token = bearer_token(token)?;
    let path = format!("/snapshots/{snapshot_id}/restore");
    let data = api_post(
        &base,
        &token,
        &path,
        serde_json::json!({ "vault_id": vault }),
    )
    .await?;
    println!(
        "{}",
        data["message"]
            .as_str()
            .unwrap_or("vault snapshot restore completed")
    );
    Ok(())
}
