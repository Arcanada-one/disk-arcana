//! `disk trash` — list/restore soft-deleted files via health HTTP API (DISK-0024).

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
        .timeout(Duration::from_secs(60))
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

/// `disk trash list [--vault default]`.
pub async fn run_trash_list(
    api: Option<&str>,
    token: Option<&str>,
    vault: &str,
    limit: u32,
    offset: u32,
) -> Result<()> {
    let base = api_base(api);
    let token = bearer_token(token)?;
    let path = format!(
        "/trash?vault_id={}&limit={}&offset={}",
        urlencoding(vault),
        limit,
        offset
    );
    let data = api_get(&base, &token, &path).await?;
    if data["pruned_expired"].as_u64().unwrap_or(0) > 0 {
        println!(
            "pruned {} expired item(s) (plan: {})",
            data["pruned_expired"].as_u64().unwrap_or(0),
            data["plan_tier"].as_str().unwrap_or("?"),
        );
    }
    let rows = data["items"].as_array().cloned().unwrap_or_default();
    if rows.is_empty() {
        println!("trash empty for vault {vault}");
        return Ok(());
    }
    println!("{:<36}  {:>10}  {:>12}  blob", "path", "size", "deleted_at");
    println!("{}", "-".repeat(72));
    for row in rows {
        println!(
            "{:<36}  {:>10}  {:>12}  {}",
            row["path"].as_str().unwrap_or("?"),
            format_bytes(row["size"].as_u64().unwrap_or(0)),
            row["deleted_at"].as_i64().unwrap_or(0),
            row["blob_available"].as_bool().unwrap_or(false),
        );
    }
    Ok(())
}

/// `disk trash restore --path <rel> [--vault default]`.
pub async fn run_trash_restore(
    api: Option<&str>,
    token: Option<&str>,
    vault: &str,
    path: &str,
) -> Result<()> {
    let base = api_base(api);
    let token = bearer_token(token)?;
    let data = api_post(
        &base,
        &token,
        "/trash/restore",
        serde_json::json!({ "vault_id": vault, "path": path }),
    )
    .await?;
    println!(
        "{}",
        data["message"].as_str().unwrap_or("restored from trash")
    );
    Ok(())
}

/// `disk trash delete --path <rel> [--vault default]`.
pub async fn run_trash_delete(
    api: Option<&str>,
    token: Option<&str>,
    vault: &str,
    path: &str,
) -> Result<()> {
    let base = api_base(api);
    let token = bearer_token(token)?;
    let data = api_post(
        &base,
        &token,
        "/trash/delete",
        serde_json::json!({ "vault_id": vault, "path": path }),
    )
    .await?;
    println!(
        "{}",
        data["message"].as_str().unwrap_or("deleted from trash")
    );
    Ok(())
}

/// `disk trash empty [--vault default]`.
pub async fn run_trash_empty(
    api: Option<&str>,
    token: Option<&str>,
    vault: &str,
    confirm: bool,
) -> Result<()> {
    if !confirm {
        anyhow::bail!("pass --yes to permanently empty the recycle bin");
    }
    let base = api_base(api);
    let token = bearer_token(token)?;
    let data = api_post(
        &base,
        &token,
        "/trash/empty",
        serde_json::json!({ "vault_id": vault, "confirm": true }),
    )
    .await?;
    println!("{}", data["message"].as_str().unwrap_or("trash emptied"));
    Ok(())
}
