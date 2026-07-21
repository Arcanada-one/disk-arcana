//! `disk selective-sync` — per-device folder subset rules (DISK-0023).

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

async fn api_put(api: &str, token: &str, path: &str, json_body: Value) -> Result<Value> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()?;
    let url = format!("{api}{path}");
    let resp = client
        .put(&url)
        .bearer_auth(token)
        .json(&json_body)
        .send()
        .await
        .with_context(|| format!("PUT {url}"))?;
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        let msg = body
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("request failed");
        anyhow::bail!("PUT {path} HTTP {status}: {msg}");
    }
    Ok(body)
}

fn urlencoding(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u8),
        })
        .collect()
}

/// `disk selective-sync list --vault default --node macbook`.
pub async fn run_list(
    api: Option<&str>,
    token: Option<&str>,
    vault: &str,
    node: &str,
) -> Result<()> {
    let base = api_base(api);
    let token = bearer_token(token)?;
    let path = format!(
        "/selective-sync?vault_id={}&node_id={}",
        urlencoding(vault),
        urlencoding(node)
    );
    let data = api_get(&base, &token, &path).await?;
    if data["sync_all"].as_bool().unwrap_or(false) {
        println!("node {node} vault {vault}: sync all folders (no filter)");
        return Ok(());
    }
    for prefix in data["includes"].as_array().cloned().unwrap_or_default() {
        println!("{}", prefix.as_str().unwrap_or("?"));
    }
    Ok(())
}

/// `disk selective-sync set --vault default --node macbook --include docs,photos`.
pub async fn run_set(
    api: Option<&str>,
    token: Option<&str>,
    vault: &str,
    node: &str,
    includes: &[String],
) -> Result<()> {
    let base = api_base(api);
    let token = bearer_token(token)?;
    let data = api_put(
        &base,
        &token,
        "/selective-sync",
        serde_json::json!({
            "vault_id": vault,
            "node_id": node,
            "includes": includes,
        }),
    )
    .await?;
    if data["sync_all"].as_bool().unwrap_or(false) {
        println!("cleared selective sync for node {node} vault {vault} (sync all)");
    } else {
        println!(
            "set {} include prefix(es) for node {node} vault {vault}",
            data["includes"].as_array().map(|a| a.len()).unwrap_or(0)
        );
    }
    Ok(())
}
