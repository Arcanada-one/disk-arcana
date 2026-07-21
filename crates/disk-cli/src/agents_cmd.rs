//! `disk agents` — webhooks, revision lookup, and optimistic writes (DISK-0028 slice 3).

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use base64::Engine;
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

async fn api_delete_json(api: &str, token: &str, path: &str, json_body: Value) -> Result<Value> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;
    let url = format!("{api}{path}");
    let resp = client
        .delete(&url)
        .bearer_auth(token)
        .json(&json_body)
        .send()
        .await
        .with_context(|| format!("DELETE {url}"))?;
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        let msg = body
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("request failed");
        anyhow::bail!("DELETE {path} HTTP {status}: {msg}");
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

/// `disk agents webhooks list --vault default`.
pub async fn run_webhooks_list(api: Option<&str>, token: Option<&str>, vault: &str) -> Result<()> {
    let base = api_base(api);
    let token = bearer_token(token)?;
    let path = format!("/agents/webhooks?vault_id={}", urlencoding(vault));
    let data = api_get(&base, &token, &path).await?;
    let rows = data["webhooks"].as_array().cloned().unwrap_or_default();
    if rows.is_empty() {
        println!("no webhooks registered for vault {vault}");
        return Ok(());
    }
    println!("vault: {vault}");
    for row in rows {
        let events = row["events"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default();
        let label = row["label"].as_str().unwrap_or("—");
        println!(
            "{}  enabled={}  events=[{events}]  label={label}  url={}",
            row["webhook_id"].as_str().unwrap_or("?"),
            row["enabled"].as_bool().unwrap_or(false),
            row["url"].as_str().unwrap_or("?"),
        );
    }
    Ok(())
}

/// `disk agents webhooks register --url <https://...> --events <csv>`.
pub async fn run_webhooks_register(
    api: Option<&str>,
    token: Option<&str>,
    vault: &str,
    url: &str,
    events: &[String],
    label: Option<&str>,
) -> Result<()> {
    if events.is_empty() {
        anyhow::bail!(
            "--events required (comma-separated, e.g. agent.write_ok,agent.write_conflict)"
        );
    }
    let base = api_base(api);
    let token = bearer_token(token)?;
    let mut body = serde_json::json!({
        "vault_id": vault,
        "url": url,
        "events": events,
    });
    if let Some(l) = label.filter(|s| !s.is_empty()) {
        body["label"] = Value::String(l.to_string());
    }
    let data = api_post(&base, &token, "/agents/webhooks", body).await?;
    println!("webhook_id: {}", data["webhook_id"].as_str().unwrap_or("?"));
    println!(
        "webhook_secret: {}",
        data["webhook_secret"].as_str().unwrap_or("?")
    );
    println!("(store webhook_secret securely — shown once)");
    Ok(())
}

/// `disk agents webhooks delete --webhook-id <id>`.
pub async fn run_webhooks_delete(
    api: Option<&str>,
    token: Option<&str>,
    webhook_id: &str,
) -> Result<()> {
    let base = api_base(api);
    let token = bearer_token(token)?;
    let data = api_delete_json(
        &base,
        &token,
        "/agents/webhooks",
        serde_json::json!({ "webhook_id": webhook_id }),
    )
    .await?;
    if data["deleted"].as_bool().unwrap_or(false) {
        println!("deleted webhook {webhook_id}");
    } else {
        println!("webhook {webhook_id} not found");
    }
    Ok(())
}

/// `disk agents revision --path <path> [--vault default]`.
pub async fn run_revision(
    api: Option<&str>,
    token: Option<&str>,
    path: &str,
    vault: &str,
) -> Result<()> {
    let base = api_base(api);
    let token = bearer_token(token)?;
    let qs = format!(
        "/agents/revision?path={}&vault_id={}",
        urlencoding(path),
        urlencoding(vault)
    );
    let data = api_get(&base, &token, &qs).await?;
    println!(
        "path: {}  vault: {}  revision: {}  exists: {}",
        data["path"].as_str().unwrap_or(path),
        data["vault_id"].as_str().unwrap_or(vault),
        data["revision"].as_u64().unwrap_or(0),
        data["exists"].as_bool().unwrap_or(false),
    );
    if let Some(hash) = data["content_hash_hex"].as_str() {
        println!("content_hash_hex: {hash}");
    }
    Ok(())
}

/// Inputs for `disk agents write`.
pub struct AgentsWriteParams<'a> {
    pub path: &'a str,
    pub vault: &'a str,
    pub file: Option<&'a Path>,
    pub content_base64: Option<&'a str>,
    pub if_match_revision: Option<u64>,
    pub agent_id: Option<&'a str>,
}

/// `disk agents write --path <path> [--file <path>|--content-base64 <b64>]`.
pub async fn run_write(
    api: Option<&str>,
    token: Option<&str>,
    params: AgentsWriteParams<'_>,
) -> Result<()> {
    let AgentsWriteParams {
        path,
        vault,
        file,
        content_base64,
        if_match_revision,
        agent_id,
    } = params;
    let encoded = match (file, content_base64) {
        (Some(f), None) => {
            let bytes = std::fs::read(f).with_context(|| format!("read file {}", f.display()))?;
            base64::engine::general_purpose::STANDARD.encode(bytes)
        }
        (None, Some(b64)) => b64.to_string(),
        (Some(_), Some(_)) => {
            anyhow::bail!("use only one of --file or --content-base64");
        }
        (None, None) => {
            anyhow::bail!("provide --file or --content-base64");
        }
    };

    let base = api_base(api);
    let token = bearer_token(token)?;
    let mut body = serde_json::json!({
        "path": path,
        "vault_id": vault,
        "content_base64": encoded,
    });
    if let Some(rev) = if_match_revision {
        body["if_match_revision"] = Value::from(rev);
    }
    if let Some(id) = agent_id.filter(|s| !s.is_empty()) {
        body["agent_id"] = Value::String(id.to_string());
    }

    let data = api_post(&base, &token, "/agents/write", body).await?;
    println!(
        "write ok: path={} revision={} size={} hash={}",
        data["path"].as_str().unwrap_or(path),
        data["revision"].as_u64().unwrap_or(0),
        data["size"].as_u64().unwrap_or(0),
        data["content_hash_hex"].as_str().unwrap_or("?"),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlencoding_encodes_slashes() {
        assert_eq!(urlencoding("notes/a.md"), "notes%2Fa.md");
    }
}
