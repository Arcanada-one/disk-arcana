//! `disk sharing` — vault invite links and collaborator RBAC (DISK-0022).

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

fn urlencoding(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u8),
        })
        .collect()
}

/// `disk sharing invites create --vault wiki --role viewer`.
pub async fn run_invite_create(
    api: Option<&str>,
    token: Option<&str>,
    vault: &str,
    role: &str,
    ttl_hours: u32,
) -> Result<()> {
    let base = api_base(api);
    let token = bearer_token(token)?;
    let data = api_post(
        &base,
        &token,
        "/sharing/invites",
        serde_json::json!({ "vault_id": vault, "role": role, "ttl_hours": ttl_hours }),
    )
    .await?;
    println!("invite_id: {}", data["invite_id"].as_str().unwrap_or("?"));
    println!(
        "invite_token: {}",
        data["invite_token"].as_str().unwrap_or("?")
    );
    if let Some(url) = data["invite_url"].as_str() {
        println!("invite_url: {url}");
    }
    Ok(())
}

/// `disk sharing invites list --vault wiki`.
pub async fn run_invite_list(api: Option<&str>, token: Option<&str>, vault: &str) -> Result<()> {
    let base = api_base(api);
    let token = bearer_token(token)?;
    let path = format!("/sharing/invites?vault_id={}", urlencoding(vault));
    let data = api_get(&base, &token, &path).await?;
    let rows = data["invites"].as_array().cloned().unwrap_or_default();
    if rows.is_empty() {
        println!("no pending invites for vault {vault}");
        return Ok(());
    }
    for row in rows {
        println!(
            "{}  role={}  expires={}  redeemed={}",
            row["invite_id"].as_str().unwrap_or("?"),
            row["role"].as_str().unwrap_or("?"),
            row["expires_at"].as_i64().unwrap_or(0),
            row["redeemed"].as_bool().unwrap_or(false),
        );
    }
    Ok(())
}

/// `disk sharing invites accept --token <hex>`.
pub async fn run_invite_accept(
    api: Option<&str>,
    token: Option<&str>,
    invite_token: &str,
) -> Result<()> {
    let base = api_base(api);
    let token = bearer_token(token)?;
    let data = api_post(
        &base,
        &token,
        "/sharing/invites/accept",
        serde_json::json!({ "token": invite_token }),
    )
    .await?;
    println!("{}", data["message"].as_str().unwrap_or("invite accepted"));
    Ok(())
}

/// `disk sharing members list --vault wiki`.
pub async fn run_members_list(api: Option<&str>, token: Option<&str>, vault: &str) -> Result<()> {
    let base = api_base(api);
    let token = bearer_token(token)?;
    let path = format!("/sharing/members?vault_id={}", urlencoding(vault));
    let data = api_get(&base, &token, &path).await?;
    let rows = data["members"].as_array().cloned().unwrap_or_default();
    if rows.is_empty() {
        println!("no external collaborators for vault {vault}");
        return Ok(());
    }
    for row in rows {
        println!(
            "{}  {}  role={}",
            row["user_id"].as_str().unwrap_or("?"),
            row["email"].as_str().unwrap_or("?"),
            row["role"].as_str().unwrap_or("?"),
        );
    }
    Ok(())
}

/// `disk sharing members remove --vault wiki --user <id>`.
pub async fn run_member_remove(
    api: Option<&str>,
    token: Option<&str>,
    vault: &str,
    user_id: &str,
) -> Result<()> {
    let base = api_base(api);
    let token = bearer_token(token)?;
    api_post(
        &base,
        &token,
        "/sharing/members/remove",
        serde_json::json!({ "vault_id": vault, "user_id": user_id }),
    )
    .await?;
    println!("removed {user_id} from vault {vault}");
    Ok(())
}
