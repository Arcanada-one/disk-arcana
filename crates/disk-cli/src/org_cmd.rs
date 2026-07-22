//! `disk org` — team workspace CLI + local `x-disk-tenant` sync (DISK-0030 slice 3).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};

use crate::commands;
use crate::config_tenant::set_node_tenant_id;
use crate::paths;

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

fn config_path(override_path: Option<&Path>) -> PathBuf {
    override_path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(paths::DEFAULT_CONFIG))
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

async fn resolve_org_id(api: &str, token: &str, org_ref: &str) -> Result<String> {
    let data = api_get(api, token, "/orgs").await?;
    let rows = data["orgs"].as_array().cloned().unwrap_or_default();
    for row in rows {
        if row["org_id"].as_str() == Some(org_ref) || row["slug"].as_str() == Some(org_ref) {
            return row["org_id"]
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| anyhow!("org list entry missing org_id"));
        }
    }
    Err(anyhow!("organization not found: {org_ref}"))
}

pub async fn apply_local_tenant_sync(
    cfg_path: &Path,
    tenant_id: &str,
    reload_daemon: bool,
    daemon_addr: Option<SocketAddr>,
) -> Result<()> {
    set_node_tenant_id(cfg_path, tenant_id)?;
    println!("disk.toml tenant_id -> {tenant_id}");
    if reload_daemon {
        commands::run_config_reload(daemon_addr).await?;
        println!("daemon config reload queued (x-disk-tenant picks up on next sync cycle)");
    }
    Ok(())
}

/// `disk org list`.
pub async fn run_list(api: Option<&str>, token: Option<&str>) -> Result<()> {
    let base = api_base(api);
    let token = bearer_token(token)?;
    let data = api_get(&base, &token, "/orgs").await?;
    let rows = data["orgs"].as_array().cloned().unwrap_or_default();
    if rows.is_empty() {
        println!("no organizations");
        return Ok(());
    }
    for row in rows {
        println!(
            "{}  slug={}  tenant={}  role={}  name={}",
            row["org_id"].as_str().unwrap_or("?"),
            row["slug"].as_str().unwrap_or("?"),
            row["tenant_id"].as_str().unwrap_or("?"),
            row["role"].as_str().unwrap_or("?"),
            row["name"].as_str().unwrap_or("?"),
        );
    }
    Ok(())
}

/// `disk org create --name --slug`.
pub async fn run_create(
    api: Option<&str>,
    token: Option<&str>,
    name: &str,
    slug: &str,
) -> Result<()> {
    let base = api_base(api);
    let token = bearer_token(token)?;
    let data = api_post(
        &base,
        &token,
        "/orgs",
        json!({ "name": name, "slug": slug }),
    )
    .await?;
    println!("org_id: {}", data["org_id"].as_str().unwrap_or("?"));
    println!("tenant_id: {}", data["tenant_id"].as_str().unwrap_or("?"));
    Ok(())
}

/// `disk org context`.
pub async fn run_context(api: Option<&str>, token: Option<&str>) -> Result<()> {
    let base = api_base(api);
    let token = bearer_token(token)?;
    let data = api_get(&base, &token, "/orgs/context").await?;
    println!("mode: {}", data["mode"].as_str().unwrap_or("?"));
    println!(
        "active_tenant_id: {}",
        data["active_tenant_id"].as_str().unwrap_or("?")
    );
    println!(
        "personal_tenant_id: {}",
        data["personal_tenant_id"].as_str().unwrap_or("?")
    );
    if let Some(org) = data.get("organization").filter(|v| !v.is_null()) {
        println!(
            "organization: {} ({}) role={}",
            org["name"].as_str().unwrap_or("?"),
            org["slug"].as_str().unwrap_or("?"),
            org["role"].as_str().unwrap_or("?"),
        );
    }
    Ok(())
}

/// `disk org switch --personal | --org <id|slug>`.
pub async fn run_switch(
    api: Option<&str>,
    token: Option<&str>,
    personal: bool,
    org_ref: Option<&str>,
    config: Option<&Path>,
    reload_daemon: bool,
    daemon_addr: Option<SocketAddr>,
) -> Result<()> {
    if personal == org_ref.is_some() {
        return Err(anyhow!("specify exactly one of --personal or --org"));
    }

    let base = api_base(api);
    let token = bearer_token(token)?;
    let org_id = if personal {
        None
    } else {
        let reference = org_ref.expect("org ref checked above");
        Some(resolve_org_id(&base, &token, reference).await?)
    };

    let data = api_put(&base, &token, "/orgs/context", json!({ "org_id": org_id })).await?;

    let tenant = data["active_tenant_id"]
        .as_str()
        .context("server response missing active_tenant_id")?;
    println!(
        "workspace: {} (tenant_id={tenant})",
        data["mode"].as_str().unwrap_or("?")
    );

    apply_local_tenant_sync(&config_path(config), tenant, reload_daemon, daemon_addr).await
}

/// `disk org sync` — mirror server active tenant into disk.toml (+ optional reload).
pub async fn run_sync(
    api: Option<&str>,
    token: Option<&str>,
    config: Option<&Path>,
    reload_daemon: bool,
    daemon_addr: Option<SocketAddr>,
) -> Result<()> {
    let base = api_base(api);
    let token = bearer_token(token)?;
    let data = api_get(&base, &token, "/orgs/context").await?;
    let tenant = data["active_tenant_id"]
        .as_str()
        .context("server response missing active_tenant_id")?;
    apply_local_tenant_sync(&config_path(config), tenant, reload_daemon, daemon_addr).await
}

/// `disk org members list --org`.
pub async fn run_members_list(api: Option<&str>, token: Option<&str>, org_ref: &str) -> Result<()> {
    let base = api_base(api);
    let token = bearer_token(token)?;
    let org_id = resolve_org_id(&base, &token, org_ref).await?;
    let path = format!("/orgs/members?org_id={}", urlencoding(&org_id));
    let data = api_get(&base, &token, &path).await?;
    let rows = data["members"].as_array().cloned().unwrap_or_default();
    if rows.is_empty() {
        println!("no members for org {org_id}");
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

/// `disk org members add --org --email --role`.
pub async fn run_members_add(
    api: Option<&str>,
    token: Option<&str>,
    org_ref: &str,
    email: &str,
    role: &str,
) -> Result<()> {
    let base = api_base(api);
    let token = bearer_token(token)?;
    let org_id = resolve_org_id(&base, &token, org_ref).await?;
    let data = api_post(
        &base,
        &token,
        "/orgs/members",
        json!({ "org_id": org_id, "email": email, "role": role }),
    )
    .await?;
    println!(
        "added {} as {} to {}",
        data["email"].as_str().unwrap_or(email),
        data["role"].as_str().unwrap_or(role),
        data["org_id"].as_str().unwrap_or(&org_id),
    );
    Ok(())
}
