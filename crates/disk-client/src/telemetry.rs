//! Anonymous product analytics for the CLI daemon (DISK-0026 slice 2).
//!
//! Events are sent to PostHog only when `[telemetry] opt_in = true` in
//! `disk.toml` **and** the server exposes a project key via
//! `GET /telemetry/config`. Fail-soft: telemetry never blocks sync.

use std::path::Path;
use std::sync::Arc;

use crate::config::TelemetrySection;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::RwLock;
use tracing::debug;

const INSTALL_ID_FILE: &str = ".telemetry-install-id";
const DEFAULT_HEALTH_PORT: u16 = 9446;

#[derive(Debug, Clone, Deserialize)]
struct TelemetryConfigResponse {
    enabled: bool,
    project_key: Option<String>,
    api_host: String,
}

/// Fire-and-forget PostHog client for the daemon.
#[derive(Clone)]
pub struct ClientTelemetry {
    http: reqwest::Client,
    health_base: String,
    install_id: String,
    node_id: String,
    runtime: Arc<RwLock<Option<RuntimeConfig>>>,
}

#[derive(Debug, Clone)]
struct RuntimeConfig {
    project_key: String,
    api_host: String,
}

impl ClientTelemetry {
    /// Open a telemetry handle when `section.opt_in` is true.
    pub fn open(
        state_dir: &Path,
        section: &TelemetrySection,
        server_address: &str,
        node_id: &str,
    ) -> Option<Arc<Self>> {
        if !section.opt_in {
            return None;
        }
        let install_id = load_or_create_install_id(state_dir).ok()?;
        let health_base = section
            .health_base_url
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| default_health_base(server_address));
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .ok()?;
        Some(Arc::new(Self {
            http,
            health_base,
            install_id,
            node_id: node_id.to_string(),
            runtime: Arc::new(RwLock::new(None)),
        }))
    }

    /// Queue an analytics event (non-blocking).
    pub fn capture(&self, event: &str, mut properties: Value) {
        let event = event.to_string();
        let client = self.clone();
        tokio::spawn(async move {
            if let Err(e) = client.capture_inner(&event, &mut properties).await {
                debug!(error = %e, event = %event, "telemetry: capture failed (ignored)");
            }
        });
    }

    async fn capture_inner(&self, event: &str, properties: &mut Value) -> Result<(), String> {
        let runtime = self.ensure_runtime().await?;
        let capture_url = format!("{}/capture/", runtime.api_host.trim_end_matches('/'));
        let props = match properties {
            Value::Object(map) => map,
            _ => &mut serde_json::Map::new(),
        };
        props.insert("distinct_id".into(), json!(self.install_id));
        props.insert("node_id".into(), json!(self.node_id));
        props.insert("$lib".into(), json!("disk-client"));
        let body = json!({
            "api_key": runtime.project_key,
            "event": event,
            "properties": Value::Object(props.clone()),
        });
        self.http
            .post(capture_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| e.to_string())?
            .error_for_status()
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    async fn ensure_runtime(&self) -> Result<RuntimeConfig, String> {
        if let Some(cfg) = self.runtime.read().await.clone() {
            return Ok(cfg);
        }
        let url = format!(
            "{}/telemetry/config",
            self.health_base.trim_end_matches('/')
        );
        let resp: TelemetryConfigResponse = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| e.to_string())?
            .error_for_status()
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())?;
        if !resp.enabled {
            return Err("server telemetry disabled".into());
        }
        let project_key = resp
            .project_key
            .filter(|k| !k.trim().is_empty())
            .ok_or_else(|| "server telemetry missing project_key".to_string())?;
        let cfg = RuntimeConfig {
            project_key,
            api_host: resp.api_host,
        };
        *self.runtime.write().await = Some(cfg.clone());
        Ok(cfg)
    }
}

/// Derive `http://{host}:9446` from a gRPC `host:port` address.
pub fn default_health_base(server_address: &str) -> String {
    let host = if let Some((h, _port)) = server_address.rsplit_once(':') {
        if h.starts_with('[') {
            h.to_string()
        } else if server_address.matches(':').count() > 1 {
            format!("[{h}]")
        } else {
            h.to_string()
        }
    } else {
        server_address.to_string()
    };
    format!("http://{host}:{DEFAULT_HEALTH_PORT}")
}

fn load_or_create_install_id(state_dir: &Path) -> std::io::Result<String> {
    let path = state_dir.join(INSTALL_ID_FILE);
    if path.is_file() {
        let id = std::fs::read_to_string(&path)?;
        let trimmed = id.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }
    std::fs::create_dir_all(state_dir)?;
    let id = hex::encode(rand::random::<[u8; 16]>());
    std::fs::write(&path, format!("{id}\n"))?;
    Ok(id)
}

/// Map sync-loop state to a coarse outcome label (no paths).
pub fn sync_outcome_label(state: crate::sync_loop::LoopState, had_error: bool) -> &'static str {
    use crate::sync_loop::LoopState;
    match state {
        LoopState::Idle if !had_error => "idle",
        LoopState::Backoff | LoopState::ServerUnreachable => "backoff",
        LoopState::AclMismatch => "acl_mismatch",
        LoopState::Error => "error",
        _ if had_error => "error",
        _ => "ok",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TelemetrySection;
    use tempfile::tempdir;

    #[test]
    fn default_health_base_strips_port() {
        assert_eq!(
            default_health_base("disk.arcanada.ai:9443"),
            "http://disk.arcanada.ai:9446"
        );
        assert_eq!(default_health_base("[::1]:9443"), "http://[::1]:9446");
    }

    #[test]
    fn install_id_persists() {
        let dir = tempdir().unwrap();
        let id1 = load_or_create_install_id(dir.path()).unwrap();
        let id2 = load_or_create_install_id(dir.path()).unwrap();
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 32);
    }

    #[test]
    fn telemetry_disabled_when_opt_out() {
        let dir = tempdir().unwrap();
        let section = TelemetrySection {
            opt_in: false,
            ..Default::default()
        };
        assert!(ClientTelemetry::open(dir.path(), &section, "host:9443", "node-a").is_none());
    }
}
