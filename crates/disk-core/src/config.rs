use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::ConfigError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub sync: SyncConfig,
    pub server: ServerConfig,
    #[serde(default)]
    pub filter: FilterConfig,
    #[serde(default)]
    pub ignore: IgnoreConfig,
    #[serde(default)]
    pub conflict: ConflictConfig,
    #[serde(default)]
    pub archive: ArchiveConfig,
    #[serde(default)]
    pub daemon: DaemonConfig,
    #[serde(default)]
    pub tombstone: TombstoneConfig,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConfig {
    pub vault_path: PathBuf,
    pub interval_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub url: String,
    pub api_key: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FilterConfig {
    #[serde(default)]
    pub max_file_size_mb: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IgnoreConfig {
    #[serde(default)]
    pub patterns: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConflictConfig {
    #[serde(default)]
    pub strategy: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ArchiveConfig {
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DaemonConfig {
    #[serde(default)]
    pub log_level: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TombstoneConfig {
    #[serde(default)]
    pub ttl_days: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TelemetryConfig {
    #[serde(default)]
    pub opt_in: bool,
}

impl Config {
    pub fn parse_toml(input: &str) -> Result<Self, ConfigError> {
        let cfg: Config = toml::from_str(input)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn load(path: &std::path::Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)?;
        Self::parse_toml(&text)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.sync.interval_secs == 0 {
            return Err(ConfigError::Validation(
                "sync.interval_secs must be > 0".into(),
            ));
        }
        if self.server.url.is_empty() {
            return Err(ConfigError::Validation("server.url must be set".into()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[sync]
vault_path = "/home/user/vault"
interval_secs = 30

[server]
url = "https://disk.example.com"
api_key = "secret"
"#;

    #[test]
    fn parses_minimal_config() {
        let cfg = Config::parse_toml(SAMPLE).expect("parse");
        assert_eq!(cfg.sync.interval_secs, 30);
        assert_eq!(cfg.server.url, "https://disk.example.com");
    }

    #[test]
    fn rejects_invalid_toml() {
        let err = Config::parse_toml("not = = toml").unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)));
    }

    #[test]
    fn rejects_zero_interval() {
        let bad = r#"
[sync]
vault_path = "/x"
interval_secs = 0

[server]
url = "https://x"
api_key = "k"
"#;
        let err = Config::parse_toml(bad).unwrap_err();
        assert!(matches!(err, ConfigError::Validation(_)));
    }
}
