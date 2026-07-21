//! PostHog runtime configuration from environment (DISK-0026 slice 1).

/// Default PostHog ingest host (EU region for GDPR-friendly deployment).
pub const DEFAULT_POSTHOG_API_HOST: &str = "https://eu.i.posthog.com";

/// Resolved server-side analytics configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetryRuntimeConfig {
    pub enabled: bool,
    pub project_key: Option<String>,
    pub api_host: String,
}

impl TelemetryRuntimeConfig {
    /// Load from `DISK_POSTHOG_PROJECT_KEY` and optional `DISK_POSTHOG_API_HOST`.
    pub fn from_env() -> Self {
        let project_key = std::env::var("DISK_POSTHOG_PROJECT_KEY")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let api_host = std::env::var("DISK_POSTHOG_API_HOST")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| DEFAULT_POSTHOG_API_HOST.to_string());

        Self {
            enabled: project_key.is_some(),
            project_key,
            api_host,
        }
    }
}
