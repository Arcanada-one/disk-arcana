//! C04 test-only access to the actual private telemetry reader.
use super::TelemetryRuntimeConfig;
use crate::config_env_probe as env_probe;
use serde_json::json;

#[test]
fn config_probe_child() {
    let Some(expected) = env_probe::expected() else {
        return;
    };
    let c = TelemetryRuntimeConfig::from_env();
    env_probe::check(
        json!({"enabled":c.enabled, "project_key":c.project_key, "api_host":c.api_host}),
        expected,
    );
}

#[test]
fn c04_telemetry_fresh_environment_matrix() {
    env_probe::run(
        "telemetry::config::env_canary::config_probe_child",
        include_str!("../../tests/fixtures/telemetry-environment.json"),
    );
}
