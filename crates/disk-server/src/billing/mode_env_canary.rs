//! C04 test-only access to the actual private billing env reader.
use super::default_plan_tier_from_env;
use crate::config::ConfigError;
use crate::config_env_probe as env_probe;
use serde_json::json;

#[test]
fn config_probe_child() {
    let Some(expected) = env_probe::expected() else {
        return;
    };
    let actual = match default_plan_tier_from_env() {
        Ok(tier) => json!({"tier":format!("{tier:?}")}),
        Err(ConfigError::InvalidValue(key, _)) => json!({"error_key":key}),
        Err(_) => panic!("unexpected synthetic config error"),
    };
    env_probe::check(actual, expected);
}

#[test]
fn c04_billing_fresh_environment_matrix() {
    env_probe::run(
        "billing::mode::env_canary::config_probe_child",
        include_str!("../../tests/fixtures/billing-environment.json"),
    );
}
