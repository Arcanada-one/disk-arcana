//! C01: actual ServerConfig reader only. No listener, database or token use.
#![cfg(target_os = "linux")]
#[path = "../../../test-support/env_probe.rs"]
mod env_probe;
use disk_server::{ConfigError, ServerConfig};
use serde_json::{json, Value};

fn projection(c: ServerConfig) -> Value {
    let mut result = json!({
        "bind_addr": c.bind_addr.to_string(), "health_bind_addr": c.health_bind_addr.to_string(),
        "enrollment_bind_addr": c.enrollment_bind_addr.to_string(),
        "db_path": c.db_path, "sync_root": c.sync_root, "share_roots": c.share_roots,
        "tls_cert_path": c.tls_cert_path, "tls_key_path": c.tls_key_path,
        "tls_ca_path": c.tls_ca_path, "acl_yaml_path": c.acl_yaml_path,
        "acl_sig_path": c.acl_sig_path, "acl_gnupghome": c.acl_gnupghome,
        "tenant_db_dir": c.tenant_db_dir, "ops_bot_url": c.ops_bot_url,
        "admin_token": c.admin_token, "ca_mode": format!("{:?}", c.ca_mode),
        "use_stub_ca": c.use_stub_ca, "acl_allow_unsigned": c.acl_allow_unsigned,
        "register_node_mode": format!("{:?}", c.register_node_mode),
        "billing_mode": format!("{:?}", c.billing_mode), "stripe_webhook_secret": c.stripe_webhook_secret,
    });
    let auth = json!({
        "auth_mode": format!("{:?}", c.auth_mode), "jwt_signing_key": c.jwt_signing_key,
        "jwt_ttl_secs": c.jwt_ttl_secs, "jwt_mode": format!("{:?}", c.jwt_mode),
        "jwt_issuer": c.jwt_issuer, "jwt_jwks_uri": c.jwt_jwks_uri,
        "oauth_mode": format!("{:?}", c.oauth_mode), "oauth_issuer": c.oauth_issuer,
        "oauth_client_id": c.oauth_client_id, "oauth_client_secret": c.oauth_client_secret,
        "oauth_redirect_uri": c.oauth_redirect_uri, "oauth_public_base_url": c.oauth_public_base_url,
        "email_verify_mode": format!("{:?}", c.email_verify_mode),
        "email_verify_base_url": c.email_verify_base_url, "email_verify_ttl_secs": c.email_verify_ttl_secs
    });
    result
        .as_object_mut()
        .unwrap()
        .extend(auth.as_object().unwrap().clone());
    result
}

#[test]
fn config_probe_child() {
    let Some(expected) = env_probe::expected() else {
        return;
    };
    let actual = match ServerConfig::from_env() {
        Ok(c) => projection(c),
        Err(ConfigError::MissingEnv(key)) => json!({"error_kind":"missing", "error_key":key}),
        Err(ConfigError::InvalidValue(key, _)) => json!({"error_kind":"invalid", "error_key":key}),
    };
    env_probe::check(actual, expected);
}

#[test]
fn c01_server_config_fresh_environment_matrix() {
    env_probe::run(
        "config_probe_child",
        include_str!("fixtures/config-environment.json"),
    );
}

#[test]
#[should_panic(expected = "did not execute its reader")]
fn verifier_rejects_zero_selected_child_tests() {
    env_probe::run(
        "nonexistent_config_probe_child",
        r#"[{"id":"negative-zero-tests","env":{},"expected":{"never":"reached"}}]"#,
    );
}

#[test]
#[should_panic(expected = "configuration probe")]
fn verifier_rejects_wrong_field_expectation() {
    env_probe::run(
        "config_probe_child",
        r#"[{"id":"negative-wrong-field","env":{},"expected":{"error_key":"WRONG_SYNTHETIC_KEY"}}]"#,
    );
}
