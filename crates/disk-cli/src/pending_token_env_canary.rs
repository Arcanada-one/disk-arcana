//! C18: synthetic admin-token selection only; no connection, files or RPC.
use super::{resolve_pending_admin_token, PendingTokenArgs};
use crate::config_env_probe;
use serde_json::json;

#[test]
fn c18_pending_token_child() {
    let Some(mut expected) = config_env_probe::expected() else {
        return;
    };
    // This is a fixture input, removed before checking reader output fields.
    let cli_token = expected
        .as_object_mut()
        .expect("synthetic expected fields")
        .remove("fixture_cli_admin_token")
        .expect("explicit synthetic CLI input");
    assert!(cli_token.is_null() || cli_token.is_string());
    let args = PendingTokenArgs {
        server: "http://127.0.0.1:1".to_owned(),
        hostname: "synthetic-node".to_owned(),
        ttl_secs: 3600,
        tenant: None,
        admin_token: cli_token.as_str().map(str::to_owned),
        ca_cert: None,
        insecure_localhost: true,
        tls_domain: None,
    };
    let actual = match resolve_pending_admin_token(&args) {
        Ok(token) => json!({"admin_token": token, "error": null}),
        Err(error) => json!({"admin_token": null, "error": error.to_string()}),
    };
    config_env_probe::check(actual, expected);
}

#[test]
fn c18_pending_token_fresh_environment_matrix() {
    config_env_probe::run(
        "pending_token_env_canary::c18_pending_token_child",
        r#"[
        {"id":"C18-admin-absent","env":{},"expected":{"fixture_cli_admin_token":null,"admin_token":null,"error":"--admin-token or DISK_ADMIN_TOKEN required"}},
        {"id":"C18-admin-env","env":{"DISK_ADMIN_TOKEN":"synthetic-env"},"expected":{"fixture_cli_admin_token":null,"admin_token":"synthetic-env","error":null}},
        {"id":"C18-admin-env-empty","env":{"DISK_ADMIN_TOKEN":""},"expected":{"fixture_cli_admin_token":null,"admin_token":"","error":null}},
        {"id":"C18-admin-env-space","env":{"DISK_ADMIN_TOKEN":" synthetic "},"expected":{"fixture_cli_admin_token":null,"admin_token":" synthetic ","error":null}},
        {"id":"C18-admin-cli","env":{},"expected":{"fixture_cli_admin_token":"synthetic-cli","admin_token":"synthetic-cli","error":null}},
        {"id":"C18-admin-cli-precedence","env":{"DISK_ADMIN_TOKEN":"synthetic-env"},"expected":{"fixture_cli_admin_token":"synthetic-cli","admin_token":"synthetic-cli","error":null}},
        {"id":"C18-admin-cli-empty-precedence","env":{"DISK_ADMIN_TOKEN":"synthetic-env"},"expected":{"fixture_cli_admin_token":"","admin_token":"","error":null}},
        {"id":"C18-admin-cli-space-precedence","env":{"DISK_ADMIN_TOKEN":"synthetic-env"},"expected":{"fixture_cli_admin_token":" synthetic " ,"admin_token":" synthetic ","error":null}}
        ]"#,
    );
}

#[test]
fn c18_wrong_admin_projection_is_refused() {
    let result = std::panic::catch_unwind(|| {
        config_env_probe::run(
            "pending_token_env_canary::c18_pending_token_child",
            r#"[{"id":"C18-wrong-projection-control","env":{"DISK_ADMIN_TOKEN":"synthetic-env"},"expected":{"fixture_cli_admin_token":null,"admin_token":"wrong-value"}}]"#,
        );
    });
    let failure = result.expect_err("wrong reader projection must fail");
    let message = failure
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| failure.downcast_ref::<&str>().copied())
        .expect("reader assertion failure text");
    assert!(
        message.contains("configuration field admin_token"),
        "refusal must be caused by the wrong reader value: {message}"
    );
}
