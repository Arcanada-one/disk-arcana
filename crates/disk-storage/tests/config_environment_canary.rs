//! C03: config constructors only; never construct an S3 client or send a request.
#![cfg(target_os = "linux")]
#[path = "../../../test-support/env_probe.rs"]
mod env_probe;
use disk_storage::S3BackendConfig;
use serde_json::json;

#[test]
fn config_probe_child() {
    let Some(mut expected) = env_probe::expected() else {
        return;
    };
    let backend = expected.as_object_mut().unwrap().remove("backend").unwrap();
    let result = match backend.as_str().unwrap() {
        "b2" => S3BackendConfig::backblaze_from_env(),
        "r2" => S3BackendConfig::cloudflare_r2_from_env(),
        _ => panic!("unknown synthetic backend"),
    };
    let actual = match result {
        Ok(c) => json!({"endpoint_url":c.endpoint_url, "region":c.region,
            "bucket":c.bucket, "access_key_id":c.access_key_id,
            "secret_access_key":c.secret_access_key, "force_path_style":c.force_path_style}),
        Err(error) => json!({"error":error.to_string()}),
    };
    env_probe::check(actual, expected);
}

#[test]
fn c03_s3_config_fresh_environment_matrix() {
    env_probe::run(
        "config_probe_child",
        include_str!("fixtures/config-environment.json"),
    );
}
