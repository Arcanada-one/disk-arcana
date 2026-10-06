//! Shared C11 test driver; actual reader functions stay in their owning modules.
use crate::config_env_probe;
use serde_json::{json, Value};

type ApiReader = fn(Option<&str>) -> String;
type TokenReader = fn(Option<&str>) -> anyhow::Result<String>;

pub(crate) fn check_reader(api_reader: ApiReader, token_reader: TokenReader) {
    let Some(mut expected) = config_env_probe::expected() else {
        return;
    };
    let fields = expected.as_object_mut().expect("synthetic projection");
    let api_override: Option<String> = serde_json::from_value(
        fields
            .remove("api_override")
            .expect("explicit override case"),
    )
    .expect("optional synthetic API argument");
    let token_override: Option<String> = serde_json::from_value(
        fields
            .remove("token_override")
            .expect("explicit override case"),
    )
    .expect("optional synthetic token argument");
    let api_base = api_reader(api_override.as_deref());
    let (token, token_error) = match token_reader(token_override.as_deref()) {
        Ok(token) => (Some(token), None),
        Err(error) => (None, Some(error.to_string())),
    };
    config_env_probe::check(
        json!({"api_base":api_base, "token":token, "token_error":token_error}),
        expected,
    );
}

pub(crate) fn run_reader(reader: &str) {
    let mut cases: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/cli-config-environment.json"
    ))
    .expect("C11 fixtures");
    for case in cases.as_array_mut().expect("C11 case list") {
        let suffix = case["id"].as_str().expect("case suffix");
        case["id"] = json!(format!("C11-{reader}-{suffix}"));
    }
    config_env_probe::run(
        &format!("{reader}::env_canary::config_probe_child"),
        &cases.to_string(),
    );
}

#[test]
#[should_panic(expected = "configuration field token")]
fn c11_wrong_token_expectation_is_rejected() {
    config_env_probe::run(
        "agents_cmd::env_canary::config_probe_child",
        r#"[{"id":"C11-negative-wrong-token","env":{"DISK_ACCESS_TOKEN":"fixture-actual"},"expected":{"api_override":null,"token_override":null,"token":"fixture-wrong"}}]"#,
    );
}
