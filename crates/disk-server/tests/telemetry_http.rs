//! DISK-0026 telemetry HTTP integration tests (separate crate — env mutation allowed).

use disk_core::meta_db::MetaDb;
use disk_server::accounts::routes::auth_http_state_for_tests;
use disk_server::health;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;

struct EnvGuard {
    key: &'static str,
    previous: Option<String>,
}

impl EnvGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let previous = std::env::var(key).ok();
        unsafe { std::env::set_var(key, value) };
        Self { key, previous }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.previous {
            Some(value) => unsafe { std::env::set_var(self.key, value) },
            None => unsafe { std::env::remove_var(self.key) },
        }
    }
}

async fn spawn_auth_server(meta_db: MetaDb) -> u16 {
    let bundle = auth_http_state_for_tests(meta_db);
    let state = Arc::new(bundle);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    tokio::spawn(async move {
        health::serve(addr, None, Some(state), std::future::pending::<()>())
            .await
            .unwrap();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    addr.port()
}

#[tokio::test]
async fn telemetry_config_public_and_preference_round_trip() {
    let dir = tempdir().unwrap();
    let meta_db = MetaDb::open(&dir.path().join("telemetry-http.sqlite"))
        .await
        .unwrap();

    let email = disk_core::normalize_email("tel@corp.test");
    let hash_pw = disk_core::hash_password("long-password").unwrap();
    meta_db
        .create_user_account("usr_tel", &email, &hash_pw, "corp")
        .await
        .unwrap();

    let port = spawn_auth_server(meta_db).await;
    let client = reqwest::Client::new();

    let config: serde_json::Value = client
        .get(format!("http://127.0.0.1:{port}/telemetry/config"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(config["api_host"].is_string());

    let login: serde_json::Value = client
        .post(format!("http://127.0.0.1:{port}/auth/login"))
        .json(&serde_json::json!({ "email": email, "password": "long-password" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = login["access_token"].as_str().unwrap();

    let initial: serde_json::Value = client
        .get(format!("http://127.0.0.1:{port}/telemetry"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(initial["opt_in"], false);
    assert_eq!(initial["user_id"], "usr_tel");

    let _key = EnvGuard::set("DISK_POSTHOG_PROJECT_KEY", "phc_test");
    let enabled: serde_json::Value = client
        .put(format!("http://127.0.0.1:{port}/telemetry"))
        .bearer_auth(token)
        .json(&serde_json::json!({ "opt_in": true }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(enabled["opt_in"], true);
    drop(_key);

    let consents: serde_json::Value = client
        .get(format!("http://127.0.0.1:{port}/compliance/consents"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let events = consents["events"].as_array().unwrap();
    assert!(
        events
            .iter()
            .any(|e| e["consent_type"] == "product_analytics"),
        "analytics consent must be recorded; got {events:?}"
    );
}
