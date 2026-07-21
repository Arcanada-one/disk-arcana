//! HTTP handlers for `/onboarding` (DISK-0025 slice 3).

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::accounts::routes::{resolve_user_from_access, verify_bearer, AuthHttpState};

#[derive(Debug, Serialize)]
pub struct OnboardingResponse {
    pub user_id: String,
    pub dismissed: bool,
    pub dismissed_at: Option<i64>,
    pub updated_at: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct PutOnboardingRequest {
    pub dismissed: bool,
}

pub async fn get_onboarding(
    State(state): State<std::sync::Arc<AuthHttpState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    match get_onboarding_inner(&state, &headers).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err((code, msg)) => (code, Json(json!({ "error": msg }))).into_response(),
    }
}

async fn get_onboarding_inner(
    state: &AuthHttpState,
    headers: &HeaderMap,
) -> Result<OnboardingResponse, (StatusCode, &'static str)> {
    let claims = verify_bearer(state, headers).await?;
    let user = resolve_user_from_access(state, &claims).await?;

    let row = state
        .meta_db
        .get_user_onboarding(&user.id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    Ok(OnboardingResponse {
        user_id: user.id,
        dismissed: row.dismissed,
        dismissed_at: row.dismissed_at,
        updated_at: if row.updated_at == 0 {
            None
        } else {
            Some(row.updated_at)
        },
    })
}

pub async fn put_onboarding(
    State(state): State<std::sync::Arc<AuthHttpState>>,
    headers: HeaderMap,
    Json(body): Json<PutOnboardingRequest>,
) -> impl IntoResponse {
    match put_onboarding_inner(&state, &headers, body).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err((code, msg)) => (code, Json(json!({ "error": msg }))).into_response(),
    }
}

async fn put_onboarding_inner(
    state: &AuthHttpState,
    headers: &HeaderMap,
    body: PutOnboardingRequest,
) -> Result<OnboardingResponse, (StatusCode, &'static str)> {
    let claims = verify_bearer(state, headers).await?;
    let user = resolve_user_from_access(state, &claims).await?;

    let row = state
        .meta_db
        .upsert_user_onboarding_dismissed(&user.id, body.dismissed)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    Ok(OnboardingResponse {
        user_id: user.id,
        dismissed: row.dismissed,
        dismissed_at: row.dismissed_at,
        updated_at: Some(row.updated_at),
    })
}

#[cfg(test)]
mod integration_tests {
    use crate::health;
    use disk_core::meta_db::MetaDb;
    use std::time::Duration;
    use tempfile::tempdir;

    async fn spawn_auth_server(meta_db: MetaDb) -> u16 {
        let bundle = crate::accounts::routes::auth_http_state_for_tests(meta_db);
        let state = std::sync::Arc::new(bundle);

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
    async fn onboarding_get_put_round_trip() {
        let dir = tempdir().unwrap();
        let meta_db = MetaDb::open(&dir.path().join("onboarding-http.sqlite"))
            .await
            .unwrap();

        let email = disk_core::normalize_email("onb@corp.test");
        let hash_pw = disk_core::hash_password("long-password").unwrap();
        meta_db
            .create_user_account("usr_onb", &email, &hash_pw, "corp")
            .await
            .unwrap();

        let port = spawn_auth_server(meta_db).await;
        let client = reqwest::Client::new();

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
            .get(format!("http://127.0.0.1:{port}/onboarding"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(initial["dismissed"], false);
        assert_eq!(initial["user_id"], "usr_onb");

        let dismissed: serde_json::Value = client
            .put(format!("http://127.0.0.1:{port}/onboarding"))
            .bearer_auth(token)
            .json(&serde_json::json!({ "dismissed": true }))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(dismissed["dismissed"], true);
        assert!(dismissed["dismissed_at"].is_number());

        let loaded: serde_json::Value = client
            .get(format!("http://127.0.0.1:{port}/onboarding"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(loaded["dismissed"], true);
    }
}
