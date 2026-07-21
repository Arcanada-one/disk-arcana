//! HTTP handlers for `/auth/*` (DISK-0016 slice 1).

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use disk_core::billing::PlanTier;
use disk_core::meta_db::MetaDb;
use disk_core::{
    default_tenant_from_email, hash_password, issue_token, new_user_id, normalize_email,
    sanitize_tenant_slug, validate_email, verify_password, verify_token,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::oauth::OAuthConfig;

#[derive(Clone)]
pub struct AuthHttpState {
    pub meta_db: MetaDb,
    pub signing_key: Vec<u8>,
    pub token_ttl_secs: u64,
    pub oauth: OAuthConfig,
}

#[derive(Debug, Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub tenant_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct AuthTokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    pub user: UserProfile,
}

#[derive(Debug, Serialize)]
pub struct UserProfile {
    pub user_id: String,
    pub email: String,
    pub tenant_id: String,
    pub email_verified: bool,
}

pub async fn signup(
    State(state): State<Arc<AuthHttpState>>,
    Json(body): Json<SignupRequest>,
) -> impl IntoResponse {
    match signup_inner(&state, body).await {
        Ok(resp) => (StatusCode::CREATED, Json(resp)).into_response(),
        Err((code, msg)) => (code, Json(json!({ "error": msg }))).into_response(),
    }
}

pub async fn login(
    State(state): State<Arc<AuthHttpState>>,
    Json(body): Json<LoginRequest>,
) -> impl IntoResponse {
    match login_inner(&state, body).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err((code, msg)) => (code, Json(json!({ "error": msg }))).into_response(),
    }
}

pub async fn me(State(state): State<Arc<AuthHttpState>>, headers: HeaderMap) -> impl IntoResponse {
    match me_inner(&state, &headers).await {
        Ok(profile) => (StatusCode::OK, Json(profile)).into_response(),
        Err((code, msg)) => (code, Json(json!({ "error": msg }))).into_response(),
    }
}

async fn signup_inner(
    state: &AuthHttpState,
    body: SignupRequest,
) -> Result<AuthTokenResponse, (StatusCode, &'static str)> {
    let email = normalize_email(&body.email);
    if !validate_email(&email) {
        return Err((StatusCode::BAD_REQUEST, "invalid email"));
    }

    let tenant_id = match body.tenant_id.as_deref() {
        Some(raw) => {
            sanitize_tenant_slug(raw).ok_or((StatusCode::BAD_REQUEST, "invalid tenant_id"))?
        }
        None => default_tenant_from_email(&email)
            .ok_or((StatusCode::BAD_REQUEST, "could not derive tenant_id"))?,
    };

    let password_hash = hash_password(&body.password)
        .map_err(|_| (StatusCode::BAD_REQUEST, "password too short"))?;

    let user_id = new_user_id();
    if let Err(e) = state
        .meta_db
        .create_user_account(&user_id, &email, &password_hash, &tenant_id)
        .await
    {
        if is_unique_violation(&e) {
            return Err((StatusCode::CONFLICT, "email already registered"));
        }
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "database error"));
    }

    // Bootstrap free-tier billing row for the new tenant.
    let _ = state
        .meta_db
        .set_plan_tier(Some(&tenant_id), PlanTier::Free)
        .await;

    build_token_response(state, &user_id, &email, &tenant_id, false)
}

async fn login_inner(
    state: &AuthHttpState,
    body: LoginRequest,
) -> Result<AuthTokenResponse, (StatusCode, &'static str)> {
    let email = normalize_email(&body.email);
    let user = state
        .meta_db
        .get_user_by_email(&email)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?
        .ok_or((StatusCode::UNAUTHORIZED, "invalid credentials"))?;

    if user.is_oauth_only() {
        return Err((StatusCode::UNAUTHORIZED, "use oauth login"));
    }

    let ok = verify_password(&body.password, &user.password_hash)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "password verify failed"))?;
    if !ok {
        return Err((StatusCode::UNAUTHORIZED, "invalid credentials"));
    }

    build_token_response(
        state,
        &user.id,
        &user.email,
        &user.tenant_id,
        user.email_verified,
    )
}

async fn me_inner(
    state: &AuthHttpState,
    headers: &HeaderMap,
) -> Result<UserProfile, (StatusCode, &'static str)> {
    let token = bearer_token(headers).ok_or((StatusCode::UNAUTHORIZED, "missing bearer token"))?;
    let claims = verify_token(&state.signing_key, token)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid token"))?;

    let user = state
        .meta_db
        .get_user_by_id(&claims.sub)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?
        .ok_or((StatusCode::UNAUTHORIZED, "user not found"))?;

    Ok(UserProfile {
        user_id: user.id,
        email: user.email,
        tenant_id: user.tenant_id,
        email_verified: user.email_verified,
    })
}

pub(crate) fn build_token_response(
    state: &AuthHttpState,
    user_id: &str,
    email: &str,
    tenant_id: &str,
    email_verified: bool,
) -> Result<AuthTokenResponse, (StatusCode, &'static str)> {
    let access_token = issue_token(
        &state.signing_key,
        user_id,
        email,
        tenant_id,
        email_verified,
        state.token_ttl_secs,
    )
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "token issue failed"))?;

    Ok(AuthTokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: state.token_ttl_secs,
        user: UserProfile {
            user_id: user_id.to_owned(),
            email: email.to_owned(),
            tenant_id: tenant_id.to_owned(),
            email_verified,
        },
    })
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let raw = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    raw.strip_prefix("Bearer ").map(str::trim)
}

fn is_unique_violation(err: &disk_core::MetaDbError) -> bool {
    matches!(
        err,
        disk_core::MetaDbError::Sqlx(sqlx::Error::Database(db))
            if db.message().contains("UNIQUE")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_parses() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer tok123".parse().unwrap(),
        );
        assert_eq!(bearer_token(&headers), Some("tok123"));
    }
}

#[cfg(test)]
mod integration_tests {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use disk_core::meta_db::MetaDb;
    use serde_json::Value;
    use tempfile::tempdir;
    use tokio::net::TcpListener;

    use super::*;
    use crate::accounts::{OAuthConfig, OAuthMode};
    use crate::health;

    const TEST_KEY: &str = "01234567890123456789012345678901";

    async fn with_auth_server<F, Fut>(meta_db: MetaDb, oauth: OAuthConfig, exercise: F)
    where
        F: FnOnce(SocketAddr) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        drop(listener);

        let state = Arc::new(AuthHttpState {
            meta_db,
            signing_key: TEST_KEY.as_bytes().to_vec(),
            token_ttl_secs: 3600,
            oauth,
        });

        let server = health::serve(addr, None, Some(state), std::future::pending::<()>());
        tokio::pin!(server);

        tokio::select! {
            result = &mut server => panic!("health server exited early: {result:?}"),
            () = async {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                exercise(addr).await;
            } => {        }
    }

    fn disabled_oauth() -> OAuthConfig {
        OAuthConfig {
            mode: OAuthMode::Disabled,
            issuer: None,
            client_id: None,
            client_secret: None,
            redirect_uri: None,
            public_base_url: None,
        }
    }

    async fn with_stub_oauth_server<F, Fut>(meta_db: MetaDb, exercise: F)
    where
        F: FnOnce(SocketAddr) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        drop(listener);

        let oauth = OAuthConfig {
            mode: OAuthMode::Stub,
            issuer: None,
            client_id: None,
            client_secret: None,
            redirect_uri: None,
            public_base_url: Some(format!("http://{addr}")),
        };

        with_auth_server(meta_db, oauth, exercise).await;
    }

    #[tokio::test]
    async fn stub_oauth_start_callback_round_trip() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("auth-oauth.sqlite"))
            .await
            .unwrap();
        with_stub_oauth_server(db, |addr| async move {
            let base = format!("http://{addr}");
            let client = reqwest::Client::new();

            let start: Value = client
                .get(format!("{base}/auth/oauth/start?provider=google"))
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap()
                .json()
                .await
                .unwrap();

            let callback_url = start["authorization_url"].as_str().unwrap();
            let oauth_state = start["state"].as_str().unwrap();
            assert!(callback_url.contains("/auth/oauth/callback"));

            let parsed = reqwest::Url::parse(callback_url).unwrap();
            let code = parsed
                .query_pairs()
                .find(|(k, _)| k == "code")
                .map(|(_, v)| v.to_string())
                .unwrap();

            let token: Value = client
                .get(format!("{base}/auth/oauth/callback"))
                .query(&[("code", code), ("state", oauth_state.to_string())])
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap()
                .json()
                .await
                .unwrap();

            assert_eq!(token["token_type"], "Bearer");
            assert!(
                token["user"]["email"]
                    .as_str()
                    .unwrap()
                    .ends_with("@stub.oauth.local")
            );
            assert_eq!(token["user"]["email_verified"], true);
        })
        .await;
    }
}

    #[tokio::test]
    async fn health_responds_when_auth_routes_mounted() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("auth-health.sqlite"))
            .await
            .unwrap();
        with_auth_server(db, disabled_oauth(), |addr| async move {
            let resp = reqwest::get(format!("http://{addr}/health")).await.unwrap();
            assert_eq!(resp.status(), 200);
        })
        .await;
    }

    #[tokio::test]
    async fn signup_login_me_round_trip() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("auth-it.sqlite"))
            .await
            .unwrap();
        with_auth_server(db, disabled_oauth(), |addr| async move {
            let base = format!("http://{addr}");
            let client = reqwest::Client::new();

            let signup: Value = client
                .post(format!("{base}/auth/signup"))
                .json(&serde_json::json!({
                    "email": "alice@example.com",
                    "password": "secure-pass",
                    "tenant_id": "alice-corp"
                }))
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap()
                .json()
                .await
                .unwrap();

            assert_eq!(signup["user"]["tenant_id"], "alice-corp");
            assert_eq!(signup["token_type"], "Bearer");
            let token = signup["access_token"].as_str().unwrap();

            let login: Value = client
                .post(format!("{base}/auth/login"))
                .json(&serde_json::json!({
                    "email": "alice@example.com",
                    "password": "secure-pass"
                }))
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap()
                .json()
                .await
                .unwrap();
            assert!(login["access_token"].is_string());

            let me: Value = client
                .get(format!("{base}/auth/me"))
                .bearer_auth(token)
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(me["email"], "alice@example.com");
            assert_eq!(me["email_verified"], false);
        })
        .await;
    }

    #[tokio::test]
    async fn duplicate_signup_returns_conflict() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("auth-dup.sqlite"))
            .await
            .unwrap();
        with_auth_server(db, disabled_oauth(), |addr| async move {
            let base = format!("http://{addr}");
            let client = reqwest::Client::new();
            let body = serde_json::json!({
                "email": "dup@example.com",
                "password": "secure-pass",
                "tenant_id": "dup-tenant"
            });

            client
                .post(format!("{base}/auth/signup"))
                .json(&body)
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap();

            let resp = client
                .post(format!("{base}/auth/signup"))
                .json(&body)
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 409);
        })
        .await;
    }

    fn disabled_oauth() -> OAuthConfig {
        OAuthConfig {
            mode: OAuthMode::Disabled,
            issuer: None,
            client_id: None,
            client_secret: None,
            redirect_uri: None,
            public_base_url: None,
        }
    }

    async fn with_stub_oauth_server<F, Fut>(meta_db: MetaDb, exercise: F)
    where
        F: FnOnce(SocketAddr) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        drop(listener);

        let oauth = OAuthConfig {
            mode: OAuthMode::Stub,
            issuer: None,
            client_id: None,
            client_secret: None,
            redirect_uri: None,
            public_base_url: Some(format!("http://{addr}")),
        };

        with_auth_server(meta_db, oauth, exercise).await;
    }

    #[tokio::test]
    async fn stub_oauth_start_callback_round_trip() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("auth-oauth.sqlite"))
            .await
            .unwrap();
        with_stub_oauth_server(db, |addr| async move {
            let base = format!("http://{addr}");
            let client = reqwest::Client::new();

            let start: Value = client
                .get(format!("{base}/auth/oauth/start?provider=google"))
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap()
                .json()
                .await
                .unwrap();

            let callback_url = start["authorization_url"].as_str().unwrap();
            let oauth_state = start["state"].as_str().unwrap();
            assert!(callback_url.contains("/auth/oauth/callback"));

            let parsed = reqwest::Url::parse(callback_url).unwrap();
            let code = parsed
                .query_pairs()
                .find(|(k, _)| k == "code")
                .map(|(_, v)| v.to_string())
                .unwrap();

            let token: Value = client
                .get(format!("{base}/auth/oauth/callback"))
                .query(&[("code", code), ("state", oauth_state.to_string())])
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap()
                .json()
                .await
                .unwrap();

            assert_eq!(token["token_type"], "Bearer");
            assert!(
                token["user"]["email"]
                    .as_str()
                    .unwrap()
                    .ends_with("@stub.oauth.local")
            );
            assert_eq!(token["user"]["email_verified"], true);
        })
        .await;
    }
}
