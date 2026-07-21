//! HTTP handlers for `/auth/*` (DISK-0016 slice 1).

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use disk_core::billing::PlanTier;
use disk_core::meta_db::MetaDb;
use disk_core::{
    default_tenant_from_email, hash_password, new_user_id, normalize_email, sanitize_tenant_slug,
    validate_email, verify_password,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::email_verify::{deliver_verification, EmailVerifyConfig, VerificationDelivery};
use super::jwt_service::{JwtConfig, VerifiedAccess};
use super::oauth::OAuthConfig;

#[derive(Clone)]
pub struct AuthHttpState {
    pub meta_db: MetaDb,
    /// Symmetric key for OAuth state + email verification HMAC (not bearer JWT in JWKS mode).
    pub signing_key: Vec<u8>,
    pub jwt: JwtConfig,
    pub oauth: OAuthConfig,
    pub email_verify: EmailVerifyConfig,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_url: Option<String>,
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
    if !state.jwt.mode.allows_local_issue() {
        return Err((
            StatusCode::FORBIDDEN,
            "password signup disabled; use /auth/oauth/start",
        ));
    }

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

    let mut resp = build_token_response(state, &user_id, &email, &tenant_id, false)?;
    attach_verification(state, &user_id, &mut resp)?;
    Ok(resp)
}

async fn login_inner(
    state: &AuthHttpState,
    body: LoginRequest,
) -> Result<AuthTokenResponse, (StatusCode, &'static str)> {
    if !state.jwt.mode.allows_local_issue() {
        return Err((
            StatusCode::FORBIDDEN,
            "password login disabled; use /auth/oauth/start",
        ));
    }

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
    let claims = verify_bearer(state, headers).await?;
    let user = resolve_user_from_access(state, &claims).await?;

    Ok(UserProfile {
        user_id: user.id,
        email: user.email,
        tenant_id: user.tenant_id,
        email_verified: user.email_verified,
    })
}

pub(crate) async fn verify_bearer(
    state: &AuthHttpState,
    headers: &HeaderMap,
) -> Result<VerifiedAccess, (StatusCode, &'static str)> {
    let token = bearer_token(headers).ok_or((StatusCode::UNAUTHORIZED, "missing bearer token"))?;
    state
        .jwt
        .verify(token)
        .await
        .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid token"))
}

pub(crate) async fn resolve_user_from_access(
    state: &AuthHttpState,
    claims: &VerifiedAccess,
) -> Result<disk_core::meta_db::UserAccount, (StatusCode, &'static str)> {
    if let Ok(Some(user)) = state.meta_db.get_user_by_id(&claims.sub).await {
        return Ok(user);
    }
    if let Ok(Some(user)) = state
        .meta_db
        .get_user_by_oauth("auth_arcana", &claims.sub)
        .await
    {
        return Ok(user);
    }
    if let Some(email) = claims.email.as_deref() {
        if let Ok(Some(user)) = state.meta_db.get_user_by_email(email).await {
            return Ok(user);
        }
    }
    Err((StatusCode::UNAUTHORIZED, "user not found"))
}

pub(crate) fn build_token_response(
    state: &AuthHttpState,
    user_id: &str,
    email: &str,
    tenant_id: &str,
    email_verified: bool,
) -> Result<AuthTokenResponse, (StatusCode, &'static str)> {
    let access_token = state
        .jwt
        .issue_local(user_id, email, tenant_id, email_verified)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "token issue failed"))?;

    Ok(AuthTokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: state.jwt.token_ttl_secs,
        user: UserProfile {
            user_id: user_id.to_owned(),
            email: email.to_owned(),
            tenant_id: tenant_id.to_owned(),
            email_verified,
        },
        refresh_token: None,
        verification_token: None,
        verification_url: None,
    })
}

pub(crate) fn build_external_token_response(
    access_token: String,
    expires_in: u64,
    user_id: &str,
    email: &str,
    tenant_id: &str,
    email_verified: bool,
    refresh_token: Option<String>,
) -> AuthTokenResponse {
    AuthTokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in,
        user: UserProfile {
            user_id: user_id.to_owned(),
            email: email.to_owned(),
            tenant_id: tenant_id.to_owned(),
            email_verified,
        },
        refresh_token,
        verification_token: None,
        verification_url: None,
    }
}

fn attach_verification(
    state: &AuthHttpState,
    user_id: &str,
    resp: &mut AuthTokenResponse,
) -> Result<(), (StatusCode, &'static str)> {
    let VerificationDelivery {
        verification_token,
        verification_url,
    } = deliver_verification(state, user_id)?;
    resp.verification_token = verification_token;
    resp.verification_url = verification_url;
    Ok(())
}

pub(crate) fn bearer_token(headers: &HeaderMap) -> Option<&str> {
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
    use crate::accounts::{
        EmailVerifyConfig, EmailVerifyMode, JwksCache, JwtConfig, JwtMode, OAuthConfig, OAuthMode,
    };
    use crate::health;

    const TEST_KEY: &str = "01234567890123456789012345678901";

    fn local_jwt() -> JwtConfig {
        JwtConfig {
            mode: JwtMode::Local,
            local_signing_key: TEST_KEY.as_bytes().to_vec(),
            token_ttl_secs: 3600,
            issuer: disk_core::DEFAULT_ISSUER.into(),
            jwks: Arc::new(JwksCache::new("http://127.0.0.1:9/jwks")),
        }
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

    fn disabled_email_verify() -> EmailVerifyConfig {
        EmailVerifyConfig {
            mode: EmailVerifyMode::Disabled,
            public_base_url: None,
            token_ttl_secs: 86_400,
        }
    }

    fn stub_email_verify(base: &str) -> EmailVerifyConfig {
        EmailVerifyConfig {
            mode: EmailVerifyMode::Stub,
            public_base_url: Some(base.to_string()),
            token_ttl_secs: 86_400,
        }
    }

    async fn with_auth_server<F, Fut>(meta_db: MetaDb, oauth: OAuthConfig, exercise: F)
    where
        F: FnOnce(SocketAddr) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        with_auth_server_full(meta_db, oauth, disabled_email_verify(), exercise).await;
    }

    async fn with_auth_server_full<F, Fut>(
        meta_db: MetaDb,
        oauth: OAuthConfig,
        email_verify: EmailVerifyConfig,
        exercise: F,
    ) where
        F: FnOnce(SocketAddr) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        drop(listener);

        let state = Arc::new(AuthHttpState {
            meta_db,
            signing_key: TEST_KEY.as_bytes().to_vec(),
            jwt: local_jwt(),
            oauth,
            email_verify,
        });

        let server = health::serve(addr, None, Some(state), std::future::pending::<()>());
        tokio::pin!(server);

        tokio::select! {
            result = &mut server => panic!("health server exited early: {result:?}"),
            () = async {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                exercise(addr).await;
            } => {}
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

    async fn with_stub_email_verify_server<F, Fut>(meta_db: MetaDb, exercise: F)
    where
        F: FnOnce(SocketAddr) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        drop(listener);

        let email_verify = stub_email_verify(&format!("http://{addr}"));
        with_auth_server_full(meta_db, disabled_oauth(), email_verify, exercise).await;
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
            assert!(token["user"]["email"]
                .as_str()
                .unwrap()
                .ends_with("@stub.oauth.local"));
            assert_eq!(token["user"]["email_verified"], true);
        })
        .await;
    }

    #[tokio::test]
    async fn stub_email_verify_signup_and_confirm_round_trip() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("auth-email-verify.sqlite"))
            .await
            .unwrap();
        with_stub_email_verify_server(db, |addr| async move {
            let base = format!("http://{addr}");
            let client = reqwest::Client::new();

            let signup: Value = client
                .post(format!("{base}/auth/signup"))
                .json(&serde_json::json!({
                    "email": "verify@example.com",
                    "password": "secure-pass",
                    "tenant_id": "verify-corp"
                }))
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap()
                .json()
                .await
                .unwrap();

            assert_eq!(signup["user"]["email_verified"], false);
            let verify_token = signup["verification_token"]
                .as_str()
                .expect("stub mode must return verification_token");
            assert!(signup["verification_url"]
                .as_str()
                .unwrap()
                .contains("/auth/verify-email?token="));

            let verified: Value = client
                .get(format!("{base}/auth/verify-email"))
                .query(&[("token", verify_token)])
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap()
                .json()
                .await
                .unwrap();

            assert_eq!(verified["user"]["email_verified"], true);
            let new_token = verified["access_token"].as_str().unwrap();

            let me: Value = client
                .get(format!("{base}/auth/me"))
                .bearer_auth(new_token)
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(me["email_verified"], true);
        })
        .await;
    }

    #[tokio::test]
    async fn resend_verification_returns_stub_token() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("auth-resend.sqlite"))
            .await
            .unwrap();
        with_stub_email_verify_server(db, |addr| async move {
            let base = format!("http://{addr}");
            let client = reqwest::Client::new();

            let signup: Value = client
                .post(format!("{base}/auth/signup"))
                .json(&serde_json::json!({
                    "email": "resend@example.com",
                    "password": "secure-pass",
                    "tenant_id": "resend-corp"
                }))
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap()
                .json()
                .await
                .unwrap();

            let token = signup["access_token"].as_str().unwrap();
            let resend: Value = client
                .post(format!("{base}/auth/resend-verification"))
                .bearer_auth(token)
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap()
                .json()
                .await
                .unwrap();

            assert_eq!(resend["sent"], true);
            assert!(resend["verification_token"].is_string());
        })
        .await;
    }

    #[tokio::test]
    async fn refresh_not_mounted_for_stub_oauth() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("auth-refresh-stub.sqlite"))
            .await
            .unwrap();
        with_stub_oauth_server(db, |addr| async move {
            let base = format!("http://{addr}");
            let client = reqwest::Client::new();

            let resp = client
                .post(format!("{base}/auth/refresh"))
                .json(&serde_json::json!({ "refresh_token": "rt-stub" }))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 404);
        })
        .await;
    }

    #[tokio::test]
    async fn password_login_forbidden_in_auth_arcana_jwt_mode() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("auth-arcana-mode.sqlite"))
            .await
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        drop(listener);

        let jwt = JwtConfig {
            mode: JwtMode::AuthArcana,
            local_signing_key: TEST_KEY.as_bytes().to_vec(),
            token_ttl_secs: 3600,
            issuer: "https://auth.test".into(),
            jwks: Arc::new(JwksCache::new("http://127.0.0.1:9/jwks")),
        };
        let state = Arc::new(AuthHttpState {
            meta_db: db,
            signing_key: TEST_KEY.as_bytes().to_vec(),
            jwt,
            oauth: disabled_oauth(),
            email_verify: disabled_email_verify(),
        });

        let server = health::serve(addr, None, Some(state), std::future::pending::<()>());
        tokio::pin!(server);

        tokio::select! {
            result = &mut server => panic!("health server exited early: {result:?}"),
            () = async {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                let base = format!("http://{addr}");
                let resp = reqwest::Client::new()
                    .post(format!("{base}/auth/login"))
                    .json(&serde_json::json!({
                        "email": "a@example.com",
                        "password": "secret"
                    }))
                    .send()
                    .await
                    .unwrap();
                assert_eq!(resp.status(), 403);
                let body: Value = resp.json().await.unwrap();
                assert!(body["error"]
                    .as_str()
                    .unwrap()
                    .contains("/auth/oauth/start"));
            } => {}
        }
    }
}
