//! OAuth social login — stub + Auth Arcana OIDC RP (DISK-0016 slice 2).

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use base64::Engine;
use disk_core::billing::PlanTier;
use disk_core::meta_db::NewOAuthUser;
use disk_core::{
    default_tenant_from_email, new_user_id, normalize_email, validate_email,
    OAUTH_PASSWORD_SENTINEL,
};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;

use super::jwt_mode::JwtMode;
use super::oauth_mode::OAuthMode;
use super::routes::{
    build_external_token_response, build_token_response, AuthHttpState, AuthTokenResponse,
};

type HmacSha256 = Hmac<Sha256>;

/// OAuth runtime configuration wired into [`AuthHttpState`].
#[derive(Debug, Clone)]
pub struct OAuthConfig {
    pub mode: OAuthMode,
    pub issuer: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub redirect_uri: Option<String>,
    /// Public base URL for stub callback assembly (e.g. `http://127.0.0.1:9446`).
    pub public_base_url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OAuthStartQuery {
    pub provider: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OAuthCallbackQuery {
    pub code: String,
    pub state: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct OAuthStartResponse {
    pub authorization_url: String,
    pub state: String,
}

#[derive(Debug, Clone)]
struct OAuthExchange {
    identity: OAuthIdentity,
    access_token: Option<String>,
    expires_in: Option<u64>,
}

#[derive(Debug, Clone)]
struct OAuthIdentity {
    provider: String,
    subject: String,
    email: String,
    email_verified: bool,
}

pub async fn oauth_start(
    State(state): State<Arc<AuthHttpState>>,
    Query(query): Query<OAuthStartQuery>,
) -> impl IntoResponse {
    match oauth_start_inner(&state, query).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err((code, msg)) => (code, Json(json!({ "error": msg }))).into_response(),
    }
}

pub async fn oauth_callback(
    State(state): State<Arc<AuthHttpState>>,
    Query(query): Query<OAuthCallbackQuery>,
) -> impl IntoResponse {
    match oauth_callback_inner(&state, query).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err((code, msg)) => (code, Json(json!({ "error": msg }))).into_response(),
    }
}

async fn oauth_start_inner(
    state: &AuthHttpState,
    query: OAuthStartQuery,
) -> Result<OAuthStartResponse, (StatusCode, &'static str)> {
    if !state.oauth.mode.is_active() {
        return Err((StatusCode::NOT_FOUND, "oauth disabled"));
    }

    let provider = query.provider.unwrap_or_else(|| "auth_arcana".to_string());
    let oauth_state = issue_oauth_state(&state.signing_key, &provider)?;

    let authorization_url = match state.oauth.mode {
        OAuthMode::Stub => build_stub_authorization_url(state, &provider, &oauth_state)?,
        OAuthMode::AuthArcana => build_auth_arcana_authorization_url(state, &oauth_state)?,
        OAuthMode::Disabled => return Err((StatusCode::NOT_FOUND, "oauth disabled")),
    };

    Ok(OAuthStartResponse {
        authorization_url,
        state: oauth_state,
    })
}

async fn oauth_callback_inner(
    state: &AuthHttpState,
    query: OAuthCallbackQuery,
) -> Result<AuthTokenResponse, (StatusCode, &'static str)> {
    if !state.oauth.mode.is_active() {
        return Err((StatusCode::NOT_FOUND, "oauth disabled"));
    }

    let exchange = match state.oauth.mode {
        OAuthMode::Stub => OAuthExchange {
            identity: parse_stub_code(&query.code)?,
            access_token: None,
            expires_in: None,
        },
        OAuthMode::AuthArcana => {
            let state_param = query
                .state
                .as_deref()
                .ok_or((StatusCode::BAD_REQUEST, "missing state"))?;
            verify_oauth_state(&state.signing_key, state_param)?;
            exchange_auth_arcana_code(state, &query.code).await?
        }
        OAuthMode::Disabled => return Err((StatusCode::NOT_FOUND, "oauth disabled")),
    };

    login_or_create_oauth_user(state, exchange).await
}

fn build_stub_authorization_url(
    state: &AuthHttpState,
    provider: &str,
    oauth_state: &str,
) -> Result<String, (StatusCode, &'static str)> {
    let base = state
        .oauth
        .public_base_url
        .as_deref()
        .or(state.oauth.redirect_uri.as_deref())
        .ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "oauth base url not configured",
        ))?;

    let subject = format!("stub-{}", random_hex(8));
    let email = format!("{subject}@stub.oauth.local");
    let code = encode_stub_code(provider, &subject, &email);
    let callback = format!(
        "{base}/auth/oauth/callback?code={}&state={}",
        urlencoding::encode(&code),
        urlencoding::encode(oauth_state)
    );
    Ok(callback)
}

fn build_auth_arcana_authorization_url(
    state: &AuthHttpState,
    oauth_state: &str,
) -> Result<String, (StatusCode, &'static str)> {
    let issuer = state.oauth.issuer.as_deref().ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "oauth issuer not configured",
    ))?;
    let client_id = state.oauth.client_id.as_deref().ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "oauth client_id not configured",
    ))?;
    let redirect_uri = state.oauth.redirect_uri.as_deref().ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "oauth redirect_uri not configured",
    ))?;

    let issuer = issuer.trim_end_matches('/');
    Ok(format!(
        "{issuer}/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid%20email&state={}",
        urlencoding::encode(client_id),
        urlencoding::encode(redirect_uri),
        urlencoding::encode(oauth_state),
    ))
}

async fn exchange_auth_arcana_code(
    state: &AuthHttpState,
    code: &str,
) -> Result<OAuthExchange, (StatusCode, &'static str)> {
    let issuer = state.oauth.issuer.as_deref().ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "oauth issuer not configured",
    ))?;
    let client_id = state.oauth.client_id.as_deref().ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "oauth client_id not configured",
    ))?;
    let client_secret = state.oauth.client_secret.as_deref().ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "oauth client_secret not configured",
    ))?;
    let redirect_uri = state.oauth.redirect_uri.as_deref().ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "oauth redirect_uri not configured",
    ))?;

    let issuer = issuer.trim_end_matches('/');
    let discovery_url = format!("{issuer}/.well-known/openid-configuration");
    let discovery: serde_json::Value = reqwest::Client::new()
        .get(&discovery_url)
        .send()
        .await
        .map_err(|_| (StatusCode::BAD_GATEWAY, "oidc discovery failed"))?
        .error_for_status()
        .map_err(|_| (StatusCode::BAD_GATEWAY, "oidc discovery failed"))?
        .json()
        .await
        .map_err(|_| (StatusCode::BAD_GATEWAY, "oidc discovery invalid"))?;

    let token_endpoint = discovery["token_endpoint"]
        .as_str()
        .ok_or((StatusCode::BAD_GATEWAY, "oidc token_endpoint missing"))?;
    let userinfo_endpoint = discovery["userinfo_endpoint"]
        .as_str()
        .ok_or((StatusCode::BAD_GATEWAY, "oidc userinfo_endpoint missing"))?;

    let token_resp: serde_json::Value = reqwest::Client::new()
        .post(token_endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", client_id),
            ("client_secret", client_secret),
        ])
        .send()
        .await
        .map_err(|_| (StatusCode::BAD_GATEWAY, "token exchange failed"))?
        .error_for_status()
        .map_err(|_| (StatusCode::BAD_GATEWAY, "token exchange rejected"))?
        .json()
        .await
        .map_err(|_| (StatusCode::BAD_GATEWAY, "token response invalid"))?;

    let access_token = token_resp["access_token"]
        .as_str()
        .ok_or((StatusCode::BAD_GATEWAY, "access_token missing"))?
        .to_owned();
    let expires_in = token_resp["expires_in"].as_u64();

    let userinfo: serde_json::Value = reqwest::Client::new()
        .get(userinfo_endpoint)
        .bearer_auth(&access_token)
        .send()
        .await
        .map_err(|_| (StatusCode::BAD_GATEWAY, "userinfo failed"))?
        .error_for_status()
        .map_err(|_| (StatusCode::BAD_GATEWAY, "userinfo rejected"))?
        .json()
        .await
        .map_err(|_| (StatusCode::BAD_GATEWAY, "userinfo invalid"))?;

    let subject = userinfo["sub"]
        .as_str()
        .ok_or((StatusCode::BAD_GATEWAY, "userinfo sub missing"))?
        .to_owned();
    let email = userinfo["email"]
        .as_str()
        .ok_or((StatusCode::BAD_GATEWAY, "userinfo email missing"))?
        .to_owned();
    let email_verified = userinfo["email_verified"].as_bool().unwrap_or(false);

    Ok(OAuthExchange {
        identity: OAuthIdentity {
            provider: "auth_arcana".to_owned(),
            subject,
            email: normalize_email(&email),
            email_verified,
        },
        access_token: Some(access_token),
        expires_in,
    })
}

async fn login_or_create_oauth_user(
    state: &AuthHttpState,
    exchange: OAuthExchange,
) -> Result<AuthTokenResponse, (StatusCode, &'static str)> {
    let OAuthExchange {
        identity,
        access_token,
        expires_in,
    } = exchange;
    if !validate_email(&identity.email) {
        return Err((StatusCode::BAD_REQUEST, "invalid email from oauth"));
    }

    if let Some(user) = state
        .meta_db
        .get_user_by_oauth(&identity.provider, &identity.subject)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?
    {
        return finish_oauth_login(
            state,
            &user.id,
            &user.email,
            &user.tenant_id,
            user.email_verified,
            access_token.clone(),
            expires_in,
        );
    }

    let tenant_id = default_tenant_from_email(&identity.email)
        .ok_or((StatusCode::BAD_REQUEST, "could not derive tenant_id"))?;

    let user_id = new_user_id();
    let new_user = NewOAuthUser {
        id: user_id.clone(),
        email: identity.email.clone(),
        tenant_id: tenant_id.clone(),
        oauth_provider: identity.provider.clone(),
        oauth_subject: identity.subject.clone(),
        email_verified: identity.email_verified,
    };
    if let Err(e) = state
        .meta_db
        .create_oauth_user_account(&new_user, OAUTH_PASSWORD_SENTINEL)
        .await
    {
        if is_unique_violation(&e) {
            // Race or email collision — try lookup again.
            if let Some(user) = state
                .meta_db
                .get_user_by_oauth(&identity.provider, &identity.subject)
                .await
                .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?
            {
                return finish_oauth_login(
                    state,
                    &user.id,
                    &user.email,
                    &user.tenant_id,
                    user.email_verified,
                    access_token.clone(),
                    expires_in,
                );
            }
            return Err((StatusCode::CONFLICT, "email already registered"));
        }
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "database error"));
    }

    let _ = state
        .meta_db
        .set_plan_tier(Some(&tenant_id), PlanTier::Free)
        .await;

    finish_oauth_login(
        state,
        &user_id,
        &identity.email,
        &tenant_id,
        identity.email_verified,
        access_token,
        expires_in,
    )
}

fn finish_oauth_login(
    state: &AuthHttpState,
    user_id: &str,
    email: &str,
    tenant_id: &str,
    email_verified: bool,
    access_token: Option<String>,
    expires_in: Option<u64>,
) -> Result<AuthTokenResponse, (StatusCode, &'static str)> {
    if state.jwt.mode == JwtMode::AuthArcana {
        if let Some(token) = access_token {
            let expires = expires_in.unwrap_or(state.jwt.token_ttl_secs);
            return Ok(build_external_token_response(
                token,
                expires,
                user_id,
                email,
                tenant_id,
                email_verified,
            ));
        }
    }
    build_token_response(state, user_id, email, tenant_id, email_verified)
}

fn encode_stub_code(provider: &str, subject: &str, email: &str) -> String {
    let payload = format!("stub.v1|{provider}|{subject}|{email}");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.as_bytes())
}

fn parse_stub_code(code: &str) -> Result<OAuthIdentity, (StatusCode, &'static str)> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(code)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid oauth code"))?;
    let payload =
        String::from_utf8(bytes).map_err(|_| (StatusCode::BAD_REQUEST, "invalid oauth code"))?;
    let mut parts = payload.splitn(4, '|');
    let version = parts
        .next()
        .ok_or((StatusCode::BAD_REQUEST, "invalid oauth code"))?;
    if version != "stub.v1" {
        return Err((StatusCode::BAD_REQUEST, "invalid oauth code"));
    }
    let provider = parts
        .next()
        .ok_or((StatusCode::BAD_REQUEST, "invalid oauth code"))?
        .to_owned();
    let subject = parts
        .next()
        .ok_or((StatusCode::BAD_REQUEST, "invalid oauth code"))?
        .to_owned();
    let email = normalize_email(
        parts
            .next()
            .ok_or((StatusCode::BAD_REQUEST, "invalid oauth code"))?,
    );
    if !validate_email(&email) {
        return Err((StatusCode::BAD_REQUEST, "invalid oauth code"));
    }
    Ok(OAuthIdentity {
        provider,
        subject,
        email,
        email_verified: true,
    })
}

fn issue_oauth_state(
    signing_key: &[u8],
    provider: &str,
) -> Result<String, (StatusCode, &'static str)> {
    let mut nonce = [0u8; 16];
    rand::rng().fill_bytes(&mut nonce);
    let nonce_hex = hex::encode(nonce);
    let exp = unix_now() + 600;
    let payload = format!("{provider}:{nonce_hex}:{exp}");
    let sig = sign_state(signing_key, &payload)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "state issue failed"))?;
    Ok(format!("{payload}.{sig}"))
}

fn verify_oauth_state(signing_key: &[u8], state: &str) -> Result<(), (StatusCode, &'static str)> {
    let (payload, sig) = state
        .rsplit_once('.')
        .ok_or((StatusCode::BAD_REQUEST, "invalid state"))?;
    let expected =
        sign_state(signing_key, payload).map_err(|_| (StatusCode::BAD_REQUEST, "invalid state"))?;
    if subtle::ConstantTimeEq::ct_eq(expected.as_bytes(), sig.as_bytes()).into() {
        let exp: i64 = payload
            .rsplit_once(':')
            .and_then(|(_, exp)| exp.parse().ok())
            .ok_or((StatusCode::BAD_REQUEST, "invalid state"))?;
        if unix_now() > exp {
            return Err((StatusCode::BAD_REQUEST, "state expired"));
        }
        Ok(())
    } else {
        Err((StatusCode::BAD_REQUEST, "invalid state"))
    }
}

fn sign_state(signing_key: &[u8], payload: &str) -> Result<String, ()> {
    let mut mac = HmacSha256::new_from_slice(signing_key).map_err(|_| ())?;
    mac.update(payload.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn random_hex(n: usize) -> String {
    let mut buf = vec![0u8; n];
    rand::rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

fn unix_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
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
    fn stub_code_round_trip() {
        let code = encode_stub_code("google", "sub123", "user@example.com");
        let id = parse_stub_code(&code).unwrap();
        assert_eq!(id.provider, "google");
        assert_eq!(id.subject, "sub123");
        assert_eq!(id.email, "user@example.com");
        assert!(id.email_verified);
    }

    #[test]
    fn oauth_state_round_trip() {
        let key = b"01234567890123456789012345678901";
        let state = issue_oauth_state(key, "google").unwrap();
        verify_oauth_state(key, &state).unwrap();
    }
}
