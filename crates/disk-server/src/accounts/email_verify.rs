//! Email verification flow — HMAC tokens + stub/log delivery (DISK-0016 slice 3).

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;
use tracing::info;

use super::email_verify_mode::EmailVerifyMode;
use super::routes::{bearer_token, build_token_response, AuthHttpState, AuthTokenResponse};

type HmacSha256 = Hmac<Sha256>;

/// Email verification runtime configuration wired into [`AuthHttpState`].
#[derive(Debug, Clone)]
pub struct EmailVerifyConfig {
    pub mode: EmailVerifyMode,
    /// Public base URL for stub verification links (e.g. `http://127.0.0.1:9446`).
    pub public_base_url: Option<String>,
    /// Verification token TTL seconds (default 24h).
    pub token_ttl_secs: u64,
}

#[derive(Debug, Deserialize)]
pub struct VerifyEmailQuery {
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct ResendVerificationResponse {
    pub sent: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_url: Option<String>,
}

/// Optional verification fields attached to signup when verification is active.
#[derive(Debug, Clone, Default, Serialize)]
pub struct VerificationDelivery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_url: Option<String>,
}

pub async fn verify_email(
    State(state): State<Arc<AuthHttpState>>,
    Query(query): Query<VerifyEmailQuery>,
) -> impl IntoResponse {
    match verify_email_inner(&state, &query.token).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err((code, msg)) => (code, Json(json!({ "error": msg }))).into_response(),
    }
}

pub async fn resend_verification(
    State(state): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    match resend_verification_inner(&state, &headers).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err((code, msg)) => (code, Json(json!({ "error": msg }))).into_response(),
    }
}

/// Issue verification delivery for a newly registered password user.
pub fn deliver_verification(
    state: &AuthHttpState,
    user_id: &str,
) -> Result<VerificationDelivery, (StatusCode, &'static str)> {
    if !state.email_verify.mode.is_active() {
        return Ok(VerificationDelivery::default());
    }

    let token = issue_verification_token(
        &state.signing_key,
        user_id,
        state.email_verify.token_ttl_secs,
    )?;
    let url = build_verification_url(state, &token)?;

    match state.email_verify.mode {
        EmailVerifyMode::Stub => Ok(VerificationDelivery {
            verification_token: Some(token),
            verification_url: url,
        }),
        EmailVerifyMode::Log => {
            if let Some(ref link) = url {
                info!(user_id, verification_url = %link, "email verification link");
            } else {
                info!(user_id, verification_token = %token, "email verification token");
            }
            Ok(VerificationDelivery::default())
        }
        EmailVerifyMode::Disabled => Ok(VerificationDelivery::default()),
    }
}

async fn verify_email_inner(
    state: &AuthHttpState,
    token: &str,
) -> Result<AuthTokenResponse, (StatusCode, &'static str)> {
    if !state.email_verify.mode.is_active() {
        return Err((StatusCode::NOT_FOUND, "email verification disabled"));
    }

    let user_id = verify_verification_token(&state.signing_key, token)?;

    let user = state
        .meta_db
        .get_user_by_id(&user_id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?
        .ok_or((StatusCode::BAD_REQUEST, "invalid token"))?;

    if user.email_verified {
        return build_token_response(state, &user.id, &user.email, &user.tenant_id, true);
    }

    state
        .meta_db
        .set_email_verified(&user.id, true)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    build_token_response(state, &user.id, &user.email, &user.tenant_id, true)
}

async fn resend_verification_inner(
    state: &AuthHttpState,
    headers: &HeaderMap,
) -> Result<ResendVerificationResponse, (StatusCode, &'static str)> {
    if !state.email_verify.mode.is_active() {
        return Err((StatusCode::NOT_FOUND, "email verification disabled"));
    }

    let bearer = bearer_token(headers).ok_or((StatusCode::UNAUTHORIZED, "missing bearer token"))?;
    let claims = disk_core::verify_token(&state.signing_key, bearer)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid token"))?;

    let user = state
        .meta_db
        .get_user_by_id(&claims.sub)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?
        .ok_or((StatusCode::UNAUTHORIZED, "user not found"))?;

    if user.email_verified {
        return Err((StatusCode::CONFLICT, "email already verified"));
    }

    let delivery = deliver_verification(state, &user.id)?;
    Ok(ResendVerificationResponse {
        sent: true,
        verification_token: delivery.verification_token,
        verification_url: delivery.verification_url,
    })
}

fn build_verification_url(
    state: &AuthHttpState,
    token: &str,
) -> Result<Option<String>, (StatusCode, &'static str)> {
    let base = state
        .email_verify
        .public_base_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    Ok(base.map(|b| {
        let base = b.trim_end_matches('/');
        format!(
            "{base}/auth/verify-email?token={}",
            urlencoding::encode(token)
        )
    }))
}

fn issue_verification_token(
    signing_key: &[u8],
    user_id: &str,
    ttl_secs: u64,
) -> Result<String, (StatusCode, &'static str)> {
    let mut nonce = [0u8; 16];
    rand::rng().fill_bytes(&mut nonce);
    let nonce_hex = hex::encode(nonce);
    let exp = unix_now() + ttl_secs as i64;
    let payload = format!("ev:{user_id}:{nonce_hex}:{exp}");
    let sig = sign_token(signing_key, &payload)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "token issue failed"))?;
    Ok(format!("{payload}.{sig}"))
}

fn verify_verification_token(
    signing_key: &[u8],
    token: &str,
) -> Result<String, (StatusCode, &'static str)> {
    let (payload, sig) = token
        .rsplit_once('.')
        .ok_or((StatusCode::BAD_REQUEST, "invalid token"))?;
    let expected =
        sign_token(signing_key, payload).map_err(|_| (StatusCode::BAD_REQUEST, "invalid token"))?;
    let valid: bool =
        subtle::ConstantTimeEq::ct_eq(expected.as_bytes(), sig.as_bytes()).into();
    if !valid {
        return Err((StatusCode::BAD_REQUEST, "invalid token"));
    }

    let rest = payload
        .strip_prefix("ev:")
        .ok_or((StatusCode::BAD_REQUEST, "invalid token"))?;
    let (user_and_nonce, exp_str) = rest
        .rsplit_once(':')
        .ok_or((StatusCode::BAD_REQUEST, "invalid token"))?;
    let exp: i64 = exp_str
        .parse()
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid token"))?;
    if unix_now() > exp {
        return Err((StatusCode::BAD_REQUEST, "token expired"));
    }
    let (user_id, _nonce) = user_and_nonce
        .rsplit_once(':')
        .ok_or((StatusCode::BAD_REQUEST, "invalid token"))?;
    Ok(user_id.to_string())
}

fn sign_token(signing_key: &[u8], payload: &str) -> Result<String, ()> {
    let mut mac = HmacSha256::new_from_slice(signing_key).map_err(|_| ())?;
    mac.update(payload.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn unix_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"01234567890123456789012345678901";

    #[test]
    fn verification_token_round_trip() {
        let token = issue_verification_token(KEY, "usr_abc123", 3600).unwrap();
        let user_id = verify_verification_token(KEY, &token).unwrap();
        assert_eq!(user_id, "usr_abc123");
    }

    #[test]
    fn verification_token_rejects_tamper() {
        let token = issue_verification_token(KEY, "usr_abc123", 3600).unwrap();
        let tampered = format!("{}x", token);
        assert!(verify_verification_token(KEY, &tampered).is_err());
    }
}
