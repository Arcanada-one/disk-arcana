//! Auth Arcana refresh-token exchange (DISK-0016 slice 5).

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use super::oauth_mode::OAuthMode;
use super::oidc_client::exchange_refresh_token;
use super::routes::{
    build_external_token_response, resolve_user_from_access, AuthHttpState, AuthTokenResponse,
};

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

pub async fn refresh_token(
    State(state): State<Arc<AuthHttpState>>,
    Json(body): Json<RefreshRequest>,
) -> impl IntoResponse {
    match refresh_token_inner(&state, body).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err((code, msg)) => (code, Json(json!({ "error": msg }))).into_response(),
    }
}

async fn refresh_token_inner(
    state: &AuthHttpState,
    body: RefreshRequest,
) -> Result<AuthTokenResponse, (StatusCode, &'static str)> {
    if state.oauth.mode != OAuthMode::AuthArcana {
        return Err((StatusCode::NOT_FOUND, "refresh not available"));
    }
    if !state.jwt.mode.allows_jwks_verify() {
        return Err((StatusCode::NOT_FOUND, "refresh not available"));
    }

    let grant = exchange_refresh_token(&state.oauth, &body.refresh_token).await?;

    let claims = state
        .jwt
        .verify(&grant.access_token)
        .await
        .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid refreshed token"))?;
    let user = resolve_user_from_access(state, &claims).await?;

    let expires = grant.expires_in.unwrap_or(state.jwt.token_ttl_secs);
    Ok(build_external_token_response(
        grant.access_token,
        expires,
        &user.id,
        &user.email,
        &user.tenant_id,
        user.email_verified,
        grant.refresh_token,
    ))
}

#[cfg(test)]
mod tests {
    use super::super::jwt_mode::JwtMode;

    #[test]
    fn refresh_blocked_in_local_jwt_mode() {
        // Compile-time guard: refresh requires JWKS-capable JWT mode.
        assert!(!JwtMode::Local.allows_jwks_verify());
    }
}
