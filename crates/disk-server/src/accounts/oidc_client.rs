//! Shared OIDC discovery helpers for Auth Arcana RP (DISK-0016 slice 5).

use axum::http::StatusCode;

use super::oauth::OAuthConfig;

pub(crate) struct TokenGrantResponse {
    pub access_token: String,
    pub expires_in: Option<u64>,
    pub refresh_token: Option<String>,
}

pub(crate) struct OidcDiscovery {
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
}

pub(crate) async fn fetch_oidc_discovery(
    oauth: &OAuthConfig,
) -> Result<OidcDiscovery, (StatusCode, &'static str)> {
    let issuer = oauth.issuer.as_deref().ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "oauth issuer not configured",
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
        .ok_or((StatusCode::BAD_GATEWAY, "oidc token_endpoint missing"))?
        .to_owned();
    let userinfo_endpoint = discovery["userinfo_endpoint"]
        .as_str()
        .ok_or((StatusCode::BAD_GATEWAY, "oidc userinfo_endpoint missing"))?
        .to_owned();

    Ok(OidcDiscovery {
        token_endpoint,
        userinfo_endpoint,
    })
}

pub(crate) async fn fetch_token_endpoint(
    oauth: &OAuthConfig,
) -> Result<String, (StatusCode, &'static str)> {
    Ok(fetch_oidc_discovery(oauth).await?.token_endpoint)
}

pub(crate) async fn exchange_refresh_token(
    oauth: &OAuthConfig,
    refresh_token: &str,
) -> Result<TokenGrantResponse, (StatusCode, &'static str)> {
    let token_endpoint = fetch_token_endpoint(oauth).await?;
    let client_id = oauth.client_id.as_deref().ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "oauth client_id not configured",
    ))?;
    let client_secret = oauth.client_secret.as_deref().ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "oauth client_secret not configured",
    ))?;

    let token_resp: serde_json::Value = reqwest::Client::new()
        .post(&token_endpoint)
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", client_id),
            ("client_secret", client_secret),
        ])
        .send()
        .await
        .map_err(|_| (StatusCode::BAD_GATEWAY, "token refresh failed"))?
        .error_for_status()
        .map_err(|_| (StatusCode::BAD_GATEWAY, "token refresh rejected"))?
        .json()
        .await
        .map_err(|_| (StatusCode::BAD_GATEWAY, "token response invalid"))?;

    let access_token = token_resp["access_token"]
        .as_str()
        .ok_or((StatusCode::BAD_GATEWAY, "access_token missing"))?
        .to_owned();
    let expires_in = token_resp["expires_in"].as_u64();
    let refresh_token = token_resp["refresh_token"].as_str().map(str::to_owned);

    Ok(TokenGrantResponse {
        access_token,
        expires_in,
        refresh_token,
    })
}
