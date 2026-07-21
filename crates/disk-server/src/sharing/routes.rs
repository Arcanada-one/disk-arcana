//! HTTP handlers for `/sharing/*` (DISK-0022).

use std::sync::Arc;

use axum::extract::Query;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use disk_core::meta_db::VaultShareRole;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::accounts::routes::{resolve_user_from_access, verify_bearer, AuthHttpState};

#[derive(Debug, Deserialize)]
pub struct CreateInviteRequest {
    #[serde(default = "default_vault")]
    pub vault_id: String,
    pub role: String,
    #[serde(default = "default_ttl_hours")]
    pub ttl_hours: u32,
}

#[derive(Debug, Deserialize)]
pub struct ListInvitesQuery {
    #[serde(default = "default_vault")]
    pub vault_id: String,
}

#[derive(Debug, Deserialize)]
pub struct AcceptInviteRequest {
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct ListMembersQuery {
    #[serde(default = "default_vault")]
    pub vault_id: String,
}

#[derive(Debug, Deserialize)]
pub struct RemoveMemberRequest {
    #[serde(default = "default_vault")]
    pub vault_id: String,
    pub user_id: String,
}

fn default_vault() -> String {
    "default".into()
}

fn default_ttl_hours() -> u32 {
    168
}

#[derive(Debug, Serialize)]
pub struct InviteResponse {
    pub invite_id: String,
    pub vault_id: String,
    pub role: String,
    pub expires_at: i64,
    pub invite_token: String,
    pub invite_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct InviteListResponse {
    pub vault_id: String,
    pub invites: Vec<InviteSummary>,
}

#[derive(Debug, Serialize)]
pub struct InviteSummary {
    pub invite_id: String,
    pub role: String,
    pub expires_at: i64,
    pub redeemed: bool,
    pub created_at: i64,
}

#[derive(Debug, Serialize)]
pub struct AcceptInviteResponse {
    pub accepted: bool,
    pub vault_id: String,
    pub tenant_id: String,
    pub role: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct MemberListResponse {
    pub vault_id: String,
    pub owning_tenant_id: String,
    pub members: Vec<MemberEntry>,
}

#[derive(Debug, Serialize)]
pub struct MemberEntry {
    pub user_id: String,
    pub email: String,
    pub role: String,
    pub granted_by: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Serialize)]
pub struct RemoveMemberResponse {
    pub removed: bool,
    pub user_id: String,
    pub vault_id: String,
}

async fn assert_vault_manager(
    state: &AuthHttpState,
    user_tenant: &str,
    vault_id: &str,
) -> Result<(), (StatusCode, &'static str)> {
    let tenant_key = Some(user_tenant);
    if !state
        .meta_db
        .vault_exists_for_tenant(tenant_key, vault_id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?
    {
        return Err((StatusCode::NOT_FOUND, "vault not found"));
    }
    Ok(())
}

fn parse_share_role(raw: &str) -> Result<VaultShareRole, (StatusCode, &'static str)> {
    VaultShareRole::parse(raw).ok_or((StatusCode::BAD_REQUEST, "invalid role"))
}

fn new_invite_id() -> String {
    let mut raw = [0u8; 8];
    rand::rng().fill_bytes(&mut raw);
    format!("inv_{}", hex::encode(raw))
}

fn issue_invite_token() -> ([u8; 32], String) {
    let mut raw = [0u8; 32];
    rand::rng().fill_bytes(&mut raw);
    let token = hex::encode(raw);
    (raw, token)
}

fn token_hash(raw: &[u8; 32]) -> [u8; 32] {
    *blake3::hash(raw).as_bytes()
}

pub async fn create_invite(
    axum::extract::State(state): axum::extract::State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    Json(body): Json<CreateInviteRequest>,
) -> impl IntoResponse {
    match create_invite_inner(&state, &headers, body).await {
        Ok(resp) => (StatusCode::CREATED, Json(resp)).into_response(),
        Err((code, msg)) => (code, Json(json!({ "error": msg }))).into_response(),
    }
}

async fn create_invite_inner(
    state: &AuthHttpState,
    headers: &HeaderMap,
    body: CreateInviteRequest,
) -> Result<InviteResponse, (StatusCode, &'static str)> {
    let claims = verify_bearer(state, headers).await?;
    let user = resolve_user_from_access(state, &claims).await?;
    assert_vault_manager(state, &user.tenant_id, &body.vault_id).await?;

    let role = parse_share_role(&body.role)?;
    let ttl_secs = (body.ttl_hours.clamp(1, 24 * 30) as i64) * 3600;
    let expires_at = unix_now() + ttl_secs;

    let (raw, token) = issue_invite_token();
    let hash = token_hash(&raw);
    let invite_id = new_invite_id();
    let tenant_key = Some(user.tenant_id.as_str());

    state
        .meta_db
        .insert_vault_invite(
            &invite_id,
            tenant_key,
            &body.vault_id,
            &hash,
            role,
            &user.id,
            expires_at,
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    let invite_url = state.email_verify.public_base_url.as_deref().map(|base| {
        format!(
            "{}/dashboard/?sharing_accept={}",
            base.trim_end_matches('/'),
            urlencoding::encode(&token)
        )
    });

    Ok(InviteResponse {
        invite_id,
        vault_id: body.vault_id,
        role: role.as_str().to_string(),
        expires_at,
        invite_token: token,
        invite_url,
    })
}

pub async fn list_invites(
    axum::extract::State(state): axum::extract::State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    Query(query): Query<ListInvitesQuery>,
) -> impl IntoResponse {
    match list_invites_inner(&state, &headers, query).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err((code, msg)) => (code, Json(json!({ "error": msg }))).into_response(),
    }
}

async fn list_invites_inner(
    state: &AuthHttpState,
    headers: &HeaderMap,
    query: ListInvitesQuery,
) -> Result<InviteListResponse, (StatusCode, &'static str)> {
    let claims = verify_bearer(state, headers).await?;
    let user = resolve_user_from_access(state, &claims).await?;
    assert_vault_manager(state, &user.tenant_id, &query.vault_id).await?;

    let rows = state
        .meta_db
        .list_vault_invites(Some(user.tenant_id.as_str()), &query.vault_id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    let invites = rows
        .into_iter()
        .map(|row| InviteSummary {
            invite_id: row.id,
            role: row.role.as_str().to_string(),
            expires_at: row.expires_at,
            redeemed: row.redeemed_at.is_some(),
            created_at: row.created_at,
        })
        .collect();

    Ok(InviteListResponse {
        vault_id: query.vault_id,
        invites,
    })
}

pub async fn accept_invite(
    axum::extract::State(state): axum::extract::State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    Json(body): Json<AcceptInviteRequest>,
) -> impl IntoResponse {
    match accept_invite_inner(&state, &headers, body).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err((code, msg)) => (code, Json(json!({ "error": msg }))).into_response(),
    }
}

async fn accept_invite_inner(
    state: &AuthHttpState,
    headers: &HeaderMap,
    body: AcceptInviteRequest,
) -> Result<AcceptInviteResponse, (StatusCode, &'static str)> {
    let claims = verify_bearer(state, headers).await?;
    let user = resolve_user_from_access(state, &claims).await?;

    let raw =
        hex::decode(body.token.trim()).map_err(|_| (StatusCode::BAD_REQUEST, "invalid token"))?;
    if raw.len() != 32 {
        return Err((StatusCode::BAD_REQUEST, "invalid token"));
    }
    let mut token_bytes = [0u8; 32];
    token_bytes.copy_from_slice(&raw);
    let hash = token_hash(&token_bytes);

    let invite = state
        .meta_db
        .get_vault_invite_by_token_hash(&hash)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?
        .ok_or((StatusCode::NOT_FOUND, "invite not found"))?;

    if invite.redeemed_at.is_some() {
        return Err((StatusCode::CONFLICT, "invite already redeemed"));
    }
    if invite.expires_at < unix_now() {
        return Err((StatusCode::GONE, "invite expired"));
    }

    let redeemed = state
        .meta_db
        .redeem_vault_invite(&invite.id, &user.id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;
    if !redeemed {
        return Err((StatusCode::CONFLICT, "invite already redeemed"));
    }

    state
        .meta_db
        .upsert_vault_member(
            invite.tenant_id.as_deref(),
            &invite.vault_id,
            &user.id,
            invite.role,
            &invite.created_by,
        )
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    let tenant_id = invite.tenant_id.unwrap_or_else(|| "default".into());
    let message = format!(
        "Joined vault {} as {}",
        invite.vault_id,
        invite.role.as_str()
    );

    Ok(AcceptInviteResponse {
        accepted: true,
        vault_id: invite.vault_id,
        tenant_id,
        role: invite.role.as_str().to_string(),
        message,
    })
}

pub async fn list_members(
    axum::extract::State(state): axum::extract::State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    Query(query): Query<ListMembersQuery>,
) -> impl IntoResponse {
    match list_members_inner(&state, &headers, query).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err((code, msg)) => (code, Json(json!({ "error": msg }))).into_response(),
    }
}

async fn list_members_inner(
    state: &AuthHttpState,
    headers: &HeaderMap,
    query: ListMembersQuery,
) -> Result<MemberListResponse, (StatusCode, &'static str)> {
    let claims = verify_bearer(state, headers).await?;
    let user = resolve_user_from_access(state, &claims).await?;
    assert_vault_manager(state, &user.tenant_id, &query.vault_id).await?;

    let rows = state
        .meta_db
        .list_vault_members(Some(user.tenant_id.as_str()), &query.vault_id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    let members = rows
        .into_iter()
        .map(|row| MemberEntry {
            user_id: row.user_id,
            email: row.email,
            role: row.role.as_str().to_string(),
            granted_by: row.granted_by,
            created_at: row.created_at,
        })
        .collect();

    Ok(MemberListResponse {
        vault_id: query.vault_id,
        owning_tenant_id: user.tenant_id,
        members,
    })
}

pub async fn remove_member(
    axum::extract::State(state): axum::extract::State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    Json(body): Json<RemoveMemberRequest>,
) -> impl IntoResponse {
    match remove_member_inner(&state, &headers, body).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err((code, msg)) => (code, Json(json!({ "error": msg }))).into_response(),
    }
}

async fn remove_member_inner(
    state: &AuthHttpState,
    headers: &HeaderMap,
    body: RemoveMemberRequest,
) -> Result<RemoveMemberResponse, (StatusCode, &'static str)> {
    let claims = verify_bearer(state, headers).await?;
    let user = resolve_user_from_access(state, &claims).await?;
    assert_vault_manager(state, &user.tenant_id, &body.vault_id).await?;

    let removed = state
        .meta_db
        .remove_vault_member(Some(user.tenant_id.as_str()), &body.vault_id, &body.user_id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "database error"))?;

    if !removed {
        return Err((StatusCode::NOT_FOUND, "member not found"));
    }

    Ok(RemoveMemberResponse {
        removed: true,
        user_id: body.user_id,
        vault_id: body.vault_id,
    })
}

fn unix_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::health;
    use disk_core::meta_db::MetaDb;
    use std::time::Duration;
    use tempfile::tempdir;

    async fn spawn_auth_server(meta_db: MetaDb) -> u16 {
        let bundle = crate::accounts::routes::auth_http_state_for_tests(meta_db);
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
    async fn sharing_invite_accept_round_trip() {
        let dir = tempdir().unwrap();
        let meta_db = MetaDb::open(&dir.path().join("sharing.sqlite"))
            .await
            .unwrap();

        let email_owner = disk_core::normalize_email("owner@corp.test");
        let hash_pw = disk_core::hash_password("long-password").unwrap();
        meta_db
            .create_user_account("own1", &email_owner, &hash_pw, "corp")
            .await
            .unwrap();

        let email_guest = disk_core::normalize_email("guest@other.test");
        meta_db
            .create_user_account("gst1", &email_guest, &hash_pw, "other")
            .await
            .unwrap();

        sqlx::query(
            "INSERT INTO tenant_vaults (tenant_id, vault_id, created_at) VALUES ('corp', 'wiki', 1)",
        )
        .execute(meta_db.pool())
        .await
        .unwrap();

        let port = spawn_auth_server(meta_db).await;
        let client = reqwest::Client::new();

        let login_owner: serde_json::Value = client
            .post(format!("http://127.0.0.1:{port}/auth/login"))
            .json(&json!({ "email": email_owner, "password": "long-password" }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let owner_token = login_owner["access_token"].as_str().unwrap();

        let invite: serde_json::Value = client
            .post(format!("http://127.0.0.1:{port}/sharing/invites"))
            .bearer_auth(owner_token)
            .json(&json!({ "vault_id": "wiki", "role": "viewer", "ttl_hours": 24 }))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        let invite_token = invite["invite_token"].as_str().unwrap();

        let login_guest: serde_json::Value = client
            .post(format!("http://127.0.0.1:{port}/auth/login"))
            .json(&json!({ "email": email_guest, "password": "long-password" }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let guest_token = login_guest["access_token"].as_str().unwrap();

        let accept: serde_json::Value = client
            .post(format!("http://127.0.0.1:{port}/sharing/invites/accept"))
            .bearer_auth(guest_token)
            .json(&json!({ "token": invite_token }))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(accept["accepted"].as_bool(), Some(true));

        let members: serde_json::Value = client
            .get(format!(
                "http://127.0.0.1:{port}/sharing/members?vault_id=wiki"
            ))
            .bearer_auth(owner_token)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(members["members"].as_array().unwrap().len(), 1);
    }
}
