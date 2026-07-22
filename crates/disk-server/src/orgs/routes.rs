//! HTTP handlers for `/orgs/*` (DISK-0030 slice 1).

use std::sync::Arc;

use axum::extract::Query;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use disk_core::meta_db::OrgRole;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::accounts::routes::{resolve_user_from_access, verify_bearer, AuthHttpState};

#[derive(Debug, Deserialize)]
pub struct CreateOrgRequest {
    pub name: String,
    pub slug: String,
}

#[derive(Debug, Deserialize)]
pub struct ListMembersQuery {
    pub org_id: String,
}

#[derive(Debug, Deserialize)]
pub struct AddMemberRequest {
    pub org_id: String,
    pub email: String,
    pub role: String,
}

#[derive(Debug, Serialize)]
pub struct OrgSummary {
    pub org_id: String,
    pub slug: String,
    pub name: String,
    pub tenant_id: String,
    pub role: String,
}

#[derive(Debug, Serialize)]
pub struct CreateOrgResponse {
    pub org_id: String,
    pub slug: String,
    pub name: String,
    pub tenant_id: String,
    pub role: String,
}

#[derive(Debug, Serialize)]
pub struct OrgListResponse {
    pub orgs: Vec<OrgSummary>,
}

#[derive(Debug, Serialize)]
pub struct OrgMemberEntry {
    pub user_id: String,
    pub email: String,
    pub role: String,
    pub created_at: i64,
}

#[derive(Debug, Serialize)]
pub struct OrgMemberListResponse {
    pub org_id: String,
    pub members: Vec<OrgMemberEntry>,
}

#[derive(Debug, Serialize)]
pub struct AddMemberResponse {
    pub added: bool,
    pub org_id: String,
    pub user_id: String,
    pub email: String,
    pub role: String,
}

fn new_org_id() -> String {
    let mut raw = [0u8; 8];
    rand::rng().fill_bytes(&mut raw);
    format!("org_{}", hex::encode(raw))
}

fn unix_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn org_summary(org: &disk_core::meta_db::OrganizationRow, role: OrgRole) -> OrgSummary {
    OrgSummary {
        org_id: org.id.clone(),
        slug: org.slug.clone(),
        name: org.name.clone(),
        tenant_id: org.tenant_id.clone(),
        role: role.as_str().to_string(),
    }
}

/// `POST /orgs` — create organization; caller becomes owner.
pub async fn create_org(
    headers: HeaderMap,
    state: axum::extract::State<Arc<AuthHttpState>>,
    Json(body): Json<CreateOrgRequest>,
) -> impl IntoResponse {
    let claims = match verify_bearer(&state, &headers).await {
        Ok(c) => c,
        Err((status, msg)) => return (status, msg).into_response(),
    };
    let user = match resolve_user_from_access(&state, &claims).await {
        Ok(u) => u,
        Err((status, msg)) => return (status, msg).into_response(),
    };

    let name = body.name.trim();
    if name.is_empty() || name.len() > 128 {
        return (StatusCode::BAD_REQUEST, "invalid name").into_response();
    }

    let slug = match disk_core::sanitize_tenant_slug(body.slug.trim()) {
        Some(s) => s,
        None => return (StatusCode::BAD_REQUEST, "invalid slug").into_response(),
    };

    if state
        .meta_db
        .organization_slug_taken(&slug)
        .await
        .unwrap_or(true)
    {
        return (StatusCode::CONFLICT, "slug taken").into_response();
    }

    let org_id = new_org_id();
    let now = unix_now();
    if state
        .meta_db
        .create_organization(&org_id, &slug, name, &slug, &user.id, now)
        .await
        .is_err()
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response();
    }
    if state
        .meta_db
        .add_organization_member(&org_id, &user.id, OrgRole::Owner, now)
        .await
        .is_err()
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response();
    }

    (
        StatusCode::CREATED,
        Json(CreateOrgResponse {
            org_id: org_id.clone(),
            slug: slug.clone(),
            name: name.to_string(),
            tenant_id: slug,
            role: OrgRole::Owner.as_str().to_string(),
        }),
    )
        .into_response()
}

/// `GET /orgs` — list organizations for the authenticated user.
pub async fn list_orgs(
    headers: HeaderMap,
    state: axum::extract::State<Arc<AuthHttpState>>,
) -> impl IntoResponse {
    let claims = match verify_bearer(&state, &headers).await {
        Ok(c) => c,
        Err((status, msg)) => return (status, msg).into_response(),
    };
    let user = match resolve_user_from_access(&state, &claims).await {
        Ok(u) => u,
        Err((status, msg)) => return (status, msg).into_response(),
    };

    let rows = match state.meta_db.list_user_organizations(&user.id).await {
        Ok(r) => r,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response(),
    };

    let orgs = rows
        .into_iter()
        .map(|row| org_summary(&row.organization, row.role))
        .collect();

    Json(OrgListResponse { orgs }).into_response()
}

/// `GET /orgs/members?org_id=` — list organization members.
pub async fn list_members(
    headers: HeaderMap,
    state: axum::extract::State<Arc<AuthHttpState>>,
    Query(query): Query<ListMembersQuery>,
) -> impl IntoResponse {
    let claims = match verify_bearer(&state, &headers).await {
        Ok(c) => c,
        Err((status, msg)) => return (status, msg).into_response(),
    };
    let user = match resolve_user_from_access(&state, &claims).await {
        Ok(u) => u,
        Err((status, msg)) => return (status, msg).into_response(),
    };

    let role = match state
        .meta_db
        .get_org_member_role(&query.org_id, &user.id)
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::FORBIDDEN, "not a member").into_response(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response(),
    };
    let _ = role;

    let members = match state.meta_db.list_organization_members(&query.org_id).await {
        Ok(m) => m,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response(),
    };

    Json(OrgMemberListResponse {
        org_id: query.org_id,
        members: members
            .into_iter()
            .map(|m| OrgMemberEntry {
                user_id: m.user_id,
                email: m.email,
                role: m.role.as_str().to_string(),
                created_at: m.created_at,
            })
            .collect(),
    })
    .into_response()
}

/// `POST /orgs/members` — add an existing user to the organization (admin+).
pub async fn add_member(
    headers: HeaderMap,
    state: axum::extract::State<Arc<AuthHttpState>>,
    Json(body): Json<AddMemberRequest>,
) -> impl IntoResponse {
    let claims = match verify_bearer(&state, &headers).await {
        Ok(c) => c,
        Err((status, msg)) => return (status, msg).into_response(),
    };
    let user = match resolve_user_from_access(&state, &claims).await {
        Ok(u) => u,
        Err((status, msg)) => return (status, msg).into_response(),
    };

    let actor_role = match state
        .meta_db
        .get_org_member_role(&body.org_id, &user.id)
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::FORBIDDEN, "not a member").into_response(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response(),
    };
    if !actor_role.can_manage_members() {
        return (StatusCode::FORBIDDEN, "admin required").into_response();
    }

    let role = match OrgRole::parse(body.role.trim()) {
        Some(OrgRole::Member) | Some(OrgRole::Admin) => OrgRole::parse(body.role.trim()).unwrap(),
        Some(OrgRole::Owner) => {
            return (StatusCode::BAD_REQUEST, "cannot assign owner via invite").into_response();
        }
        None => return (StatusCode::BAD_REQUEST, "invalid role").into_response(),
    };

    let email = disk_core::normalize_email(&body.email);
    let target = match state.meta_db.get_user_by_email(&email).await {
        Ok(Some(u)) => u,
        Ok(None) => return (StatusCode::NOT_FOUND, "user not found").into_response(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response(),
    };

    if state
        .meta_db
        .get_org_member_role(&body.org_id, &target.id)
        .await
        .ok()
        .flatten()
        .is_some()
    {
        return (StatusCode::CONFLICT, "already a member").into_response();
    }

    let now = unix_now();
    if state
        .meta_db
        .add_organization_member(&body.org_id, &target.id, role, now)
        .await
        .is_err()
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response();
    }

    (
        StatusCode::CREATED,
        Json(AddMemberResponse {
            added: true,
            org_id: body.org_id,
            user_id: target.id,
            email,
            role: role.as_str().to_string(),
        }),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
pub struct PutOrgContextRequest {
    pub org_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct OrgContextOrganization {
    pub org_id: String,
    pub slug: String,
    pub name: String,
    pub tenant_id: String,
    pub role: String,
}

#[derive(Debug, Serialize)]
pub struct OrgContextResponse {
    pub mode: String,
    pub active_org_id: Option<String>,
    pub active_tenant_id: String,
    pub personal_tenant_id: String,
    pub organization: Option<OrgContextOrganization>,
}

async fn build_org_context(
    state: &AuthHttpState,
    user: &disk_core::meta_db::UserAccount,
) -> Result<OrgContextResponse, (StatusCode, &'static str)> {
    let active_org_id = state
        .meta_db
        .get_user_org_context(&user.id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?;

    if let Some(org_id) = active_org_id.as_deref() {
        let role = match state
            .meta_db
            .get_org_member_role(org_id, &user.id)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?
        {
            Some(r) => r,
            None => {
                let _ = state
                    .meta_db
                    .set_user_org_context(&user.id, None, unix_now())
                    .await;
                return Ok(OrgContextResponse {
                    mode: "personal".into(),
                    active_org_id: None,
                    active_tenant_id: user.tenant_id.clone(),
                    personal_tenant_id: user.tenant_id.clone(),
                    organization: None,
                });
            }
        };
        let org = state
            .meta_db
            .get_organization(org_id)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db error"))?
            .ok_or((StatusCode::NOT_FOUND, "organization not found"))?;
        return Ok(OrgContextResponse {
            mode: "organization".into(),
            active_org_id: Some(org_id.to_string()),
            active_tenant_id: org.tenant_id.clone(),
            personal_tenant_id: user.tenant_id.clone(),
            organization: Some(OrgContextOrganization {
                org_id: org.id,
                slug: org.slug,
                name: org.name,
                tenant_id: org.tenant_id,
                role: role.as_str().to_string(),
            }),
        });
    }

    Ok(OrgContextResponse {
        mode: "personal".into(),
        active_org_id: None,
        active_tenant_id: user.tenant_id.clone(),
        personal_tenant_id: user.tenant_id.clone(),
        organization: None,
    })
}

/// `GET /orgs/context` — active workspace (personal vs organization).
pub async fn get_org_context(
    headers: HeaderMap,
    state: axum::extract::State<Arc<AuthHttpState>>,
) -> impl IntoResponse {
    let claims = match verify_bearer(&state, &headers).await {
        Ok(c) => c,
        Err((status, msg)) => return (status, msg).into_response(),
    };
    let user = match resolve_user_from_access(&state, &claims).await {
        Ok(u) => u,
        Err((status, msg)) => return (status, msg).into_response(),
    };

    match build_org_context(&state, &user).await {
        Ok(resp) => Json(resp).into_response(),
        Err((status, msg)) => (status, msg).into_response(),
    }
}

/// `PUT /orgs/context` — switch active workspace.
pub async fn put_org_context(
    headers: HeaderMap,
    state: axum::extract::State<Arc<AuthHttpState>>,
    Json(body): Json<PutOrgContextRequest>,
) -> impl IntoResponse {
    let claims = match verify_bearer(&state, &headers).await {
        Ok(c) => c,
        Err((status, msg)) => return (status, msg).into_response(),
    };
    let user = match resolve_user_from_access(&state, &claims).await {
        Ok(u) => u,
        Err((status, msg)) => return (status, msg).into_response(),
    };

    let org_id = match body.org_id.as_deref() {
        None | Some("") => None,
        Some(id) => match state.meta_db.get_org_member_role(id, &user.id).await {
            Ok(Some(_)) => Some(id),
            Ok(None) => return (StatusCode::FORBIDDEN, "not a member").into_response(),
            Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response(),
        },
    };

    if state
        .meta_db
        .set_user_org_context(&user.id, org_id, unix_now())
        .await
        .is_err()
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response();
    }

    match build_org_context(&state, &user).await {
        Ok(resp) => Json(resp).into_response(),
        Err((status, msg)) => (status, msg).into_response(),
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::health;
    use disk_core::meta_db::MetaDb;
    use serde_json::json;
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
    async fn org_create_add_member_round_trip() {
        let dir = tempdir().unwrap();
        let meta_db = MetaDb::open(&dir.path().join("orgs-http.sqlite"))
            .await
            .unwrap();

        let email_owner = disk_core::normalize_email("owner@corp.test");
        let hash_pw = disk_core::hash_password("long-password").unwrap();
        meta_db
            .create_user_account("own1", &email_owner, &hash_pw, "corp")
            .await
            .unwrap();

        let email_member = disk_core::normalize_email("member@corp.test");
        meta_db
            .create_user_account("mem1", &email_member, &hash_pw, "member")
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

        let created: serde_json::Value = client
            .post(format!("http://127.0.0.1:{port}/orgs"))
            .bearer_auth(owner_token)
            .json(&json!({ "name": "Corp Team", "slug": "corp-team" }))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        let org_id = created["org_id"].as_str().unwrap();

        let added: serde_json::Value = client
            .post(format!("http://127.0.0.1:{port}/orgs/members"))
            .bearer_auth(owner_token)
            .json(&json!({
                "org_id": org_id,
                "email": email_member,
                "role": "member"
            }))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(added["added"].as_bool(), Some(true));

        let members: serde_json::Value = client
            .get(format!(
                "http://127.0.0.1:{port}/orgs/members?org_id={org_id}"
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
        assert_eq!(members["members"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn org_context_switch_round_trip() {
        let dir = tempdir().unwrap();
        let meta_db = MetaDb::open(&dir.path().join("orgs-ctx-http.sqlite"))
            .await
            .unwrap();

        let email = disk_core::normalize_email("owner@corp.test");
        let hash_pw = disk_core::hash_password("long-password").unwrap();
        meta_db
            .create_user_account("own1", &email, &hash_pw, "corp")
            .await
            .unwrap();

        let port = spawn_auth_server(meta_db).await;
        let client = reqwest::Client::new();

        let login: serde_json::Value = client
            .post(format!("http://127.0.0.1:{port}/auth/login"))
            .json(&json!({ "email": email, "password": "long-password" }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let token = login["access_token"].as_str().unwrap();

        let created: serde_json::Value = client
            .post(format!("http://127.0.0.1:{port}/orgs"))
            .bearer_auth(token)
            .json(&json!({ "name": "Corp Team", "slug": "corp-team" }))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        let org_id = created["org_id"].as_str().unwrap();

        let personal: serde_json::Value = client
            .get(format!("http://127.0.0.1:{port}/orgs/context"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(personal["mode"].as_str(), Some("personal"));

        let switched: serde_json::Value = client
            .put(format!("http://127.0.0.1:{port}/orgs/context"))
            .bearer_auth(token)
            .json(&json!({ "org_id": org_id }))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(switched["mode"].as_str(), Some("organization"));
        assert_eq!(switched["active_tenant_id"].as_str(), Some("corp-team"));
    }
}
