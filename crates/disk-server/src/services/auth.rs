//! `AuthService` gRPC implementation.
//!
//! - `RegisterNode`: issues a fresh `ApiKey` (one-time; stored blake3-hashed).
//! - `Authenticate`: validates `ApiKey`, returns a 24h `SessionToken`.

use tonic::{Request, Response, Status};

use disk_proto::disk::{
    auth_service_server::AuthService, NodeAuthRequest, NodeAuthResponse, NodeRegisterRequest,
    NodeRegisterResponse,
};

use crate::auth::{check_register_gate, AuthStore};
use crate::config::RegisterNodeMode;
use sqlx::SqlitePool;

/// Concrete `AuthService` implementation.
#[derive(Debug, Clone)]
pub struct AuthServiceImpl {
    pub store: AuthStore,
    register_mode: RegisterNodeMode,
    pool: Option<SqlitePool>,
    admin_token: Option<String>,
}

impl AuthServiceImpl {
    pub fn new(store: AuthStore) -> Self {
        Self {
            store,
            register_mode: RegisterNodeMode::Open,
            pool: None,
            admin_token: None,
        }
    }

    /// Wire production `RegisterNode` gate (OWASP T2.10).
    pub fn with_register_gate(
        mut self,
        mode: RegisterNodeMode,
        pool: SqlitePool,
        admin_token: Option<String>,
    ) -> Self {
        self.register_mode = mode;
        self.pool = Some(pool);
        self.admin_token = admin_token;
        self
    }
}

#[tonic::async_trait]
impl AuthService for AuthServiceImpl {
    async fn register_node(
        &self,
        request: Request<NodeRegisterRequest>,
    ) -> Result<Response<NodeRegisterResponse>, Status> {
        let node_id = request.get_ref().node_id.trim().to_owned();
        if node_id.is_empty() {
            return Err(Status::invalid_argument("node_id must not be empty"));
        }

        check_register_gate(
            self.register_mode,
            self.pool.as_ref(),
            self.admin_token.as_deref(),
            &request,
            &node_id,
        )
        .await?;

        let req = request.into_inner();
        let display_name = req.display_name.trim();
        let platform = req.platform.trim();

        match self.store.register_node(&node_id, display_name, platform) {
            Ok(api_key) => {
                let registered_at = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                Ok(Response::new(NodeRegisterResponse {
                    api_key: api_key.as_str().to_owned(),
                    assigned_id: node_id.clone(),
                    registered_at,
                }))
            }
            Err(crate::auth::storage::AuthError::AlreadyExists) => {
                Err(Status::already_exists("node_id already registered"))
            }
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }

    async fn authenticate(
        &self,
        request: Request<NodeAuthRequest>,
    ) -> Result<Response<NodeAuthResponse>, Status> {
        let req = request.into_inner();

        match self.store.authenticate(&req.node_id, &req.api_key) {
            Ok((token, expires_at)) => Ok(Response::new(NodeAuthResponse {
                session_token: token.as_str().to_owned(),
                expires_at,
            })),
            Err(crate::auth::storage::AuthError::Unauthenticated) => {
                Err(Status::unauthenticated("invalid node_id or api_key"))
            }
            Err(crate::auth::storage::AuthError::RateLimited { retry_after_secs }) => {
                Err(Status::resource_exhausted(format!(
                    "too many failed auth attempts; retry after {retry_after_secs}s"
                )))
            }
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use disk_proto::disk::auth_service_server::AuthService;

    fn make_service() -> AuthServiceImpl {
        AuthServiceImpl::new(AuthStore::new())
    }

    #[tokio::test]
    async fn register_ok() {
        let svc = make_service();
        let resp = svc
            .register_node(Request::new(NodeRegisterRequest {
                node_id: "node-test".into(),
                display_name: "Test".into(),
                platform: "darwin".into(),
                ..Default::default()
            }))
            .await
            .unwrap();
        let inner = resp.into_inner();
        assert_eq!(inner.assigned_id, "node-test");
        assert!(inner.api_key.starts_with("arc_disk_"));
    }

    #[tokio::test]
    async fn register_duplicate_fails() {
        let svc = make_service();
        svc.register_node(Request::new(NodeRegisterRequest {
            node_id: "dup".into(),
            ..Default::default()
        }))
        .await
        .unwrap();
        let err = svc
            .register_node(Request::new(NodeRegisterRequest {
                node_id: "dup".into(),
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::AlreadyExists);
    }

    #[tokio::test]
    async fn authenticate_ok() {
        let svc = make_service();
        let reg_resp = svc
            .register_node(Request::new(NodeRegisterRequest {
                node_id: "auth-node".into(),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();

        let auth_resp = svc
            .authenticate(Request::new(NodeAuthRequest {
                node_id: "auth-node".into(),
                api_key: reg_resp.api_key.clone(),
            }))
            .await
            .unwrap()
            .into_inner();

        assert!(auth_resp.session_token.starts_with("arc_disk_sess_"));
        assert!(auth_resp.expires_at > 0);
    }

    #[tokio::test]
    async fn authenticate_wrong_key_unauthenticated() {
        let svc = make_service();
        svc.register_node(Request::new(NodeRegisterRequest {
            node_id: "n2".into(),
            ..Default::default()
        }))
        .await
        .unwrap();
        let err = svc
            .authenticate(Request::new(NodeAuthRequest {
                node_id: "n2".into(),
                api_key: "arc_disk_WRONGKEY".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn authenticate_rate_limited_after_repeated_failures() {
        use std::sync::Arc;
        use std::time::Duration;

        use crate::auth::rate_limit::AuthAttemptLimiter;

        let limiter = Arc::new(AuthAttemptLimiter::new(3, Duration::from_secs(60)));
        let store = AuthStore::with_rate_limiter(Some(limiter));
        let svc = AuthServiceImpl::new(store);
        svc.register_node(Request::new(NodeRegisterRequest {
            node_id: "rl-node".into(),
            ..Default::default()
        }))
        .await
        .unwrap();

        for _ in 0..3 {
            let err = svc
                .authenticate(Request::new(NodeAuthRequest {
                    node_id: "rl-node".into(),
                    api_key: "arc_disk_WRONG".into(),
                }))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::Unauthenticated);
        }

        let err = svc
            .authenticate(Request::new(NodeAuthRequest {
                node_id: "rl-node".into(),
                api_key: "arc_disk_WRONG".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
    }

    #[tokio::test]
    async fn register_empty_node_id_invalid() {
        let svc = make_service();
        let err = svc
            .register_node(Request::new(NodeRegisterRequest {
                node_id: "".into(),
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }
}
