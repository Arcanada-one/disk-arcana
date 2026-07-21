//! Integration: `Authenticate` returns `ResourceExhausted` after repeated failures (OWASP G1).

use std::sync::Arc;
use std::time::Duration;

use disk_proto::disk::{auth_service_server::AuthService, NodeAuthRequest, NodeRegisterRequest};
use disk_server::auth::rate_limit::AuthAttemptLimiter;
use disk_server::auth::AuthStore;
use disk_server::services::auth::AuthServiceImpl;
use tonic::{Code, Request};

#[tokio::test]
async fn authenticate_rate_limited_resource_exhausted() {
    let limiter = Arc::new(AuthAttemptLimiter::new(5, Duration::from_secs(60)));
    let svc = AuthServiceImpl::new(AuthStore::with_rate_limiter(Some(limiter)));

    svc.register_node(Request::new(NodeRegisterRequest {
        node_id: "g1-node".into(),
        display_name: "G1".into(),
        platform: "linux".into(),
        ..Default::default()
    }))
    .await
    .expect("register");

    for _ in 0..5 {
        let err = svc
            .authenticate(Request::new(NodeAuthRequest {
                node_id: "g1-node".into(),
                api_key: "arc_disk_BAD".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::Unauthenticated);
    }

    let err = svc
        .authenticate(Request::new(NodeAuthRequest {
            node_id: "g1-node".into(),
            api_key: "arc_disk_BAD".into(),
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::ResourceExhausted);
    assert!(
        err.message()
            .contains("retry after"),
        "expected retry hint in message: {}",
        err.message()
    );
}
