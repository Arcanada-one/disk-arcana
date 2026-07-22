//! Disk Arcana gRPC server — Phase 3 transport.
//!
//! Exposes two services over TLS 1.3:
//! - `AuthService` — node registration and API-key → session-token auth.
//! - `SyncService` — bidi state sync, client-stream delta upload, server-stream delta download.

#![forbid(unsafe_code)]

pub mod accounts;
pub mod acl;
pub mod agents;
pub mod audit;
pub mod auth;
pub mod billing;
pub mod compliance;
pub mod config;
pub mod dashboard;
pub mod enrollment;
pub mod health;
pub mod middleware;
pub mod multi_node;
pub mod onboarding;
pub mod orgs;
pub mod publisher;
pub mod selective_sync;
pub mod services;
pub mod sharing;
pub mod snapshots;
pub mod telemetry;
pub mod tls;
pub mod trash;
pub mod versions;

pub use acl::reload::{ReloadHandle, SessionInvalidate};
pub use config::{CaMode, ConfigError, RegisterNodeMode, ServerConfig};

pub use accounts::{
    oauth_callback, oauth_start, refresh_token, resend_verification, routes::AuthHttpState,
    verify_email, AuthMode, EmailVerifyConfig, EmailVerifyMode, JwksCache, JwtConfig, JwtMode,
    OAuthConfig, OAuthMode,
};
pub use acl::{
    load_from_yaml, AclEnforcer, AclError, AclLoadError, AclState, AclYamlFile, AlwaysFailVerifier,
    CertFingerprint, EnforcedRole, EnforcementTable, GpgVerifier, LoadOutcome, NoopVerifier,
    RevokedSignerVerifier, SignatureVerifier, UnhealthyReason,
};
pub use agents::{
    agent_write, delete_webhook, get_revision, list_webhooks, register_webhook,
    spawn_agent_webhook_dispatcher, AgentWebhookDispatcher, AgentWebhookJob,
};
pub use audit::{AuditEmitter, AuditError, AuditEvent, AuditKind};
pub use auth::{ApiKey, AuthStore, CertIdentity, SessionToken};
pub use billing::webhook::WebhookState;
pub use billing::{BillingMode, QuotaEnforcer};
pub use compliance::{delete_account, export_data, list_consents, sub_processors};
pub use dashboard::{resolve_conflict, summary};
pub use enrollment::{EnrollErrorKind, EnrollmentServiceImpl};
pub use middleware::{BombError, ReplayError, ReplayGuard};
pub use multi_node::{lifecycle::revoke_node, vclock::VClock};
pub use onboarding::{get_onboarding, put_onboarding};
pub use orgs::{add_member, create_org, get_org_context, list_members, list_orgs, put_org_context};
pub use publisher::{
    build_signed_payload, FileMetadata as PublisherFileMetadata, PublisherSignatureProof,
    PublisherVerifier, StubKeyFetcher, VerifyError,
};
pub use services::{AuthServiceImpl, SyncServiceImpl};
pub use snapshots::{create_snapshot, get_snapshot, list_snapshots, restore_snapshot};
pub use telemetry::{get_telemetry, get_telemetry_config, put_telemetry};
pub use tls::{
    build_mtls_from_files, tls13_mtls_server_config, CertProvider, DevSelfSignedMtlsProvider,
    DevSelfSignedProvider, StaticPemProvider, TlsError,
};
pub use trash::{list_trash, restore_trash};
pub use versions::{list_versions, restore_version};
