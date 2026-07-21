//! Disk Arcana gRPC server — Phase 3 transport.
//!
//! Exposes two services over TLS 1.3:
//! - `AuthService` — node registration and API-key → session-token auth.
//! - `SyncService` — bidi state sync, client-stream delta upload, server-stream delta download.

#![forbid(unsafe_code)]

pub mod accounts;
pub mod acl;
pub mod audit;
pub mod auth;
pub mod billing;
pub mod config;
pub mod dashboard;
pub mod enrollment;
pub mod health;
pub mod middleware;
pub mod multi_node;
pub mod publisher;
pub mod services;
pub mod tls;

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
pub use audit::{AuditEmitter, AuditError, AuditEvent, AuditKind};
pub use auth::{ApiKey, AuthStore, CertIdentity, SessionToken};
pub use billing::webhook::WebhookState;
pub use billing::{BillingMode, QuotaEnforcer};
pub use dashboard::summary;
pub use enrollment::{EnrollErrorKind, EnrollmentServiceImpl};
pub use middleware::{BombError, ReplayError, ReplayGuard};
pub use multi_node::{lifecycle::revoke_node, vclock::VClock};
pub use publisher::{
    build_signed_payload, FileMetadata as PublisherFileMetadata, PublisherSignatureProof,
    PublisherVerifier, StubKeyFetcher, VerifyError,
};
pub use services::{AuthServiceImpl, SyncServiceImpl};
pub use tls::{
    build_mtls_from_files, tls13_mtls_server_config, CertProvider, DevSelfSignedMtlsProvider,
    DevSelfSignedProvider, StaticPemProvider, TlsError,
};
