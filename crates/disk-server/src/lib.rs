//! Disk Arcana gRPC server — Phase 3 transport.
//!
//! Exposes two services over TLS 1.3:
//! - `AuthService` — node registration and API-key → session-token auth.
//! - `SyncService` — bidi state sync, client-stream delta upload, server-stream delta download.

#![forbid(unsafe_code)]

pub mod acl;
pub mod audit;
pub mod auth;
pub mod middleware;
pub mod services;
pub mod tls;

pub use acl::{
    load_from_yaml, AclEnforcer, AclError, AclLoadError, AclState, AclYamlFile, AlwaysFailVerifier,
    CertFingerprint, EnforcedRole, EnforcementTable, LoadOutcome, NoopVerifier,
    RevokedSignerVerifier, SignatureVerifier, UnhealthyReason,
};
pub use audit::{AuditEmitter, AuditError, AuditEvent, AuditKind};
pub use auth::{ApiKey, AuthStore, SessionToken};
pub use middleware::{BombError, ReplayError, ReplayGuard};
pub use services::{AuthServiceImpl, SyncServiceImpl};
pub use tls::{CertProvider, DevSelfSignedProvider, StaticPemProvider, TlsError};
