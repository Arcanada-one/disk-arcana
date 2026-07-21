//! Disk Arcana core: types, errors, configuration, metadata DB, and sync engine.
//!
//! Phase 1 (DISK-0002) shipped scaffolding: types, errors, config parser, and
//! `MetaDb::open` with migrations. Phase 2 (DISK-0003) adds the live sync
//! engine — file scanner, path-traversal guard, ignore filter, vector clock,
//! tombstone helpers, metadata CRUD and the 30-scenario reconciliation engine.

//! Disk Arcana core: types, errors, configuration, metadata DB, sync engine,
//! and delta algorithm.
//!
//! Phase 3 (DISK-0004) adds the delta module: Adler32 rolling checksum, blake3
//! strong hash, fixed-block chunker, and delta plan build/apply.

#![forbid(unsafe_code)]

pub mod accounts;
pub mod archive;
pub mod billing;
pub mod config;
pub mod conflict;
pub mod delta;
pub mod e2ee;
pub mod error;
pub mod filter;
pub mod meta_db;
pub mod path_guard;
pub mod platform;
pub mod reconciler;
pub mod scanner;
pub mod tenant;
pub mod tenant_db;
pub mod tombstone;
pub mod types;
pub mod vector_clock;

pub use accounts::{
    default_tenant_from_email, hash_password, issue_token, new_user_id, normalize_email,
    sanitize_tenant_slug, validate_email, verify_password, verify_token, DiskJwtClaims, JwtError,
    PasswordError, DEFAULT_ISSUER, JWT_DEFAULT_TTL_SECS, MIN_PASSWORD_LEN, OAUTH_PASSWORD_SENTINEL,
};
pub use billing::{
    check_node_capacity, check_storage_delta, check_vault_capacity, compute_v1_signature,
    parse_stripe_subscription_event, verify_stripe_webhook_signature, PlanTier, QuotaError,
    QuotaLimits, StripeSigError, StripeSubscriptionEvent,
};
pub use config::Config;
pub use e2ee::{
    decrypt, encrypt, overlay_scanned_meta, random_salt, E2eeCachedWire, E2eeError, EncryptedBlob,
    UploadPayload, VaultKey, KEY_LEN, NONCE_LEN, SALT_LEN,
};
pub use error::{
    ConfigError, FilterError, MetaDbError, PathGuardError, ReconcileError, ScannerError,
};
pub use filter::{Filter, FilterRules};

pub use meta_db::conflicts::DEFAULT_CONFLICT_TTL_SECS;
pub use meta_db::MetaDb;
pub use path_guard::validate as validate_path;
pub use platform::FileIdentity;
pub use reconciler::ReconciliationEngine;
pub use scanner::FileScanner;
pub use tenant::{enforce_node_tenant, resolve_tenant_id, TenantScope, TenantViolation};
pub use tenant_db::{tenant_db_path, tenant_shard_key, TenantMetaRouter};
pub use tombstone::{Tombstone, DEFAULT_TTL_SECS};
pub use types::{
    ActionType, ConflictKind, ConflictRecord, ConflictReport, FileMeta, NodeId, RenamePair,
    SyncAction, TenantId, VaultId, VersionId,
};
pub use vector_clock::{Causality, VectorClock};
