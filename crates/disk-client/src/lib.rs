//! Disk Arcana gRPC client — Phase 3 transport.
//!
//! Provides a high-level `DiskClient` that manages connection, authentication,
//! and sync operations against a `disk-arcana-server`.

#![forbid(unsafe_code)]

pub mod config;
pub mod connection;
pub mod enrollment;
pub mod import_state;
pub mod keychain;
pub mod mtls;
pub mod rest_api;
pub mod sync_loop;
pub mod watcher;

pub use config::{spawn_config_watcher, ConfigSnapshot, ConfigWatcher, ReloadStatus};
pub use connection::{ClientConfig, ClientError, DiskClient};
pub use enrollment::{
    gen_keypair_and_csr, parse_bootstrap_file, redact_token, write_cert_file, write_key_file,
    BootstrapFile, EnrollmentClient, EnrollmentError,
};
pub use import_state::{hash_file, import_state, ImportEntry, ImportError, ImportReport};
pub use keychain::{
    detect_or_file, validate_label, FileKeyStore, KeyStore, KeyStoreError, OsKeyStore,
    DEFAULT_OS_KEYRING_SERVICE,
};
pub use mtls::{
    audit_key_permissions, build_client_tls_config, load_client_identity, load_server_ca, MtlsError,
};
pub use rest_api::{
    assert_loopback_bind, direction_to_schema, format_iso8601, loop_state_to_schema, router, serve,
    AcceptedResponse, DaemonState, RestApiError, ShareSnapshot, StatusResponse, StatusShare,
    DEFAULT_PORT, LOOPBACK_BIND_PREFIX,
};
pub use sync_loop::{
    classify_client_error, classify_tonic_status, Backoff, LoopError, LoopState, LoopTrigger,
    RemoteSync, SyncLoop, SyncTransport, BACKOFF_BASE, BACKOFF_CAP, BACKOFF_JITTER, POLL_INTERVAL,
};
pub use watcher::{
    translate_notify_event, FsEvent, FsEventDebouncer, FsWatcher, WatcherError,
    DEFAULT_DEBOUNCE_WINDOW,
};
