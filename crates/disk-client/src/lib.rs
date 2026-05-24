//! Disk Arcana gRPC client — Phase 3 transport.
//!
//! Provides a high-level `DiskClient` that manages connection, authentication,
//! and sync operations against a `disk-arcana-server`.

#![forbid(unsafe_code)]

pub mod config;
pub mod connection;
pub mod enrollment;
pub mod keychain;
pub mod mtls;
pub mod sync_loop;
pub mod watcher;

pub use connection::{ClientConfig, ClientError, DiskClient};
pub use enrollment::{
    gen_keypair_and_csr, parse_bootstrap_file, redact_token, write_cert_file, write_key_file,
    BootstrapFile, EnrollmentClient, EnrollmentError,
};
pub use keychain::{
    detect_or_file, validate_label, FileKeyStore, KeyStore, KeyStoreError, OsKeyStore,
    DEFAULT_OS_KEYRING_SERVICE,
};
pub use mtls::{
    audit_key_permissions, build_client_tls_config, load_client_identity, load_server_ca, MtlsError,
};
pub use sync_loop::{
    classify_client_error, classify_tonic_status, Backoff, LoopError, LoopState, LoopTrigger,
    RemoteSync, SyncLoop, SyncTransport, BACKOFF_BASE, BACKOFF_CAP, BACKOFF_JITTER, POLL_INTERVAL,
};
pub use watcher::{
    translate_notify_event, FsEvent, FsEventDebouncer, FsWatcher, WatcherError,
    DEFAULT_DEBOUNCE_WINDOW,
};
