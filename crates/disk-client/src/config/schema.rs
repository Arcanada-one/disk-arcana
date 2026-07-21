//! `disk.toml` schema types — pure data, no validation logic.
//!
//! Schema source: PRD-DISK-0001 §4.11.3 Per-Host Directional Policy.
//! Inheritance: `share.intended_direction = None` falls back to
//! `node.default.intended_direction`. All other fields use serde defaults.

use std::path::PathBuf;

use serde::Deserialize;

/// Per-share directional intent.
///
/// `receive_only` — node accepts pushes from the server, never pushes;
/// `send_only` — node pushes to the server, never pulls;
/// `bidirectional` — full two-way sync;
/// `publisher` — node owns the data, signs every artefact (publisher gate).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    ReceiveOnly,
    SendOnly,
    Bidirectional,
    Publisher,
}

/// Filter mode for a share.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterMode {
    Whitelist,
    Blacklist,
}

/// Top-level `disk.toml` config.
#[derive(Debug, Clone, Deserialize)]
pub struct DiskConfig {
    pub node: NodeSection,
    pub server: ServerSection,
    #[serde(default)]
    pub vault: VaultSection,
    #[serde(default, rename = "share")]
    pub shares: Vec<ShareSection>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NodeSection {
    pub id: String,
    #[serde(default)]
    pub display_name: Option<String>,
    /// SaaS tenant id — sent as `x-disk-tenant` on sync RPCs (DISK-0017).
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub default: NodeDefault,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct NodeDefault {
    /// Direction inherited by shares that do not specify their own.
    /// Absent → no per-share default; share without explicit
    /// `intended_direction` is a validation error.
    #[serde(default)]
    pub intended_direction: Option<Direction>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerSection {
    /// gRPC endpoint in `host:port` form (e.g. `disk.arcanada.ai:9443`).
    pub address: String,
    /// TLS handling mode (`"auto"` for system trust store, otherwise rely on
    /// `server_ca` PEM). String at the schema layer; loader-level enum lives
    /// in R4 once mTLS cert handling lands.
    #[serde(default = "default_tls_mode")]
    pub tls: String,
    /// Path to client cert PEM (set by `disk enroll`).
    pub client_cert: PathBuf,
    /// Path to client private key PEM (set by `disk enroll`, mode 0600).
    pub client_key: PathBuf,
    /// Path to server CA PEM bundle (when `tls != "auto"`).
    #[serde(default)]
    pub server_ca: Option<PathBuf>,
    /// Expected TLS domain (cert SAN) when `address` is an IP address.
    ///
    /// When the server endpoint is specified by IP (e.g. `65.108.236.39:9443`)
    /// but the server certificate only carries a DNS SAN (e.g.
    /// `disk.arcanada.ai`), TLS name verification fails unless this field
    /// pins the expected name.  When absent, the host portion of `address`
    /// is used for name verification — which works when `address` is a DNS
    /// name that matches the cert SAN (DISK-0060).
    ///
    /// Example `disk.toml`:
    /// ```toml
    /// [server]
    /// address = "65.108.236.39:9443"
    /// tls_domain = "disk.arcanada.ai"
    /// ```
    #[serde(default)]
    pub tls_domain: Option<String>,
}

fn default_tls_mode() -> String {
    "auto".to_owned()
}

/// Client-side vault / E2EE options (DISK-0015).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct VaultSection {
    /// When true, uploads encrypt plaintext before `DeltaUpload`.
    /// Requires `disk vault unlock` (keychain) or `DISK_VAULT_PASSPHRASE` + `DISK_VAULT_SALT` env.
    #[serde(default)]
    pub e2ee_enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ShareSection {
    pub name: String,
    pub path: PathBuf,
    /// Per-share direction. `None` → inherits `node.default.intended_direction`.
    #[serde(default)]
    pub intended_direction: Option<Direction>,
    #[serde(default)]
    pub filter: Option<FilterSection>,
    #[serde(default)]
    pub publisher: Option<PublisherSection>,
}

impl ShareSection {
    /// Resolve effective direction: explicit > node default.
    /// Returns `None` when neither is set — validator raises an error.
    pub fn effective_direction(&self, node_default: Option<Direction>) -> Option<Direction> {
        self.intended_direction.or(node_default)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct FilterSection {
    pub mode: FilterMode,
    #[serde(default)]
    pub extensions: Vec<String>,
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PublisherSection {
    /// Vault reference for the signing key, e.g. `vault:transit/keys/disk-arcana-arcana-ai-publisher`.
    pub sign_key_ref: String,
    /// On signature verification failure: send to quarantine bucket
    /// instead of dropping the artefact silently.
    #[serde(default = "default_true")]
    pub quarantine_on_failure: bool,
}

fn default_true() -> bool {
    true
}
