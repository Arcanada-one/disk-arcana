#![forbid(unsafe_code)]

mod agents_cmd;
mod archive_cmd;
mod commands;
mod daemon;
mod embeddings_cmd;
mod paths;
mod selective_sync_cmd;
mod share_init;
mod sharing_cmd;
mod snapshots_cmd;
mod trash_cmd;
mod vault;
mod versions_cmd;

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use disk_client::{
    gen_keypair_and_csr, parse_bootstrap_file, redact_token, write_cert_file, write_key_file,
    BootstrapFile, EnrollmentClient,
};
use tracing_subscriber::EnvFilter;

use crate::share_init::Preset;

#[derive(Parser, Debug)]
#[command(
    name = "disk",
    version,
    about = "Disk Arcana CLI — sync your vault over gRPC/TLS"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Initialise a new vault config (DISK-0010).
    Init,

    /// Sync vault with a remote Disk Arcana server (Phase 3).
    Sync(SyncArgs),

    /// Enrol this node with a Disk Arcana server: generate Ed25519 keypair,
    /// build CSR, submit it with the operator-issued opaque token, and write
    /// the returned cert + private key to disk.
    Enroll(EnrollArgs),

    /// Operator-side admin commands (require `DISK_ADMIN_TOKEN`).
    Admin(AdminArgs),

    /// Seed the local SQLite `MetaDb` from an existing filesystem tree —
    /// the DISK-RB-003 cutover entry point for migrating off the bash MVP.
    ImportState(ImportStateArgs),

    /// Manage shares declared in `disk.toml`.
    Share(ShareArgs),

    /// Daemon lifecycle (foreground; launchd / systemd own background).
    Daemon(DaemonArgs),

    /// Show the running daemon's status snapshot (GET loopback /status).
    Status(StatusArgs),

    /// Inspect or manage the `disk.toml` configuration.
    Config(ConfigArgs),

    /// Manage sync conflicts: list unresolved or resolve by action.
    Conflicts(ConflictsArgs),

    /// Create, inspect, or restore indexed `.disk-archive` folder snapshots.
    Archive(ArchiveArgs),

    /// E2EE vault key unlock / lock (OS keychain).
    Vault(vault::VaultArgs),

    /// File version history — list and restore via health HTTP API (DISK-0020).
    Versions(VersionsArgs),

    /// Point-in-time vault snapshots (DISK-0020 slice 4).
    Snapshots(SnapshotsArgs),

    /// Recycle bin — list and restore soft-deleted files (DISK-0024).
    Trash(TrashArgs),

    /// Vault sharing — invite links and collaborator RBAC (DISK-0022).
    Sharing(SharingArgs),

    /// Per-device folder subset sync rules (DISK-0023).
    SelectiveSync(SelectiveSyncArgs),

    /// AI agent webhooks, revision lookup, and optimistic writes (DISK-0028).
    Agents(AgentsArgs),

    /// LAN peer discovery for P2P sync acceleration (DISK-0027).
    Lan(LanArgs),

    /// Embedding sidecar co-storage diagnostics (DISK-0029).
    Embeddings(EmbeddingsArgs),
}

/// `disk daemon <subcmd>` — wrapper.
#[derive(clap::Args, Debug)]
pub struct DaemonArgs {
    #[command(subcommand)]
    pub command: DaemonCommand,
}

#[derive(Subcommand, Debug)]
pub enum DaemonCommand {
    /// Run the daemon in the foreground (the only supported mode in v0.0.1).
    Start(daemon::DaemonStartArgs),
}

/// `disk status` — query the loopback REST `/status` endpoint.
#[derive(clap::Args, Debug)]
pub struct StatusArgs {
    /// Daemon REST address. Defaults to `127.0.0.1:9444`.
    #[arg(long)]
    pub addr: Option<SocketAddr>,
}

/// `disk config <subcmd>` — wrapper for config subcommands.
#[derive(clap::Args, Debug)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub command: ConfigCommand,
}

#[derive(Subcommand, Debug)]
pub enum ConfigCommand {
    /// Statically load + validate a `disk.toml` (no daemon required).
    Validate(ConfigValidateArgs),

    /// Ask the running daemon to hot-reload its config (POST /config/reload).
    Reload(ConfigReloadArgs),
}

/// `disk config validate [--file <path>]`.
#[derive(clap::Args, Debug)]
pub struct ConfigValidateArgs {
    /// Path to the `disk.toml` to validate. Defaults to
    /// `/etc/disk-arcana/disk.toml`.
    #[arg(long)]
    pub file: Option<PathBuf>,
}

/// `disk config reload [--addr <ip:port>]`.
#[derive(clap::Args, Debug)]
pub struct ConfigReloadArgs {
    /// Daemon REST address. Defaults to `127.0.0.1:9444`.
    #[arg(long)]
    pub addr: Option<SocketAddr>,
}

/// `disk archive <subcmd>` — indexed folder archives (DISK-0009).
#[derive(clap::Args, Debug)]
pub struct ArchiveArgs {
    #[command(subcommand)]
    pub command: ArchiveCommand,
}

#[derive(Subcommand, Debug)]
pub enum ArchiveCommand {
    /// Compress a folder into a content-addressed `.disk-archive` directory.
    Create(ArchiveCreateArgs),
    /// Print the JSON index entries for an archive.
    List(ArchiveListArgs),
    /// Restore files from an archive into a destination directory.
    Restore(ArchiveRestoreArgs),
}

#[derive(clap::Args, Debug)]
pub struct ArchiveCreateArgs {
    /// Source directory to archive.
    #[arg(long)]
    pub source: PathBuf,
    /// Output archive directory (created if missing).
    #[arg(long)]
    pub output: PathBuf,
}

#[derive(clap::Args, Debug)]
pub struct ArchiveListArgs {
    /// Path to an archive directory containing `index.json`.
    #[arg(long)]
    pub archive: PathBuf,
}

#[derive(clap::Args, Debug)]
pub struct ArchiveRestoreArgs {
    /// Path to the archive directory.
    #[arg(long)]
    pub archive: PathBuf,
    /// Destination directory for restored files.
    #[arg(long)]
    pub destination: PathBuf,
}

/// `disk conflicts <subcmd>` — wrapper for conflict management.
#[derive(clap::Args, Debug)]
pub struct ConflictsArgs {
    #[command(subcommand)]
    pub command: ConflictsCommand,
}

#[derive(Subcommand, Debug)]
pub enum ConflictsCommand {
    /// List all unresolved sync conflicts.
    List(ConflictsListArgs),
    /// Resolve a specific conflict (or all conflicts) with the given action.
    Resolve(ResolveArgs),
    /// Show a side-by-side diff of the local file versus its fork (remote version).
    Show(ConflictsShowArgs),
}

/// `disk conflicts list [--vault <name>] [--addr <ip:port>]`.
#[derive(clap::Args, Debug)]
pub struct ConflictsListArgs {
    /// Filter listed conflicts to one share/vault name.
    #[arg(long)]
    pub vault: Option<String>,

    /// Daemon REST address. Defaults to `127.0.0.1:9444`.
    #[arg(long)]
    pub addr: Option<std::net::SocketAddr>,
}

/// `disk conflicts show <path> [--vault <name>] [--addr <ip:port>]` — side-by-side diff.
#[derive(clap::Args, Debug)]
pub struct ConflictsShowArgs {
    /// Vault-relative path of the conflict to show.
    #[arg(long)]
    pub path: String,

    /// Share/vault name when the same path exists on multiple shares.
    #[arg(long)]
    pub vault: Option<String>,

    /// Daemon REST address. Defaults to `127.0.0.1:9444`.
    #[arg(long)]
    pub addr: Option<std::net::SocketAddr>,
}

/// `disk conflicts resolve` — resolve one conflict or all at once.
#[derive(clap::Args, Debug)]
pub struct ResolveArgs {
    /// Vault-relative path of the conflict to resolve. Mutually exclusive with `--all`.
    #[arg(long, conflicts_with = "all")]
    pub path: Option<String>,

    /// Share/vault name when resolving a single path (required when ambiguous).
    #[arg(long)]
    pub vault: Option<String>,

    /// Resolve all unresolved conflicts with the given action. Mutually exclusive with `--path`.
    #[arg(long, conflicts_with = "path")]
    pub all: bool,

    /// Resolution action to apply.
    #[arg(long, value_enum)]
    pub action: ResolveAction,

    /// Daemon REST address. Defaults to `127.0.0.1:9444`.
    #[arg(long)]
    pub addr: Option<std::net::SocketAddr>,
}

/// Valid resolution actions for `disk conflicts resolve`.
#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveAction {
    /// Write a fork copy from the local version; keep remote as-is.
    ForkLocal,
    /// Write a fork copy from the remote version; keep local as-is.
    ForkRemote,
    /// Attempt a 3-way merge; falls back to fork on conflict.
    Merge,
    /// Keep the local version; discard the remote change.
    KeepLocal,
    /// Keep the remote version; discard the local change.
    KeepRemote,
}

impl ResolveAction {
    /// Convert to the REST API action string.
    pub fn as_str(&self) -> &'static str {
        match self {
            ResolveAction::ForkLocal => "fork-local",
            ResolveAction::ForkRemote => "fork-remote",
            ResolveAction::Merge => "merge",
            ResolveAction::KeepLocal => "keep-local",
            ResolveAction::KeepRemote => "keep-remote",
        }
    }
}

/// `disk versions <subcmd>` — file version history (DISK-0020).
#[derive(clap::Args, Debug)]
pub struct VersionsArgs {
    #[command(subcommand)]
    pub command: VersionsCommand,
}

#[derive(Subcommand, Debug)]
pub enum VersionsCommand {
    /// List historical revisions for a vault-relative path.
    List(VersionsListArgs),
    /// Restore a historical revision (creates a new version on the server).
    Restore(VersionsRestoreArgs),
}

/// `disk versions list --path <path>`.
#[derive(clap::Args, Debug)]
pub struct VersionsListArgs {
    /// Vault-relative file path.
    #[arg(long)]
    pub path: String,

    /// Vault / share id.
    #[arg(long, default_value = "default")]
    pub vault: String,

    /// Page size (server clamps to 200).
    #[arg(long, default_value_t = 20)]
    pub limit: u32,

    /// Pagination offset into historical rows.
    #[arg(long, default_value_t = 0)]
    pub offset: u32,

    /// Health HTTP API base URL. Defaults to `DISK_API_BASE` or `http://127.0.0.1:9446`.
    #[arg(long)]
    pub api: Option<String>,

    /// Bearer JWT. Defaults to `DISK_ACCESS_TOKEN`.
    #[arg(long)]
    pub token: Option<String>,
}

/// `disk versions restore --path <path> --version-id <n>`.
#[derive(clap::Args, Debug)]
pub struct VersionsRestoreArgs {
    /// Vault-relative file path.
    #[arg(long)]
    pub path: String,

    /// Historical `version_id` to restore.
    #[arg(long)]
    pub version_id: u64,

    /// Vault / share id.
    #[arg(long, default_value = "default")]
    pub vault: String,

    /// Health HTTP API base URL.
    #[arg(long)]
    pub api: Option<String>,

    /// Bearer JWT.
    #[arg(long)]
    pub token: Option<String>,
}

/// `disk snapshots <subcmd>` — vault-wide point-in-time captures.
#[derive(clap::Args, Debug)]
pub struct SnapshotsArgs {
    #[command(subcommand)]
    pub command: SnapshotsCommand,
}

#[derive(Subcommand, Debug)]
pub enum SnapshotsCommand {
    /// Capture the current vault file index as a snapshot.
    Create(SnapshotsCreateArgs),
    /// List snapshots for a vault.
    List(SnapshotsListArgs),
    /// Show one snapshot and its file index.
    Show(SnapshotsShowArgs),
    /// Restore all live files from a snapshot.
    Restore(SnapshotsRestoreArgs),
}

#[derive(clap::Args, Debug)]
pub struct SnapshotsCreateArgs {
    #[arg(long, default_value = "default")]
    pub vault: String,
    #[arg(long)]
    pub label: Option<String>,
    #[arg(long)]
    pub api: Option<String>,
    #[arg(long)]
    pub token: Option<String>,
}

#[derive(clap::Args, Debug)]
pub struct SnapshotsListArgs {
    #[arg(long, default_value = "default")]
    pub vault: String,
    #[arg(long, default_value_t = 20)]
    pub limit: u32,
    #[arg(long, default_value_t = 0)]
    pub offset: u32,
    #[arg(long)]
    pub api: Option<String>,
    #[arg(long)]
    pub token: Option<String>,
}

#[derive(clap::Args, Debug)]
pub struct SnapshotsShowArgs {
    #[arg(long)]
    pub id: u64,
    #[arg(long, default_value = "default")]
    pub vault: String,
    #[arg(long)]
    pub api: Option<String>,
    #[arg(long)]
    pub token: Option<String>,
}

#[derive(clap::Args, Debug)]
pub struct SnapshotsRestoreArgs {
    #[arg(long)]
    pub id: u64,
    #[arg(long, default_value = "default")]
    pub vault: String,
    #[arg(long)]
    pub api: Option<String>,
    #[arg(long)]
    pub token: Option<String>,
}

/// `disk trash <subcmd>` — soft-deleted file recycle bin.
#[derive(clap::Args, Debug)]
pub struct TrashArgs {
    #[command(subcommand)]
    pub command: TrashCommand,
}

#[derive(Subcommand, Debug)]
pub enum TrashCommand {
    /// List trashed files for a vault.
    List(TrashListArgs),
    /// Restore a file from trash.
    Restore(TrashRestoreArgs),
    /// Permanently delete one file from trash.
    Delete(TrashDeleteArgs),
    /// Permanently empty the recycle bin for a vault.
    Empty(TrashEmptyArgs),
}

#[derive(clap::Args, Debug)]
pub struct TrashListArgs {
    #[arg(long, default_value = "default")]
    pub vault: String,
    #[arg(long, default_value_t = 20)]
    pub limit: u32,
    #[arg(long, default_value_t = 0)]
    pub offset: u32,
    #[arg(long)]
    pub api: Option<String>,
    #[arg(long)]
    pub token: Option<String>,
}

#[derive(clap::Args, Debug)]
pub struct TrashRestoreArgs {
    #[arg(long)]
    pub path: String,
    #[arg(long, default_value = "default")]
    pub vault: String,
    #[arg(long)]
    pub api: Option<String>,
    #[arg(long)]
    pub token: Option<String>,
}

#[derive(clap::Args, Debug)]
pub struct TrashDeleteArgs {
    #[arg(long)]
    pub path: String,
    #[arg(long, default_value = "default")]
    pub vault: String,
    #[arg(long)]
    pub api: Option<String>,
    #[arg(long)]
    pub token: Option<String>,
}

#[derive(clap::Args, Debug)]
pub struct TrashEmptyArgs {
    #[arg(long, default_value = "default")]
    pub vault: String,
    /// Required to confirm permanent deletion of all trashed files.
    #[arg(long)]
    pub yes: bool,
    #[arg(long)]
    pub api: Option<String>,
    #[arg(long)]
    pub token: Option<String>,
}

/// `disk sharing <subcmd>` — vault invite links and collaborator RBAC.
#[derive(clap::Args, Debug)]
pub struct SharingArgs {
    #[command(subcommand)]
    pub command: SharingCommand,
}

#[derive(Subcommand, Debug)]
pub enum SharingCommand {
    /// Manage vault invite links.
    Invites(SharingInvitesArgs),
    /// List or revoke vault collaborators.
    Members(SharingMembersArgs),
}

#[derive(clap::Args, Debug)]
pub struct SharingInvitesArgs {
    #[command(subcommand)]
    pub command: SharingInvitesCommand,
}

#[derive(Subcommand, Debug)]
pub enum SharingInvitesCommand {
    /// Create a new invite link for a vault.
    Create(SharingInviteCreateArgs),
    /// List pending invites for a vault.
    List(SharingInviteListArgs),
    /// Accept an invite token.
    Accept(SharingInviteAcceptArgs),
}

#[derive(clap::Args, Debug)]
pub struct SharingInviteCreateArgs {
    #[arg(long, default_value = "default")]
    pub vault: String,
    #[arg(long, default_value = "viewer")]
    pub role: String,
    #[arg(long, default_value_t = 168)]
    pub ttl_hours: u32,
    #[arg(long)]
    pub api: Option<String>,
    #[arg(long)]
    pub token: Option<String>,
}

#[derive(clap::Args, Debug)]
pub struct SharingInviteListArgs {
    #[arg(long, default_value = "default")]
    pub vault: String,
    #[arg(long)]
    pub api: Option<String>,
    #[arg(long)]
    pub token: Option<String>,
}

#[derive(clap::Args, Debug)]
pub struct SharingInviteAcceptArgs {
    #[arg(long)]
    pub invite_token: String,
    #[arg(long)]
    pub api: Option<String>,
    #[arg(long)]
    pub token: Option<String>,
}

#[derive(clap::Args, Debug)]
pub struct SharingMembersArgs {
    #[command(subcommand)]
    pub command: SharingMembersCommand,
}

#[derive(Subcommand, Debug)]
pub enum SharingMembersCommand {
    /// List external collaborators on a vault.
    List(SharingMembersListArgs),
    /// Revoke a collaborator.
    Remove(SharingMembersRemoveArgs),
}

#[derive(clap::Args, Debug)]
pub struct SharingMembersListArgs {
    #[arg(long, default_value = "default")]
    pub vault: String,
    #[arg(long)]
    pub api: Option<String>,
    #[arg(long)]
    pub token: Option<String>,
}

#[derive(clap::Args, Debug)]
pub struct SharingMembersRemoveArgs {
    #[arg(long)]
    pub user: String,
    #[arg(long, default_value = "default")]
    pub vault: String,
    #[arg(long)]
    pub api: Option<String>,
    #[arg(long)]
    pub token: Option<String>,
}

/// `disk selective-sync <subcmd>` — per-device folder include rules.
#[derive(clap::Args, Debug)]
pub struct SelectiveSyncArgs {
    #[command(subcommand)]
    pub command: SelectiveSyncCommand,
}

#[derive(Subcommand, Debug)]
pub enum SelectiveSyncCommand {
    /// Show folder include prefixes for a device.
    List(SelectiveSyncListArgs),
    /// Replace folder include prefixes (omit --include to sync all).
    Set(SelectiveSyncSetArgs),
}

#[derive(clap::Args, Debug)]
pub struct SelectiveSyncListArgs {
    #[arg(long, default_value = "default")]
    pub vault: String,
    #[arg(long)]
    pub node: String,
    #[arg(long)]
    pub api: Option<String>,
    #[arg(long)]
    pub token: Option<String>,
}

#[derive(clap::Args, Debug)]
pub struct SelectiveSyncSetArgs {
    #[arg(long, default_value = "default")]
    pub vault: String,
    #[arg(long)]
    pub node: String,
    /// Comma-separated folder prefixes (e.g. `docs,photos/2024`). Omit to clear filter.
    #[arg(long, value_delimiter = ',')]
    pub include: Vec<String>,
    #[arg(long)]
    pub api: Option<String>,
    #[arg(long)]
    pub token: Option<String>,
}

/// `disk lan <subcmd>` — LAN sync helpers (DISK-0027).
#[derive(clap::Args, Debug)]
pub struct LanArgs {
    #[command(subcommand)]
    pub command: LanCommand,
}

#[derive(Subcommand, Debug)]
pub enum LanCommand {
    /// List mDNS-discovered Disk Arcana peers on the local network.
    Peers(LanPeersArgs),
}

#[derive(clap::Args, Debug)]
pub struct LanPeersArgs {
    /// Daemon REST address. Defaults to `127.0.0.1:9444`.
    #[arg(long)]
    pub addr: Option<SocketAddr>,
}

/// `disk embeddings <subcmd>` — vector sidecar co-storage (DISK-0029).
#[derive(clap::Args, Debug)]
pub struct EmbeddingsArgs {
    #[command(subcommand)]
    pub command: EmbeddingsCommand,
}

#[derive(Subcommand, Debug)]
pub enum EmbeddingsCommand {
    /// Report fresh/stale/missing embedding sidecars for configured shares.
    Status(EmbeddingsStatusArgs),
    /// Ingest an external embedding vector for a source file (writes sidecar artefacts).
    Write(EmbeddingsWriteArgs),
}

#[derive(clap::Args, Debug)]
pub struct EmbeddingsStatusArgs {
    /// Share name from `disk.toml`. Defaults to all shares.
    #[arg(long)]
    pub share: Option<String>,
    /// Path to `disk.toml`. Defaults to platform install path.
    #[arg(long)]
    pub config: Option<PathBuf>,
}

/// `disk embeddings write` — external embedder ingest (DISK-0029 slice 3).
#[derive(clap::Args, Debug)]
pub struct EmbeddingsWriteArgs {
    /// Share name from `disk.toml`.
    #[arg(long)]
    pub share: String,
    /// Vault-relative source path (e.g. `notes/a.md`).
    #[arg(long)]
    pub path: String,
    /// Raw f32 LE vector blob file (`dimensions * 4` bytes).
    #[arg(long, conflicts_with = "vector_base64")]
    pub vector_file: Option<PathBuf>,
    /// Base64-encoded vector blob (alternative to `--vector-file`).
    #[arg(long, conflicts_with = "vector_file")]
    pub vector_base64: Option<String>,
    /// Path to `disk.toml`. Defaults to platform install path.
    #[arg(long)]
    pub config: Option<PathBuf>,
}

/// `disk agents <subcmd>` — AI Agents API CLI (DISK-0028 slice 3).
#[derive(clap::Args, Debug)]
pub struct AgentsArgs {
    #[command(subcommand)]
    pub command: AgentsCommand,
}

#[derive(Subcommand, Debug)]
pub enum AgentsCommand {
    /// Manage outbound agent webhooks.
    Webhooks(AgentsWebhooksArgs),
    /// Read the agent-facing revision for a vault path.
    Revision(AgentsRevisionArgs),
    /// Optimistic write to a vault path over HTTP.
    Write(AgentsWriteArgs),
}

#[derive(clap::Args, Debug)]
pub struct AgentsWebhooksArgs {
    #[command(subcommand)]
    pub command: AgentsWebhooksCommand,
}

#[derive(Subcommand, Debug)]
pub enum AgentsWebhooksCommand {
    /// List registered webhooks for a vault.
    List(AgentsWebhooksListArgs),
    /// Register a new HTTPS webhook callback.
    Register(AgentsWebhooksRegisterArgs),
    /// Delete a webhook by id.
    Delete(AgentsWebhooksDeleteArgs),
}

#[derive(clap::Args, Debug)]
pub struct AgentsWebhooksListArgs {
    #[arg(long, default_value = "default")]
    pub vault: String,
    #[arg(long)]
    pub api: Option<String>,
    #[arg(long)]
    pub token: Option<String>,
}

#[derive(clap::Args, Debug)]
pub struct AgentsWebhooksRegisterArgs {
    #[arg(long)]
    pub url: String,
    /// Comma-separated event names (e.g. `agent.write_ok,agent.write_conflict`).
    #[arg(long, value_delimiter = ',')]
    pub events: Vec<String>,
    #[arg(long, default_value = "default")]
    pub vault: String,
    #[arg(long)]
    pub label: Option<String>,
    #[arg(long)]
    pub api: Option<String>,
    #[arg(long)]
    pub token: Option<String>,
}

#[derive(clap::Args, Debug)]
pub struct AgentsWebhooksDeleteArgs {
    #[arg(long)]
    pub webhook_id: String,
    #[arg(long)]
    pub api: Option<String>,
    #[arg(long)]
    pub token: Option<String>,
}

#[derive(clap::Args, Debug)]
pub struct AgentsRevisionArgs {
    #[arg(long)]
    pub path: String,
    #[arg(long, default_value = "default")]
    pub vault: String,
    #[arg(long)]
    pub api: Option<String>,
    #[arg(long)]
    pub token: Option<String>,
}

#[derive(clap::Args, Debug)]
pub struct AgentsWriteArgs {
    #[arg(long)]
    pub path: String,
    /// Local file to upload (mutually exclusive with --content-base64).
    #[arg(long, conflicts_with = "content_base64")]
    pub file: Option<PathBuf>,
    /// Pre-encoded base64 payload (mutually exclusive with --file).
    #[arg(long, conflicts_with = "file")]
    pub content_base64: Option<String>,
    #[arg(long, default_value = "default")]
    pub vault: String,
    #[arg(long)]
    pub if_match_revision: Option<u64>,
    #[arg(long)]
    pub agent_id: Option<String>,
    #[arg(long)]
    pub api: Option<String>,
    #[arg(long)]
    pub token: Option<String>,
}

/// `disk share <subcmd>` — wrapper for share management subcommands.
#[derive(clap::Args, Debug)]
pub struct ShareArgs {
    #[command(subcommand)]
    pub command: ShareCommand,
}

#[derive(Subcommand, Debug)]
pub enum ShareCommand {
    /// Append a new `[[share]]` block to `disk.toml` using a preset.
    Init(ShareInitArgs),
}

/// `disk share init` — declare a new share with one of the four directional presets.
#[derive(clap::Args, Debug)]
pub struct ShareInitArgs {
    /// Preset directional intent. `publish` additionally requires `--sign-key-ref`.
    #[arg(long, value_enum)]
    pub preset: Preset,

    /// Logical share name (must be unique within `disk.toml`).
    #[arg(long)]
    pub name: String,

    /// Absolute path to the directory the share covers.
    #[arg(long)]
    pub path: PathBuf,

    /// Vault key reference for the `publish` preset (e.g. `vault:transit/keys/foo`).
    #[arg(long)]
    pub sign_key_ref: Option<String>,

    /// Path to the `disk.toml` to extend.
    #[arg(long, default_value = crate::paths::DEFAULT_CONFIG)]
    pub config: PathBuf,
}

/// `disk import-state` — seed MetaDb without driving any network sync.
#[derive(clap::Args, Debug)]
pub struct ImportStateArgs {
    /// Directory holding the legacy rsync / bash-MVP layout.
    #[arg(long)]
    pub from_rsync: PathBuf,

    /// Share name — free-form label until disk.toml lookup lands in R10.
    #[arg(long = "as-share")]
    pub as_share: String,

    /// Path to the SQLite metadata database the daemon will use.
    #[arg(long, default_value = crate::paths::DEFAULT_META_DB)]
    pub db_path: PathBuf,

    /// Node ID recorded as the writer of every seeded row. Defaults to
    /// hostname (the same fallback `disk enroll` uses).
    #[arg(long)]
    pub node_id: Option<String>,

    /// Print the plan but do not write any DB rows.
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,
}

/// Arguments for the `sync` subcommand.
#[derive(clap::Args, Debug)]
pub struct SyncArgs {
    /// Server address in host:port format (e.g. disk.arcanada.ai:9443).
    #[arg(long, default_value = "disk.arcanada.ai:9443")]
    pub server: String,

    /// Allow self-signed certificates (localhost testing only).
    /// **Never use in production.**
    #[arg(long, default_value_t = false)]
    pub insecure_localhost: bool,

    /// Node ID for this device (defaults to hostname).
    #[arg(long)]
    pub node_id: Option<String>,

    /// Path to `disk.toml` configuration file.
    #[arg(long, default_value = "disk.toml")]
    pub config: PathBuf,
}

/// `disk enroll` — exchange an opaque enrollment token for a signed cert.
#[derive(clap::Args, Debug)]
pub struct EnrollArgs {
    /// EnrollmentService gRPC endpoint (e.g. `https://disk.arcanada.ai:9445`).
    #[arg(long)]
    pub server: Option<String>,

    /// Hex-encoded opaque token from `disk admin pending-token`.
    #[arg(long, conflicts_with = "from_bootstrap_file")]
    pub token: Option<String>,

    /// TOML file containing `server` + `token` (+ optional `node_id_hint`,
    /// `ca_cert_pem`). Overrides `--server` / `--token` when present.
    #[arg(long)]
    pub from_bootstrap_file: Option<PathBuf>,

    /// Subject CN for the CSR. Defaults to the system hostname.
    #[arg(long)]
    pub node_id: Option<String>,

    /// Path to PEM-encoded CA bundle for TLS verification.
    #[arg(long)]
    pub ca_cert: Option<PathBuf>,

    /// Disable TLS — localhost test only. Server must be reachable via `http://`.
    #[arg(long, default_value_t = false)]
    pub insecure_localhost: bool,

    /// Output path for the signed client cert (PEM).
    #[arg(long, default_value = crate::paths::DEFAULT_CLIENT_CERT)]
    pub cert_out: PathBuf,

    /// Output path for the private key (PEM, mode 0600).
    #[arg(long, default_value = crate::paths::DEFAULT_CLIENT_KEY)]
    pub key_out: PathBuf,
}

#[derive(clap::Args, Debug)]
pub struct AdminArgs {
    #[command(subcommand)]
    pub command: AdminCommand,
}

#[derive(Subcommand, Debug)]
pub enum AdminCommand {
    /// Issue a fresh enrollment token bound to a hostname.
    PendingToken(PendingTokenArgs),
}

/// `disk admin pending-token` — admin-bearer-protected RPC.
#[derive(clap::Args, Debug)]
pub struct PendingTokenArgs {
    /// EnrollmentService gRPC endpoint.
    #[arg(long, default_value = "https://disk.arcanada.ai:9445")]
    pub server: String,

    /// Target hostname / node_id_hint to bind the token to.
    #[arg(long)]
    pub hostname: String,

    /// Token TTL in seconds (server clamps to 3600 default, 86400 max).
    #[arg(long, default_value_t = 3600)]
    pub ttl_secs: u64,

    /// SaaS tenant id to bind the enrolled node (DISK-0017).
    #[arg(long)]
    pub tenant: Option<String>,

    /// Admin bearer token (overrides `DISK_ADMIN_TOKEN` env var).
    #[arg(long)]
    pub admin_token: Option<String>,

    /// Path to PEM-encoded CA bundle for TLS verification.
    #[arg(long)]
    pub ca_cert: Option<PathBuf>,

    /// Disable TLS — localhost test only.
    #[arg(long, default_value_t = false)]
    pub insecure_localhost: bool,
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .try_init();
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let cli = Cli::parse();
    match cli.command {
        Some(Command::Init) => {
            println!("disk init: not implemented yet (DISK-0010)");
            Ok(())
        }
        Some(Command::Sync(args)) => {
            println!("disk sync: connecting to {}", args.server);
            println!(
                "  insecure-localhost: {}, config: {}",
                args.insecure_localhost,
                args.config.display()
            );
            println!("  Full sync loop not yet implemented — use disk-client library.");
            Ok(())
        }
        Some(Command::Enroll(args)) => run_enroll(args).await,
        Some(Command::Admin(args)) => match args.command {
            AdminCommand::PendingToken(p) => run_admin_pending_token(p).await,
        },
        Some(Command::ImportState(args)) => run_import_state(args).await,
        Some(Command::Daemon(args)) => match args.command {
            DaemonCommand::Start(s) => daemon::run_start(s).await,
        },
        Some(Command::Share(args)) => match args.command {
            ShareCommand::Init(s) => run_share_init(s),
        },
        Some(Command::Status(args)) => commands::run_status(args.addr).await,
        Some(Command::Config(args)) => match args.command {
            ConfigCommand::Validate(c) => commands::run_config_validate(c.file),
            ConfigCommand::Reload(c) => commands::run_config_reload(c.addr).await,
        },
        Some(Command::Conflicts(args)) => match args.command {
            ConflictsCommand::List(l) => {
                commands::run_conflicts_list(l.addr, l.vault.as_deref()).await
            }
            ConflictsCommand::Resolve(r) => {
                commands::run_conflicts_resolve(r.addr, r.vault, r.path, r.all, r.action.as_str())
                    .await
            }
            ConflictsCommand::Show(s) => {
                commands::run_conflicts_show(s.addr, s.vault.as_deref(), &s.path).await
            }
        },
        Some(Command::Archive(args)) => match args.command {
            ArchiveCommand::Create(c) => archive_cmd::run_create(c.source, c.output),
            ArchiveCommand::List(l) => archive_cmd::run_list(l.archive),
            ArchiveCommand::Restore(r) => archive_cmd::run_restore(r.archive, r.destination),
        },
        Some(Command::Vault(args)) => match args.command {
            vault::VaultCommand::Unlock(u) => vault::run_unlock(u),
            vault::VaultCommand::Lock(l) => vault::run_lock(l),
            vault::VaultCommand::Status(s) => vault::run_status(s),
        },
        Some(Command::Versions(args)) => match args.command {
            VersionsCommand::List(l) => {
                versions_cmd::run_versions_list(
                    l.api.as_deref(),
                    l.token.as_deref(),
                    &l.path,
                    &l.vault,
                    l.limit,
                    l.offset,
                )
                .await
            }
            VersionsCommand::Restore(r) => {
                versions_cmd::run_versions_restore(
                    r.api.as_deref(),
                    r.token.as_deref(),
                    &r.path,
                    &r.vault,
                    r.version_id,
                )
                .await
            }
        },
        Some(Command::Snapshots(args)) => match args.command {
            SnapshotsCommand::Create(c) => {
                snapshots_cmd::run_snapshots_create(
                    c.api.as_deref(),
                    c.token.as_deref(),
                    &c.vault,
                    c.label.as_deref(),
                )
                .await
            }
            SnapshotsCommand::List(l) => {
                snapshots_cmd::run_snapshots_list(
                    l.api.as_deref(),
                    l.token.as_deref(),
                    &l.vault,
                    l.limit,
                    l.offset,
                )
                .await
            }
            SnapshotsCommand::Show(s) => {
                snapshots_cmd::run_snapshots_show(
                    s.api.as_deref(),
                    s.token.as_deref(),
                    &s.vault,
                    s.id,
                )
                .await
            }
            SnapshotsCommand::Restore(r) => {
                snapshots_cmd::run_snapshots_restore(
                    r.api.as_deref(),
                    r.token.as_deref(),
                    &r.vault,
                    r.id,
                )
                .await
            }
        },
        Some(Command::Trash(args)) => match args.command {
            TrashCommand::List(l) => {
                trash_cmd::run_trash_list(
                    l.api.as_deref(),
                    l.token.as_deref(),
                    &l.vault,
                    l.limit,
                    l.offset,
                )
                .await
            }
            TrashCommand::Restore(r) => {
                trash_cmd::run_trash_restore(
                    r.api.as_deref(),
                    r.token.as_deref(),
                    &r.vault,
                    &r.path,
                )
                .await
            }
            TrashCommand::Delete(d) => {
                trash_cmd::run_trash_delete(d.api.as_deref(), d.token.as_deref(), &d.vault, &d.path)
                    .await
            }
            TrashCommand::Empty(e) => {
                trash_cmd::run_trash_empty(e.api.as_deref(), e.token.as_deref(), &e.vault, e.yes)
                    .await
            }
        },
        Some(Command::Sharing(args)) => match args.command {
            SharingCommand::Invites(i) => match i.command {
                SharingInvitesCommand::Create(c) => {
                    sharing_cmd::run_invite_create(
                        c.api.as_deref(),
                        c.token.as_deref(),
                        &c.vault,
                        &c.role,
                        c.ttl_hours,
                    )
                    .await
                }
                SharingInvitesCommand::List(l) => {
                    sharing_cmd::run_invite_list(l.api.as_deref(), l.token.as_deref(), &l.vault)
                        .await
                }
                SharingInvitesCommand::Accept(a) => {
                    sharing_cmd::run_invite_accept(
                        a.api.as_deref(),
                        a.token.as_deref(),
                        &a.invite_token,
                    )
                    .await
                }
            },
            SharingCommand::Members(m) => match m.command {
                SharingMembersCommand::List(l) => {
                    sharing_cmd::run_members_list(l.api.as_deref(), l.token.as_deref(), &l.vault)
                        .await
                }
                SharingMembersCommand::Remove(r) => {
                    sharing_cmd::run_member_remove(
                        r.api.as_deref(),
                        r.token.as_deref(),
                        &r.vault,
                        &r.user,
                    )
                    .await
                }
            },
        },
        Some(Command::SelectiveSync(args)) => match args.command {
            SelectiveSyncCommand::List(l) => {
                selective_sync_cmd::run_list(
                    l.api.as_deref(),
                    l.token.as_deref(),
                    &l.vault,
                    &l.node,
                )
                .await
            }
            SelectiveSyncCommand::Set(s) => {
                selective_sync_cmd::run_set(
                    s.api.as_deref(),
                    s.token.as_deref(),
                    &s.vault,
                    &s.node,
                    &s.include,
                )
                .await
            }
        },
        Some(Command::Lan(args)) => match args.command {
            LanCommand::Peers(p) => commands::run_lan_peers(p.addr).await,
        },
        Some(Command::Embeddings(args)) => match args.command {
            EmbeddingsCommand::Status(s) => {
                let config = s
                    .config
                    .clone()
                    .unwrap_or_else(|| PathBuf::from(paths::DEFAULT_CONFIG));
                embeddings_cmd::run_embeddings_status(&config, s.share.as_deref())
            }
            EmbeddingsCommand::Write(w) => {
                let config = w
                    .config
                    .clone()
                    .unwrap_or_else(|| PathBuf::from(paths::DEFAULT_CONFIG));
                embeddings_cmd::run_embeddings_write(
                    &config,
                    embeddings_cmd::EmbeddingsWriteParams {
                        share: &w.share,
                        path: &w.path,
                        vector_file: w.vector_file.as_deref(),
                        vector_base64: w.vector_base64.as_deref(),
                    },
                )
            }
        },
        Some(Command::Agents(args)) => match args.command {
            AgentsCommand::Webhooks(w) => match w.command {
                AgentsWebhooksCommand::List(l) => {
                    agents_cmd::run_webhooks_list(l.api.as_deref(), l.token.as_deref(), &l.vault)
                        .await
                }
                AgentsWebhooksCommand::Register(r) => {
                    agents_cmd::run_webhooks_register(
                        r.api.as_deref(),
                        r.token.as_deref(),
                        &r.vault,
                        &r.url,
                        &r.events,
                        r.label.as_deref(),
                    )
                    .await
                }
                AgentsWebhooksCommand::Delete(d) => {
                    agents_cmd::run_webhooks_delete(
                        d.api.as_deref(),
                        d.token.as_deref(),
                        &d.webhook_id,
                    )
                    .await
                }
            },
            AgentsCommand::Revision(r) => {
                agents_cmd::run_revision(r.api.as_deref(), r.token.as_deref(), &r.path, &r.vault)
                    .await
            }
            AgentsCommand::Write(w) => {
                agents_cmd::run_write(
                    w.api.as_deref(),
                    w.token.as_deref(),
                    agents_cmd::AgentsWriteParams {
                        path: &w.path,
                        vault: &w.vault,
                        file: w.file.as_deref(),
                        content_base64: w.content_base64.as_deref(),
                        if_match_revision: w.if_match_revision,
                        agent_id: w.agent_id.as_deref(),
                    },
                )
                .await
            }
        },
        None => {
            let version = env!("CARGO_PKG_VERSION");
            println!("disk v{version} — run `disk --help` for available commands");
            Ok(())
        }
    }
}

/// Resolve effective enrollment inputs from CLI flags and the optional
/// bootstrap file. The bootstrap file is the canonical source when present;
/// CLI flags override individual fields.
fn resolve_enroll_inputs(args: &EnrollArgs) -> Result<ResolvedEnroll> {
    let bf: Option<BootstrapFile> = match &args.from_bootstrap_file {
        Some(path) => {
            let raw = std::fs::read_to_string(path)
                .with_context(|| format!("read bootstrap file {}", path.display()))?;
            Some(parse_bootstrap_file(&raw)?)
        }
        None => None,
    };

    let server = args
        .server
        .clone()
        .or_else(|| bf.as_ref().map(|b| b.server.clone()))
        .ok_or_else(|| anyhow!("--server (or bootstrap-file server=) required"))?;

    let token_hex = args
        .token
        .clone()
        .or_else(|| bf.as_ref().map(|b| b.token.clone()))
        .ok_or_else(|| anyhow!("--token (or bootstrap-file token=) required"))?;

    let node_id = args
        .node_id
        .clone()
        .or_else(|| bf.as_ref().and_then(|b| b.node_id_hint.clone()))
        .unwrap_or_else(default_hostname);

    let ca_pem = match &args.ca_cert {
        Some(path) => {
            Some(std::fs::read(path).with_context(|| format!("read {}", path.display()))?)
        }
        None => bf
            .as_ref()
            .and_then(|b| b.ca_cert_pem.clone())
            .map(|s| s.into_bytes()),
    };

    Ok(ResolvedEnroll {
        server,
        token_hex,
        node_id,
        ca_pem,
        insecure_localhost: args.insecure_localhost,
        cert_out: args.cert_out.clone(),
        key_out: args.key_out.clone(),
    })
}

struct ResolvedEnroll {
    server: String,
    token_hex: String,
    node_id: String,
    ca_pem: Option<Vec<u8>>,
    insecure_localhost: bool,
    cert_out: PathBuf,
    key_out: PathBuf,
}

fn default_hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .unwrap_or_else(|| "disk-node".to_owned())
}

async fn run_enroll(args: EnrollArgs) -> Result<()> {
    let inputs = resolve_enroll_inputs(&args)?;
    let token_bytes = hex::decode(&inputs.token_hex).context("decode --token (expected hex)")?;
    tracing::info!(
        server = %inputs.server,
        node_id = %inputs.node_id,
        token = %redact_token(&inputs.token_hex),
        "enrolling node"
    );

    let (key_pem, csr_pem) = gen_keypair_and_csr(&inputs.node_id)?;

    let client = EnrollmentClient::connect(
        &inputs.server,
        inputs.ca_pem.as_deref(),
        inputs.insecure_localhost,
    )
    .await
    .context("connect to enrollment endpoint")?;

    let resp = client
        .enroll(token_bytes, csr_pem.into_bytes(), inputs.node_id.clone())
        .await
        .context("Enroll RPC failed")?;

    let cert_pem =
        String::from_utf8(resp.client_cert_pem).context("server returned non-UTF8 cert")?;
    write_cert_file(&inputs.cert_out, &cert_pem).context("write cert file")?;
    write_key_file(&inputs.key_out, &key_pem).context("write key file")?;

    println!(
        "enrolled node_id={} cert={} key={} expires_at_unix_ms={}",
        inputs.node_id,
        inputs.cert_out.display(),
        inputs.key_out.display(),
        resp.expires_at_ms
    );
    Ok(())
}

async fn run_admin_pending_token(args: PendingTokenArgs) -> Result<()> {
    let admin_token = args
        .admin_token
        .clone()
        .or_else(|| std::env::var("DISK_ADMIN_TOKEN").ok())
        .ok_or_else(|| anyhow!("--admin-token or DISK_ADMIN_TOKEN required"))?;

    let ca_pem = match &args.ca_cert {
        Some(path) => {
            Some(std::fs::read(path).with_context(|| format!("read {}", path.display()))?)
        }
        None => None,
    };

    let client =
        EnrollmentClient::connect(&args.server, ca_pem.as_deref(), args.insecure_localhost)
            .await
            .context("connect to enrollment endpoint")?;

    let resp = client
        .issue_pending_token(
            &admin_token,
            &args.hostname,
            args.ttl_secs,
            args.tenant.as_deref(),
        )
        .await
        .context("IssuePendingToken RPC failed")?;

    let token_hex = hex::encode(&resp.opaque_token);
    println!(
        "token={} expires_at_unix_ms={} hostname={}",
        token_hex, resp.expires_at_ms, args.hostname
    );
    Ok(())
}

async fn run_import_state(args: ImportStateArgs) -> Result<()> {
    use disk_client::{import_state, ImportError};
    use disk_core::MetaDb;

    let node_id = args.node_id.unwrap_or_else(default_hostname);
    let from = args.from_rsync.clone();

    if !from.exists() {
        return Err(anyhow!(
            "--from-rsync path does not exist: {}",
            from.display()
        ));
    }

    if let Some(parent) = args.db_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create MetaDb parent dir {}", parent.display()))?;
        }
    }
    let db = MetaDb::open(&args.db_path)
        .await
        .with_context(|| format!("open MetaDb at {}", args.db_path.display()))?;

    tracing::info!(
        share = %args.as_share,
        from = %from.display(),
        db_path = %args.db_path.display(),
        dry_run = args.dry_run,
        "disk import-state seeding"
    );

    let report = import_state(&from, &node_id, &db, args.dry_run)
        .await
        .map_err(|e: ImportError| anyhow!("import-state failed: {e}"))?;

    if args.dry_run {
        for entry in &report.entries {
            println!(
                "DRY {hash} {size:>10}  {path}",
                hash = hex::encode(entry.content_hash),
                size = entry.size,
                path = entry.relative_path.display(),
            );
        }
    }
    println!(
        "import-state: share={share} files_seen={seen} files_imported={imp} bytes_total={bytes} escapes_blocked={esc} dry_run={dry}",
        share = args.as_share,
        seen = report.files_seen,
        imp = report.files_imported,
        bytes = report.bytes_total,
        esc = report.escapes_blocked,
        dry = report.dry_run,
    );
    Ok(())
}

fn run_share_init(args: ShareInitArgs) -> Result<()> {
    let written = share_init::append_share(
        &args.config,
        args.preset,
        &args.name,
        &args.path,
        args.sign_key_ref.as_deref(),
    )?;
    tracing::info!(
        share = %args.name,
        preset = ?args.preset,
        path = %args.path.display(),
        config = %written.display(),
        "share declared in disk.toml",
    );
    println!(
        "share '{}' added to {} (preset={:?})",
        args.name,
        written.display(),
        args.preset
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_parses_sync_subcommand() {
        let cli = Cli::try_parse_from(["disk", "sync", "--server", "localhost:9443"]).unwrap();
        match cli.command {
            Some(Command::Sync(args)) => {
                assert_eq!(args.server, "localhost:9443");
                assert!(!args.insecure_localhost);
            }
            _ => panic!("expected sync subcommand"),
        }
    }

    #[test]
    fn cli_parses_sync_insecure() {
        let cli = Cli::try_parse_from([
            "disk",
            "sync",
            "--server",
            "localhost:9443",
            "--insecure-localhost",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Sync(args)) => {
                assert!(args.insecure_localhost);
            }
            _ => panic!("expected sync subcommand"),
        }
    }

    #[test]
    fn cli_default_server() {
        let cli = Cli::try_parse_from(["disk", "sync"]).unwrap();
        match cli.command {
            Some(Command::Sync(args)) => {
                assert_eq!(args.server, "disk.arcanada.ai:9443");
            }
            _ => panic!("expected sync subcommand"),
        }
    }

    #[test]
    fn cli_help_does_not_panic() {
        // Verify the CLI structure is valid.
        Cli::command().debug_assert();
    }

    #[test]
    fn cli_parses_enroll_subcommand() {
        let cli = Cli::try_parse_from([
            "disk",
            "enroll",
            "--server",
            "https://disk.example:9445",
            "--token",
            "deadbeef",
            "--node-id",
            "macos-1",
            "--cert-out",
            "/tmp/c.crt",
            "--key-out",
            "/tmp/c.key",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Enroll(args)) => {
                assert_eq!(args.server.as_deref(), Some("https://disk.example:9445"));
                assert_eq!(args.token.as_deref(), Some("deadbeef"));
                assert_eq!(args.node_id.as_deref(), Some("macos-1"));
            }
            _ => panic!("expected enroll subcommand"),
        }
    }

    #[test]
    fn cli_rejects_token_with_bootstrap_file() {
        let res = Cli::try_parse_from([
            "disk",
            "enroll",
            "--token",
            "ab",
            "--from-bootstrap-file",
            "/tmp/bf.toml",
        ]);
        assert!(res.is_err(), "clap should reject conflicting flags");
    }

    #[test]
    fn cli_parses_admin_pending_token() {
        let cli = Cli::try_parse_from([
            "disk",
            "admin",
            "pending-token",
            "--server",
            "https://disk.example:9445",
            "--hostname",
            "new-node-1",
            "--ttl-secs",
            "7200",
            "--admin-token",
            "secret",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Admin(AdminArgs {
                command: AdminCommand::PendingToken(p),
            })) => {
                assert_eq!(p.hostname, "new-node-1");
                assert_eq!(p.ttl_secs, 7200);
                assert_eq!(p.admin_token.as_deref(), Some("secret"));
            }
            _ => panic!("expected admin pending-token subcommand"),
        }
    }

    #[test]
    fn resolve_enroll_inputs_uses_bootstrap_file() {
        let tmp = tempfile::tempdir().unwrap();
        let bf_path = tmp.path().join("bf.toml");
        std::fs::write(
            &bf_path,
            r#"
server = "https://disk.example:9445"
token = "cafef00d"
node_id_hint = "from-bf"
"#,
        )
        .unwrap();

        let args = EnrollArgs {
            server: None,
            token: None,
            from_bootstrap_file: Some(bf_path),
            node_id: None,
            ca_cert: None,
            insecure_localhost: false,
            cert_out: PathBuf::from("/tmp/c.crt"),
            key_out: PathBuf::from("/tmp/c.key"),
        };
        let r = resolve_enroll_inputs(&args).unwrap();
        assert_eq!(r.server, "https://disk.example:9445");
        assert_eq!(r.token_hex, "cafef00d");
        assert_eq!(r.node_id, "from-bf");
    }

    #[test]
    fn resolve_enroll_inputs_cli_overrides_bootstrap() {
        let tmp = tempfile::tempdir().unwrap();
        let bf_path = tmp.path().join("bf.toml");
        std::fs::write(
            &bf_path,
            r#"
server = "https://disk.example:9445"
token = "cafef00d"
node_id_hint = "from-bf"
"#,
        )
        .unwrap();

        let args = EnrollArgs {
            server: Some("https://override:9999".into()),
            token: None,
            from_bootstrap_file: Some(bf_path),
            node_id: Some("override-node".into()),
            ca_cert: None,
            insecure_localhost: false,
            cert_out: PathBuf::from("/tmp/c.crt"),
            key_out: PathBuf::from("/tmp/c.key"),
        };
        let r = resolve_enroll_inputs(&args).unwrap();
        assert_eq!(r.server, "https://override:9999");
        assert_eq!(r.token_hex, "cafef00d"); // still from bf
        assert_eq!(r.node_id, "override-node");
    }

    #[test]
    fn cli_parses_archive_create() {
        let cli = Cli::try_parse_from([
            "disk",
            "archive",
            "create",
            "--source",
            "/data/wiki",
            "--output",
            "/data/wiki.disk-archive",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Archive(ArchiveArgs {
                command: ArchiveCommand::Create(c),
            })) => {
                assert_eq!(c.source, PathBuf::from("/data/wiki"));
                assert_eq!(c.output, PathBuf::from("/data/wiki.disk-archive"));
            }
            other => panic!("expected archive create, got {other:?}"),
        }
    }

    #[test]
    fn cli_parses_archive_list_and_restore() {
        let list =
            Cli::try_parse_from(["disk", "archive", "list", "--archive", "/tmp/arc"]).unwrap();
        match list.command {
            Some(Command::Archive(ArchiveArgs {
                command: ArchiveCommand::List(l),
            })) => assert_eq!(l.archive, PathBuf::from("/tmp/arc")),
            other => panic!("expected archive list, got {other:?}"),
        }

        let restore = Cli::try_parse_from([
            "disk",
            "archive",
            "restore",
            "--archive",
            "/tmp/arc",
            "--destination",
            "/tmp/out",
        ])
        .unwrap();
        match restore.command {
            Some(Command::Archive(ArchiveArgs {
                command: ArchiveCommand::Restore(r),
            })) => {
                assert_eq!(r.archive, PathBuf::from("/tmp/arc"));
                assert_eq!(r.destination, PathBuf::from("/tmp/out"));
            }
            other => panic!("expected archive restore, got {other:?}"),
        }
    }

    // ── conflicts CLI parsing ────────────────────────────────────────────────

    /// `disk conflicts list` parses into Command::Conflicts / ConflictsCommand::List.
    #[test]
    fn conflicts_resolve_roundtrip_list_parses() {
        let cli = Cli::try_parse_from(["disk", "conflicts", "list"]).unwrap();
        match cli.command {
            Some(Command::Conflicts(ConflictsArgs {
                command: ConflictsCommand::List(_),
            })) => {}
            other => panic!("expected conflicts list, got {other:?}"),
        }
    }

    /// `disk conflicts resolve <path> --action merge` parses correctly.
    #[test]
    fn conflicts_resolve_roundtrip_resolve_path_parses() {
        let cli = Cli::try_parse_from([
            "disk",
            "conflicts",
            "resolve",
            "--path",
            "notes/todo.md",
            "--action",
            "merge",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Conflicts(ConflictsArgs {
                command: ConflictsCommand::Resolve(r),
            })) => {
                assert_eq!(r.path.as_deref(), Some("notes/todo.md"));
                assert_eq!(r.action, ResolveAction::Merge);
                assert!(!r.all);
            }
            other => panic!("expected conflicts resolve, got {other:?}"),
        }
    }

    /// `disk conflicts resolve --all --action fork-local` parses correctly.
    #[test]
    fn conflicts_resolve_roundtrip_resolve_all_parses() {
        let cli = Cli::try_parse_from([
            "disk",
            "conflicts",
            "resolve",
            "--all",
            "--action",
            "fork-local",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Conflicts(ConflictsArgs {
                command: ConflictsCommand::Resolve(r),
            })) => {
                assert!(r.all);
                assert!(r.path.is_none());
                assert_eq!(r.action, ResolveAction::ForkLocal);
            }
            other => panic!("expected conflicts resolve --all, got {other:?}"),
        }
    }

    /// `disk conflicts resolve --path P --all` is rejected by clap (mutual exclusion).
    #[test]
    fn conflicts_resolve_roundtrip_path_and_all_conflict() {
        let res = Cli::try_parse_from([
            "disk",
            "conflicts",
            "resolve",
            "--path",
            "file.md",
            "--all",
            "--action",
            "keep-local",
        ]);
        assert!(res.is_err(), "clap must reject --path and --all together");
    }

    /// Round-trip: list → resolve via live loopback REST (in-process mock daemon).
    ///
    /// This test spins up the REST router with a real MetaDb, seeds one conflict,
    /// calls run_conflicts_list + run_conflicts_resolve, then verifies the conflict
    /// is gone from list_unresolved_conflicts.
    #[tokio::test]
    async fn conflicts_resolve_roundtrip_live() {
        use disk_core::types::ConflictRecord;
        use std::net::SocketAddr;

        let dir = tempfile::tempdir().unwrap();
        let db = disk_core::MetaDb::open(&dir.path().join("meta.db"))
            .await
            .unwrap();

        // Seed a conflict.
        let rec = ConflictRecord {
            id: None,
            vault_id: "default".into(),
            path: "notes/roundtrip.md".into(),
            conflict_type: "Concurrent".into(),
            local_hash: None,
            remote_hash: None,
            base_hash: None,
            resolution: None,
            fork_path: Some("notes/roundtrip.sync-conflict-abc12345-20260101-120000.md".into()),
            resolved: false,
            created_at: 0,
            resolved_at: None,
        };
        db.create_conflict(&rec).await.unwrap();
        let db_ref = std::sync::Arc::new(db.clone());

        // Start loopback REST server.
        let (state, _, _) = disk_client::DaemonState::new("test-node", "v0");
        let state = state.with_meta_db(db);
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let shutdown = futures::future::pending::<()>();
        let local_addr = disk_client::serve(state, bind, shutdown).await.unwrap();

        let addr = Some(local_addr);

        // run_conflicts_list should succeed (no assertion on output, just no error).
        commands::run_conflicts_list(addr, None).await.unwrap();

        // run_conflicts_resolve for the specific path.
        commands::run_conflicts_resolve(
            addr,
            None,
            Some("notes/roundtrip.md".into()),
            false,
            "keep-local",
        )
        .await
        .unwrap();

        // Verify via DB that conflict is resolved.
        let remaining = db_ref.list_unresolved_conflicts().await.unwrap();
        assert!(
            remaining.is_empty(),
            "conflict must be resolved after run_conflicts_resolve"
        );
    }

    #[test]
    fn cli_parses_versions_list() {
        let cli = Cli::try_parse_from([
            "disk",
            "versions",
            "list",
            "--path",
            "notes/a.md",
            "--vault",
            "wiki",
            "--api",
            "http://127.0.0.1:9446",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Versions(VersionsArgs {
                command: VersionsCommand::List(l),
            })) => {
                assert_eq!(l.path, "notes/a.md");
                assert_eq!(l.vault, "wiki");
                assert_eq!(l.api.as_deref(), Some("http://127.0.0.1:9446"));
            }
            other => panic!("expected versions list, got {other:?}"),
        }
    }

    #[test]
    fn cli_parses_versions_restore() {
        let cli = Cli::try_parse_from([
            "disk",
            "versions",
            "restore",
            "--path",
            "notes/a.md",
            "--version-id",
            "3",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Versions(VersionsArgs {
                command: VersionsCommand::Restore(r),
            })) => {
                assert_eq!(r.path, "notes/a.md");
                assert_eq!(r.version_id, 3);
            }
            other => panic!("expected versions restore, got {other:?}"),
        }
    }

    #[test]
    fn cli_parses_snapshots_create() {
        let cli = Cli::try_parse_from([
            "disk",
            "snapshots",
            "create",
            "--vault",
            "wiki",
            "--label",
            "cutover",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Snapshots(SnapshotsArgs {
                command: SnapshotsCommand::Create(c),
            })) => {
                assert_eq!(c.vault, "wiki");
                assert_eq!(c.label.as_deref(), Some("cutover"));
            }
            other => panic!("expected snapshots create, got {other:?}"),
        }
    }

    #[test]
    fn cli_parses_trash_list() {
        let cli = Cli::try_parse_from(["disk", "trash", "list", "--vault", "wiki"]).unwrap();
        match cli.command {
            Some(Command::Trash(TrashArgs {
                command: TrashCommand::List(l),
            })) => {
                assert_eq!(l.vault, "wiki");
            }
            other => panic!("expected trash list, got {other:?}"),
        }
    }

    #[test]
    fn cli_parses_lan_peers() {
        let cli = Cli::try_parse_from(["disk", "lan", "peers"]).unwrap();
        match cli.command {
            Some(Command::Lan(LanArgs {
                command: LanCommand::Peers(p),
            })) => {
                assert!(p.addr.is_none());
            }
            other => panic!("expected lan peers, got {other:?}"),
        }
    }

    #[test]
    fn cli_parses_embeddings_status() {
        let cli = Cli::try_parse_from(["disk", "embeddings", "status", "--share", "wiki"]).unwrap();
        match cli.command {
            Some(Command::Embeddings(EmbeddingsArgs {
                command: EmbeddingsCommand::Status(s),
            })) => {
                assert_eq!(s.share.as_deref(), Some("wiki"));
                assert!(s.config.is_none());
            }
            other => panic!("expected embeddings status, got {other:?}"),
        }
    }

    #[test]
    fn cli_parses_embeddings_write() {
        let cli = Cli::try_parse_from([
            "disk",
            "embeddings",
            "write",
            "--share",
            "wiki",
            "--path",
            "notes/a.md",
            "--vector-file",
            "/tmp/vec.bin",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Embeddings(EmbeddingsArgs {
                command: EmbeddingsCommand::Write(w),
            })) => {
                assert_eq!(w.share, "wiki");
                assert_eq!(w.path, "notes/a.md");
                assert_eq!(w.vector_file.as_deref(), Some(std::path::Path::new("/tmp/vec.bin")));
                assert!(w.vector_base64.is_none());
            }
            other => panic!("expected embeddings write, got {other:?}"),
        }
    }

    #[test]
    fn cli_parses_agents_revision() {
        let cli = Cli::try_parse_from([
            "disk",
            "agents",
            "revision",
            "--path",
            "notes/a.md",
            "--vault",
            "wiki",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Agents(AgentsArgs {
                command: AgentsCommand::Revision(r),
            })) => {
                assert_eq!(r.path, "notes/a.md");
                assert_eq!(r.vault, "wiki");
            }
            other => panic!("expected agents revision, got {other:?}"),
        }
    }

    #[test]
    fn cli_parses_agents_webhooks_register() {
        let cli = Cli::try_parse_from([
            "disk",
            "agents",
            "webhooks",
            "register",
            "--url",
            "https://hooks.example/agent",
            "--events",
            "agent.write_ok,agent.write_conflict",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Agents(AgentsArgs {
                command:
                    AgentsCommand::Webhooks(AgentsWebhooksArgs {
                        command: AgentsWebhooksCommand::Register(r),
                    }),
            })) => {
                assert_eq!(r.url, "https://hooks.example/agent");
                assert_eq!(r.events, vec!["agent.write_ok", "agent.write_conflict"]);
            }
            other => panic!("expected agents webhooks register, got {other:?}"),
        }
    }

    #[test]
    fn cli_parses_agents_write_file() {
        let cli = Cli::try_parse_from([
            "disk",
            "agents",
            "write",
            "--path",
            "notes/a.md",
            "--file",
            "/tmp/a.md",
            "--if-match-revision",
            "3",
            "--agent-id",
            "dreamer",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Agents(AgentsArgs {
                command: AgentsCommand::Write(w),
            })) => {
                assert_eq!(w.path, "notes/a.md");
                assert_eq!(
                    w.file.as_deref(),
                    Some(PathBuf::from("/tmp/a.md").as_path())
                );
                assert_eq!(w.if_match_revision, Some(3));
                assert_eq!(w.agent_id.as_deref(), Some("dreamer"));
            }
            other => panic!("expected agents write, got {other:?}"),
        }
    }

    // `disk conflicts show` subcommand parse────────────────────

    /// `disk conflicts show --path <file>` parses into
    /// `ConflictsCommand::Show(ConflictsShowArgs { path, addr: None })`.
    ///
    /// This test proves the new subcommand is wired in the clap tree — it
    /// catches regressions where the variant is defined but not registered
    /// in the `Subcommand` derive, which would make the command silently
    /// disappear from the CLI.
    #[test]
    fn cli_parses_conflicts_show_subcommand() {
        let cli =
            Cli::try_parse_from(["disk", "conflicts", "show", "--path", "docs/notes.md"]).unwrap();
        match cli.command {
            Some(Command::Conflicts(ConflictsArgs {
                command: ConflictsCommand::Show(s),
            })) => {
                assert_eq!(
                    s.path, "docs/notes.md",
                    "show path must match the --path argument"
                );
                assert!(
                    s.addr.is_none(),
                    "addr must default to None when not provided"
                );
            }
            other => panic!(
                "expected conflicts show, got {other:?}; \
                 the Show variant may not be registered in ConflictsCommand"
            ),
        }
    }

    /// `disk conflicts show --path <file> --addr 127.0.0.1:9444` parses
    /// the optional `--addr` override correctly.
    #[test]
    fn cli_parses_conflicts_show_with_addr_override() {
        use std::net::{Ipv4Addr, SocketAddr};

        let cli = Cli::try_parse_from([
            "disk",
            "conflicts",
            "show",
            "--path",
            "notes/daily.md",
            "--addr",
            "127.0.0.1:9444",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Conflicts(ConflictsArgs {
                command: ConflictsCommand::Show(s),
            })) => {
                assert_eq!(s.path, "notes/daily.md");
                assert_eq!(
                    s.addr,
                    Some(SocketAddr::new(
                        std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                        9444
                    ))
                );
            }
            other => panic!("expected conflicts show --addr, got {other:?}"),
        }
    }
}
