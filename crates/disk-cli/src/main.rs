#![forbid(unsafe_code)]

mod archive_cmd;
mod commands;
mod daemon;
mod paths;
mod share_init;

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
    /// Filter by vault name (reserved for future use).
    #[arg(long)]
    pub vault: Option<String>,

    /// Daemon REST address. Defaults to `127.0.0.1:9444`.
    #[arg(long)]
    pub addr: Option<std::net::SocketAddr>,
}

/// `disk conflicts show <path> [--addr <ip:port>]` — side-by-side diff.
#[derive(clap::Args, Debug)]
pub struct ConflictsShowArgs {
    /// Vault-relative path of the conflict to show.
    #[arg(long)]
    pub path: String,

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
            ConflictsCommand::List(l) => commands::run_conflicts_list(l.addr).await,
            ConflictsCommand::Resolve(r) => {
                commands::run_conflicts_resolve(r.addr, r.path, r.all, r.action.as_str()).await
            }
            ConflictsCommand::Show(s) => commands::run_conflicts_show(s.addr, &s.path).await,
        },
        Some(Command::Archive(args)) => match args.command {
            ArchiveCommand::Create(c) => archive_cmd::run_create(c.source, c.output),
            ArchiveCommand::List(l) => archive_cmd::run_list(l.archive),
            ArchiveCommand::Restore(r) => archive_cmd::run_restore(r.archive, r.destination),
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
        .issue_pending_token(&admin_token, &args.hostname, args.ttl_secs)
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
        commands::run_conflicts_list(addr).await.unwrap();

        // run_conflicts_resolve for the specific path.
        commands::run_conflicts_resolve(
            addr,
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
