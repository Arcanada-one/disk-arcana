#![forbid(unsafe_code)]

mod daemon;
mod share_init;

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

    /// Path to the `disk.toml` to extend. Defaults to `/etc/disk-arcana/disk.toml`.
    #[arg(long, default_value = "/etc/disk-arcana/disk.toml")]
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
    #[arg(long, default_value = "/var/lib/disk-arcana/meta.db")]
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
    /// Server address in host:port format (e.g. disk.arcanada.one:9443).
    #[arg(long, default_value = "disk.arcanada.one:9443")]
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
    /// EnrollmentService gRPC endpoint (e.g. `https://disk.arcanada.one:9445`).
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
    #[arg(long, default_value = "/etc/disk-arcana/client.crt")]
    pub cert_out: PathBuf,

    /// Output path for the private key (PEM, mode 0600).
    #[arg(long, default_value = "/etc/disk-arcana/client.key")]
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
    #[arg(long, default_value = "https://disk.arcanada.one:9445")]
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
                assert_eq!(args.server, "disk.arcanada.one:9443");
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
}
