#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

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
    pub config: std::path::PathBuf,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let cli = Cli::parse();
    match cli.command {
        Some(Command::Init) => {
            println!("disk init: not implemented yet (DISK-0010)");
        }
        Some(Command::Sync(args)) => {
            println!("disk sync: connecting to {}", args.server);
            println!(
                "  insecure-localhost: {}, config: {}",
                args.insecure_localhost,
                args.config.display()
            );
            println!("  Full sync loop not yet implemented — use disk-client library.");
        }
        None => {
            let version = env!("CARGO_PKG_VERSION");
            println!("disk v{version} — run `disk --help` for available commands");
        }
    }
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
}
