#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "disk", version, about = "Disk Arcana CLI (Phase 1 stub)")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Initialise a new vault config (not implemented yet — see DISK-0010).
    Init,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Init) => {
            println!("disk init: not implemented yet (DISK-0010 will land this)");
        }
        None => {
            let version = env!("CARGO_PKG_VERSION");
            println!("disk-cli v{version} (Phase 1 stub)");
        }
    }
}
