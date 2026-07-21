//! `disk vault` — E2EE key unlock / lock via OS keychain (DISK-0015 slice 4).

use std::io::{self, BufRead, IsTerminal, Write};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use disk_client::config::DiskConfig;
use disk_client::{
    lock_vault_key, resolve_vault_key, unlock_vault_key, vault_key_status, VaultLockState,
};

use crate::paths;

/// `disk vault <subcmd>`.
#[derive(clap::Args, Debug)]
pub struct VaultArgs {
    #[command(subcommand)]
    pub command: VaultCommand,
}

#[derive(clap::Subcommand, Debug)]
pub enum VaultCommand {
    /// Derive the vault key from a passphrase and store it in the OS keychain.
    Unlock(VaultUnlockArgs),
    /// Remove the derived key from the keychain (lock).
    Lock(VaultLockArgs),
    /// Show whether the vault E2EE key is unlocked in the keychain.
    Status(VaultStatusArgs),
}

#[derive(clap::Args, Debug)]
pub struct VaultUnlockArgs {
    /// Path to `disk.toml` (reads `[node].id` for the keychain label).
    #[arg(long, default_value = paths::DEFAULT_CONFIG)]
    pub config: PathBuf,

    /// State directory for file-key fallback (`{state_dir}/keys`).
    #[arg(long, default_value = paths::DEFAULT_STATE_DIR)]
    pub state_dir: PathBuf,

    /// Passphrase (omit to read from stdin; on a TTY a prompt is shown).
    #[arg(long)]
    pub passphrase: Option<String>,

    /// Hex-encoded Argon2 salt for first-time setup (generated when omitted).
    #[arg(long)]
    pub salt: Option<String>,
}

#[derive(clap::Args, Debug)]
pub struct VaultLockArgs {
    #[arg(long, default_value = paths::DEFAULT_CONFIG)]
    pub config: PathBuf,

    #[arg(long, default_value = paths::DEFAULT_STATE_DIR)]
    pub state_dir: PathBuf,
}

#[derive(clap::Args, Debug)]
pub struct VaultStatusArgs {
    #[arg(long, default_value = paths::DEFAULT_CONFIG)]
    pub config: PathBuf,

    #[arg(long, default_value = paths::DEFAULT_STATE_DIR)]
    pub state_dir: PathBuf,
}

pub fn run_unlock(args: VaultUnlockArgs) -> Result<()> {
    let cfg = DiskConfig::load(&args.config)
        .with_context(|| format!("load {}", args.config.display()))?;
    let passphrase = read_passphrase(args.passphrase.as_deref())?;
    let salt = match args.salt.as_deref() {
        Some(hex) => Some(hex::decode(hex.trim()).with_context(|| "invalid --salt hex")?),
        None => None,
    };
    unlock_vault_key(
        passphrase.as_bytes(),
        &cfg.node.id,
        &args.state_dir,
        salt.as_deref(),
    )?;
    // Verify load path works before telling the operator we're done.
    let _ = resolve_vault_key(&cfg.node.id, &args.state_dir)
        .context("verify keychain round-trip after unlock")?
        .expect("key must be loadable immediately after unlock");
    println!(
        "vault unlocked for node '{}' (E2EE key stored in OS keychain / file fallback)",
        cfg.node.id
    );
    Ok(())
}

pub fn run_lock(args: VaultLockArgs) -> Result<()> {
    let cfg = DiskConfig::load(&args.config)
        .with_context(|| format!("load {}", args.config.display()))?;
    let had = lock_vault_key(&cfg.node.id, &args.state_dir)?;
    if had {
        println!("vault locked for node '{}'", cfg.node.id);
    } else {
        println!("vault already locked for node '{}'", cfg.node.id);
    }
    Ok(())
}

pub fn run_status(args: VaultStatusArgs) -> Result<()> {
    let cfg = DiskConfig::load(&args.config)
        .with_context(|| format!("load {}", args.config.display()))?;
    let state = vault_key_status(&cfg.node.id, &args.state_dir)?;
    let env_override = std::env::var("DISK_VAULT_PASSPHRASE")
        .map(|v| !v.is_empty())
        .unwrap_or(false);
    match state {
        VaultLockState::Unlocked => {
            println!("vault: unlocked (keychain) for node '{}'", cfg.node.id);
        }
        VaultLockState::Locked => {
            println!("vault: locked for node '{}'", cfg.node.id);
        }
    }
    if env_override {
        println!("note: DISK_VAULT_PASSPHRASE is set — daemon prefers env over keychain");
    }
    Ok(())
}

fn read_passphrase(flag: Option<&str>) -> Result<String> {
    if let Some(p) = flag {
        if p.is_empty() {
            bail!("passphrase must not be empty");
        }
        return Ok(p.to_owned());
    }

    let stdin = io::stdin();
    if stdin.is_terminal() {
        eprint!("Vault passphrase: ");
        io::stderr().flush()?;
        read_passphrase_tty()
    } else {
        let mut line = String::new();
        stdin.lock().read_line(&mut line)?;
        let line = line.trim_end_matches(['\r', '\n']).to_owned();
        if line.is_empty() {
            bail!("passphrase must not be empty");
        }
        Ok(line)
    }
}

#[cfg(unix)]
fn read_passphrase_tty() -> Result<String> {
    let pass = rpassword::read_password().context("read passphrase from TTY")?;
    if pass.is_empty() {
        bail!("passphrase must not be empty");
    }
    Ok(pass)
}

#[cfg(not(unix))]
fn read_passphrase_tty() -> Result<String> {
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    let line = line.trim_end_matches(['\r', '\n']).to_owned();
    if line.is_empty() {
        bail!("passphrase must not be empty");
    }
    Ok(line)
}
