//! `disk share init --preset` wizard (DISK-0006 R10).
//!
//! Plan §CLI surface:
//!   `disk share init --preset <backup|distribute|collaborate|publish>
//!                    --name <SHARE> --path <DIR>`
//!
//! The wizard appends a new `[[share]]` block to an existing `disk.toml`
//! and re-validates the resulting file by parsing it through
//! [`DiskConfig::from_str`]. If validation fails after the append, the
//! original file content is restored on disk — never leave the operator
//! with a broken config.
//!
//! Pure-data helpers ([`Preset::direction`], [`render_share_section`],
//! [`append_share`]) live here so the CLI binary stays a thin wrapper.

use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{anyhow, bail, Context, Result};
use disk_client::config::{Direction, DiskConfig};

/// Preset directional intent. Maps 1:1 onto [`Direction`] for the four
/// supported `intended_direction` values in [`PRD §4.11.3`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[clap(rename_all = "lowercase")]
pub enum Preset {
    /// This host PUSHES to the server (server keeps backup copies).
    Backup,
    /// Server PUSHES to this host (this host consumes the distributed content).
    Distribute,
    /// Two-way sync.
    Collaborate,
    /// This host owns the data and signs every artefact (publisher gate).
    Publish,
}

impl Preset {
    /// The TOML enum literal written into `intended_direction`.
    pub fn direction_str(&self) -> &'static str {
        match self {
            Preset::Backup => "send_only",
            Preset::Distribute => "receive_only",
            Preset::Collaborate => "bidirectional",
            Preset::Publish => "publisher",
        }
    }

    /// Matching [`Direction`] enum value — used to cross-check the
    /// generated TOML parses back to the right variant.
    pub fn direction(&self) -> Direction {
        match self {
            Preset::Backup => Direction::SendOnly,
            Preset::Distribute => Direction::ReceiveOnly,
            Preset::Collaborate => Direction::Bidirectional,
            Preset::Publish => Direction::Publisher,
        }
    }

    /// `publish` preset requires a Vault key reference for signing.
    pub fn requires_sign_key_ref(&self) -> bool {
        matches!(self, Preset::Publish)
    }
}

/// Render a `[[share]]` TOML block for the given preset.
///
/// `sign_key_ref` is required when `preset == Publish` (caller validated).
pub fn render_share_section(
    preset: Preset,
    name: &str,
    path: &Path,
    sign_key_ref: Option<&str>,
) -> Result<String> {
    if preset.requires_sign_key_ref() && sign_key_ref.is_none() {
        bail!("preset 'publish' requires --sign-key-ref <vault-ref>");
    }
    if !preset.requires_sign_key_ref() && sign_key_ref.is_some() {
        bail!("--sign-key-ref is only valid with preset 'publish'");
    }

    let path_str = path
        .to_str()
        .ok_or_else(|| anyhow!("path is not valid UTF-8: {}", path.display()))?;

    let mut out = String::new();
    out.push_str("\n[[share]]\n");
    out.push_str(&format!("name = {}\n", toml_string(name)));
    out.push_str(&format!("path = {}\n", toml_string(path_str)));
    out.push_str(&format!(
        "intended_direction = \"{}\"\n",
        preset.direction_str()
    ));
    if preset == Preset::Publish {
        let key_ref = sign_key_ref.expect("checked above");
        out.push_str("\n[share.publisher]\n");
        out.push_str(&format!("sign_key_ref = {}\n", toml_string(key_ref)));
        out.push_str("quarantine_on_failure = true\n");
    }
    Ok(out)
}

/// Append a rendered `[[share]]` block to an existing `disk.toml`.
///
/// Contract:
/// 1. `cfg_path` MUST already exist and parse cleanly. If it doesn't, the
///    operator hasn't completed enrollment — surface a clear error.
/// 2. A share named `name` MUST NOT already exist (no silent overwrite).
/// 3. On successful append, the resulting file is re-parsed through
///    [`DiskConfig::from_str`]; if validation fails, the original file
///    content is restored verbatim before returning the error.
///
/// Returns the absolute path of the modified config file.
pub fn append_share(
    cfg_path: &Path,
    preset: Preset,
    name: &str,
    path: &Path,
    sign_key_ref: Option<&str>,
) -> Result<PathBuf> {
    if !cfg_path.exists() {
        bail!(
            "{} does not exist — run `disk enroll` first to bootstrap disk.toml",
            cfg_path.display()
        );
    }

    let original =
        fs::read_to_string(cfg_path).with_context(|| format!("read {}", cfg_path.display()))?;

    let cfg: DiskConfig = DiskConfig::from_str(&original).with_context(|| {
        format!(
            "existing {} is invalid; refusing to extend it",
            cfg_path.display()
        )
    })?;

    if cfg.shares.iter().any(|s| s.name == name) {
        bail!(
            "share '{}' already declared in {} — pick a different --name",
            name,
            cfg_path.display()
        );
    }

    let block = render_share_section(preset, name, path, sign_key_ref)?;
    let updated = format!("{original}{block}");

    fs::write(cfg_path, &updated).with_context(|| format!("write {}", cfg_path.display()))?;

    if let Err(e) = DiskConfig::from_str(&updated) {
        // Rollback: restore the original file before bubbling the error up
        // so the operator never sees a broken disk.toml on disk.
        fs::write(cfg_path, &original).with_context(|| {
            format!(
                "rollback failed: could not restore original {}",
                cfg_path.display()
            )
        })?;
        return Err(anyhow!(
            "generated share block failed validation; original config restored: {}",
            e
        ));
    }

    Ok(cfg_path.to_path_buf())
}

fn toml_string(s: &str) -> String {
    // TOML basic-string escape — sufficient for our inputs (names + paths
    // + vault refs are all ASCII-friendly; double quote and backslash are
    // the two characters we must escape).
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"
[node]
id = "dev"
[node.default]
intended_direction = "bidirectional"

[server]
address = "host:9443"
client_cert = "/etc/disk-arcana/client.crt"
client_key  = "/etc/disk-arcana/client.key"
"#;

    fn write_base(dir: &Path) -> PathBuf {
        let p = dir.join("disk.toml");
        fs::write(&p, BASE).unwrap();
        p
    }

    #[test]
    fn preset_direction_mapping_is_complete() {
        assert_eq!(Preset::Backup.direction(), Direction::SendOnly);
        assert_eq!(Preset::Distribute.direction(), Direction::ReceiveOnly);
        assert_eq!(Preset::Collaborate.direction(), Direction::Bidirectional);
        assert_eq!(Preset::Publish.direction(), Direction::Publisher);
    }

    #[test]
    fn render_backup_emits_send_only() {
        let s =
            render_share_section(Preset::Backup, "vault", Path::new("/data/vault"), None).unwrap();
        assert!(s.contains("name = \"vault\""));
        assert!(s.contains("path = \"/data/vault\""));
        assert!(s.contains("intended_direction = \"send_only\""));
        assert!(!s.contains("[share.publisher]"));
    }

    #[test]
    fn render_collaborate_emits_bidirectional() {
        let s = render_share_section(Preset::Collaborate, "wiki", Path::new("/data/wiki"), None)
            .unwrap();
        assert!(s.contains("intended_direction = \"bidirectional\""));
    }

    #[test]
    fn render_publish_requires_sign_key_ref() {
        let err =
            render_share_section(Preset::Publish, "pub", Path::new("/data/pub"), None).unwrap_err();
        assert!(err.to_string().contains("--sign-key-ref"));
    }

    #[test]
    fn render_publish_emits_publisher_section() {
        let s = render_share_section(
            Preset::Publish,
            "hermes",
            Path::new("/var/disk-arcana/hermes"),
            Some("vault:transit/keys/hermes-publisher"),
        )
        .unwrap();
        assert!(s.contains("intended_direction = \"publisher\""));
        assert!(s.contains("[share.publisher]"));
        assert!(s.contains("sign_key_ref = \"vault:transit/keys/hermes-publisher\""));
        assert!(s.contains("quarantine_on_failure = true"));
    }

    #[test]
    fn render_rejects_sign_key_ref_for_non_publish() {
        let err = render_share_section(Preset::Backup, "x", Path::new("/x"), Some("vault:foo"))
            .unwrap_err();
        assert!(err.to_string().contains("only valid with preset 'publish'"));
    }

    #[test]
    fn append_to_existing_config_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_base(dir.path());
        append_share(
            &p,
            Preset::Collaborate,
            "wiki",
            Path::new("/data/wiki"),
            None,
        )
        .unwrap();
        let cfg = DiskConfig::from_str(&fs::read_to_string(&p).unwrap()).unwrap();
        assert_eq!(cfg.shares.len(), 1);
        assert_eq!(cfg.shares[0].name, "wiki");
        assert_eq!(cfg.share_direction("wiki"), Some(Direction::Bidirectional));
    }

    #[test]
    fn append_publish_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_base(dir.path());
        append_share(
            &p,
            Preset::Publish,
            "hermes",
            Path::new("/var/disk-arcana/hermes"),
            Some("vault:transit/keys/hermes-publisher"),
        )
        .unwrap();
        let cfg = DiskConfig::from_str(&fs::read_to_string(&p).unwrap()).unwrap();
        assert_eq!(cfg.shares.len(), 1);
        assert_eq!(cfg.share_direction("hermes"), Some(Direction::Publisher));
        assert!(cfg.shares[0].publisher.is_some());
        let pub_section = cfg.shares[0].publisher.as_ref().unwrap();
        assert_eq!(
            pub_section.sign_key_ref,
            "vault:transit/keys/hermes-publisher"
        );
        assert!(pub_section.quarantine_on_failure);
    }

    #[test]
    fn append_rejects_duplicate_share_name() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_base(dir.path());
        append_share(&p, Preset::Backup, "vault", Path::new("/v1"), None).unwrap();
        let err =
            append_share(&p, Preset::Distribute, "vault", Path::new("/v2"), None).unwrap_err();
        assert!(err.to_string().contains("already declared"));
    }

    #[test]
    fn append_refuses_missing_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("absent.toml");
        let err = append_share(&p, Preset::Backup, "v", Path::new("/x"), None).unwrap_err();
        assert!(err.to_string().contains("does not exist"));
        assert!(err.to_string().contains("disk enroll"));
    }

    #[test]
    fn append_rolls_back_on_validation_failure() {
        // Trigger the rollback path by feeding a path that the validator
        // rejects (relative paths fail validation).
        let dir = tempfile::tempdir().unwrap();
        let p = write_base(dir.path());
        let before = fs::read_to_string(&p).unwrap();

        let err =
            append_share(&p, Preset::Backup, "rel", Path::new("relative/path"), None).unwrap_err();
        assert!(err.to_string().contains("validation"));

        let after = fs::read_to_string(&p).unwrap();
        assert_eq!(before, after, "file must be restored on rollback");
    }
}
