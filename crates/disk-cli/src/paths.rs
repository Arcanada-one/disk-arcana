//! Platform-default install paths for the Disk Arcana client CLI.

#[cfg(windows)]
pub const DEFAULT_CONFIG: &str = r"C:\ProgramData\disk-arcana\disk.toml";
#[cfg(not(windows))]
pub const DEFAULT_CONFIG: &str = "/etc/disk-arcana/disk.toml";

#[cfg(windows)]
pub const DEFAULT_STATE_DIR: &str = r"C:\ProgramData\disk-arcana\state";
#[cfg(not(windows))]
pub const DEFAULT_STATE_DIR: &str = "/var/lib/disk-arcana";

#[cfg(windows)]
pub const DEFAULT_META_DB: &str = r"C:\ProgramData\disk-arcana\state\meta.db";
#[cfg(not(windows))]
pub const DEFAULT_META_DB: &str = "/var/lib/disk-arcana/meta.db";

#[cfg(windows)]
pub const DEFAULT_CLIENT_CERT: &str = r"C:\ProgramData\disk-arcana\client.crt";
#[cfg(not(windows))]
pub const DEFAULT_CLIENT_CERT: &str = "/etc/disk-arcana/client.crt";

#[cfg(windows)]
pub const DEFAULT_CLIENT_KEY: &str = r"C:\ProgramData\disk-arcana\client.key";
#[cfg(not(windows))]
pub const DEFAULT_CLIENT_KEY: &str = "/etc/disk-arcana/client.key";

/// Install location mirrored by `scripts/install-windows.ps1` / Linux `install` target.
#[allow(dead_code)]
pub const DEFAULT_INSTALL_DIR: &str = if cfg!(windows) {
    r"C:\Program Files\Disk Arcana"
} else {
    "/usr/local/bin"
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_use_platform_absolute_paths() {
        let paths = [
            DEFAULT_CONFIG,
            DEFAULT_STATE_DIR,
            DEFAULT_META_DB,
            DEFAULT_CLIENT_CERT,
            DEFAULT_CLIENT_KEY,
            DEFAULT_INSTALL_DIR,
        ];
        for path in paths {
            assert!(
                std::path::Path::new(path).is_absolute(),
                "expected absolute path, got {path}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_defaults_live_under_programdata() {
        assert!(DEFAULT_CONFIG.starts_with(r"C:\ProgramData\disk-arcana"));
        assert!(DEFAULT_STATE_DIR.starts_with(r"C:\ProgramData\disk-arcana"));
        assert_eq!(DEFAULT_INSTALL_DIR, r"C:\Program Files\Disk Arcana");
    }
}
