//! Fuzz `disk_core::path_guard::validate` — must return `Result`, never panic,
//! on adversarial candidate paths relative to a real sync root.

#![no_main]

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use disk_core::path_guard::validate;
use libfuzzer_sys::fuzz_target;

static ROOT: OnceLock<PathBuf> = OnceLock::new();

fn fuzz_root() -> &'static Path {
    ROOT.get_or_init(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("notes")).expect("mkdir notes");
        dir.keep()
    })
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    // Lossy UTF-8 paths cover null-byte rejection and `..` components.
    let candidate = PathBuf::from(String::from_utf8_lossy(data).into_owned());
    let _ = validate(&candidate, fuzz_root());
});
