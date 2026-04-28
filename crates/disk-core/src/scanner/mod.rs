//! Filesystem scanner: walks the vault root, applies the filter, computes
//! blake3 content hashes (with mtime/size fast-path), and detects renames
//! through inode reuse.

mod hash;
mod rename;
mod walk;

pub use rename::detect_renames;
pub use walk::{scan_root, FileScanner};
