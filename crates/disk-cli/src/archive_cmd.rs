//! `disk archive` — create, list, and restore indexed `.disk-archive` folders.

use std::path::PathBuf;

use anyhow::{Context, Result};
use disk_core::archive::{self, ArchiveIndex};

/// `disk archive create --source <dir> --output <archive-dir>`.
pub fn run_create(source: PathBuf, output: PathBuf) -> Result<()> {
    let index = archive::create(&source, &output)
        .with_context(|| format!("create archive from {}", source.display()))?;
    println!(
        "archive created: {} ({} file(s))",
        output.display(),
        index.entries.len()
    );
    Ok(())
}

/// `disk archive list --archive <archive-dir>`.
pub fn run_list(archive: PathBuf) -> Result<()> {
    let index = archive::read_index(&archive)
        .with_context(|| format!("read index from {}", archive.display()))?;
    print_index(&index);
    Ok(())
}

/// `disk archive restore --archive <archive-dir> --destination <dir>`.
pub fn run_restore(archive: PathBuf, destination: PathBuf) -> Result<()> {
    let index = archive::restore(&archive, &destination).with_context(|| {
        format!(
            "restore {} into {}",
            archive.display(),
            destination.display()
        )
    })?;
    println!(
        "restored {} file(s) into {}",
        index.entries.len(),
        destination.display()
    );
    Ok(())
}

fn print_index(index: &ArchiveIndex) {
    if index.entries.is_empty() {
        println!("(empty archive, version {})", index.version);
        return;
    }
    println!("version: {}", index.version);
    println!("{:<48}  {:>10}  digest", "path", "size");
    println!("{}", "-".repeat(90));
    for entry in &index.entries {
        let digest_short = if entry.digest.len() > 16 {
            &entry.digest[..16]
        } else {
            &entry.digest
        };
        println!("{:<48}  {:>10}  {digest_short}…", entry.path, entry.size,);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn cli_archive_round_trip_via_commands() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        let arc = tmp.path().join("arc");
        let dst = tmp.path().join("dst");
        fs::create_dir_all(src.join("a")).unwrap();
        fs::write(src.join("a/b.txt"), b"payload").unwrap();

        run_create(src.clone(), arc.clone()).unwrap();
        run_list(arc.clone()).unwrap();
        run_restore(arc, dst.clone()).unwrap();
        assert_eq!(fs::read(dst.join("a/b.txt")).unwrap(), b"payload");
    }
}
