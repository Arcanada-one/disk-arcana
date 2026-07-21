//! Safe, indexed folder archives stored as independently compressed entries.

use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};

const INDEX: &str = "index.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchiveEntry {
    pub path: String,
    pub size: u64,
    pub digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchiveIndex {
    pub version: u32,
    pub entries: Vec<ArchiveEntry>,
}

pub fn create(source: &Path, archive: &Path) -> io::Result<ArchiveIndex> {
    if !source.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "source is not a directory",
        ));
    }
    fs::create_dir_all(archive)?;
    let mut entries = Vec::new();
    for item in walkdir::WalkDir::new(source).follow_links(false) {
        let item = item.map_err(io::Error::other)?;
        if !item.file_type().is_file() {
            continue;
        }
        let rel = item.path().strip_prefix(source).map_err(io::Error::other)?;
        let rel = rel.to_string_lossy().replace('\\', "/");
        if rel == INDEX || rel.split('/').any(|part| part == ".disk-archive") {
            continue;
        }
        let data = fs::read(item.path())?;
        let digest = blake3::hash(&data).to_hex().to_string();
        let slot = archive.join("entries").join(format!("{digest}.zst"));
        fs::create_dir_all(slot.parent().unwrap())?;
        let mut out = fs::File::create(slot)?;
        let compressed = zstd::stream::encode_all(data.as_slice(), 3)?;
        out.write_all(&compressed)?;
        entries.push(ArchiveEntry {
            path: rel,
            size: data.len() as u64,
            digest,
        });
    }
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    let index = ArchiveIndex {
        version: 1,
        entries,
    };
    fs::write(
        archive.join(INDEX),
        serde_json::to_vec_pretty(&index).map_err(io::Error::other)?,
    )?;
    Ok(index)
}

pub fn read_index(archive: &Path) -> io::Result<ArchiveIndex> {
    serde_json::from_slice(&fs::read(archive.join(INDEX))?).map_err(io::Error::other)
}

pub fn restore(archive: &Path, destination: &Path) -> io::Result<ArchiveIndex> {
    let index = read_index(archive)?;
    fs::create_dir_all(destination)?;
    for entry in &index.entries {
        let relative = Path::new(&entry.path);
        if relative.is_absolute()
            || relative
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "archive contains unsafe path",
            ));
        }
        let mut compressed = Vec::new();
        fs::File::open(
            archive
                .join("entries")
                .join(format!("{}.zst", entry.digest)),
        )?
        .read_to_end(&mut compressed)?;
        let data = zstd::stream::decode_all(compressed.as_slice())?;
        if data.len() as u64 != entry.size || blake3::hash(&data).to_hex().as_str() != entry.digest
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "archive entry integrity check failed",
            ));
        }
        let target = destination.join(relative);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(target, data)?;
    }
    Ok(index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_is_indexed_and_compressed() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        let arc = tmp.path().join("arc");
        let dst = tmp.path().join("dst");
        fs::create_dir_all(src.join("nested")).unwrap();
        fs::write(src.join("nested/a.md"), b"hello").unwrap();
        let index = create(&src, &arc).unwrap();
        assert_eq!(index.entries[0].path, "nested/a.md");
        assert_eq!(read_index(&arc).unwrap(), index);
        restore(&arc, &dst).unwrap();
        assert_eq!(fs::read(dst.join("nested/a.md")).unwrap(), b"hello");
    }

    #[test]
    fn restore_rejects_parent_traversal_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let arc = tmp.path().join("arc");
        fs::create_dir_all(arc.join("entries")).unwrap();
        let digest = blake3::hash(b"x").to_hex().to_string();
        fs::write(arc.join("entries").join(format!("{digest}.zst")), b"").unwrap();
        let index = ArchiveIndex {
            version: 1,
            entries: vec![ArchiveEntry {
                path: "../escape.txt".into(),
                size: 1,
                digest,
            }],
        };
        fs::write(arc.join(INDEX), serde_json::to_vec_pretty(&index).unwrap()).unwrap();
        let err = restore(&arc, &tmp.path().join("dst")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
