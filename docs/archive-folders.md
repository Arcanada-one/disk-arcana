# Archive folders (DISK-0009)

Disk Arcana can snapshot a directory tree into an indexed `.disk-archive`
folder: each file is zstd-compressed and content-addressed (BLAKE3), with
metadata in `index.json`. Archives are excluded from sync scans (hardcoded deny
segment `.disk-archive`).

## CLI

```bash
# Create archive from a share subtree
disk archive create --source /path/to/folder --output /path/to/folder.disk-archive

# Inspect index
disk archive list --archive /path/to/folder.disk-archive

# Restore to a new directory (verified digests + sizes)
disk archive restore --archive /path/to/folder.disk-archive --destination /path/to/restored
```

## Layout

```
folder.disk-archive/
  index.json          # version, paths, sizes, digests
  entries/
    <blake3-hex>.zst  # one blob per unique file content
```

## Safety

- Restore rejects absolute paths and `..` traversal segments.
- Each entry is verified (size + BLAKE3) before write.
- Library: `disk_core::archive::{create, read_index, restore}`.

## Related

- Filter deny: `crates/disk-core/src/filter.rs` (`.disk-archive`)
- Config stub: `[archive] enabled = true` in `disk.toml` (future daemon hook)
