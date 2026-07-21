# DISK-0029 — Embeddings Co-storage (vector index synced alongside files)

**Status:** slice 1 on DEVS — sidecar layout, filter passthrough, `disk embeddings status`.  
**Parent:** DISK-0001 commercial / SaaS track.  
**Tracking:** DISK-0029 in Datarim backlog.

## Problem

Obsidian-style knowledge bases increasingly rely on local embedding stores for RAG and semantic search. Mass file-sync products (Syncthing, Dropbox, iCloud) corrupt or desynchronise these binary indices because they treat them as ordinary files without content-hash coupling to the source markdown.

Disk Arcana co-stores embedding vectors as **sidecar artefacts** under `.disk-embeddings/` inside each share. Sidecars ride the normal sync engine (blake3-verified deltas) while manifests bind each vector blob to the source file's content hash.

## Scope

| Slice | In scope | Out of scope |
|-------|----------|--------------|
| 1 (this PR) | `.disk-embeddings/` layout + manifest v1 schema; extension-whitelist passthrough in `filter.rs`; `[embeddings]` in `disk.toml`; `disk embeddings status` CLI | Live embedding generation, Scrutator/Model Connector integration, daemon auto-invalidation hook |
| 2 (planned) | Post-sync staleness sweep in daemon; optional webhook `embeddings.stale` | Server-side vector DB, cross-vault embedding search |
| 3 (planned) | `disk embeddings write` ingest path for external embedders | On-device model inference |

## Sidecar layout

For source `notes/welcome.md` inside a share root:

```text
notes/welcome.md
.disk-embeddings/notes/welcome.md.manifest.json
.disk-embeddings/notes/welcome.md.vec.bin
```

### Manifest v1 (`SidecarManifest`)

| Field | Type | Notes |
|-------|------|-------|
| `schema_version` | `u32` | Always `1` for this slice |
| `source_path` | `string` | Vault-relative POSIX path |
| `source_content_hash` | `string` | BLAKE3 hex of source bytes at embed time |
| `model_id` | `string` | e.g. `bge-m3` |
| `dimensions` | `u32` | Vector width |
| `vector_bytes` | `u64` | Byte length of `.vec.bin` (f32 LE) |
| `created_at_unix` | `u64?` | Optional audit timestamp |

### Vector blob

Raw little-endian `f32` components concatenated (`dimensions × 4` bytes for a single-vector sidecar). Multi-chunk documents defer to slice 2.

## Filter integration

Paths under `.disk-embeddings/` **bypass extension whitelists** so markdown-only shares still sync sidecar JSON/binary artefacts. Hardcoded deny segments (`.git`, `.disk-archive`, `.dreamer`) still apply; user `ignore_globs` still apply.

## Client config (`disk.toml`)

```toml
[embeddings]
enabled = false
model_id = "bge-m3"
dimensions = 1024
```

Validation when `enabled = true`: non-empty `model_id`, `dimensions > 0`.

## CLI

```bash
disk embeddings status [--share <name>] [--config <path>]
```

Reports per-share counts: `fresh`, `stale`, `missing`, `co_storage_files`. Lists non-fresh sources when embeddings are enabled.

## Tests

- `crates/disk-core/src/embeddings/paths.rs` — path mirroring + detection
- `crates/disk-core/src/embeddings/manifest.rs` — manifest round-trip + staleness
- `crates/disk-core/src/embeddings/scan.rs` — share inventory counts
- `crates/disk-core/src/filter.rs` — co-storage whitelist bypass
- `crates/disk-client/src/config/mod.rs` — `[embeddings]` parse
- `crates/disk-cli/src/main.rs` — clap parse for `disk embeddings status`

## References

- `README.md` — embedding stores as a first-class corruption target
- `docs/design/DISK-0028-agents-api.md` — agent-write path for machine-generated content
- `crates/disk-core/src/filter.rs` — scanner exclusion rules
- PRD-DISK-0001 v1.1 — star topology; sidecars are ordinary synced blobs
