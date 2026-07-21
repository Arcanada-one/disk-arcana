# DISK-0029 — Embeddings Co-storage (vector index synced alongside files)

**Status:** slice 3 on DEVS — `disk embeddings write` ingest for external embedders.  
**Parent:** DISK-0001 commercial / SaaS track.  
**Tracking:** DISK-0029 in Datarim backlog.

## Problem

Obsidian-style knowledge bases increasingly rely on local embedding stores for RAG and semantic search. Mass file-sync products (Syncthing, Dropbox, iCloud) corrupt or desynchronise these binary indices because they treat them as ordinary files without content-hash coupling to the source markdown.

Disk Arcana co-stores embedding vectors as **sidecar artefacts** under `.disk-embeddings/` inside each share. Sidecars ride the normal sync engine (blake3-verified deltas) while manifests bind each vector blob to the source file's content hash.

## Scope

| Slice | In scope | Out of scope |
|-------|----------|--------------|
| 1 (merged #103) | `.disk-embeddings/` layout + manifest v1 schema; extension-whitelist passthrough in `filter.rs`; `[embeddings]` in `disk.toml`; `disk embeddings status` CLI | Live embedding generation, Scrutator/Model Connector integration, daemon auto-invalidation hook |
| 2 (merged #104) | Post-sync staleness sweep in daemon; loopback `GET /embeddings/status`; `embeddings.stale` webhook event + `POST /agents/embeddings-stale` | Server-side vector DB, cross-vault embedding search |
| 3 (this PR) | `disk embeddings write` ingest path for external embedders | On-device model inference |

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
disk embeddings write --share <name> --path <rel> [--vector-file <path>|--vector-base64 <b64>] [--config <path>]
```

`status` reports per-share counts: `fresh`, `stale`, `missing`, `co_storage_files`. Lists non-fresh sources when embeddings are enabled.

`write` ingests an external f32 LE vector blob for an existing source file. Requires `[embeddings] enabled = true`. Vector size must equal `dimensions * 4` bytes from config. Writes `.disk-embeddings/` manifest + `.vec.bin` atomically (vector first, then manifest).

## Daemon sweep (slice 2)

After each successful sync iteration when `[embeddings] enabled = true`:

1. Blocking filesystem sweep via `embeddings_sweep::sweep_share`
2. `warn` log when `stale > 0` or `missing > 0`
3. Cache snapshot on `DaemonState` for loopback REST
4. Optional `POST /agents/embeddings-stale` when `DISK_ACCESS_TOKEN` is set (fail-soft)

## Loopback REST (slice 2)

| Method | Path | Auth | Notes |
|--------|------|------|-------|
| GET | `/embeddings/status` | — (loopback) | `{ enabled, shares[] }` — last sweep per share |

## Server webhook (slice 2)

| Method | Path | Auth | Notes |
|--------|------|------|-------|
| POST | `/agents/embeddings-stale` | Bearer JWT (editor+) | Body: `{ vault_id, share, fresh, stale, missing, paths[] }` → dispatches `embeddings.stale` webhooks |

Register with `disk agents webhooks register --events embeddings.stale`.

## Tests

- `crates/disk-core/src/embeddings/paths.rs` — path mirroring + detection
- `crates/disk-core/src/embeddings/manifest.rs` — manifest round-trip + staleness
- `crates/disk-core/src/embeddings/scan.rs` — share inventory counts
- `crates/disk-core/src/filter.rs` — co-storage whitelist bypass
- `crates/disk-client/src/config/mod.rs` — `[embeddings]` parse
- `crates/disk-core/src/embeddings/write.rs` — sidecar ingest + validation
- `crates/disk-cli/src/embeddings_cmd.rs` — `status` + `write` commands
- `crates/disk-cli/src/main.rs` — clap parse for `disk embeddings status` and `disk embeddings write`
- `crates/disk-client/src/embeddings_sweep.rs` — sweep + webhook reporter
- `crates/disk-client/src/rest_api/embeddings.rs` — loopback status JSON
- `crates/disk-server/src/agents/routes.rs` — `embeddings.stale` event + report handler

## References

- `README.md` — embedding stores as a first-class corruption target
- `docs/design/DISK-0028-agents-api.md` — agent-write path for machine-generated content
- `crates/disk-core/src/filter.rs` — scanner exclusion rules
- PRD-DISK-0001 v1.1 — star topology; sidecars are ordinary synced blobs
