# DISK-0027 — LAN Sync (peer-to-peer acceleration on local network)

**Status:** slice 1 on DEVS — mDNS peer discovery + loopback observability.  
**Parent:** DISK-0001 commercial / SaaS track.  
**Tracking:** DISK-0027 in Datarim backlog.

## Scope

| Slice | In scope | Out of scope |
|-------|----------|--------------|
| 1 (this PR) | `[lan_sync]` in `disk.toml`, mDNS advertise/browse (`_disk-arcana._udp`), in-memory peer registry, `GET /lan/peers`, `disk lan peers` | Direct P2P blob transfer, gRPC proxy bypass, mesh topology |
| 2 | LAN-preferred delta fetch between enrolled peers (same tenant + vault) | Full mesh sync without cloud authority |

PRD-DISK-0001 v1.1 lists mesh/P2P as out of scope for v1.0 star topology; DISK-0027 is an **opt-in acceleration layer** — cloud server remains source of truth.

## Privacy / exposure model

- **Opt-in** — `[lan_sync] enabled = false` by default.
- **mDNS only** — broadcasts node presence on the local link; no vault paths or file names in TXT records.
- **TXT records:** `node_id`, optional `tenant_id`, `grpc_port` (from `[server].address`).
- **Loopback REST** — `GET /lan/peers` on `127.0.0.1:9444` only (Tier 1 baseline).
- **Fail-soft** — mDNS errors are logged at `warn` and never block daemon startup or cloud sync.

## Client config (`disk.toml`)

```toml
[lan_sync]
enabled = false
# UDP port advertised for future LAN data-plane (slice 2). Default 9447.
advertise_port = 9447
```

## Loopback REST

| Method | Path | Auth | Notes |
|--------|------|------|-------|
| GET | `/lan/peers` | — (loopback) | `{ enabled, peers[] }` — peers seen via mDNS in the last 120s |

Peer object: `{ node_id, host, port, tenant_id?, last_seen_unix }`.

## CLI

```bash
disk lan peers [--addr 127.0.0.1:9444]
```

## Tests

- `crates/disk-client/src/lan_sync/registry.rs` — upsert, prune, snapshot unit tests
- `crates/disk-client/src/config/mod.rs` — `[lan_sync]` parse
- `crates/disk-cli/src/main.rs` — clap parse test for `disk lan peers`
- `crates/disk-client/src/rest_api/lan.rs` — JSON shape unit test

## References

- `docs/design/DISK-0028-agents-api.md` — deferred LAN acceleration note
- PRD-DISK-0001 §4 — star topology; LAN sync is optional fast path only
- `crates/disk-client/src/rest_api/mod.rs` — loopback bind contract
