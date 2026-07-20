---
title: DISK-RB-008 — Windows VM end-to-end validation
created: 2026-07-20
task: DISK-0013
status: draft
operator_gate: true
---

# DISK-RB-008 — Windows VM end-to-end validation

Operator-run playbook to validate the Disk Arcana **Windows client** beyond
`windows-latest` CI smoke. CI covers compile, unit tests, and non-admin daemon
`/status`; this runbook covers service install, enroll, share declaration, and a
minimal sync/rename check against a live server.

**Not automated on DEVS** — requires a Windows host (e.g. operator VM, vika-pc,
or dedicated Hetzner Windows instance). **Hard-gated:** do not run against prod
until operator approves target server and ACL changes.

## Preconditions

| Requirement | Notes |
|-------------|--------|
| Windows 10/11 x64 | Admin PowerShell for service install |
| Outbound TCP to `disk.arcanada.ai:9445` | Enrollment (TLS) |
| Outbound TCP to `disk.arcanada.ai:9443` | mTLS gRPC after enroll |
| `DISK_ADMIN_TOKEN` or admin host access | Issue enrollment token (DISK-RB-001 §1) |
| Server CA PEM | Save as `C:\ProgramData\disk-arcana\server-ca.crt` |
| ACL row for this node | Server-side `disk-acl.yaml` before first sync |

## Artifact source

Pick one (operator choice):

1. **CI artifact** — PR #39 workflow `disk-windows-portable-x86_64-pc-windows-msvc`
   from GitHub Actions (pre-merge validation).
2. **Release zip** — after operator tags `v*.*.*` and lifts merge gate:
   `disk-arcana-windows-x86_64.zip` from GitHub Releases.

Extract zip to a working directory (e.g. `C:\Tools\disk-arcana\`).

## Procedure

### 1. Local smoke (no admin)

From extracted directory:

```powershell
.\disk.exe --help
.\scripts\test-windows-smoke.ps1 -Binary .\disk.exe
```

Expect `==> smoke PASSED`. If this fails, stop — fix build/CI before VM service test.

### 2. Edit config

Copy `disk.toml.example` → `C:\ProgramData\disk-arcana\disk.toml` (create parent
dirs if install script not yet run). Set:

- `[server].address` = `disk.arcanada.ai:9443`
- `client_cert` / `client_key` = `C:\ProgramData\disk-arcana\client.{crt,key}`
- `[[share]].path` = absolute Windows path to test vault (e.g. `C:\Vault\test`)

Validate:

```powershell
.\disk.exe config validate --file C:\ProgramData\disk-arcana\disk.toml
```

### 3. Install service (admin)

Open **Administrator** PowerShell:

```powershell
cd C:\Tools\disk-arcana
.\install-windows.ps1 -Binary .\disk.exe
```

Expect service `DiskArcana` running and `http://127.0.0.1:9444/status` returning HTTP 200.

If config was edited after install, restart:

```powershell
Restart-Service DiskArcana
```

### 4. Enroll (DISK-RB-001 Windows paths)

On admin host, issue token (see DISK-RB-001 §1). On Windows VM:

```powershell
.\disk.exe enroll `
  --server https://disk.arcanada.ai:9445 `
  --token <hex> `
  --ca-cert C:\ProgramData\disk-arcana\server-ca.crt `
  --cert-out C:\ProgramData\disk-arcana\client.crt `
  --key-out C:\ProgramData\disk-arcana\client.key
```

Verify key mode 0600 (installer may need manual `icacls` if enroll writes loose perms).

Restart service after enroll:

```powershell
Restart-Service DiskArcana
```

### 5. Declare share

```powershell
.\disk.exe share init --preset collaborate --name vm-test `
  --path C:\Vault\test `
  --config C:\ProgramData\disk-arcana\disk.toml
Restart-Service DiskArcana
```

Provision server ACL for this node's cert fingerprint + `vm-test` share (DISK-RB-001 §4).

### 6. Sync + rename validation

1. Create `C:\Vault\test\hello.md` with known content.
2. Poll status until share state leaves `server_unreachable` / `unknown_share`:

   ```powershell
   Invoke-RestMethod http://127.0.0.1:9444/status | ConvertTo-Json -Depth 5
   ```

3. Confirm file visible on server (or delta upload logs on server).
4. **Rename test (DISK-0013 Phase 2):** rename `hello.md` → `renamed.md` locally;
   confirm server reflects rename (not duplicate upload) after sync cycle.

### 7. Cleanup (optional)

```powershell
.\scripts\uninstall-windows.ps1
```

## Pass criteria

| # | Criterion |
|---|-----------|
| 1 | `test-windows-smoke.ps1` passes |
| 2 | `install-windows.ps1` registers service; `/status` HTTP 200 |
| 3 | `disk enroll` writes cert + key under ProgramData |
| 4 | Share reaches `idle` or `syncing` (not sticky `acl_mismatch` / `unknown_share`) |
| 5 | New file propagates to server |
| 6 | Rename propagates as rename (FILE_ID identity) |

## Failure routing

| Symptom | Runbook |
|---------|---------|
| `acl_mismatch` / `unknown_share` | DISK-RB-002, DISK-RB-001 §4 |
| `server_unreachable` | DISK-RB-004 §2 |
| Service fails to start | Check `disk.toml` paths are absolute; Event Viewer → Application log |
| Enroll 401/403 | Token TTL, hostname binding, admin bearer |

## Related

- [DISK-RB-001 Enroll](DISK-RB-001-enroll.md) — token + ACL (Linux/macOS paths; adapt to ProgramData)
- `scripts/install-windows.ps1`, `scripts/uninstall-windows.ps1`
- `datarim/plans/DISK-0013-plan.md` — phase map + CI vs VM gap
