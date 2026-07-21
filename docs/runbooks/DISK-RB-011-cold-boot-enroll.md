# DISK-RB-011 — Cold-boot enrollment verification (DISK-0044)

Operator checklist to verify that a **cert-less** node can enroll via the
public TLS listener (`:9445`). Complements KB runbook
`documentation/runbooks/disk-arcana/DISK-RB-001-enroll.md`.

## Preconditions

- Server running with `DISK_CA_MODE=http` or `stub` (not `offline`).
- Log line present: `enrollment public listener listening` on `DISK_ENROLLMENT_BIND_ADDR`.
- Target host has **no** `client.crt` / `client.key` yet.
- Operator holds `DISK_ADMIN_TOKEN`.

## Verify (staging or prod-readonly)

### 1. Public listener accepts TLS without client cert

```bash
# From a host WITHOUT a fleet client cert — must NOT use :9443
openssl s_client -connect disk.arcanada.ai:9445 -servername disk.arcanada.ai </dev/null 2>/dev/null | head -5
```

Expect: TLS handshake completes (certificate chain shown). Connection to `:9443`
without a client cert should fail at handshake.

### 2. Issue token (admin)

```bash
disk admin pending-token \
  --server "https://disk.arcanada.ai:9445" \
  --hostname "$(hostname -s)" \
  --ttl-secs 600
```

Expect: hex `token=` line; no mTLS client cert required on CLI.

### 3. Enroll cold-boot node

```bash
disk enroll \
  --server "https://disk.arcanada.ai:9445" \
  --token "<hex-from-step-2>" \
  --cert-out ./client.crt \
  --key-out ./client.key
```

Expect: writes cert + key; `expires_at_unix_ms` in stdout.

### 4. Replay rejected

Repeat step 3 with the same token.

Expect: gRPC error (replay / not found).

### 5. mTLS sync path works post-enroll

Point `disk.toml` `[server]` at `:9443` with the new cert/key; run
`disk status` or trigger one sync cycle.

Expect: mTLS handshake succeeds; sync or auth RPCs reachable.

## CI evidence (no operator required)

- `crates/disk-server/tests/it_enrollment_real_binary.rs` — full cold-boot path
- `crates/disk-server/tests/it_main_boot_wiring.rs` — dual listener boot markers
- `crates/disk-server/tests/enrollment_expired_token.rs`
- `crates/disk-server/tests/enrollment_token_replay.rs`

## Sign-off

```text
Cold-boot enroll verified on: ________
Environment: staging / prod
Reviewer:
Notes (firewall, CA mode, token TTL):
```
