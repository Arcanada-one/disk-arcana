---
title: DISK-RB-010 — OWASP gRPC audit walkthrough
created: 2026-07-21
task: DISK-0012
status: draft
operator_gate: true
---

# DISK-RB-010 — OWASP gRPC audit walkthrough

Operator playbook to complete the **operator** rows in
`docs/security/OWASP-gRPC-audit.md` on a staging or read-only prod mirror.

**Agent-deliverable:** checklist v1.0 + CI evidence gate. This runbook is the
human sign-off path.

## Preconditions

- Staging disk server with mTLS + ACL loaded (`disk-acl.yaml`)
- `disk` CLI enrolled test node
- Access to server logs (journald)
- Checklist open: `docs/security/OWASP-gRPC-audit.md`

## Procedure

### 1. TLS policy (T1.5, T1.6)

```bash
# Confirm TLS 1.3 negotiated (expect TLSv1.3 in output)
openssl s_client -connect disk.staging.example:9443 -servername disk.arcanada.ai </dev/null 2>/dev/null | openssl version -a
```

- Review rustls cipher suite list against org policy.
- Walk through cert rotation per DISK-RB-001 (issue new cert, reload, revoke old).

### 2. Enrollment semantics (T2.6–T2.8)

```bash
disk admin pending-token --hostname walkthrough-node --ttl-secs 60
# Enroll once — success
# Repeat enroll with same token — expect replay error
# Wait past TTL — expect expired error
```

Document DISK-0044 bootstrap path if cold enroll without pre-issued cert is required.

### 3. ACL default deny (T3.3) — spot check

- Stop ACL file / break signature → confirm sync returns unavailable (not permissive).
- Restore valid ACL → sync resumes.

### 4. Logging (T5.3)

- Trigger failed auth; grep logs for raw `arc_disk_` secrets — must see masked tokens only.
- Confirm core dumps disabled or scrubbed per host policy.

### 5. Edge availability (T6.3)

- Confirm Cloudflare / firewall rate limits on `:9443` documented in infra runbook.

### 6. Load deferral (T6.2)

- Record: 10K-file harness not run — staging capacity / operator schedule.

## Sign-off

Copy the sign-off block from `OWASP-gRPC-audit.md` into the task archive or
operator ticket when complete.

## Related

- `scripts/validate-owasp-evidence.sh` — DEVS CI gate
- DISK-0012 snapshot / plan
