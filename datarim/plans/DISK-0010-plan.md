---
taskId: DISK-0010
title: Landing Page + docs + install script
status: in_progress
created: 2026-07-20
complexity: L2
prefix: DISK
parent: DISK-0001
branch: DISK-0010-landing
---

# DISK-0010 — Landing + Install (agent slice)

**Parent:** DISK-0001 §Phase 9. Full PHP/Tailwind site and mdBook deferred.

## This branch (DEVS-deliverable)

| Item | Status |
|------|--------|
| `deploy/www/` static landing (disk.arcanada.ai) | Done |
| `scripts/install.sh` curl installer | Done |
| `docs/installation.md` | Done |
| OWASP gRPC stub | Done (`docs/security/OWASP-gRPC-audit.md`) |
| Release client binaries on tag | Done (`build-linux-client` job) |
| Live DNS / deploy to WWW | Deferred (rsync operator) |
| mdBook docs site | Deferred |
| GA4 / GSC | Deferred |

## Deploy landing

See `deploy/www/README.md`.

## References

- Prior archive: `documentation/archive/disk/archive-DISK-0010.md` (KB)
- Websites mandate: `Projects/Websites/CLAUDE.md`
