# disk.arcanada.ai static site (DISK-0010)

**Live origin (2026-08-09):** Cloudflare orange-cloud `disk.arcanada.ai` →
`49.13.52.208` (arcana-www) `/var/www/disk.arcanada.ai/`. Prod
(`65.108.236.39`) keeps a mirror + nginx vhost, but public `:80/:443` on the
prod public IP do not complete TCP (mesh/Tailscale `:443` still works).

**gRPC / enroll:** do not rely on orange-cloud apex for non-HTTP ports. Use
grey-cloud `sync.disk.arcanada.ai` → prod (`:9443`). Enrollment WAN `:9445`
stays closed per RB-011.

Deploy to Arcana WWW webroot `/var/www/disk.arcanada.ai/`:

```bash
rsync -av deploy/www/ root@49.13.52.208:/var/www/disk.arcanada.ai/
install -m 0755 scripts/install.sh /var/www/disk.arcanada.ai/install.sh
```

Static dashboard SPA lives at `deploy/www/dashboard/` (DISK-0019). Help Center at
`deploy/www/docs/` (DISK-0025). Legal pages at
`deploy/www/legal/` (DISK-0021). Pages: `index.html`, `oauth-callback.html`,
`verify-email.html`. It calls the
health HTTP API (`DISK_HEALTH_BIND_ADDR`, default `:9446`) for `/auth/*` and
`/dashboard/summary`. Reverse-proxy both paths to the server or pass
`?api=https://your-host:9446` when opening the dashboard.

The live `install.sh` must be the canonical `scripts/install.sh` from this repo.
