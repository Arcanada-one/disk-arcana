# disk.arcanada.ai static site (DISK-0010)

Deploy to Arcana WWW webroot `/var/www/disk.arcanada.ai/`:

```bash
rsync -av deploy/www/ root@49.13.52.208:/var/www/disk.arcanada.ai/
install -m 0755 scripts/install.sh /var/www/disk.arcanada.ai/install.sh
```

Static dashboard SPA lives at `deploy/www/dashboard/` (DISK-0019). It calls the
health HTTP API (`DISK_HEALTH_BIND_ADDR`, default `:9446`) for `/auth/*` and
`/dashboard/summary`. Reverse-proxy both paths to the server or pass
`?api=https://your-host:9446` when opening the dashboard.

The live `install.sh` must be the canonical `scripts/install.sh` from this repo.
