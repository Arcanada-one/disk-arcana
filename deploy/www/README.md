# disk.arcanada.ai static site (DISK-0010)

Deploy to Arcana WWW webroot `/var/www/disk.arcanada.ai/`:

```bash
rsync -av deploy/www/ root@49.13.52.208:/var/www/disk.arcanada.ai/
install -m 0755 scripts/install.sh /var/www/disk.arcanada.ai/install.sh
```

The live `install.sh` must be the canonical `scripts/install.sh` from this repo.
