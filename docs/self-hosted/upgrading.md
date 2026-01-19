# Upgrading HeroForge

This guide covers how to safely upgrade your HeroForge installation.

---

## Quick Upgrade

The easiest way to upgrade:

```bash
heroforge update
```

This command:
1. Pulls the latest Docker image
2. Restarts the container with the new version
3. Runs any database migrations automatically

---

## Upgrade to Specific Version

To upgrade to a specific version:

```bash
# Edit configuration
heroforge config

# Change HEROFORGE_VERSION to desired version
HEROFORGE_VERSION=2.1.0

# Save and exit, then restart
heroforge restart
```

Or directly:

```bash
cd /opt/heroforge
sed -i 's/^HEROFORGE_VERSION=.*/HEROFORGE_VERSION=2.1.0/' .env
docker compose pull
docker compose up -d
```

---

## Pre-Upgrade Checklist

Before upgrading, especially for major versions:

### 1. Create a Backup

```bash
heroforge backup pre-upgrade-backup.tar.gz
```

### 2. Check Release Notes

Review the changelog for breaking changes:
- https://github.com/genialarchitect/HeroForge/releases

### 3. Verify Disk Space

```bash
df -h /var/lib/docker
```

Ensure at least 5GB free for the new image.

### 4. Plan Downtime

Typical upgrade takes 1-2 minutes. Plan accordingly for production environments.

---

## Step-by-Step Upgrade Process

### Standard Upgrade

```bash
# 1. Create backup
heroforge backup

# 2. Pull new image
cd /opt/heroforge
docker compose pull

# 3. Stop current container
heroforge stop

# 4. Start with new image
heroforge start

# 5. Verify health
heroforge status
heroforge logs
```

### Zero-Downtime Upgrade (Advanced)

For production environments requiring minimal downtime:

```bash
# 1. Pull new image in background (no downtime)
docker pull genialarchitect/heroforge:latest

# 2. Quick restart (typically < 30 seconds)
cd /opt/heroforge
docker compose up -d --force-recreate
```

---

## Rolling Back

If something goes wrong after an upgrade:

### Method 1: Use Previous Version

```bash
# Edit .env to use previous version
heroforge config
# Set: HEROFORGE_VERSION=2.0.0

# Restart with old version
heroforge restart
```

### Method 2: Restore from Backup

```bash
# Stop HeroForge
heroforge stop

# Restore data
heroforge restore pre-upgrade-backup.tar.gz

# Edit .env to previous version
heroforge config
# Set: HEROFORGE_VERSION=2.0.0

# Start
heroforge start
```

---

## Database Migrations

HeroForge automatically runs database migrations on startup. No manual action required.

**To check migration status:**
```bash
heroforge logs | grep -i migration
```

**Expected output:**
```
[INFO] Running database migrations...
[INFO] Database migrations complete
```

---

## Version Compatibility

| From Version | To Version | Notes |
|--------------|------------|-------|
| 2.0.x | 2.0.y | Direct upgrade supported |
| 2.0.x | 2.1.x | Direct upgrade supported |
| 1.x | 2.x | See migration guide below |

### Migrating from 1.x to 2.x

Major version upgrades may require additional steps:

```bash
# 1. Backup everything
heroforge backup full-backup-v1.tar.gz

# 2. Export data (if available)
heroforge shell
/app/heroforge export --output /data/export.json
exit

# 3. Update to 2.x
heroforge config
# Set: HEROFORGE_VERSION=2.0.0
heroforge restart

# 4. Verify data integrity
heroforge logs | grep -i error
```

---

## Upgrading Docker

If you need to upgrade Docker itself:

```bash
# 1. Stop HeroForge
heroforge stop

# 2. Upgrade Docker
curl -fsSL https://get.docker.com | sh

# 3. Start HeroForge
heroforge start
```

---

## Automatic Updates (Optional)

For non-production environments, you can enable automatic updates using Watchtower:

```bash
docker run -d \
  --name watchtower \
  -v /var/run/docker.sock:/var/run/docker.sock \
  containrrr/watchtower \
  heroforge \
  --interval 86400
```

This checks for updates daily and automatically restarts with new versions.

> ⚠️ **Warning:** Not recommended for production. Always test upgrades in a staging environment first.

---

## Troubleshooting Upgrades

### Container Won't Start After Upgrade

```bash
# Check logs
docker logs heroforge --tail 100

# Common fixes:
# 1. Clear cached image
docker compose pull --no-cache

# 2. Recreate container
docker compose up -d --force-recreate
```

### Database Migration Errors

```bash
# Check migration logs
heroforge logs | grep -i -E "error|migration"

# If migrations fail, restore backup and contact support
heroforge restore pre-upgrade-backup.tar.gz
```

### Out of Disk Space

```bash
# Clean up old images
docker system prune -a

# Remove old HeroForge images
docker images | grep heroforge | grep -v latest | awk '{print $3}' | xargs docker rmi
```

---

## Getting Help

If you encounter issues during upgrade:

1. Check logs: `heroforge logs`
2. Review release notes for known issues
3. Contact support: support@heroforge.io
4. GitHub Issues: https://github.com/genialarchitect/HeroForge/issues

---

## Next Steps

- [Configuration Guide](configuration.md) - Configure new features
- [Troubleshooting](troubleshooting.md) - Common issues and solutions
