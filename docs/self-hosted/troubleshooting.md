# HeroForge Troubleshooting Guide

Common issues and their solutions for self-hosted HeroForge installations.

---

## Quick Diagnostics

Run these commands to gather diagnostic information:

```bash
# Check container status
heroforge status

# View recent logs
heroforge logs 100

# Check Docker health
docker inspect heroforge --format='{{.State.Health.Status}}'

# Check resource usage
docker stats heroforge --no-stream
```

---

## Installation Issues

### "Docker is not installed"

**Error:**
```
[ERROR] Docker is not installed.
```

**Solution:**
```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
# Log out and back in
```

### "Docker Compose v2 is not installed"

**Error:**
```
[ERROR] Docker Compose v2 is not installed.
```

**Solution:**
Docker Compose v2 comes with Docker. Update Docker:
```bash
curl -fsSL https://get.docker.com | sh
```

### "Permission denied"

**Error:**
```
permission denied while trying to connect to the Docker daemon socket
```

**Solution:**
```bash
sudo usermod -aG docker $USER
# Log out and back in, or run:
newgrp docker
```

---

## Startup Issues

### Container Won't Start

**Check logs:**
```bash
docker logs heroforge --tail 100
```

**Common causes:**

1. **Port already in use:**
   ```bash
   # Find what's using the port
   sudo lsof -i :8443

   # Change HeroForge port
   heroforge config
   # Set: HEROFORGE_PORT=9443
   heroforge restart
   ```

2. **Insufficient memory:**
   ```bash
   # Check available memory
   free -h

   # Reduce memory limit
   heroforge config
   # Set: HEROFORGE_MEMORY_LIMIT=4G
   heroforge restart
   ```

3. **Missing environment variables:**
   ```bash
   # Verify .env file exists and has required keys
   cat /opt/heroforge/.env | grep -E "JWT_SECRET|DATABASE_ENCRYPTION_KEY|TOTP_ENCRYPTION_KEY"
   ```

### "Invalid JWT_SECRET" or "Invalid encryption key"

**Error:**
```
JWT_SECRET must be a valid hex string (64 characters)
```

**Solution:**
Generate new keys (only for fresh installations):
```bash
heroforge config

# Replace the keys with new 64-character hex strings:
JWT_SECRET=$(openssl rand -hex 32)
DATABASE_ENCRYPTION_KEY=$(openssl rand -hex 32)
TOTP_ENCRYPTION_KEY=$(openssl rand -hex 32)
```

> ⚠️ **Warning:** Changing these keys on an existing installation will invalidate all user sessions and encrypted data.

### Database Migration Errors

**Error:**
```
[ERROR] Database migration failed
```

**Solution:**
```bash
# Check detailed error
heroforge logs | grep -i -A5 "migration"

# If database is corrupted, restore from backup
heroforge restore your-backup.tar.gz
```

---

## Authentication Issues

### Can't Log In

**Possible causes:**

1. **Browser caching old assets:**
   - Hard refresh: `Ctrl+Shift+R` (Windows/Linux) or `Cmd+Shift+R` (Mac)
   - Or clear browser cache

2. **JWT token expired:**
   - Clear browser cookies for the HeroForge domain
   - Try incognito/private window

3. **Account locked:**
   - Too many failed login attempts
   - Wait 15 minutes or check logs for lockout details

### Two-Factor Authentication Not Working

**"Failed to start TOTP" error:**
```bash
# Verify TOTP key is configured correctly (64 hex chars)
docker exec heroforge printenv TOTP_ENCRYPTION_KEY | wc -c
# Should output: 65 (64 chars + newline)

# If not 64 chars, regenerate and restart
heroforge config
# Set: TOTP_ENCRYPTION_KEY=<new-64-char-hex-string>
heroforge restart
```

**Authenticator codes not matching:**
- Check server time: `date`
- Sync time: `sudo timedatectl set-ntp true`

### Lost MFA Access

If you've lost access to your authenticator:

1. Use a recovery code (if saved)
2. Or access the database directly:
   ```bash
   heroforge shell
   sqlite3 /data/heroforge.db "UPDATE users SET totp_enabled=0, totp_secret=NULL WHERE email='your@email.com';"
   exit
   ```

---

## Connectivity Issues

### Can't Access Web Interface

**Check if container is running:**
```bash
docker ps | grep heroforge
```

**Check if port is open:**
```bash
curl -v http://localhost:8443/health/live
```

**Check firewall:**
```bash
# Ubuntu/Debian
sudo ufw status
sudo ufw allow 8443/tcp

# RHEL/CentOS
sudo firewall-cmd --list-ports
sudo firewall-cmd --permanent --add-port=8443/tcp
sudo firewall-cmd --reload
```

### WebSocket Connection Failed

**Symptoms:** Real-time updates not working, scan progress not updating

**Solution:**
If using a reverse proxy, ensure WebSocket support:

**nginx:**
```nginx
location / {
    proxy_pass http://localhost:8443;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
}
```

**Traefik:** WebSocket support is automatic.

### SSL/TLS Certificate Errors

If using HTTPS through a reverse proxy:
```bash
# Test certificate
openssl s_client -connect your-domain:443 -servername your-domain

# Check certificate expiry
echo | openssl s_client -connect your-domain:443 2>/dev/null | openssl x509 -noout -dates
```

---

## Scanning Issues

### Scans Not Starting

**Check container capabilities:**
```bash
docker inspect heroforge --format='{{.HostConfig.CapAdd}}'
# Should include: [NET_RAW NET_ADMIN]
```

**If missing, recreate container:**
```bash
cd /opt/heroforge
docker compose down
docker compose up -d
```

### Network Scanning Fails

**"Operation not permitted" errors:**

Ensure the container has network capabilities:
```yaml
# In docker-compose.yml
cap_add:
  - NET_RAW
  - NET_ADMIN
```

**Can't reach internal networks:**

Check if the container can reach targets:
```bash
heroforge shell
ping 10.0.0.1  # Replace with your target IP
exit
```

### Scan Results Missing

**Check disk space:**
```bash
df -h /var/lib/docker
docker system df
```

**Check database:**
```bash
heroforge shell
sqlite3 /data/heroforge.db "SELECT COUNT(*) FROM scan_results;"
exit
```

---

## Performance Issues

### High Memory Usage

**Check current usage:**
```bash
docker stats heroforge --no-stream
```

**Reduce memory limit:**
```bash
heroforge config
# Set: HEROFORGE_MEMORY_LIMIT=4G
heroforge restart
```

**Clear scan history:**
Large scan histories can consume memory. Archive old scans through the UI.

### Slow Web Interface

**Possible causes:**

1. **Too many concurrent scans:** Limit active scans
2. **Large database:** Archive old data
3. **Insufficient resources:** Increase CPU/memory limits

### Container Keeps Restarting

**Check logs for crash reason:**
```bash
docker logs heroforge --tail 200 | grep -i -E "error|panic|fatal"
```

**Common causes:**
- Out of memory (OOM killed)
- Database corruption
- Configuration errors

**Check if OOM killed:**
```bash
docker inspect heroforge --format='{{.State.OOMKilled}}'
```

---

## Email Issues

### Emails Not Sending

**Check SMTP configuration:**
```bash
heroforge logs | grep -i smtp
```

**Test SMTP connectivity:**
```bash
heroforge shell
curl -v telnet://smtp.gmail.com:587
exit
```

**Common fixes:**

1. **Gmail:** Use App Password, not regular password
2. **Office 365:** Ensure account allows SMTP relay
3. **Firewall:** Ensure outbound port 587 is open

---

## Backup/Restore Issues

### Backup Fails

**Check disk space:**
```bash
df -h .
```

**Check Docker volumes:**
```bash
docker volume ls | grep heroforge
```

### Restore Fails

**Verify backup file:**
```bash
tar -tzf your-backup.tar.gz | head -20
```

**Ensure HeroForge is stopped:**
```bash
heroforge stop
heroforge restore your-backup.tar.gz
heroforge start
```

---

## Getting More Help

### Collect Diagnostic Information

```bash
# Create diagnostic report
{
  echo "=== HeroForge Diagnostics ==="
  echo "Date: $(date)"
  echo ""
  echo "=== Container Status ==="
  docker ps -a | grep heroforge
  echo ""
  echo "=== Container Logs (last 50 lines) ==="
  docker logs heroforge --tail 50 2>&1
  echo ""
  echo "=== Docker Info ==="
  docker version
  echo ""
  echo "=== System Info ==="
  uname -a
  free -h
  df -h
} > heroforge-diagnostics.txt

echo "Diagnostics saved to: heroforge-diagnostics.txt"
```

### Contact Support

- **Email:** support@heroforge.io
- **GitHub:** https://github.com/genialarchitect/HeroForge/issues

Include your diagnostic report when contacting support.

---

## Next Steps

- [Installation Guide](installation.md) - Reinstall if needed
- [Configuration Guide](configuration.md) - Verify settings
- [Upgrading](upgrading.md) - Try upgrading to latest version
