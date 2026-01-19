# Troubleshooting Guide

This guide covers common issues and their solutions when using HeroForge.

## Scan Issues

### Scan Stuck at 0%

**Symptoms:**
- Scan starts but progress never updates
- No hosts or ports discovered

**Causes & Solutions:**

1. **Targets unreachable**
   - Verify targets are online: `ping <target>`
   - Check network routing: `traceroute <target>`
   - Ensure no firewall is blocking your scanner

2. **Insufficient privileges**
   - TCP SYN scans require root: `sudo heroforge scan ...`
   - Check capabilities: `getcap /path/to/heroforge`

3. **DNS resolution failing**
   - Test hostname resolution: `nslookup <hostname>`
   - Try using IP address directly

4. **Wrong port range**
   - Ensure port syntax is correct: `80,443` or `1-1000`
   - Verify ports are not blocked by egress firewall

### Scan Completes but Finds Nothing

**Causes & Solutions:**

1. **Host is down or blocking ICMP**
   - Use `-Pn` flag to skip ping discovery
   - Try different discovery methods

2. **All ports filtered by firewall**
   - The target may have strict firewall rules
   - Try scanning from a different network location

3. **Wrong scan type**
   - Some services only respond to specific scan types
   - Try comprehensive scan for UDP services

### Service Detection Not Working

**Causes & Solutions:**

1. **Service on non-standard port**
   - Enable aggressive service detection
   - Increase detection timeout

2. **Custom or rare service**
   - Service may not be in signature database
   - Manual investigation may be required

3. **Encrypted connection**
   - TLS/SSL services may obscure service details
   - Try SSL-specific detection options

## Authentication Issues

### Cannot Log In

**Check these in order:**

1. **Correct credentials**
   - Verify username is correct (case-sensitive)
   - Use "Forgot Password" if unsure

2. **Account status**
   - Check email for verification link
   - Account may be locked after failed attempts (wait 15 minutes)

3. **Browser issues**
   - Clear cookies and cache
   - Try incognito/private mode
   - Try a different browser

4. **MFA issues**
   - Ensure device time is synchronized
   - Use backup codes if authenticator not working

### Session Expires Quickly

**Causes & Solutions:**

1. **Token expiration**
   - Access tokens expire after 1 hour
   - Refresh token extends session automatically

2. **Clock skew**
   - Ensure your system clock is accurate
   - Sync with NTP: `sudo ntpdate pool.ntp.org`

3. **Multiple tabs/sessions**
   - Each session has its own tokens
   - Logging out in one tab affects others

### MFA Not Working

**Solutions:**

1. **Time sync issue**
   - TOTP codes are time-based
   - Sync your authenticator device time

2. **Wrong account in app**
   - Verify you're using the correct authenticator entry

3. **Use backup codes**
   - Enter a backup code if available
   - Each code works only once

4. **Recovery**
   - Contact support with account verification info

## Web Dashboard Issues

### Dashboard Not Loading

**Check these:**

1. **JavaScript enabled**
   - Dashboard requires JavaScript
   - Check browser extensions blocking scripts

2. **Browser compatibility**
   - Use Chrome, Firefox, Safari, or Edge (latest versions)
   - Clear browser cache

3. **Network connectivity**
   - Check if API is reachable: `curl https://heroforge.genialarchitect.io/health/live`
   - Check for proxy issues

### WebSocket Connection Failed

**Symptoms:**
- Real-time updates not working
- Scan progress not showing

**Solutions:**

1. **Proxy/firewall blocking WebSocket**
   - WebSocket uses `/api/ws/scans/{id}`
   - Ensure proxy allows WebSocket upgrade

2. **Token expired**
   - Refresh the page to get new token
   - Re-login if issue persists

3. **Browser WebSocket issues**
   - Try a different browser
   - Check browser console for errors

### Slow Performance

**Optimizations:**

1. **Reduce data volume**
   - Paginate large result sets
   - Use filters to narrow results

2. **Browser memory**
   - Close unused tabs
   - Restart browser periodically

3. **Network latency**
   - Check your internet connection
   - Use wired connection if possible

## CLI Issues

### Command Not Found

**Linux/macOS:**
```bash
# Add to PATH
export PATH=$PATH:/path/to/heroforge

# Or create symlink
sudo ln -s /path/to/heroforge /usr/local/bin/heroforge
```

**Windows:**
```powershell
# Add to system PATH in Environment Variables
# Or run with full path: C:\path\to\heroforge.exe
```

### Permission Denied

**Linux:**
```bash
# Make executable
chmod +x /path/to/heroforge

# For privileged scans
sudo heroforge scan ...

# Or grant capabilities
sudo setcap cap_net_raw+eip /path/to/heroforge
```

**Windows:**
- Run Command Prompt or PowerShell as Administrator

### Database Errors

**"Database locked" error:**
```bash
# Check for running instances
ps aux | grep heroforge

# Kill stuck processes
kill <pid>

# If using web server, ensure only one instance runs
```

**"Database corrupt" error:**
```bash
# Backup current database
cp heroforge.db heroforge.db.corrupt

# Try recovery
sqlite3 heroforge.db ".recover" | sqlite3 heroforge_recovered.db

# Or start fresh
rm heroforge.db
heroforge serve  # Creates new database
```

## Connection Issues

### Cannot Connect to Target

**Diagnostic steps:**

```bash
# 1. Check basic connectivity
ping <target>

# 2. Check routing
traceroute <target>

# 3. Check DNS
nslookup <target>

# 4. Check specific port
nc -zv <target> <port>

# 5. Check your external IP
curl ifconfig.me
```

### Firewall Blocking Scans

**Check outbound rules:**

```bash
# Test outbound TCP
nc -zv scanme.nmap.org 80

# Test outbound UDP
nc -zuv 8.8.8.8 53
```

**Common blocked ports:**
- 25 (SMTP) - Often blocked by ISPs
- 137-139, 445 (SMB) - Often blocked
- 23 (Telnet) - Sometimes blocked

### Slow Network Performance

**Optimizations:**

1. **Reduce concurrency**
   ```bash
   heroforge scan <target> --concurrency 50
   ```

2. **Increase timeout**
   ```bash
   heroforge scan <target> --timeout 5000
   ```

3. **Scan fewer ports initially**
   ```bash
   heroforge scan <target> --top-ports 100
   ```

## Report Generation Issues

### Report Generation Fails

**Causes:**

1. **No data to report**
   - Ensure scan completed successfully
   - Check scan has results

2. **Disk space**
   - Verify sufficient disk space
   - Check reports directory permissions

3. **Large report**
   - Very large scans may timeout
   - Try generating smaller reports

### PDF Generation Issues

**Solutions:**

1. **Missing dependencies**
   - PDF generation may require additional libraries
   - Check server logs for specific errors

2. **Memory issues**
   - Large PDFs need more memory
   - Try HTML format first, convert separately

## Self-Hosted Deployment Issues

### Container Won't Start

```bash
# Check container status
docker ps -a | grep heroforge

# View logs
docker logs heroforge --tail 100

# Common issues:
# - Port already in use
# - Missing environment variables
# - Database permission issues
```

### Environment Variables Not Set

```bash
# Check if JWT_SECRET is set
echo $JWT_SECRET

# Set required variables
export JWT_SECRET=$(openssl rand -base64 32)
export DATABASE_URL=sqlite:./heroforge.db
```

### SSL/TLS Certificate Issues

**Traefik certificate problems:**
```bash
# Check Traefik logs
docker logs root-traefik-1 | grep -i cert

# Force certificate renewal
docker compose restart traefik
```

## Getting Help

If your issue isn't covered here:

1. **Check logs**
   - CLI: Run with `RUST_LOG=debug`
   - Web: Check browser console and network tab
   - Docker: `docker logs heroforge`

2. **Collect diagnostic info**
   - HeroForge version: `heroforge --version`
   - OS and version
   - Error messages (full text)
   - Steps to reproduce

3. **Contact support**
   - Email: support@heroforge.security
   - Include diagnostic information
   - Attach relevant logs (remove sensitive data)

4. **Community resources**
   - Discord/Slack community channels
   - GitHub issues for bug reports
