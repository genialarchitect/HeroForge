# HeroForge Monitoring Setup

This document describes how to set up monitoring, alerting, and backup automation for HeroForge.

## Health Check Endpoints

HeroForge exposes two health check endpoints:

| Endpoint | Purpose | Expected Response |
|----------|---------|-------------------|
| `GET /health/live` | Liveness probe - is the process running? | `{"status": "ok"}` |
| `GET /health/ready` | Readiness probe - is the service ready to accept requests? | `{"status": "ok", "database": {...}}` |

## External Monitoring (UptimeRobot)

### Setup Instructions

1. Create a free account at [uptimerobot.com](https://uptimerobot.com)

2. Add monitors for both endpoints:

   **Liveness Monitor:**
   - Monitor Type: HTTP(s)
   - URL: `https://heroforge.genialarchitect.io/health/live`
   - Monitoring Interval: 5 minutes
   - Alert Contacts: Your email/Slack/Discord

   **Readiness Monitor:**
   - Monitor Type: HTTP(s)
   - URL: `https://heroforge.genialarchitect.io/health/ready`
   - Monitoring Interval: 5 minutes
   - Alert Contacts: Your email/Slack/Discord

3. Configure alert thresholds:
   - Alert after 2 consecutive failures
   - Recovery notification when back online

### Alternative Monitoring Tools

- **Pingdom** (paid): Enterprise-grade uptime monitoring
- **StatusCake** (free tier): Basic uptime monitoring
- **Datadog** (free trial): Full observability platform
- **New Relic** (free tier): Application performance monitoring

## Error Tracking (Sentry)

### Setup Instructions

1. Create a free account at [sentry.io](https://sentry.io)

2. Create a new Rust project

3. Add Sentry DSN to environment:
   ```bash
   export SENTRY_DSN="https://your-dsn@sentry.io/project-id"
   ```

4. Sentry integration captures:
   - Unhandled panics
   - Error-level log messages
   - Performance data

### Alternative Error Tracking

- **Rollbar**: Error tracking with deployment tracking
- **Bugsnag**: Error monitoring with release health
- **Honeybadger**: Exception monitoring for production

## Logging

HeroForge uses `env_logger` for structured logging.

### Configuration

Set log level via environment variable:

```bash
# Minimal logging
export RUST_LOG=error

# Standard logging
export RUST_LOG=info

# Debug logging
export RUST_LOG=debug

# Module-specific logging
export RUST_LOG=heroforge=debug,actix_web=info
```

### Log Output

Logs are written to stdout/stderr. For Docker:

```bash
# View live logs
docker logs heroforge -f

# View last 100 lines
docker logs heroforge --tail 100

# View logs with timestamps
docker logs heroforge -t
```

### Log Aggregation

For production, consider aggregating logs:

- **Loki + Grafana**: Open-source log aggregation
- **Elasticsearch + Kibana**: Full-text search on logs
- **Datadog Logs**: Managed log management
- **Papertrail**: Simple cloud-based logging

## Automated Backups

### Backup Script

A backup script is provided at `scripts/backup.sh`:

```bash
# Run manual backup
./scripts/backup.sh

# Specify backup directory
./scripts/backup.sh /path/to/backups
```

### Cron Setup

Add to crontab for automated daily backups:

```bash
# Edit crontab
crontab -e

# Add this line (runs at 4 AM daily)
0 4 * * * /root/Development/HeroForge/scripts/backup.sh >> /var/log/heroforge-backup.log 2>&1
```

### Backup Features

- SQLite online backup (safe for running databases)
- Automatic compression (gzip)
- SHA256 checksums
- 30-day retention with rotation
- Integrity verification

### Backup Directory Structure

```
/root/heroforge_backups/
├── heroforge_20260119_040000.db.gz
├── heroforge_20260118_040000.db.gz
├── ...
└── checksums.txt
```

### Restore from Backup

```bash
# Decompress backup
gunzip -k /root/heroforge_backups/heroforge_20260119_040000.db.gz

# Stop HeroForge
docker stop heroforge

# Replace database
cp /root/heroforge_backups/heroforge_20260119_040000.db /root/Development/HeroForge/heroforge.db

# Start HeroForge
docker start heroforge
```

## Resource Monitoring

### Docker Stats

```bash
# View container resource usage
docker stats heroforge

# One-time snapshot
docker stats heroforge --no-stream
```

### System Metrics

Monitor key metrics:

| Metric | Warning | Critical |
|--------|---------|----------|
| CPU Usage | > 70% | > 90% |
| Memory Usage | > 80% | > 95% |
| Disk Usage | > 80% | > 95% |
| Response Time | > 2s | > 5s |

### Prometheus + Grafana (Optional)

For comprehensive metrics:

1. Deploy Prometheus to scrape metrics
2. Deploy Grafana for visualization
3. Import HeroForge dashboard template

## Alerting Channels

Configure alerts to multiple channels:

### Email

- Primary notification method
- Configure SMTP in HeroForge settings
- Set up alert routing in monitoring tools

### Slack

```bash
# Webhook URL format
https://hooks.slack.com/services/T.../B.../...
```

### Discord

```bash
# Webhook URL format
https://discord.com/api/webhooks/.../...
```

### PagerDuty (Enterprise)

For on-call rotation and incident management.

## Status Page

### Simple Status Page

Create a simple status page using GitHub Pages:

1. Create `status.html` in a GitHub repo
2. Update status manually or via CI
3. Access at `your-username.github.io/repo/status.html`

### Managed Status Pages

- **Statuspage.io** (Atlassian): Professional status pages
- **Cachet**: Self-hosted status page
- **Uptime Kuma**: Self-hosted monitoring with status page

## Checklist

- [ ] UptimeRobot monitors configured for `/health/live` and `/health/ready`
- [ ] Alert contacts added (email, Slack, etc.)
- [ ] Sentry DSN configured (optional)
- [ ] Backup cron job added
- [ ] Backup directory created: `mkdir -p /root/heroforge_backups`
- [ ] Verified backup script runs: `./scripts/backup.sh`
- [ ] Log level set appropriately: `RUST_LOG=info`
- [ ] Status page created (optional)

## Quick Commands

```bash
# Test health endpoints
curl -s https://heroforge.genialarchitect.io/health/live | jq
curl -s https://heroforge.genialarchitect.io/health/ready | jq

# View container logs
docker logs heroforge --tail 50

# Run manual backup
/root/Development/HeroForge/scripts/backup.sh

# Check backup status
ls -lh /root/heroforge_backups/

# Check disk space
df -h /root
```
