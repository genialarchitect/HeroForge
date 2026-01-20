# HeroForge Incident Response Runbook

**Version:** 1.0
**Last Updated:** January 2026
**Owner:** Genial Architect Cybersecurity Research Associates

---

## Table of Contents

1. [Severity Levels](#severity-levels)
2. [On-Call Responsibilities](#on-call-responsibilities)
3. [Incident Detection](#incident-detection)
4. [Response Procedures](#response-procedures)
5. [Rollback Procedures](#rollback-procedures)
6. [Communication](#communication)
7. [Post-Incident Review](#post-incident-review)

---

## Severity Levels

| Severity | Description | Response Time | Examples |
|----------|-------------|---------------|----------|
| **P1 - Critical** | Service completely unavailable or major security breach | Immediate (< 15 min) | Site down, data breach, payment system failure |
| **P2 - High** | Major feature broken, significant user impact | < 1 hour | Scans failing, auth broken, reports not generating |
| **P3 - Medium** | Minor feature broken, workaround available | < 4 hours | UI glitch, non-critical integration down, slow performance |
| **P4 - Low** | Minor issue, minimal user impact | < 24 hours | Typo, cosmetic bug, documentation error |

### Severity Decision Tree

```
Is the service completely unavailable?
├── YES → P1
└── NO → Is there a security breach or data exposure?
    ├── YES → P1
    └── NO → Is a major feature broken with no workaround?
        ├── YES → P2
        └── NO → Is there significant user impact?
            ├── YES → P3
            └── NO → P4
```

---

## On-Call Responsibilities

### Current On-Call

During bootstrap phase (until dedicated staff):
- **Primary:** Product Owner / Founder
- **Escalation:** Same (single-person operation)

### Monitoring Channels

1. **UptimeRobot Alerts** - Email + SMS for downtime
2. **Sentry Alerts** - Application errors
3. **Support Email** - support@genialarchitect.io

### On-Call Duties

- Monitor alert channels during business hours (9 AM - 9 PM EST)
- Acknowledge alerts within response time SLA
- Triage and assess severity
- Execute response procedures
- Communicate status to affected users (if applicable)

---

## Incident Detection

### Automated Monitoring

| Monitor | Type | Alert Threshold |
|---------|------|-----------------|
| UptimeRobot - /health/live | HTTP | Down > 2 min |
| UptimeRobot - /health/ready | HTTP | Down > 2 min |
| Sentry | Error Rate | > 10 errors/min |
| Sentry | Response Time | P95 > 5s |

### Manual Checks

Daily (recommended during early operations):
```bash
# Check container status
docker ps | grep heroforge

# Check recent logs for errors
docker logs heroforge --tail 100 | grep -i error

# Check disk space
df -h /root/heroforge_data

# Check database size
ls -lh /root/heroforge_data/heroforge.db
```

---

## Response Procedures

### P1 - Critical Incident Response

**Time to Acknowledge:** < 15 minutes
**Time to Mitigate:** < 1 hour

#### Step 1: Assess (5 min)
```bash
# Check if container is running
docker ps | grep heroforge

# Check container logs
docker logs heroforge --tail 50

# Check if site responds
curl -s -o /dev/null -w "%{http_code}" https://heroforge.genialarchitect.io/api/health/ready

# Check system resources
docker stats heroforge --no-stream
```

#### Step 2: Immediate Actions

**If container is down:**
```bash
docker restart heroforge
# Wait 30 seconds, then verify
sleep 30 && curl -s https://heroforge.genialarchitect.io/api/health/ready
```

**If container won't start:**
```bash
# Check logs for startup errors
docker logs heroforge --tail 100

# Check if port is in use
netstat -tlnp | grep 8080

# Try rebuilding container
cd /root && docker compose build heroforge && docker compose up -d heroforge
```

**If database issue:**
```bash
# Check database file exists and has size
ls -lh /root/heroforge_data/heroforge.db

# Check for lock files
ls -la /root/heroforge_data/heroforge.db*

# Restart container (clears locks)
docker restart heroforge
```

#### Step 3: Communicate
- Update status page (if set up)
- Notify affected users if downtime > 30 min

#### Step 4: Document
- Record timeline of events
- Document root cause
- Schedule post-incident review

---

### P2 - High Priority Response

**Time to Acknowledge:** < 1 hour
**Time to Mitigate:** < 4 hours

#### Step 1: Assess
```bash
# Check application logs for specific feature
docker logs heroforge --tail 200 | grep -i "error\|fail\|panic"

# Check recent deployments
cd /root/Development/HeroForge && git log --oneline -5
```

#### Step 2: Actions

**If recent deployment caused issue:**
```bash
# Rollback to previous version (see Rollback Procedures)
```

**If database-related:**
```bash
# Check for table locks or corruption
docker exec heroforge sqlite3 /data/heroforge.db "PRAGMA integrity_check;"
```

**If resource-related:**
```bash
# Check memory/CPU
docker stats heroforge --no-stream

# Restart container to free resources
docker restart heroforge
```

---

### P3/P4 - Lower Priority Response

**Time to Acknowledge:** P3: < 4 hours, P4: < 24 hours

1. Document the issue in tracking system
2. Investigate during normal business hours
3. Schedule fix for next deployment cycle
4. Communicate timeline to reporter (if user-reported)

---

## Rollback Procedures

### Application Rollback

**When to rollback:** New deployment caused regression or critical bug

#### Quick Rollback (to previous commit)
```bash
cd /root/Development/HeroForge

# Check recent commits
git log --oneline -10

# Checkout previous working version
git checkout HEAD~1

# Rebuild and deploy
cd /root/Development/HeroForge/frontend && npm run build
cd /root/Development/HeroForge && cargo build --release
cd /root && docker compose build heroforge && docker compose up -d heroforge

# Verify
curl -s https://heroforge.genialarchitect.io/api/health/ready
```

#### Rollback to Specific Tag/Commit
```bash
cd /root/Development/HeroForge

# List available tags
git tag -l

# Checkout specific version
git checkout v1.0.0  # or specific commit hash

# Rebuild and deploy
./deploy.sh

# Verify
curl -s https://heroforge.genialarchitect.io/api/health/ready
```

### Database Rollback

**When to rollback:** Database corruption or bad migration

#### Restore from Backup
```bash
# Stop the application
docker stop heroforge

# List available backups
ls -la /root/heroforge_backups/

# Restore from backup (replace date with actual backup)
cp /root/heroforge_backups/heroforge_20260120.db /root/heroforge_data/heroforge.db

# Restart application
docker start heroforge

# Verify
curl -s https://heroforge.genialarchitect.io/api/health/ready
```

**Note:** Database backups should be encrypted. The backup script uses the DATABASE_ENCRYPTION_KEY environment variable.

### Complete Environment Rollback

**When to rollback:** Infrastructure-level changes broke everything

```bash
# Pull previous docker-compose configuration from backup
# Restore previous .env file
# Restart all services
cd /root && docker compose down && docker compose up -d
```

---

## Communication

### Internal Communication

During incident:
1. Document actions in real-time (incident log)
2. Keep notes of what worked and what didn't

### External Communication (Users)

#### P1 Incident Communication Template

**Initial (within 30 min):**
```
Subject: [HeroForge] Service Disruption - Investigating

We are aware of issues affecting HeroForge services.
Our team is actively investigating.

We will provide updates as we learn more.

Status: Investigating
Impact: [Description of affected services]
```

**Update (every 30 min during P1):**
```
Subject: [HeroForge] Service Disruption - Update

Current Status: [Investigating/Identified/Fixing]
Impact: [Current state]
Next Update: [Time]

[Additional details if available]
```

**Resolution:**
```
Subject: [HeroForge] Service Disruption - Resolved

The service disruption has been resolved.

Duration: [Start time] - [End time]
Root Cause: [Brief description]
Resolution: [What was done to fix it]

We apologize for any inconvenience.
```

### Communication Channels

- **Status Page:** [TBD - GitHub Pages or similar]
- **Email:** support@genialarchitect.io
- **Twitter/X:** [TBD]

---

## Post-Incident Review

### Required for P1 and P2 Incidents

Complete within 48 hours of resolution.

### Post-Incident Report Template

```markdown
# Post-Incident Report: [Title]

**Date:** [Date]
**Duration:** [Start] - [End] ([Total time])
**Severity:** [P1/P2]
**Author:** [Name]

## Summary
[1-2 sentence summary of what happened]

## Impact
- Users affected: [Number or percentage]
- Features affected: [List]
- Data loss: [Yes/No - details if yes]

## Timeline (all times in UTC)
- HH:MM - [Event]
- HH:MM - [Event]
- HH:MM - [Event]

## Root Cause
[Detailed explanation of what caused the incident]

## Resolution
[What was done to resolve the incident]

## Lessons Learned
### What went well
- [Point]

### What could be improved
- [Point]

## Action Items
| Action | Owner | Due Date | Status |
|--------|-------|----------|--------|
| [Action] | [Name] | [Date] | [ ] |

## Preventive Measures
[Changes to prevent similar incidents]
```

### Review Meeting Agenda

1. Timeline walkthrough (5 min)
2. Root cause analysis (10 min)
3. What went well (5 min)
4. What could be improved (10 min)
5. Action items assignment (10 min)

---

## Emergency Contacts

| Role | Contact | Method |
|------|---------|--------|
| Primary On-Call | [Founder] | Email, Phone |
| Hosting Provider | Hostinger | Support Portal |
| Domain/DNS | [Provider] | Support Portal |

---

## Quick Reference

### Common Commands

```bash
# Restart application
docker restart heroforge

# View logs
docker logs heroforge -f

# Check health
curl https://heroforge.genialarchitect.io/api/health/ready

# Force rebuild and deploy
cd /root && docker compose build heroforge && docker compose up -d heroforge

# Check disk space
df -h

# Check container resources
docker stats heroforge --no-stream
```

### Important Paths

| Path | Description |
|------|-------------|
| `/root/Development/HeroForge` | Application source |
| `/root/heroforge_data` | Persistent data (DB, configs) |
| `/root/heroforge_backups` | Database backups |
| `/root/docker-compose.yml` | Container configuration |
| `/root/.env` | Environment variables |

### Service URLs

| Service | URL |
|---------|-----|
| Production | https://heroforge.genialarchitect.io |
| Health Check | https://heroforge.genialarchitect.io/api/health/ready |
| API Docs | https://heroforge.genialarchitect.io/api/docs |

---

## Appendix: Backup Setup

### Automated Daily Backups

Add to crontab (`crontab -e`):
```bash
# Daily database backup at 4 AM UTC
0 4 * * * cp /root/heroforge_data/heroforge.db /root/heroforge_backups/heroforge_$(date +\%Y\%m\%d).db 2>/dev/null

# Keep only last 7 days of backups
0 5 * * * find /root/heroforge_backups -name "heroforge_*.db" -mtime +7 -delete
```

Create backup directory:
```bash
mkdir -p /root/heroforge_backups
```

---

*This runbook should be reviewed and updated quarterly or after any significant incident.*
