# HeroForge Incident Response Runbook

This document defines procedures for handling production incidents affecting HeroForge.

## Severity Levels

| Level | Definition | Response Time | Examples |
|-------|------------|---------------|----------|
| **P1 - Critical** | Service completely unavailable, data loss, security breach | Immediate (< 15 min) | Site down, database corruption, security incident |
| **P2 - High** | Major feature broken, significant user impact | < 1 hour | Authentication failing, scans not running, WebSocket broken |
| **P3 - Medium** | Minor feature broken, workaround available | < 4 hours | Report generation failing, specific integration broken |
| **P4 - Low** | Cosmetic issue, minimal impact | < 24 hours | UI glitch, typo, performance degradation |

## Emergency Contacts

| Role | Name | Contact |
|------|------|---------|
| Primary On-Call | [Your Name] | [Phone/Email] |
| Secondary On-Call | [Backup Name] | [Phone/Email] |
| Engineering Lead | [Lead Name] | [Phone/Email] |
| Infrastructure | [Infra Contact] | [Phone/Email] |

## Quick Response Checklist

### P1 - Critical Incident

- [ ] Acknowledge incident (respond in monitoring channel)
- [ ] Assess scope and impact
- [ ] Execute rollback if code change caused issue
- [ ] Notify stakeholders
- [ ] Document timeline in incident log
- [ ] Resolve or escalate within 15 minutes
- [ ] Post-incident: Schedule retrospective

### P2-P4 Incidents

- [ ] Acknowledge incident
- [ ] Investigate root cause
- [ ] Implement fix or workaround
- [ ] Monitor for recurrence
- [ ] Document in incident log

## Rollback Procedure

### Quick Rollback (< 5 minutes)

If a recent deployment caused issues:

```bash
# 1. SSH to production server
ssh root@heroforge.genialarchitect.io

# 2. Navigate to HeroForge directory
cd /root/Development/HeroForge

# 3. View recent commits/tags
git log --oneline -10
git tag -l --sort=-version:refname | head -5

# 4. Rollback to previous known-good version
git checkout <previous-tag-or-commit>

# 5. Rebuild frontend (if needed)
cd frontend && npm ci && npm run build && cd ..

# 6. Rebuild backend
cargo build --release

# 7. Restart container
cd /root
docker compose build heroforge
docker compose up -d heroforge

# 8. Verify service is healthy
curl -s https://heroforge.genialarchitect.io/health/ready | jq
docker logs heroforge --tail 20
```

### Database Rollback

If database corruption or bad migration:

```bash
# 1. Stop service
docker stop heroforge

# 2. Backup current (possibly corrupted) database
cp heroforge.db heroforge.db.incident-$(date +%Y%m%d%H%M%S)

# 3. Find most recent backup
ls -lt /root/heroforge_backups/heroforge_*.db.gz | head -5

# 4. Restore from backup
gunzip -c /root/heroforge_backups/heroforge_<timestamp>.db.gz > heroforge.db

# 5. Restart service
docker start heroforge

# 6. Verify data integrity
docker exec heroforge sqlite3 /root/Development/HeroForge/heroforge.db "PRAGMA integrity_check;"
```

## Common Incidents

### Service Unavailable (502/503/504)

**Symptoms:** Users get 502, 503, or 504 errors

**Diagnostic Steps:**
```bash
# Check if container is running
docker ps | grep heroforge

# Check container logs
docker logs heroforge --tail 100

# Check if backend is listening
docker exec heroforge netstat -tlnp | grep 8080

# Check Traefik logs
docker logs root-traefik-1 --tail 50

# Check system resources
docker stats heroforge --no-stream
df -h /root
free -h
```

**Resolution:**
1. If container stopped: `docker start heroforge`
2. If container crashed: Check logs, fix issue, restart
3. If Traefik issue: `docker compose restart traefik`
4. If resource exhaustion: Scale up or optimize

### Authentication Failures

**Symptoms:** Users cannot log in, "Invalid credentials" errors

**Diagnostic Steps:**
```bash
# Check if auth endpoints respond
curl -s -X POST https://heroforge.genialarchitect.io/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test"}' | jq

# Check JWT_SECRET is set
docker exec heroforge printenv | grep JWT_SECRET

# Check database connection
docker exec heroforge sqlite3 /root/Development/HeroForge/heroforge.db "SELECT COUNT(*) FROM users;"
```

**Resolution:**
1. If JWT_SECRET missing: Set in docker-compose environment
2. If database unreachable: Check file permissions, disk space
3. If widespread: Check for deployment issues, rollback if needed

### Database Locked

**Symptoms:** Operations fail with "database is locked" errors

**Diagnostic Steps:**
```bash
# Check for long-running queries
docker exec heroforge sqlite3 /root/Development/HeroForge/heroforge.db ".timeout 1000" "SELECT * FROM scan_results LIMIT 1;"

# Check WAL status
ls -la /root/Development/HeroForge/heroforge.db*
```

**Resolution:**
1. Restart the service: `docker restart heroforge`
2. If persists: Check for orphan processes accessing database
3. Consider enabling WAL mode: `PRAGMA journal_mode=WAL;`

### High Memory Usage

**Symptoms:** Service slow, OOM kills, high memory reported

**Diagnostic Steps:**
```bash
# Check container memory
docker stats heroforge --no-stream

# Check for memory leaks
docker logs heroforge 2>&1 | grep -i "memory\|oom"
```

**Resolution:**
1. Restart container: `docker restart heroforge`
2. Increase memory limit in docker-compose if needed
3. Investigate specific endpoints causing high memory

### SSL Certificate Expired

**Symptoms:** Browser shows certificate warnings, HTTPS fails

**Diagnostic Steps:**
```bash
# Check certificate expiration
echo | openssl s_client -connect heroforge.genialarchitect.io:443 2>/dev/null | openssl x509 -noout -dates

# Check Traefik ACME
docker logs root-traefik-1 | grep -i cert
```

**Resolution:**
1. Traefik should auto-renew. If not:
```bash
docker compose restart traefik
```
2. If still failing, force renewal:
```bash
docker compose down
docker volume rm root_traefik_data
docker compose up -d
```

### Disk Space Full

**Symptoms:** Operations fail, database errors, container won't start

**Diagnostic Steps:**
```bash
# Check disk usage
df -h /root

# Find large files
du -ah /root | sort -rh | head -20

# Check log sizes
ls -lh /var/log/
docker system df
```

**Resolution:**
1. Clean up old backups: `ls -t /root/heroforge_backups/*.gz | tail -n +31 | xargs rm -f`
2. Clean Docker: `docker system prune -af`
3. Clean logs: `truncate -s 0 /var/log/*.log`
4. Consider expanding disk

## Incident Communication

### Internal Updates

Post updates to the team channel every 30 minutes during active P1/P2 incidents:

```
[INCIDENT UPDATE - HeroForge]
Status: Investigating / Identified / Fixing / Resolved
Impact: [Brief description]
Current Actions: [What we're doing]
ETA: [If known]
```

### External Communication

For customer-facing incidents:

1. Update status page (if configured)
2. Send email notification for P1 incidents
3. Post on social media for extended outages

**Template:**
```
We are currently experiencing issues with [service/feature].
Impact: [What users are experiencing]
Status: Our team is actively investigating.
We will provide updates every [30 minutes / 1 hour].
```

## Post-Incident

### Incident Report Template

After resolving P1/P2 incidents, create a post-mortem:

```markdown
# Incident Report: [Title]

## Summary
- **Date/Time:** [Start time] - [End time]
- **Duration:** [Total downtime]
- **Severity:** P[1-4]
- **Impact:** [Number of affected users, features]

## Timeline
- HH:MM - Incident detected
- HH:MM - Initial response
- HH:MM - Root cause identified
- HH:MM - Fix deployed
- HH:MM - Incident resolved

## Root Cause
[Detailed technical explanation]

## Resolution
[What was done to fix the issue]

## Impact
- Users affected: [Number]
- Revenue impact: [If applicable]
- Data loss: [Yes/No, details]

## Action Items
- [ ] [Preventive measure 1]
- [ ] [Preventive measure 2]
- [ ] [Monitoring improvement]

## Lessons Learned
[Key takeaways]
```

### Blameless Retrospective

Schedule a retrospective meeting:
- Focus on systems and processes, not individuals
- Identify what went well and what could improve
- Create actionable items with owners and deadlines

## Runbook Maintenance

- Review and update this runbook quarterly
- Add new incident types as they occur
- Test rollback procedures periodically
- Update contact information when team changes

---

**Last Updated:** January 2026
**Owner:** Engineering Team
