# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

HeroForge is a network reconnaissance and triage tool written in Rust, designed for authorized penetration testing. It provides both a CLI interface and a web dashboard with real-time scanning capabilities.

**Key Technologies:**
- **Backend:** Rust with Tokio async runtime, Actix-web for HTTP server
- **Frontend:** React 18 + TypeScript + Vite + TailwindCSS
- **State Management:** Zustand (global state) + React Query (server state)
- **Database:** SQLite with sqlx for async queries, optional SQLCipher encryption (AES-256)
- **Authentication:** JWT tokens with bcrypt password hashing, TOTP-based MFA, account lockout protection

**Deployment:**
- Production URL: https://heroforge.genialarchitect.io
- Reverse proxy: Traefik (via Docker) with automatic SSL/TLS (Let's Encrypt)
- Container management: Docker Compose

## Quick Reference

```bash
# Build and test
cargo check                           # Fast type check
cargo test                            # Run all tests
cargo build --release                 # Production build

# Deploy to production
sudo ./deploy.sh                      # Full deploy (frontend + backend + Docker)

# View logs
docker logs heroforge -f              # Container logs
```

## CLI Commands

```bash
heroforge scan <TARGETS> [OPTIONS]      # Full triage scan
heroforge discover <TARGETS>            # Host discovery only
heroforge portscan <TARGETS> -p 1-1000  # Port scan only
heroforge config [PATH]                 # Generate config file
heroforge serve --bind 127.0.0.1:8080   # Start web server
```

### Scan Types (`-s, --scan-type`)

| Type | Description | Privileges |
|------|-------------|------------|
| `tcp-connect` | Standard 3-way handshake (default) | None |
| `tcp-syn` | Half-open SYN scanning | root/CAP_NET_RAW |
| `udp` | Protocol-specific probes with ICMP detection | root |
| `comprehensive` | Combined TCP + UDP scan | root |

### Common Scan Examples

```bash
# Basic scan
cargo run -- scan 192.168.1.0/24 --ports 1-1000

# Fast scan (skip detection)
cargo run -- scan 192.168.1.0/24 --no-os-detect --no-service-detect

# UDP/privileged scans (require root)
sudo ./target/release/heroforge scan 192.168.1.0/24 --scan-type udp
sudo ./target/release/heroforge scan 192.168.1.0/24 --scan-type comprehensive
```

## Development

### Backend (Rust)

```bash
cargo check                           # Fast type check (no codegen)
cargo test                            # All tests
cargo test -- --nocapture             # With output
cargo test scanner::                  # Test specific module
cargo test scanner::comparison::tests::test_compare_scans  # Specific test
```

### Frontend (React/TypeScript)

```bash
cd frontend
npm install                           # Install dependencies
npm run build                         # Production build
npm run dev                           # Development server (hot reload)
npm run lint                          # Lint TypeScript/React
```

### Deployment

```bash
sudo ./deploy.sh                      # Automated: builds frontend + backend, deploys via Docker

# Manual steps (if needed)
cd frontend && npm install && npm run build
cargo build --release
cd /root && docker compose build heroforge && docker compose up -d heroforge
```

## Database

```bash
# Auto-initialized on first run at ./heroforge.db
sqlite3 heroforge.db ".schema"
sqlite3 heroforge.db "SELECT id, name, status, created_at FROM scan_results;"
```

**Encryption:** Optional AES-256 encryption via SQLCipher. Set `DATABASE_ENCRYPTION_KEY` env var to enable. See `DATABASE_ENCRYPTION_MIGRATION.md` for migration instructions.

## Architecture Overview

### Backend Module Organization

```
src/
├── main.rs              # CLI argument parsing and entry point
├── config.rs            # Configuration file handling (TOML)
├── types.rs             # Core data structures (HostInfo, PortInfo, ScanConfig)
├── scanner/             # Network scanning engine
│   ├── mod.rs           # Scan orchestration
│   ├── host_discovery.rs, port_scanner.rs, syn_scanner.rs
│   ├── service_detection.rs, os_fingerprint.rs
│   ├── udp_scanner.rs, udp_probes.rs, udp_service_detection.rs
│   ├── ssl_scanner.rs   # SSL/TLS certificate analysis
│   ├── dns_recon.rs     # DNS reconnaissance (subdomains, zone transfers, records)
│   ├── comparison.rs    # Scan diff between results
│   ├── webapp/          # Web application scanning (XSS, SQLi, headers, forms, crawler)
│   └── enumeration/     # Service-specific enumeration (http, dns, smb, ftp, ssh, snmp, etc.)
├── cve/                 # CVE lookup: offline_db → cache → NVD API
├── vuln/                # Vulnerability scanning and misconfiguration detection
├── compliance/          # Security compliance frameworks
│   ├── frameworks/      # CIS, NIST 800-53, NIST CSF, PCI-DSS, HIPAA, SOC2, FERPA, OWASP
│   ├── controls/        # Control mappings and compliance checks
│   └── analyzer.rs, scanner.rs, scoring.rs
├── notifications/       # Multi-channel notifications (Slack, Microsoft Teams, email)
├── integrations/        # External integrations
│   ├── jira.rs          # Jira ticket creation
│   └── siem/            # SIEM integrations (Splunk, Elasticsearch, Syslog)
├── email/               # SMTP notifications (scan complete, critical vulns)
├── reports/             # Report generation (JSON, HTML, PDF, CSV) with risk scoring
├── output/              # CLI output formatting (terminal, json, csv)
├── db/                  # SQLite via sqlx (models.rs, migrations.rs, analytics.rs, assets.rs)
└── web/                 # Actix-web server
    ├── auth/            # JWT auth (jwt.rs, middleware.rs)
    ├── api/             # REST endpoints (see API section below)
    ├── websocket/       # Real-time scan progress with aggregation
    ├── rate_limit.rs    # Request rate limiting
    └── scheduler.rs     # Background job scheduler
```

### Frontend Routes

| Route | Description |
|-------|-------------|
| `/` | Login page |
| `/dashboard` | Scan list and new scan form |
| `/dashboard/:scanId` | Scan details with results/progress |
| `/admin` | Admin panel (requires admin role) |
| `/settings` | Target Groups, Scheduled Scans, Templates, Notifications, Profile, API Keys, JIRA, SIEM |
| `/assets` | Asset inventory management |
| `/webapp-scan` | Web application security scanning |
| `/dns-tools` | DNS reconnaissance tools |
| `/compliance` | Compliance framework analysis |
| `/remediation` | Vulnerability remediation workflow board |

### REST API Endpoints

#### Authentication & User Management
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login and receive JWT token
- `POST /api/auth/refresh` - Refresh JWT token
- `POST /api/auth/logout` - Logout user
- `GET /api/auth/me` - Get current user info
- `PUT /api/auth/profile` - Update user profile
- `PUT /api/auth/password` - Change password

#### MFA (Multi-Factor Authentication)
- `POST /api/auth/mfa/setup` - Initialize MFA setup (returns TOTP secret)
- `POST /api/auth/mfa/verify-setup` - Complete MFA setup with verification code
- `POST /api/auth/mfa/verify` - Verify MFA during login (public endpoint)
- `DELETE /api/auth/mfa` - Disable MFA
- `POST /api/auth/mfa/recovery-codes` - Regenerate recovery codes

#### GDPR Compliance
- `GET /api/auth/terms-status` - Get terms acceptance status
- `POST /api/auth/accept-terms` - Accept terms of service
- `GET /api/auth/export` - Export all user data (GDPR data portability)
- `DELETE /api/auth/account` - Delete user account and all data

#### Scans
- `GET /api/scans` - List all scans
- `POST /api/scans` - Create new scan (rate limited: 10/hour)
- `GET /api/scans/stats` - Get aggregated scan statistics
- `GET /api/scans/{id}` - Get scan details
- `DELETE /api/scans/{id}` - Delete scan
- `GET /api/scans/{id}/results` - Get scan results
- `GET /api/scans/{id}/export` - Export scan as CSV
- `GET /api/scans/{id}/topology` - Get network topology visualization data
- `POST /api/scans/compare` - Compare two scan results
- `POST /api/scans/bulk-export` - Bulk export multiple scans
- `POST /api/scans/bulk-delete` - Bulk delete multiple scans
- `GET /api/scan-presets` - Get predefined scan configurations

#### Reports
- `POST /api/reports` - Generate report (JSON, HTML, PDF, CSV)
- `GET /api/reports` - List all reports
- `GET /api/reports/templates` - Get report templates
- `GET /api/reports/{id}` - Get report details
- `GET /api/reports/{id}/download` - Download report file
- `DELETE /api/reports/{id}` - Delete report

#### Scan Templates
- `POST /api/templates` - Create scan template
- `GET /api/templates` - List templates
- `GET /api/templates/{id}` - Get template details
- `PUT /api/templates/{id}` - Update template
- `DELETE /api/templates/{id}` - Delete template
- `GET /api/templates/{id}/export` - Export template as JSON
- `POST /api/templates/import` - Import template from JSON
- `POST /api/templates/{id}/scan` - Create scan from template

#### Target Groups
- `POST /api/target-groups` - Create target group
- `GET /api/target-groups` - List target groups
- `GET /api/target-groups/{id}` - Get target group
- `PUT /api/target-groups/{id}` - Update target group
- `DELETE /api/target-groups/{id}` - Delete target group

#### Scheduled Scans
- `POST /api/scheduled-scans` - Create scheduled scan
- `GET /api/scheduled-scans` - List scheduled scans
- `GET /api/scheduled-scans/{id}` - Get scheduled scan
- `PUT /api/scheduled-scans/{id}` - Update scheduled scan
- `DELETE /api/scheduled-scans/{id}` - Delete scheduled scan
- `GET /api/scheduled-scans/{id}/history` - Get execution history

#### Notifications
- `GET /api/notifications/settings` - Get notification settings
- `PUT /api/notifications/settings` - Update notification settings
- `POST /api/notifications/test-slack` - Test Slack webhook
- `POST /api/notifications/test-teams` - Test Microsoft Teams webhook

#### Analytics
- `GET /api/analytics/summary` - Get analytics summary
- `GET /api/analytics/hosts` - Get hosts discovered over time
- `GET /api/analytics/vulnerabilities` - Get vulnerabilities over time
- `GET /api/analytics/services` - Get top services found
- `GET /api/analytics/frequency` - Get scan frequency data

#### Asset Inventory
- `GET /api/assets` - List assets (filters: `status`, `tags`, `days_inactive`)
- `GET /api/assets/{id}` - Get asset details
- `PATCH /api/assets/{id}` - Update asset metadata (status, tags, notes)
- `DELETE /api/assets/{id}` - Delete asset
- `GET /api/assets/{id}/history` - Get asset scan history

#### Vulnerability Management
- `GET /api/vulnerabilities` - List vulnerabilities (requires `scan_id`, optional `status`, `severity`)
- `GET /api/vulnerabilities/stats` - Get vulnerability statistics
- `GET /api/vulnerabilities/{id}` - Get vulnerability details
- `PUT /api/vulnerabilities/{id}` - Update vulnerability (status, assignee, notes, due_date)
- `POST /api/vulnerabilities/{id}/comments` - Add comment to vulnerability
- `GET /api/vulnerabilities/{id}/timeline` - Get vulnerability remediation timeline
- `POST /api/vulnerabilities/{id}/verify` - Mark vulnerability for re-verification
- `POST /api/vulnerabilities/bulk-update` - Bulk update vulnerability status
- `POST /api/vulnerabilities/bulk-export` - Bulk export to CSV/JSON
- `POST /api/vulnerabilities/bulk-assign` - Bulk assign to user

#### Compliance
- `GET /api/compliance/frameworks` - List available compliance frameworks
- `GET /api/compliance/frameworks/{id}` - Get framework details
- `GET /api/compliance/frameworks/{id}/controls` - Get framework controls
- `POST /api/scans/{id}/compliance` - Run compliance analysis on scan
- `GET /api/scans/{id}/compliance` - Get compliance results for scan
- `POST /api/scans/{id}/compliance/report` - Generate compliance report (PDF/HTML/JSON)
- `GET /api/compliance/reports/{id}/download` - Download compliance report

#### DNS Reconnaissance
- `POST /api/dns/recon` - Perform DNS reconnaissance (subdomains, zone transfers, records)
- `GET /api/dns/recon` - List DNS recon results
- `GET /api/dns/recon/{id}` - Get specific DNS recon result
- `DELETE /api/dns/recon/{id}` - Delete DNS recon result
- `GET /api/dns/wordlist` - Get built-in subdomain wordlist

#### Web Application Scanning
- `POST /api/webapp/scan` - Start web application scan (XSS, SQLi, headers, forms)
- `GET /api/webapp/scan/{scan_id}` - Get web app scan status/results

#### JIRA Integration
- `GET /api/integrations/jira/settings` - Get JIRA settings
- `POST /api/integrations/jira/settings` - Create/update JIRA settings
- `POST /api/integrations/jira/test` - Test JIRA connection
- `GET /api/integrations/jira/projects` - List JIRA projects
- `GET /api/integrations/jira/issue-types` - List JIRA issue types
- `POST /api/vulnerabilities/{id}/create-ticket` - Create JIRA ticket from vulnerability

#### SIEM Integration
- `GET /api/integrations/siem/settings` - Get all SIEM settings
- `POST /api/integrations/siem/settings` - Create SIEM settings (syslog, splunk, elasticsearch)
- `PUT /api/integrations/siem/settings/{id}` - Update SIEM settings
- `DELETE /api/integrations/siem/settings/{id}` - Delete SIEM settings
- `POST /api/integrations/siem/settings/{id}/test` - Test SIEM connection
- `POST /api/integrations/siem/export/{scan_id}` - Export scan to SIEM

#### API Keys
- `GET /api/api-keys` - List API keys
- `POST /api/api-keys` - Create API key
- `PATCH /api/api-keys/{id}` - Update API key
- `DELETE /api/api-keys/{id}` - Revoke API key

#### Dashboard Customization
- `GET /api/dashboard/widgets` - Get dashboard widget configuration
- `PUT /api/dashboard/widgets` - Update dashboard widget layout
- `GET /api/dashboard/data/{widget_type}` - Get widget data (recent_scans, vulnerability_summary, compliance_scores, scan_activity_chart, top_risky_hosts, critical_vulns, upcoming_scheduled_scans)

#### Admin (requires admin role)
- `GET /api/admin/users` - List all users
- `PUT /api/admin/users/{id}/roles` - Update user roles
- `DELETE /api/admin/users/{id}` - Delete user
- `GET /api/admin/audit-logs` - Get audit logs

#### Other
- `GET /api/privacy-policy` - Get privacy policy (public, no auth)
- `WS /api/ws/scans/{id}` - WebSocket for real-time scan progress (requires JWT query param)

### Data Flow

**CLI Scans:** `main.rs` → `scanner::run_scan()` → `output::display_results()`

**Web API Scans:** POST `/api/scans` → spawns async task → progress via broadcast channel to WebSocket → results stored in SQLite

### Scan Pipeline

1. Host Discovery → 2. Port Scanning → 3. Service Detection → 4. OS Fingerprinting → 5. Service Enumeration → 6. Vulnerability Scanning

Progress updates sent via `ScanProgressMessage` broadcast channel to WebSocket clients.

### CVE Lookup (Three-tier)

1. **Offline DB** (`cve::offline_db`) - Embedded common CVEs
2. **SQLite Cache** (`cve::cache`) - Cached NVD results (30-day TTL)
3. **NVD API** (`cve::nvd_client`) - Real-time queries on cache miss

### Compliance Frameworks

Supported frameworks in `compliance/frameworks/`:
- CIS Benchmarks
- NIST 800-53
- NIST CSF (Cybersecurity Framework)
- PCI-DSS
- HIPAA
- SOC 2
- FERPA
- OWASP Top 10

### Key Architectural Patterns

**Concurrency:** Tokio runtime, semaphore-limited concurrent port scanning, `tokio::sync::broadcast` for WebSocket updates

**Database:** Async SQLite via `sqlx::SqlitePool`, auto-migrations on startup

**Auth Flow:** Register/login → bcrypt hash → JWT token → `JwtMiddleware` validates Bearer tokens

**Error Handling:** Use `anyhow::Error` (not `Box<dyn std::error::Error>`) for `Send` compatibility in async spawned tasks

**Enumeration:** Service-specific modules with depth levels (Passive, Light, Aggressive). Uses native async drivers for databases, external tools (smbclient, enum4linux) for SMB

## Configuration

### Files

| File | Purpose |
|------|---------|
| `heroforge.toml` | Scan configuration (generated with `heroforge config`) |
| `/root/docker-compose.yml` | Container definition with Traefik SSL |
| `deploy.sh` | Automated deployment (frontend + backend + Docker) |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `JWT_SECRET` | **Required.** JWT signing key for authentication tokens |
| `DATABASE_URL` | SQLite path (default: `./heroforge.db`) |
| `DATABASE_ENCRYPTION_KEY` | SQLCipher encryption key (enables AES-256 database encryption) |
| `BCRYPT_COST` | Password hashing cost factor (default: 12) |
| `TOTP_ENCRYPTION_KEY` | Encryption key for MFA TOTP secrets |
| `ADMIN_USERNAME` | Username to auto-grant admin role on registration |
| `CORS_ALLOWED_ORIGINS` | Comma-separated list of allowed CORS origins |
| `REPORTS_DIR` | Directory for generated reports (default: `./reports`) |
| `SMTP_HOST` | SMTP server hostname |
| `SMTP_PORT` | SMTP server port |
| `SMTP_USER` | SMTP authentication username |
| `SMTP_PASSWORD` | SMTP authentication password |
| `SMTP_FROM_ADDRESS` | Email sender address |
| `SMTP_FROM_NAME` | Email sender display name |
| `BACKUP_GPG_PASSPHRASE` | GPG passphrase for encrypted database backups |

## Integrations

### Notification Channels

HeroForge supports multi-channel notifications for scan events:

**Slack Integration:**
- Configure via Settings > Notifications in web UI
- Provide Slack Incoming Webhook URL
- Events: Scan completed, Critical vulnerabilities found, Scheduled scan started/completed

**Microsoft Teams Integration:**
- Configure via Settings > Notifications in web UI
- Provide Teams Incoming Webhook URL
- Same event types as Slack

**Email Notifications:**
- Requires SMTP environment variables (see above)
- Sends formatted HTML emails for scan completion and critical findings

### JIRA Integration

Create JIRA tickets directly from discovered vulnerabilities:

1. Configure in Settings > JIRA:
   - JIRA URL (e.g., `https://yourcompany.atlassian.net`)
   - Username (email) and API token
   - Default project key and issue type
   - Optional default assignee

2. Features:
   - Auto-maps vulnerability severity to JIRA priority
   - Formats vulnerability details in ticket description
   - Links ticket back to vulnerability in HeroForge
   - Supports custom labels per ticket

### SIEM Integration

Export scan results and vulnerability findings to SIEM systems:

**Supported SIEM Types:**
| Type | Configuration |
|------|---------------|
| Syslog | Endpoint URL (host:port), Protocol (tcp/udp) |
| Splunk HEC | HEC endpoint URL, HEC token (required) |
| Elasticsearch | Elasticsearch URL, API key (optional) |

**Exported Events:**
- `scan_complete` - Scan finished with summary
- `vulnerability_found` - Each vulnerability with severity, CVE IDs, CVSS scores
- `host_discovered` - New hosts found

Configure via Settings > SIEM or API endpoints.

### Compliance Frameworks

Supported frameworks for compliance analysis:

| Framework | ID | Description |
|-----------|-----|-------------|
| PCI-DSS 4.0 | `pci_dss` | Payment Card Industry Data Security Standard |
| NIST 800-53 | `nist_800_53` | Security and Privacy Controls |
| NIST CSF | `nist_csf` | Cybersecurity Framework |
| CIS Benchmarks | `cis` | Center for Internet Security Benchmarks |
| HIPAA | `hipaa` | Health Insurance Portability and Accountability Act |
| SOC 2 | `soc2` | Service Organization Control 2 |
| FERPA | `ferpa` | Family Educational Rights and Privacy Act |
| OWASP Top 10 | `owasp_top10` | Web Application Security Risks |

Run compliance analysis via:
```bash
# API
POST /api/scans/{id}/compliance
{ "frameworks": ["pci_dss", "nist_800_53", "owasp_top10"] }

# Generate report
POST /api/scans/{id}/compliance/report
{ "frameworks": ["pci_dss"], "format": "pdf", "include_evidence": true }
```

## Rate Limiting

The API implements rate limiting per IP address:

| Endpoint Category | Limit | Window |
|-------------------|-------|--------|
| Auth endpoints (`/api/auth/*`) | 5 requests | per minute |
| Scan creation (`POST /api/scans`) | 10 requests | per hour |
| General API endpoints | 100 requests | per minute |

Rate limit responses return HTTP 429 with `Retry-After` header.

## Important Notes

**Security:** This is a penetration testing tool for **authorized security testing only**. Never remove security warnings.

**Error Types:** Use `anyhow::Error` (not `Box<dyn std::error::Error>`) in async spawned tasks for `Send` compatibility.

**Frontend:** Served from `frontend/dist`. Run `npm run build` after changes (deploy.sh handles this).

**Database:** Dev: `./heroforge.db` | Prod: `/root/Development/HeroForge/heroforge.db` (mounted in container)

**WebSocket Auth:** `/api/ws/scans/{id}` requires JWT as query parameter.

**Wordlists:** Built-in at `scanner/enumeration/wordlists.rs`, custom via `--enum-wordlist` flag.

## Troubleshooting

### Compilation Errors About `Send`
Replace `Box<dyn std::error::Error>` with `anyhow::Error`. Ensure shared state uses `Arc` or `web::Data`.

### Frontend Not Updating
```bash
cd frontend && npm run build                    # Rebuild
docker compose build heroforge && docker compose up -d heroforge  # Restart container
```
Also try clearing browser cache.

### Database Locked Errors
SQLite doesn't handle high concurrency well. Check pool size in `db::init_database()` (default: 5). Consider WAL mode: `PRAGMA journal_mode=WAL`.

### Container Won't Start
```bash
docker ps -a | grep heroforge
docker logs heroforge --tail 50
# Common: missing binary, port in use, missing frontend/dist
```

### SSL Certificate Issues
```bash
docker logs root-traefik-1 --tail 50 | grep -i cert
cd /root && docker compose restart traefik     # Force refresh
```

### Enumeration Not Working
Requires `--enum` flag and successful service detection. For SMB, ensure `smbclient` and `enum4linux` are installed. Use `-v` for debug logs.
