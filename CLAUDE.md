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

# Container operations
docker logs heroforge -f              # View logs
docker exec -it heroforge /bin/bash   # Shell access
docker restart heroforge              # Restart container
```

**Container Configuration:** The production container runs with `CAP_NET_RAW` for raw socket operations (SYN scans), resource limits of 2 CPUs and 2GB memory, and mounts `/root/heroforge_data` for persistent storage.

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
cargo test -- --test-threads=1        # Sequential (for DB-dependent tests)
cargo test scanner::                  # Test specific module
cargo test scanner::comparison::tests::test_compare_scans  # Specific test
```

### Frontend (React/TypeScript)

```bash
cd frontend
npm install                           # Install dependencies
npm run build                         # Production build
npm run build:check                   # TypeScript check + build
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
├── db/                  # SQLite via sqlx (models.rs, migrations.rs, analytics.rs, assets.rs, crm.rs)
└── web/                 # Actix-web server
    ├── auth/            # JWT auth (jwt.rs, middleware.rs)
    ├── api/             # REST endpoints (see API section below)
    │   └── portal/      # Customer portal API (separate auth)
    ├── websocket/       # Real-time scan progress with aggregation
    ├── error.rs         # Unified API error types (ApiErrorKind, ResponseError impl)
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
| `/manual-assessments` | Manual compliance rubric assessments |
| `/manual-assessments/:id` | Assessment detail/edit view |
| `/remediation` | Vulnerability remediation workflow board |
| `/portal/login` | Customer portal login |
| `/portal/dashboard` | Customer portal dashboard |
| `/portal/engagements` | Customer engagement list |
| `/portal/vulnerabilities` | Customer vulnerability view |
| `/portal/reports` | Customer report downloads |

### REST API

Full API documentation available via Swagger UI at `/api/docs` (requires running server).

**Key endpoint categories:**
- `/api/auth/*` - Public auth endpoints (register, login, logout, refresh, MFA verify)
- `/api/user/*` - Protected user endpoints (me, profile, password, MFA management, GDPR)
- `/api/portal/*` - Customer portal (separate auth system for external customers)
- `/api/scans/*` - Scan CRUD, results, export, compare, bulk operations
- `/api/reports/*` - Report generation (JSON, HTML, PDF, CSV)
- `/api/templates/*` - Scan template management
- `/api/target-groups/*` - Target group management
- `/api/scheduled-scans/*` - Scheduled scan CRUD and history
- `/api/assets/*` - Asset inventory management
- `/api/vulnerabilities/*` - Vulnerability management and remediation workflow
- `/api/compliance/*` - Compliance framework analysis, reports, manual rubrics, assessments, campaigns
- `/api/dns/*` - DNS reconnaissance
- `/api/webapp/*` - Web application scanning
- `/api/integrations/jira/*` - JIRA ticket creation
- `/api/integrations/siem/*` - SIEM export (Splunk, Elasticsearch, Syslog)
- `/api/admin/*` - User management, audit logs (admin role required)
- `WS /api/ws/scans/{id}` - WebSocket for real-time scan progress (JWT as query param)

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

### Manual Compliance Assessments

For controls that cannot be digitally verified (physical security, policies, training), HeroForge provides a manual assessment rubric system in `src/compliance/manual_assessment/`:

- **Rubrics** - Assessment templates with criteria, rating scales, and evidence requirements
- **Assessments** - User-submitted evaluations with workflow (Draft → Pending Review → Approved/Rejected)
- **Evidence** - File uploads, links, screenshots, and notes attached to assessments
- **Campaigns** - Group multiple assessments for coordinated compliance efforts
- **Combined Reports** - Merge automated scan results with manual assessments

Default rubrics are seeded for 45+ non-automated controls across PCI-DSS, SOC2, HIPAA, and NIST 800-53.

### Key Architectural Patterns

**Concurrency:** Tokio runtime, semaphore-limited concurrent port scanning, `tokio::sync::broadcast` for WebSocket updates

**Database:** Async SQLite via `sqlx::SqlitePool`, auto-migrations on startup

**Auth Flow:** Register/login → bcrypt hash → JWT token → `JwtMiddleware` validates Bearer tokens. Customer portal uses separate `PortalAuthMiddleware` with its own JWT issuer.

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

**WebSocket Auth:** `/api/ws/scans/{id}` requires JWT as query parameter (`?token=...`). The JwtMiddleware skips `/ws/` paths; WebSocket handler performs its own token verification.

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

### WebSocket Connection Fails
If scans show "connection failed" or "failed to connect to web socket":
1. Check browser console for WebSocket errors
2. Verify JWT token is valid and not expired
3. Ensure middleware skips `/ws/` paths (check `src/web/auth/middleware.rs`)
4. Check Traefik logs for WebSocket upgrade issues: `docker logs root-traefik-1 | grep -i websocket`

## Feature Roadmap

Planned features organized by implementation complexity and priority.

### Tier 1: Quick Wins (1-2 days each)

Low complexity, high immediate value.

| Feature | Effort | Status | Description |
|---------|--------|--------|-------------|
| Asset Tagging & Groups | 1 day | Planned | Organize assets by environment, criticality, owner |
| Vulnerability Assignments | 1 day | Planned | Assign vulns to team members with due dates |
| ~~Audit Trail Enhancement~~ | 1 day | **Done** | Enhanced logging of all user actions |
| SSL/TLS Grading | 1-2 days | Planned | Detailed certificate health scores (like SSL Labs) |
| ~~Dark/Light Theme Toggle~~ | 1 day | **Done** | User-selectable UI theme |
| ~~Export Scan to Markdown~~ | 0.5 day | **Done** | Markdown format for scan reports |
| Bulk Vulnerability Actions | 1 day | Planned | Mass update/assign/close vulnerabilities |
| Scan Tags/Labels | 1 day | Planned | Categorize and filter scans |
| Duplicate Scan | 0.5 day | Planned | Clone existing scan configuration |
| Vulnerability Notes/Comments | 1 day | Planned | Add notes and discussion to findings |
| ~~Finding Templates~~ | 1 day | **Done** | Reusable vulnerability finding definitions |

### Tier 2: Medium Features (3-5 days each)

Moderate complexity, strong value proposition.

| Feature | Effort | Status | Description |
|---------|--------|--------|-------------|
| ~~Slack/Teams Notifications~~ | 2-3 days | **Done** | Real-time alerts for critical findings |
| Scan Comparison Dashboard | 3-4 days | Planned | Visual diff between scan runs (comparison.rs exists) |
| Automated Report Scheduling | 3 days | Planned | Schedule and email PDF reports |
| ~~SLA Tracking & Alerts~~ | 3-4 days | **Done** | Track remediation against defined SLAs |
| Custom Webhooks (outbound) | 2-3 days | Planned | Send events to external systems |
| Secret Detection Scanner | 4-5 days | Planned | Detect exposed API keys, passwords |
| Vulnerability Trends/Charts | 3 days | Planned | Historical vulnerability analytics |
| ServiceNow Integration | 4-5 days | Planned | Create incidents/changes from vulns |
| MFA Setup UI | 2-3 days | Planned | TOTP setup wizard (backend exists) |
| API Rate Limit Dashboard | 2 days | Planned | Visualize rate limiting stats |
| Scan Profiles/Presets | 2-3 days | Planned | Enhanced template management |
| Host/Port Exclusions | 2 days | Planned | Global and per-scan exclusion lists |
| ~~Methodology Tracking~~ | 3 days | **Done** | Pentest phases, checklists, progress tracking |
| ~~Time Tracking~~ | 2 days | **Done** | Track time spent on engagements |

### Tier 3: Major Features (1-2 weeks each)

High complexity, significant new capabilities.

| Feature | Effort | Status | Description |
|---------|--------|--------|-------------|
| ~~Credential Audit~~ | 1-2 weeks | **Done** | Password policy checking, breach detection |
| Container/K8s Scanning | 2 weeks | Planned | Docker and Kubernetes security |
| CI/CD Integration | 1 week | Planned | GitHub Actions, Jenkins plugins |
| Custom Remediation Workflows | 1-2 weeks | Planned | Configurable approval chains |
| Terraform/IaC Scanning | 2 weeks | Planned | Infrastructure-as-Code security |
| ~~Cloud Security Posture~~ | 2-3 weeks | **Done** | AWS/Azure/GCP configuration audit |
| Agent-Based Scanning | 2-3 weeks | Planned | Lightweight agents for internal networks |
| AI Vulnerability Prioritization | 1-2 weeks | Planned | ML-based risk scoring |
| ~~Multi-Tenancy / Customer Portal~~ | 2-3 weeks | **Done** | Isolated customer environments with portal |
| SAML/SSO Authentication | 1-2 weeks | Planned | Enterprise identity provider support |
| ~~Threat Intelligence~~ | 2 weeks | **Done** | CVE feeds, exploit DB, Shodan integration |
| ~~API Security Scanning~~ | 2 weeks | **Done** | Endpoint discovery, auth testing, injection |
| ~~Attack Path Analysis~~ | 2 weeks | **Done** | Graph-based attack path visualization |
| ~~Active Directory Assessment~~ | 2 weeks | **Done** | LDAP enumeration, Kerberoasting detection |
| ~~CRM System~~ | 2-3 weeks | **Done** | Customer management, engagements, contracts |
| ~~VPN Integration~~ | 1 week | **Done** | Route scans through OpenVPN/WireGuard |

### Tier 4: Platform Expansions (1+ months)

Strategic initiatives that transform the product.

| Feature | Effort | Status | Description |
|---------|--------|--------|-------------|
| Mobile App | 4-6 weeks | Planned | React Native companion app |
| Distributed Scanning Agents | 4-6 weeks | Planned | Mesh of scanning agents |
| Plugin Marketplace | 6-8 weeks | Planned | Extensible plugin architecture |
| Compliance Automation | 4-6 weeks | Planned | Full SOC2/ISO27001 evidence collection |
| Breach & Attack Simulation | 6-8 weeks | Planned | Safe exploit simulation framework |
| Full SIEM Capabilities | 8-12 weeks | Planned | Log ingestion and correlation engine |

### Implementation Notes

When implementing features:
1. **Tier 1 items** - Can be done independently, good for quick iterations
2. **Tier 2 items** - May have dependencies on existing modules
3. **Tier 3+ items** - Require planning phase, consider using `EnterPlanMode`

### Current Sprint

Track active work here:
- [ ] No items currently in progress

### Completed Features

| Feature | Tier | Completed |
|---------|------|-----------|
| Dark/Light Theme Toggle | 1 | 2025-12-20 |
| Audit Trail Enhancement | 1 | 2025-12-20 |
| Export Scan to Markdown | 1 | 2025-12-20 |
| Finding Templates | 1 | 2025-12-20 |
| Slack/Teams Notifications | 2 | 2025-12-20 |
| SLA Tracking & Alerts | 2 | 2025-12-20 |
| Methodology Tracking | 2 | 2025-12-20 |
| Time Tracking | 2 | 2025-12-20 |
| Credential Audit | 3 | 2025-12-20 |
| Cloud Security Posture (AWS/Azure/GCP) | 3 | 2025-12-20 |
| Multi-Tenancy / Customer Portal | 3 | 2025-12-20 |
| Threat Intelligence | 3 | 2025-12-20 |
| API Security Scanning | 3 | 2025-12-20 |
| Attack Path Analysis | 3 | 2025-12-20 |
| Active Directory Assessment | 3 | 2025-12-20 |
| CRM System | 3 | 2025-12-20 |
| VPN Integration | 3 | 2025-12-20 |
