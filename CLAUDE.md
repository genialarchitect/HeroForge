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
│   ├── dns_recon.rs     # DNS reconnaissance
│   ├── comparison.rs    # Scan diff between results
│   ├── webapp/          # Web application scanning (XSS, SQLi, headers, forms)
│   └── enumeration/     # Service-specific enumeration (http, dns, smb, ftp, ssh, snmp)
├── cve/                 # CVE lookup: offline_db → cache → NVD API
├── vuln/                # Vulnerability scanning and misconfiguration detection
├── compliance/          # Security compliance frameworks
│   ├── frameworks/      # CIS, NIST 800-53, NIST CSF, PCI-DSS, HIPAA, SOC2, FERPA, OWASP
│   ├── controls/        # Control mappings and compliance checks
│   ├── manual_assessment/  # Rubrics for non-automated controls
│   └── analyzer.rs, scanner.rs, scoring.rs
├── agents/              # Distributed scanning agents and mesh networking
├── ai/                  # AI-powered vulnerability prioritization
├── plugins/             # Plugin marketplace and extensibility
├── siem/                # Full SIEM capabilities (log ingestion, correlation)
├── threat_intel/        # Threat intelligence feeds (CVE, exploit DB, Shodan)
├── vpn/                 # VPN integration (OpenVPN, WireGuard)
├── webhooks/            # Outbound webhook notifications
├── workflows/           # Custom remediation workflows
├── notifications/       # Multi-channel notifications (Slack, Teams, email)
├── integrations/        # External integrations (JIRA, ServiceNow, SIEM export)
├── email/               # SMTP notifications
├── reports/             # Report generation (JSON, HTML, PDF, CSV, Markdown)
├── output/              # CLI output formatting
├── db/                  # SQLite via sqlx (models, migrations, analytics, assets, crm)
└── web/                 # Actix-web server
    ├── auth/            # JWT auth (jwt.rs, middleware.rs)
    ├── api/             # REST endpoints
    │   └── portal/      # Customer portal API (separate auth)
    ├── websocket/       # Real-time scan progress
    ├── error.rs         # Unified API error types
    ├── rate_limit.rs    # Request rate limiting
    └── scheduler.rs     # Background job scheduler
```

### REST API

Full API documentation available via Swagger UI at `/api/docs` (requires running server).

**Key endpoint categories:**
- `/api/auth/*` - Authentication (register, login, logout, refresh, MFA)
- `/api/user/*` - User profile and settings
- `/api/portal/*` - Customer portal (separate auth system)
- `/api/scans/*` - Scan CRUD, results, export, compare
- `/api/reports/*` - Report generation
- `/api/assets/*` - Asset inventory
- `/api/vulnerabilities/*` - Vulnerability management and remediation
- `/api/compliance/*` - Compliance analysis and manual assessments
- `/api/container/*` - Container and Kubernetes security
- `/api/integrations/*` - JIRA, ServiceNow, SIEM integrations
- `/api/admin/*` - User management, audit logs (admin role required)
- `WS /api/ws/scans/{id}` - WebSocket for real-time scan progress

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
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD` | SMTP server configuration |
| `SMTP_FROM_ADDRESS`, `SMTP_FROM_NAME` | Email sender configuration |
| `BACKUP_GPG_PASSPHRASE` | GPG passphrase for encrypted database backups |

## Integrations

All integrations are configured via Settings page in the web UI or via `/api/integrations/*` endpoints.

| Integration | Purpose |
|-------------|---------|
| Slack/Teams | Real-time alerts for scan events and critical findings |
| JIRA | Create tickets from vulnerabilities with severity mapping |
| ServiceNow | Create incidents/change requests from vulnerabilities |
| SIEM (Splunk, Elasticsearch, Syslog) | Export scan results and findings |

### Compliance Frameworks

Supported: PCI-DSS 4.0, NIST 800-53, NIST CSF, CIS Benchmarks, HIPAA, SOC 2, FERPA, OWASP Top 10

## Rate Limiting

| Endpoint Category | Limit | Window |
|-------------------|-------|--------|
| Auth endpoints (`/api/auth/*`) | 5 requests | per minute |
| Scan creation (`POST /api/scans`) | 10 requests | per hour |
| General API endpoints | 100 requests | per minute |

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

### WebSocket Connection Fails
1. Check browser console for WebSocket errors
2. Verify JWT token is valid and not expired
3. Ensure middleware skips `/ws/` paths (check `src/web/auth/middleware.rs`)
4. Check Traefik logs: `docker logs root-traefik-1 | grep -i websocket`
