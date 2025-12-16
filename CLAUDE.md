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
│   ├── comparison.rs    # Scan diff between results
│   └── enumeration/     # Service-specific enumeration (http, dns, smb, ftp, ssh, etc.)
├── cve/                 # CVE lookup: offline_db → cache → NVD API
├── vuln/                # Vulnerability scanning and misconfiguration detection
├── compliance/          # Security compliance checks (CIS, NIST, GDPR)
├── email/               # SMTP notifications (scan complete, critical vulns)
├── reports/             # Report generation (JSON, HTML, PDF, CSV) with risk scoring
├── output/              # CLI output formatting (terminal, json, csv)
├── db/                  # SQLite via sqlx (models.rs, migrations.rs, analytics.rs)
└── web/                 # Actix-web server
    ├── auth/            # JWT auth (jwt.rs, middleware.rs)
    ├── api/             # REST endpoints (auth, scans, admin, reports, templates, mfa, analytics, etc.)
    ├── websocket/       # Real-time scan progress with aggregation
    ├── rate_limit.rs    # Request rate limiting
    └── scheduler.rs     # Background job scheduler
```

### Frontend Structure

```
frontend/src/
├── App.tsx, main.tsx    # Entry point and routing
├── components/          # Reusable UI (forms, tables, modals)
├── pages/               # Login, Dashboard, Settings, Admin
├── services/            # Axios API clients
├── store/               # Zustand global state
├── hooks/, types/, utils/
```

### Frontend Routes

| Route | Description |
|-------|-------------|
| `/` | Login page |
| `/dashboard` | Scan list and new scan form |
| `/dashboard/:scanId` | Scan details with results/progress |
| `/admin` | Admin panel (requires admin role) |
| `/settings` | Target Groups, Scheduled Scans, Templates, Notifications, Profile |

### REST API Endpoints

**Authentication:** `POST /api/auth/register`, `POST /api/auth/login`, `GET /api/auth/me`

**MFA:** `POST /api/mfa/setup`, `POST /api/mfa/verify`, `POST /api/mfa/disable`

**Scans:** `GET|POST /api/scans`, `GET|DELETE /api/scans/{id}`, `POST /api/scans/compare`

**Reports:** `GET|POST /api/reports`, `GET /api/reports/{id}`, `GET /api/reports/{id}/download`

**Templates:** CRUD at `/api/templates`, `POST /api/templates/{id}/scan` to create scan from template

**Target Groups:** CRUD at `/api/target-groups`

**Scheduled Scans:** CRUD at `/api/scheduled-scans`

**Notifications:** `GET|PUT /api/notifications/settings`

**Analytics:** `GET /api/analytics/dashboard`, `GET /api/analytics/trends`

**Admin:** `GET /api/admin/users`, `PUT /api/admin/users/{id}/roles`, `DELETE /api/admin/users/{id}`, `GET /api/admin/audit-logs`

**WebSocket:** `WS /api/ws/scans/{id}` (requires JWT query param)

### Database Models (`db/models.rs`)

User, Role, UserRole (RBAC) | ScanResult | Report | ScanTemplate | TargetGroup | ScheduledScan | NotificationSettings | AuditLog

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
| `JWT_SECRET` | JWT signing key (auto-generated if not set) |
| `DATABASE_URL` | SQLite path (default: `./heroforge.db`) |
| `DATABASE_ENCRYPTION_KEY` | **SQLCipher encryption key** (enables AES-256 database encryption) |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD` | Email notifications |
| `SMTP_FROM_ADDRESS`, `SMTP_FROM_NAME` | Email sender info |
| `BACKUP_GPG_PASSPHRASE` | GPG passphrase for encrypted database backups |

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
