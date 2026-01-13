# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

HeroForge is a network reconnaissance and triage tool written in Rust, designed for authorized penetration testing. It provides both a CLI interface and a web dashboard with real-time scanning capabilities.

**Key Technologies:**
- **Backend:** Rust 1.70+ (edition 2021) with Tokio async runtime, Actix-web for HTTP server
- **Frontend:** React 18 + TypeScript + Vite + TailwindCSS (see `frontend/CLAUDE.md` for frontend-specific guidance)
- **State Management:** Zustand (global state) + React Query (server state)
- **Database:** SQLite with sqlx for async queries, optional SQLCipher encryption (AES-256)
- **Authentication:** JWT tokens with bcrypt password hashing, TOTP-based MFA, account lockout protection
- **Cloud SDKs:** AWS, Azure, GCP for cloud security scanning

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

# Linting (matches CI pipeline)
cargo fmt -- --check                  # Check formatting
cargo clippy --all-targets -- -D warnings  # Lint with warnings as errors

# Deploy to production
sudo ./deploy.sh                      # Full deploy (frontend + backend + Docker)

# Container operations
docker logs heroforge -f              # View logs
docker exec -it heroforge /bin/bash   # Shell access
docker restart heroforge              # Restart container

# Debug running container
docker exec heroforge sqlite3 /root/Development/HeroForge/heroforge.db ".schema"
docker exec heroforge curl -s http://localhost:8080/api/auth/me
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
cargo test --test '*'                 # Integration tests only
RUST_BACKTRACE=1 cargo test           # With stack traces on failure
```

**Note:** DB-dependent tests use `#[serial_test::serial]` macro. Run with `--test-threads=1` if encountering database lock issues.

### Frontend (React/TypeScript)

See `frontend/CLAUDE.md` for detailed frontend architecture. Key commands:

```bash
cd frontend
npm install                           # Install dependencies
npm run build                         # Production build
npm run build:check                   # TypeScript check + build
npm run dev                           # Development server (proxies /api to :8080)
npm run lint                          # ESLint with strict warnings
```

### Deployment

```bash
sudo ./deploy.sh                      # Automated: builds frontend + backend, deploys via Docker

# Manual steps (if needed)
cd frontend && npm install && npm run build
cargo build --release
cd /root && docker compose build heroforge && docker compose up -d heroforge
```

## CI/CD Pipeline

GitHub Actions workflow in `.github/workflows/ci-cd.yml`:

| Job | Trigger | Purpose |
|-----|---------|---------|
| `lint` | All pushes/PRs | `cargo fmt --check`, `cargo clippy -D warnings` |
| `security` | All pushes/PRs | `cargo audit`, `cargo deny`, Semgrep SAST, TruffleHog secrets |
| `unit-tests` | After lint | `cargo test --lib` |
| `integration-tests` | After unit | `cargo test --test '*' -- --test-threads=1` |
| `frontend` | All pushes/PRs | `npm run lint`, `npx tsc --noEmit`, `npm run build` |
| `coverage` | After integration | `cargo tarpaulin` with 50% threshold warning |
| `build-image` | After all tests | Build and push Docker image to ghcr.io |
| `deploy-staging` | develop branch | Auto-deploy to staging |
| `deploy-production` | `v*` tags | Auto-deploy with DB backup |

**Required CI Secrets:**
- `JWT_SECRET_TEST` - Test JWT signing key
- `STAGING_HOST`, `STAGING_USER`, `STAGING_SSH_KEY` - Staging server access
- `PRODUCTION_HOST`, `PRODUCTION_USER`, `PRODUCTION_SSH_KEY` - Production server access
- `SLACK_WEBHOOK_URL` - Deployment notifications
- `CODECOV_TOKEN` - Coverage reporting

## Database

```bash
# Auto-initialized on first run at ./heroforge.db
sqlite3 heroforge.db ".schema"
sqlite3 heroforge.db "SELECT id, name, status, created_at FROM scan_results;"
```

**Migrations:** Handled automatically at startup in `db::init_database()`. Schema updates are applied via inline SQL in the initialization code.

**Encryption:** Optional AES-256 encryption via SQLCipher. Set `DATABASE_ENCRYPTION_KEY` env var to enable. See `DATABASE_ENCRYPTION_MIGRATION.md` for migration instructions.

**Test Mode:** Set `TEST_MODE=true` and `DATABASE_URL=sqlite:./test_heroforge.db` for isolated test database.

## Architecture Overview

### Backend Module Organization (~86 modules)

```
src/
├── Core
│   ├── main.rs, config.rs, types.rs
│   ├── db/                  # SQLite via sqlx (models, migrations, analytics, assets, crm, permissions)
│   └── web/                 # Actix-web server (auth/, api/, websocket/, rate_limit.rs, scheduler.rs)
│
├── Scanning Engine
│   ├── scanner/             # 30+ submodules: host_discovery, port_scanner, syn_scanner, service_detection,
│   │                        # webapp/, enumeration/, cloud/, container/, ad_assessment/, nuclei/, etc.
│   ├── vuln/                # Vulnerability scanning and misconfiguration detection
│   └── cve/                 # CVE lookup: offline_db → cache → NVD API
│
├── Team Operations (Colored Teams)
│   ├── red_team/            # Offensive operations coordination
│   ├── blue_team/           # Defensive operations
│   ├── purple_team/         # Combined red/blue exercises
│   ├── green_team/          # SOC operations (SOAR playbooks, case management)
│   ├── orange_team/         # Security awareness training and phishing
│   ├── yellow_team/         # Secure development (SAST, SCA, SBOM)
│   └── white_team/          # GRC (governance, risk, compliance, audit)
│
├── Security Domains
│   ├── ai_security/         # AI/ML model security scanning
│   ├── iot/                 # IoT device security
│   ├── ot_ics/              # OT/ICS industrial control systems
│   ├── web3/                # Web3/blockchain security
│   ├── k8s_security/        # Kubernetes security
│   └── supply_chain/        # Supply chain security
│
├── Analysis & Intelligence
│   ├── binary_analysis/     # PE/ELF/Mach-O parsing, entropy
│   ├── malware_analysis/    # Malware sandbox and tools
│   ├── traffic_analysis/    # Network packet inspection
│   ├── forensics/           # Digital forensics
│   ├── threat_hunting/      # Threat hunting analytics
│   ├── threat_intel/        # Threat feeds (CVE, Shodan, MISP, STIX)
│   ├── cti_automation/      # CTI automation
│   └── intelligence_platform/  # Intelligence aggregation
│
├── Defense & Detection
│   ├── siem/                # Log ingestion, correlation, alerting
│   ├── detection_engineering/  # Detection rule creation
│   ├── incident_response/   # IR automation and playbooks
│   ├── honeypots/           # Deception technology
│   └── honeytokens/         # Canary tokens
│
├── AI/ML
│   ├── ai/                  # LLM orchestration (Claude, GPT), ML pipeline
│   ├── ml/                  # Machine learning models
│   └── predictive_security/ # Predictive analytics
│
├── Compliance & Risk
│   ├── compliance/          # CIS, NIST, PCI-DSS, HIPAA, SOC2, FERPA, OWASP
│   ├── compliance_automation/
│   └── patch_management/    # Patch management
│
├── Infrastructure
│   ├── agents/              # Distributed scanning agents and mesh networking
│   ├── plugins/             # Plugin marketplace
│   ├── vpn/                 # OpenVPN/WireGuard tunnels
│   ├── integrations/        # JIRA, ServiceNow, SIEM export, scanner import
│   ├── webhooks/            # Outbound notifications
│   └── workflows/           # Custom remediation workflows
│
└── Supporting
    ├── reports/             # JSON, HTML, PDF, CSV, Markdown generation
    ├── output/              # CLI formatting
    ├── email/, notifications/  # SMTP and multi-channel alerts
    ├── cache/, jobs/        # Caching and background processing
    ├── rbac/, credentials/  # Access control and credential management
    └── analytics_engine/, bi/  # Analytics and business intelligence
```

### REST API

Full API documentation available via Swagger UI at `/api/docs` (requires running server).

**Key endpoint categories:**
- `/api/auth/*` - Authentication (register, login, logout, refresh, MFA, SSO)
- `/api/user/*` - User profile and settings
- `/api/portal/*` - Customer portal (separate auth system)
- `/api/scans/*` - Scan CRUD, results, export, compare
- `/api/reports/*` - Report generation (JSON, HTML, PDF, CSV, Markdown)
- `/api/assets/*` - Asset inventory and management
- `/api/vulnerabilities/*` - Vulnerability management and remediation
- `/api/compliance/*` - Compliance analysis, frameworks, manual assessments, evidence
- `/api/container/*` - Container and Kubernetes security
- `/api/cloud/*` - Cloud security (AWS, Azure, GCP)
- `/api/integrations/*` - JIRA, ServiceNow, SIEM integrations, scanner imports
- `/api/webhooks/*` - Webhook management
- `/api/workflows/*` - Custom remediation workflows
- `/api/admin/*` - User management, audit logs (admin role required)
- `/api/agents/*` - Distributed scanning agent management
- `/api/plugins/*` - Plugin marketplace and management
- `/api/ai/*` - AI-powered vulnerability prioritization, LLM integration, ML models
- `/api/siem/*` - SIEM log ingestion and correlation
- `/api/threat-intel/*` - Threat intelligence feeds
- `/api/crm/*` - Customer relationship management
- `/api/green-team/*` - SOC operations (SOAR playbooks, case management)
- `/api/orange-team/*` - Security awareness training and phishing
- `/api/white-team/*` - GRC (governance, risk, compliance)
- `/api/yellow-team/*` - Secure development (SAST, SCA, SBOM)
- `WS /api/ws/scans/{id}` - WebSocket for real-time scan progress

**Health Endpoints:**
- `GET /health/live` - Liveness probe (container running)
- `GET /health/ready` - Readiness probe (dependencies connected)

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

### "Colored Teams" Architecture

HeroForge implements a comprehensive security operations framework organized by team colors:

**Red Team** (`scanner/` modules) - Offensive security testing:
- Network reconnaissance, vulnerability scanning, exploitation
- Web application testing, Active Directory assessment
- Cloud security scanning, container security

**Blue Team** (`siem/`, `detection_engineering/`, `incident_response/`) - Defensive operations:
- SIEM log ingestion and correlation
- Detection rule creation and testing
- Incident response automation

**Green Team** (`green_team/`) - SOC operations:
- SOAR playbooks and orchestration
- Case management
- Threat intelligence automation
- SOC metrics and analytics

**Yellow Team** (`yellow_team/`) - Secure development:
- SAST (Static Application Security Testing)
- SCA (Software Composition Analysis)
- SBOM (Software Bill of Materials)
- Architecture security review
- API security testing

**Orange Team** (`orange_team/`) - Security awareness:
- Phishing campaign management
- Training content and gamification
- Just-in-time training
- Compliance training tracking

**White Team** (`white_team/`) - Governance, Risk, and Compliance (GRC):
- Risk assessment and management
- Security controls framework
- Audit management
- Policy lifecycle management
- Third-party vendor risk management

**Purple Team** (`purple_team/`) - Combined red/blue team exercises and collaboration

### Key Architectural Patterns

**Concurrency:** Tokio runtime, semaphore-limited concurrent port scanning, `tokio::sync::broadcast` for WebSocket updates

**Database:** Async SQLite via `sqlx::SqlitePool`, auto-migrations on startup

**Auth Flow:** Register/login → bcrypt hash → JWT token → `JwtMiddleware` validates Bearer tokens. Customer portal uses separate `PortalAuthMiddleware` with its own JWT issuer.

**SSO Support:** SAML 2.0 and OAuth 2.0 / OpenID Connect via `web/auth/sso/`

**Error Handling:** Use `anyhow::Error` (not `Box<dyn std::error::Error>`) for `Send` compatibility in async spawned tasks

**Enumeration:** Service-specific modules with depth levels (Passive, Light, Aggressive). Uses native async drivers for databases, external tools (smbclient, enum4linux) for SMB

**Plugin System:** Extensible architecture via `plugins/` module for custom scanners and integrations

**Distributed Scanning:** Agent mesh networking in `agents/mesh/` for coordinated distributed scans

## Configuration

### Files

| File | Purpose |
|------|---------|
| `heroforge.toml` | Scan configuration (generated with `heroforge config`) |
| `/root/docker-compose.yml` | Container definition with Traefik SSL (note: not in this repo) |
| `deploy.sh` | Automated deployment (frontend + backend + Docker) |
| `docs/AI_QUICK_START.md` | Quick start guide for AI/ML features |

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
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | AWS credentials for cloud security scanning |
| `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID` | Azure credentials for cloud scanning |
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to GCP service account JSON for cloud scanning |
| `SAML_IDP_METADATA_URL` | SAML Identity Provider metadata URL for SSO |
| `OAUTH_CLIENT_ID`, `OAUTH_CLIENT_SECRET` | OAuth 2.0 credentials for SSO |
| `ANTHROPIC_API_KEY` | Anthropic Claude API key for AI chat and LLM-powered features |

## Integrations

All integrations are configured via Settings page in the web UI or via `/api/integrations/*` endpoints.

| Integration | Purpose |
|-------------|---------|
| Slack/Teams | Real-time alerts for scan events and critical findings |
| JIRA | Create tickets from vulnerabilities with severity mapping |
| ServiceNow | Create incidents/change requests from vulnerabilities |
| SIEM (Splunk, Elasticsearch, Syslog) | Export scan results and findings |

### Compliance Frameworks (45 Total)

**Original 12:** CIS Benchmarks, NIST 800-53, NIST CSF, PCI-DSS 4.0, HIPAA, FERPA, SOC 2, OWASP Top 10, HITRUST CSF, ISO 27001:2022, GDPR, DoD STIG

**US Federal (16):** FedRAMP, CMMC 2.0, FISMA, NIST 800-171, NIST 800-82, NIST 800-61, StateRAMP, ITAR, EAR, DFARS, ICD 503, CNSSI 1253, RMF, DISA Cloud SRG, DoD Zero Trust, NIST Privacy Framework

**Industry/Sector (8):** CSA CCM, NERC CIP, IEC 62443, TSA Pipeline Security, CISA CPGs, EO 14028, SOX IT Controls, GLBA

**International (9):** Cyber Essentials (UK), Australian ISM, IRAP, NIS2 Directive, ENS (Spain), BSI IT-Grundschutz, C5, SecNumCloud, NATO Cyber Defence

## Rate Limiting

Implemented via `actix-governor` in `src/web/rate_limit.rs`:

| Endpoint Category | Limit | Window |
|-------------------|-------|--------|
| Auth endpoints (`/api/auth/*`) | 5 requests | per minute |
| Scan creation (`POST /api/scans`) | 10 requests | per hour |
| General API endpoints | 100 requests | per minute |

## External Tool Dependencies

Some modules use external tools for specialized functionality. These are optional but enhance capabilities:

| Tool | Module | Purpose |
|------|--------|---------|
| `smbclient` | `scanner/enumeration/smb.rs` | SMB enumeration and file listing |
| `enum4linux` | `scanner/enumeration/smb.rs` | Windows/Samba enumeration |
| `nmap` | `scanner/nuclei/` | Nuclei template engine (optional) |
| `nuclei` | `scanner/nuclei/` | Advanced vulnerability scanning with templates |
| `hashcat` | `cracking/` | Password cracking (GPU-accelerated) |
| `john` | `cracking/` | John the Ripper password cracking |
| `sqlmap` | `scanner/webapp/` | Advanced SQL injection testing (optional) |
| `ffuf` | `scanner/webapp/` | Web fuzzing (optional) |
| `gobuster` | `scanner/enumeration/http.rs` | Directory/DNS bruteforcing (optional) |

**Note:** Most functionality works without these tools. They're invoked via Bash commands only when available and when the user opts into more aggressive scanning.

## Important Notes

**Security:** This is a penetration testing tool for **authorized security testing only**. Never remove security warnings.

**Error Types:** Use `anyhow::Error` (not `Box<dyn std::error::Error>`) in async spawned tasks for `Send` compatibility.

**Frontend:** Served from `frontend/dist`. Run `npm run build` after changes (deploy.sh handles this).

**Database:** Dev: `./heroforge.db` | Prod: `/root/Development/HeroForge/heroforge.db` (mounted in container)

**WebSocket Auth:** `/api/ws/scans/{id}` requires JWT as query parameter (`?token=...`). The JwtMiddleware skips `/ws/` paths; WebSocket handler performs its own token verification.

**Wordlists:** Built-in at `scanner/enumeration/wordlists.rs`, custom via `--enum-wordlist` flag.

**SQLCipher:** Database encryption via SQLCipher (bundled with `libsqlite3-sys` feature). Overrides sqlx's default SQLite. See `DATABASE_ENCRYPTION_MIGRATION.md` for migration guide.

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

## Additional Documentation

| Document | Location | Description |
|----------|----------|-------------|
| Launch Materials | `/root/HF_Phase1/` | Phase 1 launch docs, legal drafts, CI/CD templates |
| Feature Inventory | `/root/HeroForge_Features.md` | 83 modules, 160+ endpoints, 99 pages |
| Roadmaps | `FEATURE_ROADMAP_P1.md` through `P4.md` | Development priority planning |
| Launch Status | `/root/HF_Phase1/MARKET_READINESS_STATUS.md` | Current launch readiness and action items |
