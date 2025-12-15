# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

HeroForge is a network reconnaissance and triage tool written in Rust, designed for authorized penetration testing. It provides both a CLI interface and a web dashboard with real-time scanning capabilities.

**Key Technologies:**
- **Backend:** Rust with Tokio async runtime, Actix-web for HTTP server
- **Frontend:** React 18 + TypeScript + Vite + TailwindCSS
- **State Management:** Zustand (global state) + React Query (server state)
- **Database:** SQLite with sqlx for async queries
- **Authentication:** JWT tokens with bcrypt password hashing

**Deployment:**
- Production URL: https://heroforge.genialarchitect.io
- Reverse proxy: Traefik (via Docker) with automatic SSL/TLS (Let's Encrypt)
- Container management: Docker Compose

## Build and Development Commands

### Building the Project

```bash
# Build debug version
cargo build

# Build optimized release version
cargo build --release

# The binary will be at:
./target/release/heroforge
```

### Running the Application

```bash
# CLI scan command (TCP)
cargo run -- scan 192.168.1.0/24 --ports 1-1000

# Scan with verbose output
cargo run -- scan 192.168.1.0/24 -v

# Skip OS/service detection for faster scans
cargo run -- scan 192.168.1.0/24 --no-os-detect --no-service-detect

# Output to JSON file
cargo run -- scan 192.168.1.0/24 --output json -o results.json

# UDP scan (requires root/CAP_NET_RAW)
sudo ./target/release/heroforge scan 192.168.1.0/24 --scan-type udp

# UDP scan with specific ports
sudo ./target/release/heroforge scan 192.168.1.1 --scan-type udp --udp-ports 53,123,161

# Comprehensive scan (TCP + UDP)
sudo ./target/release/heroforge scan 192.168.1.0/24 --scan-type comprehensive

# Start web server (development)
cargo run -- serve --bind 127.0.0.1:8080

# Start web server (production - via Docker)
cd /root && docker compose up -d heroforge
```

### CLI Subcommands

```bash
# Full network triage scan (host discovery + port scan + service detection + vuln scan)
heroforge scan <TARGETS> [OPTIONS]

# Quick host discovery only (no port scanning)
heroforge discover <TARGETS> [-t threads] [-T timeout]

# Port scan only (no host discovery phase)
heroforge portscan <TARGETS> [-p ports] [-t threads] [-s scan-type]

# Generate default configuration file
heroforge config [PATH]
```

### Scan Types

Use `-s, --scan-type <TYPE>` to select:
- **tcp-connect** (default): Standard 3-way handshake, no special privileges required
- **tcp-syn**: Half-open SYN scanning, requires root/CAP_NET_RAW
- **udp**: Protocol-specific probes with ICMP detection, requires root
- **comprehensive**: Combined TCP + UDP scan, requires root

### Frontend Development

```bash
cd frontend

# Install dependencies (if needed)
npm install

# Build for production
npm run build

# Development server (hot reload)
npm run dev

# Lint TypeScript/React code
npm run lint
```

### Testing

```bash
# Run all Rust tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Test specific module
cargo test scanner::

# Test specific function
cargo test scanner::comparison::tests::test_compare_scans

# Run type checking only (faster than full build)
cargo check
```

### Common Development Workflow

```bash
# Typical edit-test-deploy cycle
cargo check                        # Fast type check (catches most errors)
cargo test scanner::               # Run relevant module tests
cargo build --release              # Build optimized binary
sudo ./deploy.sh                   # Deploy to production

# Frontend changes
cd frontend && npm run build       # Rebuild frontend
cd /root && docker compose restart heroforge  # Restart to pick up changes
```

### Database Management

```bash
# Database is automatically initialized on first run
# Location: /root/Development/HeroForge/heroforge.db

# View database schema
sqlite3 heroforge.db ".schema"

# Query users
sqlite3 heroforge.db "SELECT * FROM users;"

# Query scans
sqlite3 heroforge.db "SELECT id, name, status, created_at FROM scan_results;"
```

### Deployment

```bash
# Build and deploy (uses deploy.sh script)
sudo ./deploy.sh

# Or manually:
cd /root/Development/HeroForge/frontend && npm install && npm run build
cd /root/Development/HeroForge && ~/.cargo/bin/cargo build --release
cd /root && docker compose build heroforge && docker compose up -d heroforge

# Restart container after code changes
cd /root && docker compose restart heroforge

# View logs
docker logs heroforge -f

# Check container status
docker ps | grep heroforge
```

## Architecture Overview

### Module Organization

```
src/
├── main.rs              # CLI argument parsing and entry point
├── config.rs            # Configuration file handling (TOML)
├── types.rs             # Core data structures (HostInfo, PortInfo, ScanConfig, etc.)
├── scanner/             # Network scanning engine
│   ├── mod.rs           # Main scan orchestration
│   ├── host_discovery.rs    # TCP-based host discovery
│   ├── port_scanner.rs      # Concurrent port scanning (dispatches TCP/UDP)
│   ├── syn_scanner.rs       # TCP SYN (half-open) scanner (requires root/CAP_NET_RAW)
│   ├── service_detection.rs # Banner grabbing and service fingerprinting
│   ├── os_fingerprint.rs    # OS detection based on port patterns
│   ├── udp_scanner.rs       # UDP port scanning with ICMP detection (requires root)
│   ├── udp_probes.rs        # Protocol-specific UDP probes (DNS, SNMP, NTP, etc.)
│   ├── udp_service_detection.rs  # UDP response parsing for service identification
│   ├── comparison.rs        # Scan diff/comparison between two scan results
│   └── enumeration/     # Service-specific enumeration
│       ├── mod.rs       # Enumeration orchestration
│       ├── types.rs     # Enumeration data structures
│       ├── wordlists.rs # Built-in and custom wordlist handling
│       ├── http_enum.rs # HTTP/HTTPS enumeration (dirs, files, headers)
│       ├── dns_enum.rs  # DNS enumeration (zone transfers, subdomains)
│       ├── db_enum.rs   # Database enumeration (MySQL, PostgreSQL, MongoDB, Redis)
│       ├── smb_enum.rs  # SMB enumeration (shares, users via external tools)
│       ├── ftp_enum.rs  # FTP enumeration (anonymous access, directory listing)
│       ├── ssh_enum.rs  # SSH enumeration (algorithms, auth methods)
│       ├── smtp_enum.rs # SMTP enumeration (VRFY, EXPN user enum)
│       ├── ldap_enum.rs # LDAP enumeration (anonymous bind, base DN)
│       ├── ssl_enum.rs  # SSL/TLS enumeration (ciphers, certificate info)
│       ├── rdp_enum.rs  # RDP enumeration (NLA, encryption, BlueKeep detection)
│       ├── vnc_enum.rs  # VNC enumeration (RFB version, security types)
│       ├── telnet_enum.rs # Telnet enumeration (banner, device fingerprinting)
│       └── snmp_enum.rs # SNMP enumeration (community strings, MIB-II, interfaces)
├── cve/                 # CVE database integration
│   ├── mod.rs           # CVE scanner orchestration (offline + NVD API + cache)
│   ├── offline_db.rs    # Embedded CVE database for common vulnerabilities
│   ├── nvd_client.rs    # NVD API client for real-time CVE lookups
│   └── cache.rs         # SQLite-based CVE cache layer
├── vuln/                # Vulnerability scanning
│   ├── mod.rs
│   └── scanner.rs       # CVE matching and misconfiguration detection
├── email/               # Email notification system
│   └── mod.rs           # SMTP-based email service (scan completion, critical vulns)
├── reports/             # Report generation system
│   ├── mod.rs           # Report generator service
│   ├── types.rs         # Report data structures (ReportData, ReportSummary, etc.)
│   ├── formats/         # Output format implementations
│   │   ├── json.rs      # JSON report export
│   │   ├── html.rs      # HTML report with styling
│   │   └── pdf.rs       # PDF report generation
│   ├── risk_scoring.rs  # CVSS-based risk calculations
│   ├── remediation.rs   # Auto-generated remediation recommendations
│   └── storage.rs       # Report file storage management
├── output/              # Output formatting
│   ├── mod.rs
│   ├── terminal_output.rs   # Colorized terminal output
│   ├── json_output.rs       # JSON export
│   └── csv_output.rs        # CSV export
├── db/                  # Database layer
│   ├── mod.rs           # Database initialization and queries
│   ├── models.rs        # SQLx model types (see Database Models below)
│   └── migrations.rs    # Schema migrations for all tables
└── web/                 # Web server and API
    ├── mod.rs           # Server setup and routing
    ├── broadcast.rs     # Broadcast channel for scan progress
    ├── auth/            # JWT authentication
    │   ├── jwt.rs       # Token generation/validation
    │   └── middleware.rs # Auth middleware for protected routes
    ├── api/             # REST API endpoints
    │   ├── auth.rs      # /api/auth/* endpoints
    │   ├── scans.rs     # /api/scans/* endpoints
    │   ├── admin.rs     # /api/admin/* endpoints (user/role management)
    │   ├── reports.rs   # /api/reports/* endpoints (report generation/download)
    │   ├── compare.rs   # /api/scans/compare endpoint (scan diff)
    │   ├── templates.rs # /api/templates/* endpoints (scan templates)
    │   ├── target_groups.rs # /api/target-groups/* endpoints
    │   ├── scheduled_scans.rs # /api/scheduled-scans/* endpoints
    │   └── notifications.rs # /api/notifications/* endpoints
    ├── websocket/       # Real-time scan progress
    │   └── mod.rs       # WebSocket handler for scan updates
    └── scheduler.rs     # Background job scheduler for scheduled scans
```

### Frontend Source Structure

```
frontend/src/
├── App.tsx              # Main app with React Router routing
├── main.tsx             # React entry point
├── components/          # Reusable UI components (forms, tables, modals, etc.)
├── pages/               # Page-level components (Login, Dashboard, Settings, Admin)
├── services/            # API client functions (axios-based, organized by resource)
├── store/               # Zustand global state (auth, scans, UI state)
├── hooks/               # Custom React hooks (useAuth, useScans, etc.)
├── types/               # TypeScript type definitions mirroring backend types
├── utils/               # Utility functions (formatters, validators)
└── styles/              # Global CSS and Tailwind configuration
```

### Frontend Routes

```
/ ........................ Login page
/dashboard ............... Main dashboard with scan list, new scan form
/dashboard/:scanId ....... Scan details view with results, progress, reports
/admin ................... Admin panel (requires admin role)
/settings ................ User settings with tabs:
                           - Target Groups: Organize scan targets
                           - Scheduled Scans: Recurring scan automation
                           - Scan Templates: Reusable scan configurations
                           - Notifications: Email preferences
                           - Profile: User account settings
                           - Administration: System settings (admin only)
```

### REST API Endpoints

```
Authentication:
  POST   /api/auth/register     Create new user account
  POST   /api/auth/login        Authenticate and get JWT token
  GET    /api/auth/me           Get current user info

Scans:
  GET    /api/scans             List all scans
  POST   /api/scans             Create and start new scan
  GET    /api/scans/{id}        Get scan details and results
  DELETE /api/scans/{id}        Delete a scan
  POST   /api/scans/compare     Compare two scans (body: scan_id_1, scan_id_2)

Reports:
  GET    /api/reports           List all reports
  POST   /api/reports           Generate new report
  GET    /api/reports/{id}      Get report metadata
  GET    /api/reports/{id}/download  Download report file

Templates:
  GET    /api/templates         List scan templates
  POST   /api/templates         Create template
  GET    /api/templates/{id}    Get template
  PUT    /api/templates/{id}    Update template
  DELETE /api/templates/{id}    Delete template
  POST   /api/templates/{id}/scan  Create scan from template

Target Groups:
  GET    /api/target-groups     List target groups
  POST   /api/target-groups     Create target group
  PUT    /api/target-groups/{id}    Update target group
  DELETE /api/target-groups/{id}    Delete target group

Scheduled Scans:
  GET    /api/scheduled-scans   List scheduled scans
  POST   /api/scheduled-scans   Create scheduled scan
  PUT    /api/scheduled-scans/{id}    Update scheduled scan
  DELETE /api/scheduled-scans/{id}    Delete scheduled scan

Notifications:
  GET    /api/notifications/settings  Get notification preferences
  PUT    /api/notifications/settings  Update notification preferences

Admin (requires admin role):
  GET    /api/admin/users       List all users
  PUT    /api/admin/users/{id}/roles  Update user roles
  DELETE /api/admin/users/{id}  Delete user
  GET    /api/admin/audit-logs  Get audit trail

WebSocket:
  WS     /api/ws/scans/{id}     Real-time scan progress (requires JWT)
```

### Database Models

Key models in `db/models.rs`:
- **User, Role, UserRole**: User accounts and RBAC
- **ScanResult**: Scan records with status, results JSON, timestamps
- **Report**: Generated reports with format, sections, file paths
- **ScanTemplate**: Reusable scan configurations
- **TargetGroup**: Named groups of scan targets with color coding
- **ScheduledScan**: Recurring scan schedules (daily, weekly, monthly)
- **NotificationSettings**: Per-user email notification preferences
- **AuditLog**: Admin action audit trail

### Data Flow for Scans

1. **CLI Scans:** `main.rs` → `scanner::run_scan()` → `output::display_results()`
2. **Web API Scans:**
   - Client POSTs to `/api/scans` → `api::scans::create_scan()`
   - Spawns async task with `scanner::run_scan(progress_tx)`
   - Progress messages sent via broadcast channel to WebSocket clients
   - Results stored in SQLite when complete

### Scan Pipeline Architecture

The scanner follows a multi-phase pipeline:

1. **Host Discovery** (`scanner::host_discovery`): Identifies live hosts using TCP connect probes
2. **Port Scanning** (`scanner::port_scanner`): Concurrent port scanning on discovered hosts
3. **Service Detection** (`scanner::service_detection`): Banner grabbing and service identification
4. **OS Fingerprinting** (`scanner::os_fingerprint`): Passive OS detection based on port patterns
5. **Service Enumeration** (`scanner::enumeration`): Deep service-specific probing (HTTP dirs, DNS zones, DB users, SMB shares)
6. **Vulnerability Scanning** (`vuln::scanner`): CVE matching and misconfiguration detection

Each phase sends progress updates via `ScanProgressMessage` broadcast channel to WebSocket clients.

### CVE Lookup Pipeline

The `cve` module implements a three-tier lookup strategy:

1. **Offline Database** (`cve::offline_db`): Embedded database of common CVEs for fast, offline lookup
2. **SQLite Cache** (`cve::cache`): Caches NVD API results with configurable TTL (default 30 days)
3. **NVD API** (`cve::nvd_client`): Real-time queries to NIST NVD when cache misses occur

Service names are normalized (e.g., "SSH" → "openssh") before lookup. The scanner also checks for service exposure vulnerabilities (Redis, MongoDB, etc. exposed to network).

### Scan Comparison System

The `scanner/comparison.rs` module provides diff functionality between scan results:
- Detects new/removed hosts
- Tracks port state changes (new open, newly closed)
- Identifies service version changes
- Compares vulnerability findings (new vs resolved)
- Accessible via POST `/api/scans/compare` with `scan_id_1` and `scan_id_2`

### Email Notification System

The `email` module provides SMTP-based notifications:
- Scan completion summaries with host/port/vuln counts
- Critical vulnerability alerts with finding details
- HTML + plaintext multipart emails
- Configuration via environment variables: `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM_ADDRESS`, `SMTP_FROM_NAME`

### Scan Templates and Target Groups

**Templates** (`web/api/templates.rs`): Save scan configurations for reuse
- Stores port ranges, scan type, enumeration settings
- Create scans from templates via POST `/api/templates/{id}/scan`

**Target Groups** (`web/api/target_groups.rs`): Organize scan targets
- Named collections of IP addresses/ranges/hostnames
- Color-coded for UI organization
- CRUD via `/api/target-groups`

**Scheduled Scans** (`web/api/scheduled_scans.rs`): Recurring scan automation
- Schedule types: daily, weekly, monthly
- Automatic next-run calculation
- CRUD via `/api/scheduled-scans`
- Background scheduler daemon in `web/scheduler.rs` (basic implementation exists, may need enhancement for production use)

**Notification Settings** (`web/api/notifications.rs`): Email preferences
- GET/PUT `/api/notifications/settings`
- Controls: email on scan complete, email on critical vulnerabilities
- Integrates with `email` module for SMTP delivery

### Report Generation System

Reports are generated via `reports::ReportGenerator`:

1. Fetch scan results from SQLite database
2. Calculate risk scores using CVSS-based methodology (`reports::risk_scoring`)
3. Generate remediation recommendations (`reports::remediation`)
4. Export to requested format (JSON, HTML, or PDF)
5. Store report file and update database with file path/size

### Key Architectural Patterns

**Concurrency Model:**
- Uses Tokio runtime with configurable thread pools
- Port scanning uses semaphore-limited concurrent tasks
- WebSocket broadcasts use `tokio::sync::broadcast` channels

**Database Access:**
- All DB functions are async and use `sqlx::SqlitePool`
- Database schema auto-migrates on startup in `db::run_migrations()`
- Connection pool configured in `db::init_database()`

**Authentication Flow:**
1. User registers/logs in via `/api/auth/register` or `/api/auth/login`
2. Password hashed with bcrypt, JWT token returned
3. Protected routes use `JwtMiddleware` to validate Bearer tokens
4. User ID extracted from token claims for database queries

**Error Handling:**
- Most functions return `Result<T, anyhow::Error>`
- Database functions use `anyhow::Error` for `Send` compatibility in async contexts
- Never use `Box<dyn std::error::Error>` in async spawned tasks (not `Send`)

**Enumeration System:**
- Service-specific enumeration modules in `scanner/enumeration/`
- Configurable depth levels: Passive, Light, Aggressive
- Custom or built-in wordlists for HTTP/DNS enumeration
- Database enumeration uses native async drivers (mysql_async, mongodb, redis)
- SMB enumeration uses external tools (smbclient, enum4linux) via tokio::process
- SNMP enumeration tests community strings and extracts MIB-II data (system info, interfaces, routing)

## Configuration Files

**heroforge.toml** (generated with `heroforge config`):
- Stores scan configuration for repeatable scans
- Includes targets, port ranges, scan type, feature flags
- Alternative to passing CLI flags

**docker-compose.yml** (in /root):
- Defines HeroForge container alongside other services (n8n, MinIO)
- Uses Traefik for automatic SSL/TLS via Let's Encrypt
- Container mounts source code for serving frontend

**deploy.sh**:
- Automated deployment script
- Builds frontend (npm), backend (cargo), and Docker container
- Restarts HeroForge container with new build

## Environment Variables

**Email/SMTP (optional - for notifications):**
- `SMTP_HOST` - SMTP server hostname
- `SMTP_PORT` - SMTP server port (typically 587 for TLS)
- `SMTP_USER` - SMTP authentication username
- `SMTP_PASSWORD` - SMTP authentication password
- `SMTP_FROM_ADDRESS` - Sender email address
- `SMTP_FROM_NAME` - Sender display name

**Authentication:**
- `JWT_SECRET` - Secret key for JWT token signing (auto-generated if not set)

**Database:**
- `DATABASE_URL` - SQLite database path (default: `./heroforge.db`)

## Important Notes

### Security and Authorization
This is a penetration testing tool designed for **authorized security testing only**. All code must include appropriate warnings about authorization requirements. Never remove or weaken security warnings.

### Error Type Compatibility
When spawning async tasks (e.g., in `tokio::spawn`), all error types must implement `Send`. Use `anyhow::Error` instead of `Box<dyn std::error::Error>` in database and other async functions to ensure `Send` compatibility.

### Frontend Build
The web server serves static files from `frontend/dist`. After making frontend changes, you must run `npm run build` before the changes are visible in production. The deployment script handles this automatically.

### Database Location
- Development: `./heroforge.db` (relative to project root)
- Production: `/root/Development/HeroForge/heroforge.db` (mounted into Docker container)

### Port Binding
- CLI mode: Can bind to any address (default `0.0.0.0:8080`)
- Production: Binds to `0.0.0.0:8080` inside container (Traefik reverse proxy handles external access)

### WebSocket Authentication
WebSocket connections to `/api/ws/scans/{id}` require JWT authentication. The token should be passed as a query parameter or in the handshake headers.

### Wordlists for Enumeration
- Built-in wordlists embedded in `scanner/enumeration/wordlists.rs`
- Custom wordlists via `--enum-wordlist` flag
- Located in `wordlists/` directory for external lists

## Troubleshooting

### Compilation Errors About `Send`
If you see errors like "future cannot be sent between threads safely":
- Check that all error types in spawned tasks are `Send`
- Replace `Box<dyn std::error::Error>` with `anyhow::Error`
- Ensure database pool and other shared state use `Arc` or `web::Data`

### Frontend Not Updating
- Check that `npm run build` was run after changes
- Verify `frontend/dist` directory exists and contains built files
- Clear browser cache or use incognito mode
- Rebuild Docker container: `docker compose build heroforge && docker compose up -d heroforge`

### Database Locked Errors
- SQLite doesn't handle high concurrency well
- Check connection pool size in `db::init_database()` (default: 5)
- Ensure long-running transactions are avoided
- Consider using write-ahead logging: `PRAGMA journal_mode=WAL`

### Container Won't Start
```bash
# Check container status and logs
docker ps -a | grep heroforge
docker logs heroforge --tail 50

# Common issues:
# - Binary not found (rebuild: cargo build --release)
# - Port already in use (check: sudo lsof -i :8080)
# - Database permissions (check: ls -la heroforge.db)
# - Missing frontend/dist (run: cd frontend && npm run build)
# - Container crash loop (check: docker logs heroforge)
```

### SSL Certificate Issues
```bash
# SSL is managed automatically by Traefik via Let's Encrypt
# Check Traefik logs for certificate issues
docker logs root-traefik-1 --tail 50 | grep -i cert

# View certificate store
docker exec root-traefik-1 cat /letsencrypt/acme.json | jq '.Certificates'

# Force certificate refresh (restart Traefik)
cd /root && docker compose restart traefik
```

### Enumeration Not Working
- Check that `--enum` flag is passed to enable enumeration
- Verify service was detected (enumeration requires service detection)
- For SMB: ensure `smbclient` and `enum4linux` are installed
- Check wordlist paths for custom wordlists
- Increase verbosity with `-v` to see enumeration debug logs
