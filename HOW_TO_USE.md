# HeroForge How-To Manual
## Network Triage and Reconnaissance Tool

**Version:** 0.1.0
**Platform:** Linux, macOS, Windows
**Web Dashboard:** https://heroforge.genialarchitect.io

---

## Table of Contents

1. [Overview](#overview)
2. [Getting Started](#getting-started)
3. [CLI Usage](#cli-usage)
4. [Web Dashboard](#web-dashboard)
5. [Scan Types](#scan-types)
6. [Features](#features)
7. [Configuration](#configuration)
8. [Output Formats](#output-formats)
9. [Advanced Usage](#advanced-usage)
10. [Troubleshooting](#troubleshooting)

---

## Overview

HeroForge is a comprehensive network triage and reconnaissance tool designed for penetration testing. It automates the initial phases of network assessment including:

- **Host Discovery** - Find live hosts on a network
- **Port Scanning** - Identify open ports and services
- **Service Detection** - Fingerprint running services
- **OS Fingerprinting** - Detect operating systems
- **Vulnerability Scanning** - Identify potential security issues

### Deployment Options

HeroForge can be used in two ways:

1. **Command-Line Interface (CLI)** - Direct terminal usage
2. **Web Dashboard** - Browser-based interface with real-time updates

---

## Getting Started

### Installation

**From Binary:**
```bash
# Download the binary (already installed at)
/root/Development/HeroForge/target/release/heroforge

# Make executable
chmod +x heroforge

# Move to PATH (optional)
sudo mv heroforge /usr/local/bin/
```

**From Source:**
```bash
cd /root/Development/HeroForge
cargo build --release
```

### First Run

```bash
# Check version
heroforge --version

# View help
heroforge --help
```

### Web Dashboard Access

Visit: **https://heroforge.genialarchitect.io**

**Admin Account Setup:**
Create your admin account on first launch. Set a strong password following these requirements:
- Minimum 12 characters
- Mix of uppercase, lowercase, numbers, and symbols
- Store securely in a password manager

---

## CLI Usage

### Basic Command Structure

```bash
heroforge <COMMAND> [OPTIONS]
```

### Available Commands

| Command | Description |
|---------|-------------|
| `scan` | Perform full network triage scan |
| `discover` | Discover live hosts only |
| `portscan` | Scan ports on specific hosts |
| `config` | Generate default configuration file |
| `serve` | Start web server with dashboard |

---

## Command Examples

### 1. Full Network Scan

Perform a comprehensive scan with all features:

```bash
heroforge scan 192.168.1.0/24
```

**With custom options:**
```bash
heroforge scan 192.168.1.0/24 \
  --ports 1-65535 \
  --threads 200 \
  --timeout 5000 \
  --output json \
  --output-file scan_results.json \
  --vuln-scan
```

**Parameters:**
- `targets` (required) - IP addresses or CIDR ranges
- `--ports` / `-p` - Port range (default: 1-1000)
- `--threads` / `-t` - Concurrent threads (default: 100)
- `--timeout` / `-T` - Timeout in ms (default: 3000)
- `--scan-type` / `-s` - Scan type (tcp-connect, tcp-syn, udp, comprehensive)
- `--output` / `-o` - Output format (json, csv, terminal, all)
- `--output-file` - Save results to file
- `--no-os-detect` - Skip OS detection
- `--no-service-detect` - Skip service detection
- `--vuln-scan` - Enable vulnerability scanning
- `--verbose` / `-v` - Enable verbose logging

### 2. Host Discovery

Find live hosts on a network:

```bash
heroforge discover 192.168.1.0/24
```

**Multiple networks:**
```bash
heroforge discover 192.168.1.0/24 10.0.0.0/16 172.16.0.0/12
```

**With custom timeout:**
```bash
heroforge discover 192.168.1.0/24 --timeout 1000 --threads 500
```

### 3. Port Scanning

Scan specific hosts for open ports:

```bash
# Single host
heroforge portscan 192.168.1.100 --ports 1-65535

# Multiple hosts
heroforge portscan 192.168.1.100 192.168.1.101 192.168.1.102

# Full TCP scan
heroforge portscan 192.168.1.100 --ports 1-65535 --scan-type tcp-connect

# Fast scan (common ports)
heroforge portscan 192.168.1.100 --ports 1-1000 --threads 500
```

### 4. Generate Configuration File

Create a configuration file for repeated scans:

```bash
heroforge config

# Custom path
heroforge config my_scan_config.toml
```

**Edit the generated file:**
```toml
[scan]
targets = ["192.168.1.0/24", "10.0.0.0/24"]
port_range = [1, 65535]
threads = 200
timeout_ms = 3000
scan_type = "Comprehensive"

[features]
enable_os_detection = true
enable_service_detection = true
enable_vuln_scan = true

[output]
format = "Json"
output_file = "scan_results.json"
```

### 5. Start Web Server

Run the web dashboard locally:

```bash
# Default (binds to 0.0.0.0:8080)
heroforge serve

# Custom bind address and database
heroforge serve --bind 127.0.0.1:3000 --database sqlite:///path/to/heroforge.db

# With verbose logging
heroforge serve --verbose
```

---

## Web Dashboard

### Accessing the Dashboard

**Production URL:** https://heroforge.genialarchitect.io

**Local Development:**
```bash
heroforge serve
# Visit http://localhost:8080
```

### User Management

#### Register a New User

1. Visit the registration page
2. Enter username, email, and password
3. Click "Register"
4. You'll receive a JWT token automatically

**Via API:**
```bash
curl -X POST https://heroforge.genialarchitect.io/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "pentester1",
    "email": "pentester1@example.com",
    "password": "SecurePassword123"
  }'
```

#### Login

1. Visit https://heroforge.genialarchitect.io
2. Enter username and password
3. Click "Login"

**Via API:**
```bash
curl -X POST https://heroforge.genialarchitect.io/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "SecurePass123"
  }'
```

### Dashboard Features

#### 1. Run New Scans

**From Web Interface:**
1. Click "New Scan" button
2. Enter target networks (CIDR notation)
3. Configure scan parameters:
   - Port range
   - Number of threads
   - Timeout
   - Scan type
4. Enable/disable features:
   - OS Detection
   - Service Detection
   - Vulnerability Scanning
5. Click "Start Scan"

**Via API:**
```bash
TOKEN="your_jwt_token_here"

curl -X POST https://heroforge.genialarchitect.io/api/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production Network Scan",
    "targets": ["192.168.1.0/24"],
    "port_range": [1, 65535],
    "scan_type": "Comprehensive",
    "threads": 200,
    "timeout_ms": 3000,
    "enable_os_detection": true,
    "enable_service_detection": true,
    "enable_vuln_scan": true
  }'
```

#### 2. View Scan History

**All Scans:**
```bash
curl -X GET https://heroforge.genialarchitect.io/api/scans \
  -H "Authorization: Bearer $TOKEN"
```

**Specific Scan:**
```bash
curl -X GET https://heroforge.genialarchitect.io/api/scans/SCAN_ID \
  -H "Authorization: Bearer $TOKEN"
```

#### 3. Get Scan Results

```bash
curl -X GET https://heroforge.genialarchitect.io/api/scans/SCAN_ID/results \
  -H "Authorization: Bearer $TOKEN"
```

#### 4. Real-Time Scan Progress

Connect to WebSocket for live updates:

```javascript
const token = "your_jwt_token";
const scanId = "scan_id_here";
const ws = new WebSocket(`wss://heroforge.genialarchitect.io/api/ws/scans/${scanId}`);

ws.onopen = () => {
  console.log("Connected to scan updates");
};

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log("Scan progress:", data);
};
```

---

## Scan Types

### 1. TCP Connect Scan

**Method:** Completes full TCP three-way handshake
**Speed:** Moderate
**Stealth:** Low (logged by target systems)
**Privileges:** No special privileges required

```bash
heroforge scan 192.168.1.0/24 --scan-type tcp-connect
```

**Use Case:** General purpose scanning when stealth isn't required

### 2. TCP SYN Scan

**Method:** Sends SYN packets, doesn't complete handshake
**Speed:** Fast
**Stealth:** Medium (may not be logged)
**Privileges:** Requires root/administrator

```bash
sudo heroforge scan 192.168.1.0/24 --scan-type tcp-syn
```

**Use Case:** Stealthy port scanning during penetration tests

### 3. UDP Scan

**Method:** Sends UDP packets to target ports
**Speed:** Slow (timeouts required)
**Stealth:** Medium
**Privileges:** No special privileges required

```bash
heroforge scan 192.168.1.0/24 --scan-type udp
```

**Use Case:** Finding UDP services (DNS, SNMP, etc.)

### 4. Comprehensive Scan

**Method:** Combines multiple scan techniques
**Speed:** Slow (most thorough)
**Stealth:** Low (very noisy)
**Privileges:** Requires root/administrator for some features

```bash
sudo heroforge scan 192.168.1.0/24 --scan-type comprehensive --vuln-scan
```

**Use Case:** Complete reconnaissance for authorized penetration testing

---

## Features

### OS Detection

Identifies the operating system of target hosts.

**Enable:**
```bash
heroforge scan 192.168.1.0/24  # Enabled by default
```

**Disable:**
```bash
heroforge scan 192.168.1.0/24 --no-os-detect
```

**Output Example:**
```
Host: 192.168.1.100
OS: Linux 3.x-4.x (Confidence: 95%)
```

### Service Detection

Fingerprints services running on open ports.

**Enable:**
```bash
heroforge scan 192.168.1.0/24  # Enabled by default
```

**Disable:**
```bash
heroforge scan 192.168.1.0/24 --no-service-detect
```

**Output Example:**
```
Port 80: HTTP (Apache 2.4.41)
Port 22: SSH (OpenSSH 7.9p1)
Port 3306: MySQL (5.7.32)
```

### Vulnerability Scanning

Checks for known vulnerabilities in detected services.

**Enable:**
```bash
heroforge scan 192.168.1.0/24 --vuln-scan
```

**Output Example:**
```
Host: 192.168.1.100
Port 22: SSH (OpenSSH 7.9p1)
  [MEDIUM] CVE-2020-15778: Command injection in scp
  [HIGH] Weak encryption algorithms enabled
```

---

## Output Formats

### Terminal Output (Default)

Colorized, human-readable output to the terminal.

```bash
heroforge scan 192.168.1.0/24 --output terminal
```

### JSON Output

Machine-readable JSON format for automation.

```bash
heroforge scan 192.168.1.0/24 --output json --output-file results.json
```

**Example:**
```json
{
  "scan_id": "uuid-here",
  "timestamp": "2025-12-11T00:00:00Z",
  "targets": ["192.168.1.0/24"],
  "results": [
    {
      "ip": "192.168.1.100",
      "hostname": "webserver.local",
      "os": {
        "family": "Linux",
        "version": "Ubuntu 20.04",
        "confidence": 95
      },
      "ports": [
        {
          "port": 80,
          "protocol": "TCP",
          "state": "Open",
          "service": {
            "name": "HTTP",
            "version": "Apache 2.4.41",
            "banner": "Apache/2.4.41 (Ubuntu)"
          }
        }
      ],
      "vulnerabilities": []
    }
  ]
}
```

### CSV Output

Spreadsheet-compatible format for reporting.

```bash
heroforge scan 192.168.1.0/24 --output csv --output-file results.csv
```

**Format:**
```csv
IP,Hostname,OS,Port,Protocol,State,Service,Version,Vulnerabilities
192.168.1.100,webserver.local,Linux Ubuntu 20.04,80,TCP,Open,HTTP,Apache 2.4.41,None
192.168.1.100,webserver.local,Linux Ubuntu 20.04,22,TCP,Open,SSH,OpenSSH 7.9,CVE-2020-15778
```

### All Formats

Output to terminal AND save to file.

```bash
heroforge scan 192.168.1.0/24 --output all --output-file results
```

Creates:
- `results.json`
- `results.csv`
- Terminal output

---

## Advanced Usage

### Scanning Multiple Networks

```bash
heroforge scan 192.168.1.0/24 10.0.0.0/16 172.16.0.0/12
```

### IP Ranges

```bash
# CIDR notation
heroforge scan 192.168.1.0/24

# Range notation
heroforge scan 192.168.1.1-192.168.1.254

# Single IP
heroforge scan 192.168.1.100

# Mixed
heroforge scan 192.168.1.100 192.168.2.0/24 10.0.0.1-10.0.0.50
```

### Performance Tuning

**Fast Scan (fewer ports, more threads):**
```bash
heroforge scan 192.168.1.0/24 --ports 1-1000 --threads 500 --timeout 1000
```

**Thorough Scan (all ports, careful timing):**
```bash
heroforge scan 192.168.1.0/24 --ports 1-65535 --threads 50 --timeout 5000
```

**Stealth Scan (slower, less noisy):**
```bash
sudo heroforge scan 192.168.1.0/24 --scan-type tcp-syn --threads 10 --timeout 10000
```

### Using Configuration Files

**Generate config:**
```bash
heroforge config pentest_config.toml
```

**Edit config:**
```toml
[scan]
targets = ["192.168.1.0/24"]
port_range = [1, 65535]
threads = 200
timeout_ms = 3000
scan_type = "Comprehensive"

[features]
enable_os_detection = true
enable_service_detection = true
enable_vuln_scan = true

[output]
format = "All"
output_file = "scan_results"
```

**Run with config:**
```bash
heroforge scan --config pentest_config.toml
```

### Integrating with Other Tools

**Parse JSON output with jq:**
```bash
heroforge scan 192.168.1.0/24 -o json | jq '.results[] | select(.ports != [])'
```

**Export to Metasploit:**
```bash
heroforge scan 192.168.1.0/24 -o json -f results.json
# Import results.json into Metasploit database
```

**Generate reports:**
```bash
heroforge scan 192.168.1.0/24 -o csv -f results.csv
# Open results.csv in Excel/LibreOffice for reporting
```

---

## API Reference

### Authentication Endpoints

#### Register User
```
POST /api/auth/register
Content-Type: application/json

{
  "username": "string",
  "email": "string",
  "password": "string"
}
```

#### Login
```
POST /api/auth/login
Content-Type: application/json

{
  "username": "string",
  "password": "string"
}
```

#### Get Current User
```
GET /api/auth/me
Authorization: Bearer <token>
```

### Scan Endpoints

#### Create Scan
```
POST /api/scans
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "string",
  "targets": ["string"],
  "port_range": [1, 65535],
  "scan_type": "TCPConnect|TCPSyn|UDPScan|Comprehensive",
  "threads": 100,
  "timeout_ms": 3000,
  "enable_os_detection": true,
  "enable_service_detection": true,
  "enable_vuln_scan": false
}
```

#### List Scans
```
GET /api/scans
Authorization: Bearer <token>
```

#### Get Scan Details
```
GET /api/scans/{scan_id}
Authorization: Bearer <token>
```

#### Get Scan Results
```
GET /api/scans/{scan_id}/results
Authorization: Bearer <token>
```

### WebSocket Endpoints

#### Real-Time Scan Updates
```
WS /api/ws/scans/{scan_id}
Authorization: Bearer <token>
```

**Messages:**
```json
{
  "status": "running|completed|failed",
  "progress": 45,
  "hosts_found": 12,
  "ports_scanned": 1200,
  "current_target": "192.168.1.100"
}
```

---

## Troubleshooting

### Permission Denied Errors

**Problem:** Can't perform SYN scans or raw socket operations

**Solution:**
```bash
# Run with sudo
sudo heroforge scan 192.168.1.0/24 --scan-type tcp-syn

# Or set capabilities (Linux only)
sudo setcap cap_net_raw+ep /path/to/heroforge
```

### Slow Scan Performance

**Problem:** Scans taking too long

**Solutions:**
1. Reduce port range: `--ports 1-1000`
2. Increase threads: `--threads 500`
3. Decrease timeout: `--timeout 1000`
4. Use faster scan type: `--scan-type tcp-syn`

### No Hosts Found

**Problem:** Discovery finds no live hosts

**Solutions:**
1. Check network connectivity: `ping 192.168.1.1`
2. Verify CIDR notation: `192.168.1.0/24` not `192.168.1.0/255.255.255.0`
3. Increase timeout: `--timeout 5000`
4. Check firewall rules
5. Try different scan type

### Database Errors (Web Dashboard)

**Problem:** "Database locked" or connection errors

**Solution:**
```bash
# Check database file
ls -la /root/heroforge_data/heroforge.db

# Fix permissions
chmod 666 /root/heroforge_data/heroforge.db

# Restart service
docker restart heroforge
```

### SSL Certificate Issues

**Problem:** Browser shows security warning

**Solutions:**
1. Wait for automatic SSL provisioning (30-60 minutes)
2. Click "Advanced" → "Proceed" to bypass warning (site is still secure)
3. Check Traefik logs: `docker logs root-traefik-1`

### API Authentication Errors

**Problem:** "Unauthorized" or "Invalid token"

**Solutions:**
1. Verify token is included: `-H "Authorization: Bearer <token>"`
2. Check token hasn't expired (tokens last 30 days)
3. Re-login to get fresh token
4. Verify Bearer prefix is included

---

## Best Practices

### 1. Authorization

**⚠️ CRITICAL:** Only scan networks you own or have explicit written permission to test.

- Obtain authorization before scanning
- Document scope of testing
- Follow responsible disclosure practices

### 2. Network Impact

- Start with small thread counts (100)
- Use appropriate timeouts (3000ms+)
- Avoid scanning production systems during business hours
- Consider network bandwidth limitations

### 3. Data Management

- Save scan results: `--output-file results.json`
- Date your output files: `results_$(date +%Y%m%d).json`
- Keep scan logs for documentation
- Protect sensitive scan data

### 4. Stealth vs Speed

**Noisy/Fast:**
```bash
heroforge scan 192.168.1.0/24 --threads 1000 --timeout 500
```

**Stealthy/Slow:**
```bash
sudo heroforge scan 192.168.1.0/24 --scan-type tcp-syn --threads 10 --timeout 10000
```

### 5. Verification

Always verify findings:
- Manually connect to identified services
- Cross-reference with other tools (nmap, masscan)
- Document false positives

---

## Common Use Cases

### 1. Internal Network Assessment

```bash
# Discover all live hosts
heroforge discover 10.0.0.0/8 --threads 1000

# Full scan of discovered hosts
heroforge scan 10.0.1.0/24 --ports 1-65535 --vuln-scan -o all -f internal_scan
```

### 2. External Perimeter Testing

```bash
# Scan public IP ranges (with permission!)
heroforge scan 203.0.113.0/24 --ports 1-1000 --scan-type tcp-syn -o json -f perimeter_scan.json
```

### 3. Quick Service Check

```bash
# Check specific ports on known hosts
heroforge portscan 192.168.1.100 --ports 80,443,22,3389,3306,5432
```

### 4. Continuous Monitoring

```bash
# Daily scan with timestamp
heroforge scan 192.168.1.0/24 -o json -f "scan_$(date +%Y%m%d_%H%M%S).json"

# Compare with previous scans
diff scan_20251210.json scan_20251211.json
```

### 5. Automated Reporting

```bash
# Generate CSV for management
heroforge scan 192.168.1.0/24 -o csv -f monthly_report.csv

# Email results
echo "Network scan results attached" | mail -s "Security Scan Report" -A monthly_report.csv security@company.com
```

---

## Quick Reference Card

### Essential Commands

```bash
# Full scan
heroforge scan 192.168.1.0/24

# Fast scan (common ports)
heroforge scan 192.168.1.0/24 --ports 1-1000 --threads 500

# Stealth scan
sudo heroforge scan 192.168.1.0/24 --scan-type tcp-syn --threads 10

# Comprehensive with vulnerabilities
heroforge scan 192.168.1.0/24 --ports 1-65535 --vuln-scan -o all -f results

# Web dashboard
heroforge serve --bind 0.0.0.0:8080
```

### Common Port Ranges

- **Well-known ports:** 1-1023
- **Registered ports:** 1024-49151
- **Dynamic ports:** 49152-65535
- **Common services:** 21,22,23,25,80,110,143,443,3306,3389,5432,8080

### Typical Thread Counts

- **Small network (<256 hosts):** 100-200 threads
- **Medium network (256-4096 hosts):** 500-1000 threads
- **Large network (>4096 hosts):** 1000-2000 threads
- **Stealth scan:** 10-50 threads

---

## Support and Resources

### Documentation
- **GitHub:** https://github.com/yourusername/heroforge
- **Web Dashboard:** https://heroforge.genialarchitect.io
- **API Docs:** https://heroforge.genialarchitect.io/api/docs

### Getting Help

**View Logs:**
```bash
# CLI verbose mode
heroforge scan 192.168.1.0/24 --verbose

# Web server logs
docker logs heroforge -f

# Database logs
tail -f /root/heroforge_data/heroforge.db.log
```

**Community:**
- GitHub Issues
- Discord Server
- Security Forums

---

## Legal Disclaimer

**⚠️ IMPORTANT LEGAL NOTICE**

HeroForge is designed for authorized security testing and network administration. Unauthorized scanning of networks you don't own or have permission to test is **illegal** and may result in:

- Criminal prosecution
- Civil liability
- Network access revocation
- Professional consequences

**Always:**
- Obtain written authorization before scanning
- Follow applicable laws and regulations
- Respect responsible disclosure practices
- Document your authorization and scope

**The developers of HeroForge are not responsible for misuse of this tool.**

---

## Version History

**v0.1.0** (Current)
- Initial release
- Basic host discovery
- TCP/UDP port scanning
- OS and service detection
- Web dashboard with JWT authentication
- RESTful API
- WebSocket real-time updates
- Multiple output formats

---

**End of Manual**

For the latest updates and documentation, visit:
https://heroforge.genialarchitect.io
