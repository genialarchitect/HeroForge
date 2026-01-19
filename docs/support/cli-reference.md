# HeroForge CLI Reference

The HeroForge CLI provides powerful command-line access to scanning and reconnaissance capabilities.

## Installation

### From Source

```bash
git clone https://github.com/heroforge/heroforge.git
cd heroforge
cargo build --release
```

The binary will be at `target/release/heroforge`.

### Docker

```bash
docker pull ghcr.io/heroforge/heroforge:latest
docker run --rm ghcr.io/heroforge/heroforge scan --help
```

## Commands

### scan

Perform a full security assessment scan.

```bash
heroforge scan <TARGETS> [OPTIONS]
```

**Arguments:**
- `<TARGETS>`: IP addresses, hostnames, or CIDR ranges to scan

**Options:**
| Option | Description |
|--------|-------------|
| `-p, --ports <PORTS>` | Ports to scan (e.g., `22,80,443` or `1-1000`) |
| `-s, --scan-type <TYPE>` | Scan type: `tcp-connect`, `tcp-syn`, `udp`, `comprehensive` |
| `-t, --timeout <MS>` | Connection timeout in milliseconds (default: 3000) |
| `-c, --concurrency <N>` | Maximum concurrent connections (default: 100) |
| `--service-detection` | Enable service version detection |
| `--os-fingerprint` | Enable OS fingerprinting |
| `--vuln-scan` | Enable vulnerability scanning |
| `-o, --output <FILE>` | Output file path |
| `--format <FORMAT>` | Output format: `json`, `html`, `csv`, `markdown` |
| `-v, --verbose` | Increase verbosity level |
| `-q, --quiet` | Suppress non-essential output |

**Examples:**

```bash
# Basic scan of a single host
heroforge scan 192.168.1.1

# Scan common ports on a subnet
heroforge scan 192.168.1.0/24 -p 22,80,443,8080

# Full scan with vulnerability detection
heroforge scan target.example.com -p 1-65535 --service-detection --vuln-scan

# SYN scan (requires root)
sudo heroforge scan 192.168.1.0/24 -s tcp-syn -p 1-1000

# Export results to JSON
heroforge scan 10.0.0.1 -o results.json --format json
```

### discover

Host discovery only (no port scanning).

```bash
heroforge discover <TARGETS> [OPTIONS]
```

**Options:**
| Option | Description |
|--------|-------------|
| `--method <METHOD>` | Discovery method: `icmp`, `arp`, `tcp-syn`, `tcp-ack` |
| `-t, --timeout <MS>` | Timeout per probe |
| `-o, --output <FILE>` | Output file path |

**Examples:**

```bash
# Discover live hosts on a network
heroforge discover 192.168.1.0/24

# ARP discovery (local network, requires root)
sudo heroforge discover 192.168.1.0/24 --method arp
```

### portscan

Port scanning only (assumes hosts are alive).

```bash
heroforge portscan <TARGETS> [OPTIONS]
```

**Options:**
| Option | Description |
|--------|-------------|
| `-p, --ports <PORTS>` | Ports to scan |
| `-s, --scan-type <TYPE>` | Scan type |
| `-c, --concurrency <N>` | Concurrent connections |
| `--top-ports <N>` | Scan top N common ports |

**Examples:**

```bash
# Scan top 1000 ports
heroforge portscan 192.168.1.1 --top-ports 1000

# Fast scan of specific ports
heroforge portscan 192.168.1.1 -p 80,443,8000-9000 -c 500
```

### config

Generate or validate configuration files.

```bash
heroforge config [PATH]
```

**Examples:**

```bash
# Generate default config
heroforge config > heroforge.toml

# Use custom config with scan
heroforge scan 192.168.1.1 --config /path/to/heroforge.toml
```

### serve

Start the web server (API and dashboard).

```bash
heroforge serve [OPTIONS]
```

**Options:**
| Option | Description |
|--------|-------------|
| `--bind <ADDR:PORT>` | Bind address (default: `127.0.0.1:8080`) |
| `--workers <N>` | Number of worker threads |
| `--tls-cert <PATH>` | TLS certificate file |
| `--tls-key <PATH>` | TLS private key file |

**Examples:**

```bash
# Start on default port
heroforge serve

# Start on all interfaces with custom port
heroforge serve --bind 0.0.0.0:9000

# Start with TLS
heroforge serve --bind 0.0.0.0:443 --tls-cert cert.pem --tls-key key.pem
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `JWT_SECRET` | JWT signing key (required for serve) |
| `DATABASE_URL` | SQLite database path (default: `./heroforge.db`) |
| `DATABASE_ENCRYPTION_KEY` | Enable database encryption |
| `RUST_LOG` | Log level: `error`, `warn`, `info`, `debug`, `trace` |
| `REPORTS_DIR` | Directory for generated reports |

## Configuration File

Create `heroforge.toml`:

```toml
[scan]
default_timeout = 3000
default_concurrency = 100
default_ports = "22,80,443,8080,8443"

[service_detection]
enabled = true
intensity = "normal"  # light, normal, aggressive

[vulnerability_scan]
enabled = true
cve_lookup = true

[output]
default_format = "json"
reports_dir = "./reports"
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Invalid arguments |
| 3 | Network error |
| 4 | Permission denied |
| 5 | Target unreachable |

## Privileged Operations

Some features require elevated privileges:

| Feature | Linux | Windows |
|---------|-------|---------|
| TCP SYN scan | `sudo` or `CAP_NET_RAW` | Administrator |
| UDP scan | `sudo` | Administrator |
| ARP discovery | `sudo` or `CAP_NET_RAW` | Administrator |
| OS fingerprinting | `sudo` | Administrator |

**Grant capabilities without root (Linux):**

```bash
sudo setcap cap_net_raw+eip /path/to/heroforge
```

## See Also

- [Getting Started](./getting-started.md)
- [Web Dashboard Guide](./web-dashboard.md)
- [Troubleshooting](./troubleshooting.md)
