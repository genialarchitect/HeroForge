# HeroForge

**Network Triage and Reconnaissance Tool for Penetration Testing**

HeroForge is a fast, concurrent network reconnaissance tool written in Rust, designed to automate the initial network triage phase of penetration testing engagements. It combines host discovery, port scanning, service detection, OS fingerprinting, and vulnerability assessment into a single, efficient tool.

## Features

- **Host Discovery**: Identify live hosts on the network using TCP connect probes
- **Port Scanning**: Fast concurrent TCP port scanning with configurable thread pools
- **Service Detection**: Banner grabbing and service version identification
- **OS Fingerprinting**: Passive OS detection based on open ports and service signatures
- **Vulnerability Scanning**: Basic vulnerability assessment including:
  - Known CVE matching
  - Misconfiguration detection
  - Insecure service warnings
- **Multiple Output Formats**: JSON, CSV, and colorful terminal output
- **Flexible Configuration**: CLI arguments or TOML configuration files

## Installation

### Prerequisites

- Rust 1.70 or later
- Linux, macOS, or Windows

### Building from Source

```bash
git clone https://github.com/genialarchitect/HeroForge.git
cd heroforge
cargo build --release
```

The compiled binary will be available at `target/release/heroforge`.

### Installation

```bash
cargo install --path .
```

## Usage

### Quick Start

Scan a single host:
```bash
heroforge scan 192.168.1.1
```

Scan a network range:
```bash
heroforge scan 192.168.1.0/24
```

Full scan with all features:
```bash
heroforge scan 192.168.1.0/24 --ports 1-65535 --vuln-scan -v
```

### Commands

#### Scan

Perform a comprehensive network triage scan:

```bash
heroforge scan [OPTIONS] <TARGETS>...
```

**Options:**
- `-p, --ports <RANGE>` - Port range to scan (default: 1-1000)
- `-t, --threads <NUM>` - Number of concurrent threads (default: 100)
- `-T, --timeout <MS>` - Timeout per port in milliseconds (default: 3000)
- `-s, --scan-type <TYPE>` - Scan type: tcp-connect, tcp-syn, udp, comprehensive (default: tcp-connect)
- `--no-os-detect` - Skip OS detection
- `--no-service-detect` - Skip service detection
- `--vuln-scan` - Enable vulnerability scanning
- `-o, --output-file <PATH>` - Output file path
- `-v, --verbose` - Enable verbose logging

**Examples:**
```bash
# Basic scan of common ports
heroforge scan 192.168.1.0/24

# Scan specific ports with vulnerability assessment
heroforge scan 192.168.1.100 -p 1-1000 --vuln-scan

# Fast scan with custom thread count
heroforge scan 10.0.0.0/24 -t 500 -T 1000

# Save results to file
heroforge scan 192.168.1.0/24 -o results.json --output json
```

#### Discover

Quickly discover live hosts without port scanning:

```bash
heroforge discover [OPTIONS] <TARGETS>...
```

**Options:**
- `-t, --threads <NUM>` - Number of concurrent threads
- `-T, --timeout <MS>` - Timeout in milliseconds

**Example:**
```bash
heroforge discover 192.168.1.0/24
```

#### Portscan

Scan ports on specific hosts:

```bash
heroforge portscan [OPTIONS] <TARGETS>...
```

**Options:**
- `-p, --ports <RANGE>` - Port range to scan (default: 1-65535)
- `-t, --threads <NUM>` - Number of concurrent threads
- `-s, --scan-type <TYPE>` - Scan type

**Example:**
```bash
heroforge portscan 192.168.1.100 -p 1-1000
```

#### Config

Generate a default configuration file:

```bash
heroforge config [PATH]
```

**Example:**
```bash
heroforge config my-scan.toml
```

### Output Formats

HeroForge supports multiple output formats:

- **Terminal** (default): Colorful, human-readable output with tables
- **JSON**: Machine-readable JSON format
- **CSV**: Spreadsheet-compatible CSV format
- **All**: Generate all formats simultaneously

Specify format with the `-o, --output` flag:
```bash
heroforge scan 192.168.1.0/24 --output json > results.json
heroforge scan 192.168.1.0/24 --output csv > results.csv
```

### Configuration File

Generate a configuration file and customize it:

```bash
heroforge config heroforge.toml
```

Example configuration:
```toml
[scan]
targets = ["192.168.1.0/24"]
port_range = [1, 1000]
threads = 100
timeout_ms = 3000
scan_type = "TCPConnect"

[features]
enable_os_detection = true
enable_service_detection = true
enable_vuln_scan = false

[output]
format = "Terminal"
```

## Output Example

```
════════════════════════════════════════════════════════════════════════════════
 SCAN RESULTS
════════════════════════════════════════════════════════════════════════════════

Host: 192.168.1.100
OS: Linux Ubuntu (75% confidence)
Scan Duration: 2.45s

Open Ports:
┌──────┬──────────┬──────────┬─────────┐
│ Port │ State    │ Service  │ Version │
├──────┼──────────┼──────────┼─────────┤
│ 22   │ Open     │ ssh      │ OpenSSH │
│ 80   │ Open     │ http     │ nginx   │
│ 443  │ Open     │ https    │ nginx   │
└──────┴──────────┴──────────┴─────────┘

Vulnerabilities:
  MEDIUM Unencrypted HTTP Service
    Service: http:80
    HTTP service without TLS encryption detected. Consider using HTTPS.
```

## Use Cases

### Internal Network Assessment
```bash
# Quick discovery scan
heroforge discover 10.0.0.0/8 -t 1000

# Detailed scan of live hosts
heroforge scan 10.0.1.0/24 --vuln-scan -p 1-10000
```

### External Penetration Test
```bash
# Targeted scan of internet-facing hosts
heroforge scan example.com -p 1-1000 --vuln-scan -o assessment.json
```

### Red Team Reconnaissance
```bash
# Stealth scan with longer timeouts
heroforge scan 192.168.1.0/24 -T 5000 -t 50 --no-service-detect
```

## Security Considerations

- **Authorization**: Only use HeroForge on networks you have explicit permission to test
- **Network Impact**: High thread counts may trigger IDS/IPS systems
- **Raw Sockets**: Some scan types (TCP SYN) require root/administrator privileges
- **False Positives**: Vulnerability detection is heuristic-based and may produce false positives

## Permissions

Some features require elevated privileges:

- **Linux/macOS**: Use `sudo` for raw socket operations (SYN scans)
  ```bash
  sudo heroforge scan 192.168.1.0/24 --scan-type tcp-syn
  ```

- **Windows**: Run as Administrator

## Performance Tuning

### Thread Count
- Default: 100 threads
- Fast networks: 500-1000 threads
- Slow/unstable networks: 50-100 threads

### Timeouts
- Fast networks: 1000-2000ms
- Normal networks: 3000ms (default)
- Slow networks: 5000-10000ms

### Port Ranges
- Quick scan: 1-1000 (common ports)
- Comprehensive: 1-65535 (all ports)
- Custom: Specify your own range based on target

## Troubleshooting

### "Permission denied" errors
Run with sudo/administrator privileges for raw socket operations.

### Slow scans
- Increase timeout: `-T 5000`
- Reduce threads: `-t 50`
- Reduce port range: `-p 1-100`

### No hosts found
- Check network connectivity
- Verify target specification (CIDR notation)
- Try increasing timeout
- Check firewall rules

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

HeroForge is designed for authorized security testing and network administration only. Users are solely responsible for ensuring they have proper authorization before scanning any networks or systems. Unauthorized network scanning may be illegal in your jurisdiction.

## Author

Built by your pentest/red team for efficient network reconnaissance.

## Roadmap

- [ ] ICMP ping sweep (requires raw sockets)
- [ ] UDP port scanning
- [ ] TCP SYN stealth scanning
- [ ] Integration with CVE databases
- [ ] Web application fingerprinting
- [ ] Export to common pentest frameworks (Metasploit, Burp)
- [ ] Passive monitoring mode
- [ ] Plugin system for custom checks

---

**Happy Hunting!** 🎯
