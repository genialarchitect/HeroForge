  # HeroForge Usage Examples

## Quick Start

### Basic Network Scan
```bash
# Scan common ports on a single host
./heroforge scan 192.168.1.100

# Scan a network range
./heroforge scan 192.168.1.0/24
```

### Host Discovery
```bash
# Quickly find live hosts
./heroforge discover 192.168.1.0/24

# Fast discovery with more threads
./heroforge discover 10.0.0.0/8 -t 1000
```

### Port Scanning
```bash
# Scan all ports on a specific host
./heroforge portscan 192.168.1.100 -p 1-65535

# Scan common ports on multiple hosts
./heroforge portscan 192.168.1.100 192.168.1.101 192.168.1.102 -p 1-1000
```

## Advanced Usage

### Comprehensive Security Assessment
```bash
# Full scan with vulnerability detection
./heroforge scan 192.168.1.0/24 \
  --ports 1-10000 \
  --vuln-scan \
  --threads 200 \
  -v
```

### Stealth Scanning
```bash
# Slow, low-profile scan
./heroforge scan 192.168.1.100 \
  --ports 1-1000 \
  --threads 10 \
  --timeout 10000
```

### Output Formats

#### JSON Output
```bash
# Save results as JSON
./heroforge scan 192.168.1.0/24 --output json -o scan_results.json
```

#### CSV Output
```bash
# Save results as CSV for spreadsheet analysis
./heroforge scan 192.168.1.0/24 --output csv -o scan_results.csv
```

#### All Formats
```bash
# Generate all output formats
./heroforge scan 192.168.1.0/24 --output all -o scan_results
# Creates: scan_results.json, scan_results.csv, and terminal output
```

## Real-World Scenarios

### Internal Network Assessment
```bash
# Phase 1: Discovery
./heroforge discover 10.0.0.0/8 -t 500 -o json > live_hosts.json

# Phase 2: Detailed scan of live hosts
./heroforge scan $(cat live_hosts.json | jq -r '.[].ip' | head -10) \
  --ports 1-10000 \
  --vuln-scan \
  -o internal_assessment.json
```

### External Penetration Test
```bash
# Scan internet-facing assets
./heroforge scan example.com \
  --ports 80,443,22,21,25,3389,8080,8443 \
  --vuln-scan \
  --no-os-detect \
  -o external_scan.json
```

### Web Application Testing
```bash
# Focus on web ports
./heroforge scan 192.168.1.0/24 \
  --ports 80,443,8080,8443,8000,8888 \
  --threads 50 \
  -v
```

### Database Server Discovery
```bash
# Scan for common database ports
./heroforge portscan 192.168.1.0/24 \
  --ports 1433,3306,5432,27017,6379,9200 \
  --threads 100
```

### Quick Vulnerability Check
```bash
# Scan and check for known vulnerabilities
./heroforge scan 192.168.1.100 \
  --vuln-scan \
  --ports 1-1000 \
  -v
```

## Performance Tuning

### Fast Scan (Good Network)
```bash
./heroforge scan 192.168.1.0/24 \
  --threads 1000 \
  --timeout 1000 \
  --ports 1-1000
```

### Careful Scan (Unstable Network)
```bash
./heroforge scan 192.168.1.0/24 \
  --threads 50 \
  --timeout 10000 \
  --ports 1-1000
```

### Comprehensive Deep Scan
```bash
./heroforge scan 192.168.1.100 \
  --ports 1-65535 \
  --vuln-scan \
  --threads 500 \
  --timeout 5000 \
  -v
```

## Configuration File Usage

### Generate Config
```bash
./heroforge config my-scan.toml
```

### Edit Configuration
Edit `my-scan.toml` to customize scan parameters.

### Use Configuration
Currently, configuration files can be used as templates. Future versions will support loading from config files directly.

## Tips and Best Practices

1. **Start with Discovery**: Use `discover` command first to identify live hosts
2. **Adjust Threads**: Higher threads = faster scans, but may trigger IDS/IPS
3. **Use Appropriate Timeouts**: Increase timeout for slow networks
4. **Enable Verbose Mode**: Use `-v` for detailed logging during scans
5. **Save Results**: Always save important scan results with `-o` flag
6. **Combine with Other Tools**: Export to JSON and import into other security tools
7. **Respect Rate Limits**: Don't overwhelm target networks with too many threads
8. **Get Authorization**: Always obtain written permission before scanning networks

## Interpreting Results

### Understanding Port States
- **Open**: Service is listening and accepting connections
- **Closed**: No service listening (port reachable but not open)
- **Filtered**: Port is blocked by firewall/filter

### Vulnerability Severity
- **Critical**: Immediate action required (e.g., EternalBlue)
- **High**: Serious security risk (e.g., unencrypted protocols)
- **Medium**: Moderate security concern (e.g., HTTP instead of HTTPS)
- **Low**: Minor security issue or informational

### OS Detection Confidence
- **80-100%**: High confidence in OS identification
- **60-79%**: Moderate confidence
- **Below 60%**: Low confidence, may need manual verification

## Common Issues

### Permission Denied
Some operations require root/administrator privileges:
```bash
sudo ./heroforge scan 192.168.1.0/24 --scan-type tcp-syn
```

### No Hosts Found
- Check network connectivity
- Verify CIDR notation
- Increase timeout: `--timeout 10000`
- Check firewall rules

### Slow Scans
- Increase threads: `--threads 500`
- Reduce timeout: `--timeout 1000`
- Reduce port range: `--ports 1-100`

## Integration Examples

### Export to Metasploit
```bash
# Convert JSON to Metasploit-compatible format
./heroforge scan 192.168.1.0/24 --output json > scan.json
# Process with jq and import to Metasploit
```

### Automated Scanning
```bash
#!/bin/bash
# Daily network scan script
DATE=$(date +%Y%m%d)
./heroforge scan 192.168.1.0/24 \
  --vuln-scan \
  -o "scan_${DATE}.json" \
  --output json
```

### Continuous Monitoring
```bash
# Monitor for new hosts
while true; do
  ./heroforge discover 192.168.1.0/24 --output json > "hosts_$(date +%s).json"
  sleep 3600  # Every hour
done
```
