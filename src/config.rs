#![allow(dead_code)]

use anyhow::Result;
use crate::types::ScanConfig;
use std::fs;
use std::io::Write;

pub fn generate_default_config(path: &str) -> Result<()> {
    let default_config = r#"# HeroForge Configuration File
# Network Triage and Reconnaissance Tool

[scan]
# Target IP addresses or CIDR ranges
targets = ["192.168.1.0/24"]

# Port range to scan (start, end)
port_range = [1, 1000]

# Number of concurrent threads
threads = 100

# Timeout per port in milliseconds
timeout_ms = 3000

# Scan type: TCPConnect, TCPSyn, UDPScan, Comprehensive
scan_type = "TCPConnect"

[features]
# Enable OS detection
enable_os_detection = true

# Enable service detection and banner grabbing
enable_service_detection = true

# Enable vulnerability scanning
enable_vuln_scan = false

[output]
# Output format: Json, Csv, Terminal, All
format = "Terminal"

# Output file path (optional)
# output_file = "scan_results"

# [timeouts]
# Optional scanner-specific timeouts (in seconds)
# If not set, defaults are used
#
# Service detection banner grabbing timeout (default: 2s)
# service_detection_timeout_secs = 2
#
# DNS reconnaissance query timeout (default: 5s)
# dns_timeout_secs = 5
#
# SYN scanner per-port timeout (default: 2s)
# syn_timeout_secs = 2
#
# UDP scanner per-port timeout (default: 3s)
# udp_timeout_secs = 3
"#;

    let mut file = fs::File::create(path)?;
    file.write_all(default_config.as_bytes())?;

    Ok(())
}

pub fn load_config(path: &str) -> Result<ScanConfig> {
    let contents = fs::read_to_string(path)?;
    let config: ScanConfig = toml::from_str(&contents)?;
    Ok(config)
}
