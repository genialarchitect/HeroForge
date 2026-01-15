//! Nmap Grepable output parser
//!
//! Parses nmap's grepable output format (-oG flag)
//! Format: Host: <ip> (<hostname>)  Ports: <port>/<state>/<protocol>//<service>///<version>

use anyhow::Result;
use regex::Regex;

use super::types::{
    HostStatus, ImportedPort, ImportedTopologyHost, PortState, ScanMetadata,
    TopologyImportResult, TopologyImportSource,
};

/// Parser for Nmap grepable output
pub struct NmapGrepableParser;

impl NmapGrepableParser {
    /// Parse nmap grepable content
    pub fn parse(content: &str) -> Result<TopologyImportResult> {
        let mut result = TopologyImportResult::new(TopologyImportSource::NmapGrepable);
        result.metadata.scanner = "nmap".to_string();

        // Regex patterns
        let host_re = Regex::new(r"^Host:\s+(\S+)\s+\(([^)]*)\)").unwrap();
        let ports_re = Regex::new(r"Ports:\s+(.+?)(?:\s+Ignored|$)").unwrap();
        let port_entry_re = Regex::new(r"(\d+)/([^/]*)/([^/]*)/([^/]*)/([^/]*)/([^/]*)/([^/,]*)").unwrap();
        let status_re = Regex::new(r"Status:\s+(\S+)").unwrap();
        let os_re = Regex::new(r"OS:\s+(.+)$").unwrap();

        for line in content.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                // Parse comment headers for metadata
                if line.starts_with("# Nmap") {
                    if let Some(version) = line.strip_prefix("# Nmap ") {
                        let parts: Vec<&str> = version.splitn(2, ' ').collect();
                        if !parts.is_empty() {
                            result.metadata.scanner_version = Some(parts[0].to_string());
                        }
                        if parts.len() > 1 && parts[1].starts_with("scan") {
                            result.metadata.command_line = Some(line.to_string());
                        }
                    }
                }
                continue;
            }

            // Parse host line
            if line.starts_with("Host:") {
                let mut host = ImportedTopologyHost::default();
                host.status = HostStatus::Up; // If we see it in grepable, it's up

                // Extract IP and hostname
                if let Some(caps) = host_re.captures(line) {
                    host.ip = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
                    let hostname = caps.get(2).map(|m| m.as_str().to_string()).unwrap_or_default();
                    if !hostname.is_empty() {
                        host.hostname = Some(hostname);
                    }
                }

                // Extract ports
                if let Some(caps) = ports_re.captures(line) {
                    let ports_str = caps.get(1).map(|m| m.as_str()).unwrap_or("");

                    for port_match in port_entry_re.captures_iter(ports_str) {
                        let port_num: u16 = port_match.get(1)
                            .and_then(|m| m.as_str().parse().ok())
                            .unwrap_or(0);

                        if port_num == 0 {
                            continue;
                        }

                        let state_str = port_match.get(2).map(|m| m.as_str()).unwrap_or("open");
                        let protocol = port_match.get(3).map(|m| m.as_str()).unwrap_or("tcp");
                        let _owner = port_match.get(4).map(|m| m.as_str()).unwrap_or("");
                        let service = port_match.get(5).map(|m| m.as_str()).unwrap_or("");
                        let _rpc_info = port_match.get(6).map(|m| m.as_str()).unwrap_or("");
                        let version = port_match.get(7).map(|m| m.as_str()).unwrap_or("");

                        let port = ImportedPort {
                            port: port_num,
                            protocol: protocol.to_string(),
                            state: PortState::from_str(state_str),
                            service: if service.is_empty() { None } else { Some(service.to_string()) },
                            version: if version.is_empty() { None } else { Some(version.to_string()) },
                            ..Default::default()
                        };

                        host.ports.push(port);
                    }
                }

                // Extract status if present
                if let Some(caps) = status_re.captures(line) {
                    let status = caps.get(1).map(|m| m.as_str()).unwrap_or("up");
                    host.status = match status.to_lowercase().as_str() {
                        "up" => HostStatus::Up,
                        "down" => HostStatus::Down,
                        _ => HostStatus::Unknown,
                    };
                }

                // Extract OS if present
                if let Some(caps) = os_re.captures(line) {
                    host.os = caps.get(1).map(|m| m.as_str().to_string());
                }

                if !host.ip.is_empty() {
                    result.hosts.push(host);
                }
            }
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_grepable() {
        let content = r#"# Nmap 7.91 scan initiated Fri Jan 1 00:00:00 2021 as: nmap -sV -oG output.gnmap 192.168.1.0/24
Host: 192.168.1.1 (router.local)    Ports: 22/open/tcp//ssh//OpenSSH 8.0/, 80/open/tcp//http//nginx 1.18/
Host: 192.168.1.100 ()    Ports: 22/open/tcp//ssh///, 3389/open/tcp//ms-wbt-server///
# Nmap done at Fri Jan 1 00:01:00 2021 -- 256 IP addresses (2 hosts up)"#;

        let result = NmapGrepableParser::parse(content).unwrap();

        assert_eq!(result.hosts.len(), 2);

        assert_eq!(result.hosts[0].ip, "192.168.1.1");
        assert_eq!(result.hosts[0].hostname, Some("router.local".to_string()));
        assert_eq!(result.hosts[0].ports.len(), 2);
        assert_eq!(result.hosts[0].ports[0].port, 22);
        assert_eq!(result.hosts[0].ports[0].service, Some("ssh".to_string()));
        assert_eq!(result.hosts[0].ports[0].version, Some("OpenSSH 8.0".to_string()));

        assert_eq!(result.hosts[1].ip, "192.168.1.100");
        assert!(result.hosts[1].hostname.is_none());
        assert_eq!(result.hosts[1].ports.len(), 2);
    }

    #[test]
    fn test_parse_various_port_states() {
        let content = r#"Host: 10.0.0.1 ()    Ports: 22/open/tcp//ssh///, 23/filtered/tcp//telnet///, 80/closed/tcp//http///"#;

        let result = NmapGrepableParser::parse(content).unwrap();

        assert_eq!(result.hosts.len(), 1);
        assert_eq!(result.hosts[0].ports.len(), 3);
        assert_eq!(result.hosts[0].ports[0].state, PortState::Open);
        assert_eq!(result.hosts[0].ports[1].state, PortState::Filtered);
        assert_eq!(result.hosts[0].ports[2].state, PortState::Closed);
    }
}
