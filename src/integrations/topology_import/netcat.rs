//! Netcat log output parser
//!
//! Parses various netcat output formats from connection tests

use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;

use super::types::{
    HostStatus, ImportedPort, ImportedTopologyHost, PortState, TopologyImportResult,
    TopologyImportSource,
};

/// Parser for Netcat log output
pub struct NetcatParser;

impl NetcatParser {
    /// Parse netcat log content
    ///
    /// Supports multiple netcat output formats:
    /// - `Connection to <host> <port> port [tcp/<service>] succeeded!`
    /// - `<host>:<port> open`
    /// - `nc: connect to <host> port <port> (tcp) succeeded`
    /// - `<host> <port> (tcp) open`
    pub fn parse(content: &str) -> Result<TopologyImportResult> {
        let mut result = TopologyImportResult::new(TopologyImportSource::NetcatLog);
        result.metadata.scanner = "netcat".to_string();

        // Various netcat output patterns
        let patterns = [
            // Connection to 192.168.1.1 22 port [tcp/ssh] succeeded!
            Regex::new(r"Connection to (\S+) (\d+) port \[([^/]+)/([^\]]*)\] succeeded").unwrap(),
            // Connection to 192.168.1.1 22 port [tcp/*] succeeded!
            Regex::new(r"Connection to (\S+) (\d+) port \[([^/]+)/\*\] succeeded").unwrap(),
            // 192.168.1.1:22 open
            Regex::new(r"(\S+):(\d+)\s+open").unwrap(),
            // nc: connect to 192.168.1.1 port 22 (tcp) succeeded
            Regex::new(r"nc: connect to (\S+) port (\d+) \((\w+)\) succeeded").unwrap(),
            // 192.168.1.1 22 (tcp) open
            Regex::new(r"(\S+)\s+(\d+)\s+\((\w+)\)\s+open").unwrap(),
            // (UNKNOWN) [192.168.1.1] 22 (ssh) open
            Regex::new(r"\(UNKNOWN\)\s+\[(\S+)\]\s+(\d+)\s+\(([^)]+)\)\s+open").unwrap(),
            // Simple: 192.168.1.1 22
            Regex::new(r"^(\d+\.\d+\.\d+\.\d+)\s+(\d+)$").unwrap(),
        ];

        // Patterns for failed connections (to mark as filtered/closed)
        let failed_patterns = [
            Regex::new(r"Connection to (\S+) (\d+) port .* failed").unwrap(),
            Regex::new(r"nc: connect to (\S+) port (\d+) .* failed").unwrap(),
            Regex::new(r"(\S+):(\d+)\s+(closed|filtered|refused)").unwrap(),
        ];

        let mut hosts_map: HashMap<String, ImportedTopologyHost> = HashMap::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            // Try each success pattern
            for (idx, pattern) in patterns.iter().enumerate() {
                if let Some(caps) = pattern.captures(line) {
                    let ip = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
                    let port: u16 = caps.get(2)
                        .and_then(|m| m.as_str().parse().ok())
                        .unwrap_or(0);

                    if ip.is_empty() || port == 0 {
                        continue;
                    }

                    let protocol = caps.get(3).map(|m| m.as_str().to_string()).unwrap_or_else(|| "tcp".to_string());
                    let service = if idx == 0 {
                        caps.get(4).map(|m| m.as_str().to_string())
                    } else if idx == 5 {
                        caps.get(3).map(|m| m.as_str().to_string())
                    } else {
                        None
                    };

                    let host = hosts_map.entry(ip.clone()).or_insert_with(|| {
                        let mut h = ImportedTopologyHost::default();
                        h.ip = ip;
                        h.status = HostStatus::Up;
                        h
                    });

                    let port_entry = ImportedPort {
                        port,
                        protocol: protocol.to_lowercase(),
                        state: PortState::Open,
                        service,
                        ..Default::default()
                    };

                    if !host.ports.iter().any(|p| p.port == port_entry.port && p.protocol == port_entry.protocol) {
                        host.ports.push(port_entry);
                    }

                    break;
                }
            }

            // Try failed patterns
            for pattern in &failed_patterns {
                if let Some(caps) = pattern.captures(line) {
                    let ip = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
                    let port: u16 = caps.get(2)
                        .and_then(|m| m.as_str().parse().ok())
                        .unwrap_or(0);

                    if ip.is_empty() || port == 0 {
                        continue;
                    }

                    let state = if line.contains("refused") {
                        PortState::Closed
                    } else {
                        PortState::Filtered
                    };

                    let host = hosts_map.entry(ip.clone()).or_insert_with(|| {
                        let mut h = ImportedTopologyHost::default();
                        h.ip = ip;
                        h.status = HostStatus::Up;
                        h
                    });

                    let port_entry = ImportedPort {
                        port,
                        protocol: "tcp".to_string(),
                        state,
                        ..Default::default()
                    };

                    if !host.ports.iter().any(|p| p.port == port_entry.port) {
                        host.ports.push(port_entry);
                    }

                    break;
                }
            }
        }

        result.hosts = hosts_map.into_values().collect();

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_standard_nc_output() {
        let content = r#"
Connection to 192.168.1.1 22 port [tcp/ssh] succeeded!
Connection to 192.168.1.1 80 port [tcp/http] succeeded!
Connection to 192.168.1.1 443 port [tcp/https] succeeded!
"#;

        let result = NetcatParser::parse(content).unwrap();

        assert_eq!(result.hosts.len(), 1);
        assert_eq!(result.hosts[0].ip, "192.168.1.1");
        assert_eq!(result.hosts[0].ports.len(), 3);
        assert!(result.hosts[0].ports.iter().any(|p| p.port == 22 && p.service == Some("ssh".to_string())));
    }

    #[test]
    fn test_parse_simple_format() {
        let content = r#"
192.168.1.1:22 open
192.168.1.1:80 open
192.168.1.100:443 open
"#;

        let result = NetcatParser::parse(content).unwrap();

        assert_eq!(result.hosts.len(), 2);
    }

    #[test]
    fn test_parse_with_failures() {
        let content = r#"
Connection to 10.0.0.1 22 port [tcp/ssh] succeeded!
Connection to 10.0.0.1 23 port [tcp/*] failed: Connection refused
"#;

        let result = NetcatParser::parse(content).unwrap();

        assert_eq!(result.hosts.len(), 1);
        assert_eq!(result.hosts[0].ports.len(), 2);

        let ssh_port = result.hosts[0].ports.iter().find(|p| p.port == 22).unwrap();
        assert_eq!(ssh_port.state, PortState::Open);

        let telnet_port = result.hosts[0].ports.iter().find(|p| p.port == 23).unwrap();
        assert_eq!(telnet_port.state, PortState::Closed);
    }

    #[test]
    fn test_parse_unknown_format() {
        let content = r#"
(UNKNOWN) [192.168.1.1] 22 (ssh) open
(UNKNOWN) [192.168.1.1] 80 (http) open
"#;

        let result = NetcatParser::parse(content).unwrap();

        assert_eq!(result.hosts.len(), 1);
        assert_eq!(result.hosts[0].ports.len(), 2);
    }
}
