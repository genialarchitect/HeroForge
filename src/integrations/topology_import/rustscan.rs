//! Rustscan output parser
//!
//! Parses rustscan output format (similar to nmap but with different formatting)

use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;

use super::types::{
    HostStatus, ImportedPort, ImportedTopologyHost, PortState, TopologyImportResult,
    TopologyImportSource,
};

/// Parser for Rustscan output
pub struct RustscanParser;

impl RustscanParser {
    /// Parse rustscan output content
    ///
    /// Supports multiple rustscan output formats:
    /// - Standard output: `Open 192.168.1.1:22`
    /// - Greppable: `192.168.1.1 -> [22,80,443]`
    /// - JSON-like: `{"ip":"192.168.1.1","ports":[22,80,443]}`
    pub fn parse(content: &str) -> Result<TopologyImportResult> {
        let mut result = TopologyImportResult::new(TopologyImportSource::Rustscan);
        result.metadata.scanner = "rustscan".to_string();

        // Try to detect the format and parse accordingly
        if content.contains("->") && content.contains("[") {
            Self::parse_greppable(content, &mut result);
        } else if content.starts_with("{") || content.starts_with("[") {
            Self::parse_json(content, &mut result);
        } else {
            Self::parse_standard(content, &mut result);
        }

        Ok(result)
    }

    /// Parse standard rustscan output format
    fn parse_standard(content: &str, result: &mut TopologyImportResult) {
        // Patterns for standard rustscan output
        let open_pattern = Regex::new(r"Open\s+(\S+):(\d+)").unwrap();
        let found_pattern = Regex::new(r"(\d+\.\d+\.\d+\.\d+)\s*:\s*(\d+)").unwrap();

        let mut hosts_map: HashMap<String, ImportedTopologyHost> = HashMap::new();

        for line in content.lines() {
            let line = line.trim();

            // Try Open format
            if let Some(caps) = open_pattern.captures(line) {
                let ip = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
                let port: u16 = caps.get(2)
                    .and_then(|m| m.as_str().parse().ok())
                    .unwrap_or(0);

                if !ip.is_empty() && port != 0 {
                    Self::add_port(&mut hosts_map, ip, port);
                }
                continue;
            }

            // Try IP:port format
            if let Some(caps) = found_pattern.captures(line) {
                let ip = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
                let port: u16 = caps.get(2)
                    .and_then(|m| m.as_str().parse().ok())
                    .unwrap_or(0);

                if !ip.is_empty() && port != 0 {
                    Self::add_port(&mut hosts_map, ip, port);
                }
            }
        }

        result.hosts = hosts_map.into_values().collect();
    }

    /// Parse greppable format: `192.168.1.1 -> [22,80,443]`
    fn parse_greppable(content: &str, result: &mut TopologyImportResult) {
        let pattern = Regex::new(r"(\d+\.\d+\.\d+\.\d+)\s*->\s*\[([^\]]+)\]").unwrap();

        let mut hosts_map: HashMap<String, ImportedTopologyHost> = HashMap::new();

        for line in content.lines() {
            let line = line.trim();

            if let Some(caps) = pattern.captures(line) {
                let ip = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
                let ports_str = caps.get(2).map(|m| m.as_str()).unwrap_or("");

                if ip.is_empty() {
                    continue;
                }

                for port_str in ports_str.split(',') {
                    if let Ok(port) = port_str.trim().parse::<u16>() {
                        Self::add_port(&mut hosts_map, ip.clone(), port);
                    }
                }
            }
        }

        result.hosts = hosts_map.into_values().collect();
    }

    /// Parse JSON format output
    fn parse_json(content: &str, result: &mut TopologyImportResult) {
        // Try to parse as JSON array or object
        #[derive(serde::Deserialize)]
        struct RustscanJson {
            ip: Option<String>,
            ports: Option<Vec<u16>>,
        }

        let mut hosts_map: HashMap<String, ImportedTopologyHost> = HashMap::new();

        // Try parsing as array
        if let Ok(entries) = serde_json::from_str::<Vec<RustscanJson>>(content) {
            for entry in entries {
                if let (Some(ip), Some(ports)) = (entry.ip, entry.ports) {
                    for port in ports {
                        Self::add_port(&mut hosts_map, ip.clone(), port);
                    }
                }
            }
        } else {
            // Try parsing as newline-delimited JSON
            for line in content.lines() {
                let line = line.trim();
                if let Ok(entry) = serde_json::from_str::<RustscanJson>(line) {
                    if let (Some(ip), Some(ports)) = (entry.ip, entry.ports) {
                        for port in ports {
                            Self::add_port(&mut hosts_map, ip.clone(), port);
                        }
                    }
                }
            }
        }

        result.hosts = hosts_map.into_values().collect();
    }

    /// Helper to add a port to a host
    fn add_port(hosts_map: &mut HashMap<String, ImportedTopologyHost>, ip: String, port: u16) {
        let host = hosts_map.entry(ip.clone()).or_insert_with(|| {
            let mut h = ImportedTopologyHost::default();
            h.ip = ip;
            h.status = HostStatus::Up;
            h
        });

        if !host.ports.iter().any(|p| p.port == port) {
            host.ports.push(ImportedPort {
                port,
                protocol: "tcp".to_string(),
                state: PortState::Open,
                ..Default::default()
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_open_format() {
        let content = r#"
Open 192.168.1.1:22
Open 192.168.1.1:80
Open 192.168.1.1:443
Open 192.168.1.100:22
"#;

        let result = RustscanParser::parse(content).unwrap();

        assert_eq!(result.hosts.len(), 2);

        let host1 = result.hosts.iter().find(|h| h.ip == "192.168.1.1").unwrap();
        assert_eq!(host1.ports.len(), 3);
    }

    #[test]
    fn test_parse_greppable_format() {
        let content = r#"
192.168.1.1 -> [22,80,443]
192.168.1.100 -> [22,3389]
"#;

        let result = RustscanParser::parse(content).unwrap();

        assert_eq!(result.hosts.len(), 2);

        let host1 = result.hosts.iter().find(|h| h.ip == "192.168.1.1").unwrap();
        assert_eq!(host1.ports.len(), 3);

        let host2 = result.hosts.iter().find(|h| h.ip == "192.168.1.100").unwrap();
        assert_eq!(host2.ports.len(), 2);
    }

    #[test]
    fn test_parse_json_format() {
        let content = r#"[
            {"ip": "192.168.1.1", "ports": [22, 80, 443]},
            {"ip": "192.168.1.100", "ports": [22]}
        ]"#;

        let result = RustscanParser::parse(content).unwrap();

        assert_eq!(result.hosts.len(), 2);
    }

    #[test]
    fn test_parse_ip_port_format() {
        let content = r#"
192.168.1.1:22
192.168.1.1:80
192.168.1.100:443
"#;

        let result = RustscanParser::parse(content).unwrap();

        assert_eq!(result.hosts.len(), 2);
    }
}
