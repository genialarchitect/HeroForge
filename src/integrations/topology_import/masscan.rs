//! Masscan JSON output parser
//!
//! Parses masscan's JSON output format (-oJ flag)

use anyhow::Result;
use chrono::{TimeZone, Utc};
use serde::Deserialize;
use std::collections::HashMap;

use super::types::{
    HostStatus, ImportedPort, ImportedTopologyHost, PortState, ScanMetadata,
    TopologyImportResult, TopologyImportSource,
};

/// Masscan JSON entry for a single port result
#[derive(Debug, Deserialize)]
struct MasscanEntry {
    ip: String,
    timestamp: Option<String>,
    ports: Option<Vec<MasscanPort>>,
    // Some masscan versions use different field names
    port: Option<u16>,
    proto: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MasscanPort {
    port: u16,
    proto: String,
    status: Option<String>,
    reason: Option<String>,
    ttl: Option<u8>,
    #[serde(rename = "service")]
    service: Option<MasscanService>,
}

#[derive(Debug, Deserialize)]
struct MasscanService {
    name: Option<String>,
    banner: Option<String>,
}

/// Parser for Masscan JSON output
pub struct MasscanParser;

impl MasscanParser {
    /// Parse masscan JSON content
    pub fn parse(content: &str) -> Result<TopologyImportResult> {
        let mut result = TopologyImportResult::new(TopologyImportSource::MasscanJson);
        result.metadata.scanner = "masscan".to_string();

        // Masscan JSON can be either an array or newline-delimited JSON objects
        let content = content.trim();

        // Try parsing as a JSON array first
        let entries: Vec<MasscanEntry> = if content.starts_with('[') {
            // Clean up trailing commas that masscan sometimes produces
            let cleaned = Self::clean_json_array(content);
            serde_json::from_str(&cleaned).unwrap_or_else(|_| Vec::new())
        } else {
            // Parse as newline-delimited JSON
            content
                .lines()
                .filter(|line| {
                    let line = line.trim();
                    !line.is_empty() && !line.starts_with('{') && line.contains("\"ip\"")
                })
                .filter_map(|line| {
                    let line = line.trim().trim_end_matches(',');
                    serde_json::from_str(line).ok()
                })
                .collect()
        };

        // Group entries by IP
        let mut hosts_map: HashMap<String, ImportedTopologyHost> = HashMap::new();

        for entry in entries {
            let host = hosts_map.entry(entry.ip.clone()).or_insert_with(|| {
                let mut h = ImportedTopologyHost::default();
                h.ip = entry.ip.clone();
                h.status = HostStatus::Up;

                // Parse timestamp
                if let Some(ts_str) = &entry.timestamp {
                    if let Ok(ts) = ts_str.parse::<i64>() {
                        h.scan_time = Utc.timestamp_opt(ts, 0).single();
                    }
                }

                h
            });

            // Handle ports array format
            if let Some(ports) = entry.ports {
                for p in ports {
                    let mut port = ImportedPort {
                        port: p.port,
                        protocol: p.proto,
                        state: p.status.as_ref()
                            .map(|s| PortState::from_str(s))
                            .unwrap_or(PortState::Open),
                        ..Default::default()
                    };

                    if let Some(svc) = p.service {
                        port.service = svc.name;
                        port.banner = svc.banner;
                    }

                    // Avoid duplicate ports
                    if !host.ports.iter().any(|existing| existing.port == port.port && existing.protocol == port.protocol) {
                        host.ports.push(port);
                    }
                }
            }

            // Handle flat format (port and proto at top level)
            if let (Some(port_num), Some(proto)) = (entry.port, entry.proto) {
                let port = ImportedPort {
                    port: port_num,
                    protocol: proto,
                    state: PortState::Open,
                    ..Default::default()
                };

                if !host.ports.iter().any(|existing| existing.port == port.port && existing.protocol == port.protocol) {
                    host.ports.push(port);
                }
            }
        }

        result.hosts = hosts_map.into_values().collect();

        Ok(result)
    }

    /// Clean up masscan JSON which often has trailing commas
    fn clean_json_array(content: &str) -> String {
        // Remove trailing comma before closing bracket
        let re = regex::Regex::new(r",\s*\]").unwrap();
        re.replace_all(content, "]").to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_masscan_json_array() {
        let json = r#"[
            {"ip": "192.168.1.1", "timestamp": "1609459200", "ports": [{"port": 22, "proto": "tcp", "status": "open"}]},
            {"ip": "192.168.1.1", "timestamp": "1609459200", "ports": [{"port": 80, "proto": "tcp", "status": "open"}]},
            {"ip": "192.168.1.100", "timestamp": "1609459201", "ports": [{"port": 443, "proto": "tcp", "status": "open"}]}
        ]"#;

        let result = MasscanParser::parse(json).unwrap();

        assert_eq!(result.hosts.len(), 2);

        let host1 = result.hosts.iter().find(|h| h.ip == "192.168.1.1").unwrap();
        assert_eq!(host1.ports.len(), 2);
        assert!(host1.ports.iter().any(|p| p.port == 22));
        assert!(host1.ports.iter().any(|p| p.port == 80));

        let host2 = result.hosts.iter().find(|h| h.ip == "192.168.1.100").unwrap();
        assert_eq!(host2.ports.len(), 1);
        assert_eq!(host2.ports[0].port, 443);
    }

    #[test]
    fn test_parse_with_service_info() {
        let json = r#"[
            {
                "ip": "10.0.0.1",
                "timestamp": "1609459200",
                "ports": [{
                    "port": 22,
                    "proto": "tcp",
                    "status": "open",
                    "service": {"name": "ssh", "banner": "SSH-2.0-OpenSSH_8.0"}
                }]
            }
        ]"#;

        let result = MasscanParser::parse(json).unwrap();

        assert_eq!(result.hosts.len(), 1);
        assert_eq!(result.hosts[0].ports[0].service, Some("ssh".to_string()));
        assert_eq!(result.hosts[0].ports[0].banner, Some("SSH-2.0-OpenSSH_8.0".to_string()));
    }

    #[test]
    fn test_parse_with_trailing_comma() {
        let json = r#"[
            {"ip": "192.168.1.1", "ports": [{"port": 22, "proto": "tcp"}]},
        ]"#;

        let result = MasscanParser::parse(json).unwrap();
        assert_eq!(result.hosts.len(), 1);
    }
}
