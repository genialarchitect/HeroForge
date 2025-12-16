use anyhow::Result;
use std::path::Path;
use tokio::fs;

use crate::types::{HostInfo, PortState, Severity};

/// Generate a CSV report from scan results
///
/// CSV format flattens hierarchical scan data into rows with columns:
/// host_ip, hostname, port, protocol, state, service_name, service_version,
/// vulnerability_id, vulnerability_severity, vulnerability_description
pub async fn generate(hosts: &[HostInfo], output_path: &str) -> Result<(String, i64)> {
    // Ensure parent directory exists
    if let Some(parent) = Path::new(output_path).parent() {
        fs::create_dir_all(parent).await?;
    }

    let mut csv_writer = csv::WriterBuilder::new()
        .has_headers(true)
        .from_path(output_path)?;

    // Write CSV header
    csv_writer.write_record(&[
        "host_ip",
        "hostname",
        "port",
        "protocol",
        "state",
        "service_name",
        "service_version",
        "vulnerability_id",
        "vulnerability_severity",
        "vulnerability_description",
    ])?;

    // Write data rows
    for host in hosts {
        let ip = host.target.ip.to_string();
        let hostname = host.target.hostname.as_deref().unwrap_or("");

        // If host has no ports or vulnerabilities, write one row for the host
        if host.ports.is_empty() && host.vulnerabilities.is_empty() {
            csv_writer.write_record(&[
                &ip,
                hostname,
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
            ])?;
            continue;
        }

        // Write rows for each port
        for port in &host.ports {
            let port_num = port.port.to_string();
            let protocol = match port.protocol {
                crate::types::Protocol::TCP => "TCP",
                crate::types::Protocol::UDP => "UDP",
            };
            let state = match port.state {
                PortState::Open => "open",
                PortState::Closed => "closed",
                PortState::Filtered => "filtered",
                PortState::OpenFiltered => "open|filtered",
            };
            let service_name = port.service.as_ref().map(|s| s.name.as_str()).unwrap_or("");
            let service_version = port.service.as_ref()
                .and_then(|s| s.version.as_deref())
                .unwrap_or("");

            // Find vulnerabilities related to this port's service
            let port_vulns: Vec<_> = host.vulnerabilities.iter()
                .filter(|v| {
                    v.affected_service.as_ref()
                        .map(|svc| port.service.as_ref()
                            .map(|ps| svc.contains(&ps.name))
                            .unwrap_or(false))
                        .unwrap_or(false)
                })
                .collect();

            if port_vulns.is_empty() {
                // Port with no vulnerabilities
                csv_writer.write_record(&[
                    &ip,
                    hostname,
                    &port_num,
                    protocol,
                    state,
                    service_name,
                    service_version,
                    "",
                    "",
                    "",
                ])?;
            } else {
                // Port with vulnerabilities - one row per vulnerability
                for vuln in port_vulns {
                    csv_writer.write_record(&[
                        &ip,
                        hostname,
                        &port_num,
                        protocol,
                        state,
                        service_name,
                        service_version,
                        vuln.cve_id.as_deref().unwrap_or(""),
                        &severity_to_string(&vuln.severity),
                        &vuln.description,
                    ])?;
                }
            }
        }

        // Write rows for host-level vulnerabilities (not tied to a specific port)
        let host_level_vulns: Vec<_> = host.vulnerabilities.iter()
            .filter(|v| v.affected_service.is_none())
            .collect();

        for vuln in host_level_vulns {
            csv_writer.write_record(&[
                &ip,
                hostname,
                "",
                "",
                "",
                "",
                "",
                vuln.cve_id.as_deref().unwrap_or(""),
                &severity_to_string(&vuln.severity),
                &vuln.description,
            ])?;
        }
    }

    csv_writer.flush()?;

    // Get file size
    let metadata = fs::metadata(output_path).await?;
    let file_size = metadata.len() as i64;

    Ok((output_path.to_string(), file_size))
}

fn severity_to_string(severity: &Severity) -> String {
    match severity {
        Severity::Low => "low".to_string(),
        Severity::Medium => "medium".to_string(),
        Severity::High => "high".to_string(),
        Severity::Critical => "critical".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{HostInfo, PortInfo, Protocol, PortState, ServiceInfo, Vulnerability, ScanTarget, Severity};
    use std::net::IpAddr;
    use std::time::Duration;

    #[tokio::test]
    async fn test_csv_generation_basic() {
        let host = HostInfo {
            target: ScanTarget {
                ip: "192.168.1.1".parse::<IpAddr>().unwrap(),
                hostname: Some("test.local".to_string()),
            },
            is_alive: true,
            os_guess: None,
            ports: vec![
                PortInfo {
                    port: 80,
                    protocol: Protocol::TCP,
                    state: PortState::Open,
                    service: Some(ServiceInfo {
                        name: "http".to_string(),
                        version: Some("2.4.41".to_string()),
                        banner: None,
                        cpe: None,
                        enumeration: None,
                    }),
                },
            ],
            vulnerabilities: vec![],
            scan_duration: Duration::from_secs(5),
        };

        let temp_dir = std::env::temp_dir();
        let output_path = temp_dir.join("test_scan.csv");
        let output_str = output_path.to_string_lossy().to_string();

        let result = generate(&[host], &output_str).await;
        assert!(result.is_ok());

        // Cleanup
        let _ = fs::remove_file(output_path).await;
    }

    #[tokio::test]
    async fn test_csv_generation_with_vulnerabilities() {
        let host = HostInfo {
            target: ScanTarget {
                ip: "192.168.1.1".parse::<IpAddr>().unwrap(),
                hostname: Some("test.local".to_string()),
            },
            is_alive: true,
            os_guess: None,
            ports: vec![
                PortInfo {
                    port: 22,
                    protocol: Protocol::TCP,
                    state: PortState::Open,
                    service: Some(ServiceInfo {
                        name: "ssh".to_string(),
                        version: Some("OpenSSH 7.4".to_string()),
                        banner: None,
                        cpe: None,
                        enumeration: None,
                    }),
                },
            ],
            vulnerabilities: vec![
                Vulnerability {
                    cve_id: Some("CVE-2023-1234".to_string()),
                    title: "Test Vulnerability".to_string(),
                    severity: Severity::High,
                    description: "Test description".to_string(),
                    affected_service: Some("ssh".to_string()),
                },
            ],
            scan_duration: Duration::from_secs(5),
        };

        let temp_dir = std::env::temp_dir();
        let output_path = temp_dir.join("test_scan_vuln.csv");
        let output_str = output_path.to_string_lossy().to_string();

        let result = generate(&[host], &output_str).await;
        assert!(result.is_ok());

        // Verify file exists and has content
        let content = fs::read_to_string(&output_path).await.unwrap();
        assert!(content.contains("CVE-2023-1234"));
        assert!(content.contains("high"));

        // Cleanup
        let _ = fs::remove_file(output_path).await;
    }
}
