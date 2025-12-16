use crate::types::{HostInfo, PortInfo, Vulnerability};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Represents changes between two scans
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanDiff {
    /// New hosts that appeared in scan 2
    pub new_hosts: Vec<String>,
    /// Hosts that disappeared from scan 1 to scan 2
    pub removed_hosts: Vec<String>,
    /// Changes per host (only for hosts that exist in both scans)
    pub host_changes: Vec<HostDiff>,
    /// Summary statistics
    pub summary: DiffSummary,
}

/// Summary statistics for scan comparison
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffSummary {
    pub total_new_hosts: usize,
    pub total_removed_hosts: usize,
    pub total_hosts_changed: usize,
    pub total_new_ports: usize,
    pub total_closed_ports: usize,
    pub total_new_vulnerabilities: usize,
    pub total_resolved_vulnerabilities: usize,
    pub total_service_changes: usize,
}

/// Changes for a specific host
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostDiff {
    /// IP address of the host
    pub ip: String,
    /// Hostname (if available)
    pub hostname: Option<String>,
    /// Ports that are newly open
    pub new_ports: Vec<PortInfo>,
    /// Ports that were open but are now closed/filtered
    pub closed_ports: Vec<PortInfo>,
    /// New vulnerabilities detected
    pub new_vulnerabilities: Vec<Vulnerability>,
    /// Vulnerabilities that are no longer present
    pub resolved_vulnerabilities: Vec<Vulnerability>,
    /// Changes in service detection
    pub service_changes: Vec<ServiceChange>,
    /// OS detection changes
    pub os_change: Option<OsChange>,
}

/// Represents a change in service detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceChange {
    pub port: u16,
    pub protocol: String,
    pub old_service: Option<String>,
    pub new_service: Option<String>,
    pub old_version: Option<String>,
    pub new_version: Option<String>,
    pub change_type: ServiceChangeType,
}

/// Type of service change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServiceChangeType {
    NewService,
    ServiceChanged,
    VersionChanged,
    ServiceRemoved,
}

/// Represents a change in OS detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsChange {
    pub old_os: String,
    pub new_os: String,
    pub old_confidence: u8,
    pub new_confidence: u8,
}

/// Compare two scan results and return differences
pub fn compare_scans(scan1_results: Vec<HostInfo>, scan2_results: Vec<HostInfo>) -> ScanDiff {
    // Create host maps indexed by IP address
    let hosts1: HashMap<String, HostInfo> = scan1_results
        .into_iter()
        .map(|h| (h.target.ip.to_string(), h))
        .collect();

    let hosts2: HashMap<String, HostInfo> = scan2_results
        .into_iter()
        .map(|h| (h.target.ip.to_string(), h))
        .collect();

    let ips1: HashSet<String> = hosts1.keys().cloned().collect();
    let ips2: HashSet<String> = hosts2.keys().cloned().collect();

    // Find new and removed hosts
    let new_hosts: Vec<String> = ips2.difference(&ips1).cloned().collect();
    let removed_hosts: Vec<String> = ips1.difference(&ips2).cloned().collect();

    // Find common hosts and compare them
    let common_ips: HashSet<String> = ips1.intersection(&ips2).cloned().collect();
    let mut host_changes = Vec::new();

    for ip in common_ips {
        let host1 = hosts1.get(&ip).unwrap();
        let host2 = hosts2.get(&ip).unwrap();

        let diff = compare_hosts(host1, host2);

        // Only include hosts with actual changes
        if has_changes(&diff) {
            host_changes.push(diff);
        }
    }

    // Calculate summary statistics
    let total_new_ports: usize = host_changes.iter().map(|h| h.new_ports.len()).sum();
    let total_closed_ports: usize = host_changes.iter().map(|h| h.closed_ports.len()).sum();
    let total_new_vulnerabilities: usize = host_changes
        .iter()
        .map(|h| h.new_vulnerabilities.len())
        .sum();
    let total_resolved_vulnerabilities: usize = host_changes
        .iter()
        .map(|h| h.resolved_vulnerabilities.len())
        .sum();
    let total_service_changes: usize = host_changes.iter().map(|h| h.service_changes.len()).sum();

    let summary = DiffSummary {
        total_new_hosts: new_hosts.len(),
        total_removed_hosts: removed_hosts.len(),
        total_hosts_changed: host_changes.len(),
        total_new_ports,
        total_closed_ports,
        total_new_vulnerabilities,
        total_resolved_vulnerabilities,
        total_service_changes,
    };

    ScanDiff {
        new_hosts,
        removed_hosts,
        host_changes,
        summary,
    }
}

/// Compare two hosts and return differences
fn compare_hosts(host1: &HostInfo, host2: &HostInfo) -> HostDiff {
    let ip = host1.target.ip.to_string();
    let hostname = host2.target.hostname.clone();

    // Compare ports
    let ports1: HashMap<u16, &PortInfo> = host1
        .ports
        .iter()
        .map(|p| (p.port, p))
        .collect();

    let ports2: HashMap<u16, &PortInfo> = host2
        .ports
        .iter()
        .map(|p| (p.port, p))
        .collect();

    let port_nums1: HashSet<u16> = ports1.keys().cloned().collect();
    let port_nums2: HashSet<u16> = ports2.keys().cloned().collect();

    // Find new and closed ports
    let new_port_nums: Vec<u16> = port_nums2.difference(&port_nums1).cloned().collect();
    let closed_port_nums: Vec<u16> = port_nums1.difference(&port_nums2).cloned().collect();

    let new_ports: Vec<PortInfo> = new_port_nums
        .iter()
        .filter_map(|port_num| ports2.get(port_num).map(|p| (*p).clone()))
        .collect();

    let closed_ports: Vec<PortInfo> = closed_port_nums
        .iter()
        .filter_map(|port_num| ports1.get(port_num).map(|p| (*p).clone()))
        .collect();

    // Compare services on common ports
    let common_ports: HashSet<u16> = port_nums1.intersection(&port_nums2).cloned().collect();
    let mut service_changes = Vec::new();

    for port_num in common_ports {
        let port1 = ports1.get(&port_num).unwrap();
        let port2 = ports2.get(&port_num).unwrap();

        // Check for service changes
        let service1_name = port1.service.as_ref().map(|s| s.name.as_str());
        let service2_name = port2.service.as_ref().map(|s| s.name.as_str());

        let version1 = port1.service.as_ref().and_then(|s| s.version.as_ref());
        let version2 = port2.service.as_ref().and_then(|s| s.version.as_ref());

        let protocol = format!("{:?}", port1.protocol);

        if service1_name != service2_name || version1 != version2 {
            let change_type = match (service1_name, service2_name) {
                (None, Some(_)) => ServiceChangeType::NewService,
                (Some(_), None) => ServiceChangeType::ServiceRemoved,
                (Some(s1), Some(s2)) if s1 != s2 => ServiceChangeType::ServiceChanged,
                (Some(_), Some(_)) => ServiceChangeType::VersionChanged,
                (None, None) => continue, // No change
            };

            service_changes.push(ServiceChange {
                port: port_num,
                protocol,
                old_service: service1_name.map(|s| s.to_string()),
                new_service: service2_name.map(|s| s.to_string()),
                old_version: version1.cloned(),
                new_version: version2.cloned(),
                change_type,
            });
        }
    }

    // Compare vulnerabilities
    let vulns1: HashSet<String> = host1
        .vulnerabilities
        .iter()
        .map(|v| vulnerability_key(v))
        .collect();

    let vulns2: HashSet<String> = host2
        .vulnerabilities
        .iter()
        .map(|v| vulnerability_key(v))
        .collect();

    let new_vuln_keys: Vec<String> = vulns2.difference(&vulns1).cloned().collect();
    let resolved_vuln_keys: Vec<String> = vulns1.difference(&vulns2).cloned().collect();

    let new_vulnerabilities: Vec<Vulnerability> = host2
        .vulnerabilities
        .iter()
        .filter(|v| new_vuln_keys.contains(&vulnerability_key(v)))
        .cloned()
        .collect();

    let resolved_vulnerabilities: Vec<Vulnerability> = host1
        .vulnerabilities
        .iter()
        .filter(|v| resolved_vuln_keys.contains(&vulnerability_key(v)))
        .cloned()
        .collect();

    // Compare OS detection
    let os_change = match (&host1.os_guess, &host2.os_guess) {
        (Some(os1), Some(os2)) => {
            if os1.os_family != os2.os_family {
                Some(OsChange {
                    old_os: os1.os_family.clone(),
                    new_os: os2.os_family.clone(),
                    old_confidence: os1.confidence,
                    new_confidence: os2.confidence,
                })
            } else {
                None
            }
        }
        _ => None,
    };

    HostDiff {
        ip,
        hostname,
        new_ports,
        closed_ports,
        new_vulnerabilities,
        resolved_vulnerabilities,
        service_changes,
        os_change,
    }
}

/// Check if a HostDiff has any actual changes
fn has_changes(diff: &HostDiff) -> bool {
    !diff.new_ports.is_empty()
        || !diff.closed_ports.is_empty()
        || !diff.new_vulnerabilities.is_empty()
        || !diff.resolved_vulnerabilities.is_empty()
        || !diff.service_changes.is_empty()
        || diff.os_change.is_some()
}

/// Create a unique key for a vulnerability (for comparison)
fn vulnerability_key(vuln: &Vulnerability) -> String {
    format!(
        "{}:{}:{}",
        vuln.cve_id.as_deref().unwrap_or(""),
        vuln.title,
        vuln.affected_service.as_deref().unwrap_or("")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{PortState, Protocol, ScanTarget, ServiceInfo};
    use std::net::IpAddr;
    use std::time::Duration;

    fn create_test_host(ip: &str, ports: Vec<u16>) -> HostInfo {
        HostInfo {
            target: ScanTarget {
                ip: ip.parse::<IpAddr>().unwrap(),
                hostname: None,
            },
            is_alive: true,
            os_guess: None,
            ports: ports
                .into_iter()
                .map(|p| PortInfo {
                    port: p,
                    protocol: Protocol::TCP,
                    state: PortState::Open,
                    service: Some(ServiceInfo {
                        name: format!("service_{}", p),
                        version: None,
                        banner: None,
                        cpe: None,
                        enumeration: None,
                        ssl_info: None,
                    }),
                })
                .collect(),
            vulnerabilities: Vec::new(),
            scan_duration: Duration::from_secs(1),
        }
    }

    #[test]
    fn test_compare_new_host() {
        let scan1 = vec![create_test_host("192.168.1.1", vec![80, 443])];
        let scan2 = vec![
            create_test_host("192.168.1.1", vec![80, 443]),
            create_test_host("192.168.1.2", vec![22]),
        ];

        let diff = compare_scans(scan1, scan2);
        assert_eq!(diff.new_hosts.len(), 1);
        assert_eq!(diff.new_hosts[0], "192.168.1.2");
        assert_eq!(diff.removed_hosts.len(), 0);
    }

    #[test]
    fn test_compare_removed_host() {
        let scan1 = vec![
            create_test_host("192.168.1.1", vec![80, 443]),
            create_test_host("192.168.1.2", vec![22]),
        ];
        let scan2 = vec![create_test_host("192.168.1.1", vec![80, 443])];

        let diff = compare_scans(scan1, scan2);
        assert_eq!(diff.new_hosts.len(), 0);
        assert_eq!(diff.removed_hosts.len(), 1);
        assert_eq!(diff.removed_hosts[0], "192.168.1.2");
    }

    #[test]
    fn test_compare_new_port() {
        let scan1 = vec![create_test_host("192.168.1.1", vec![80])];
        let scan2 = vec![create_test_host("192.168.1.1", vec![80, 443])];

        let diff = compare_scans(scan1, scan2);
        assert_eq!(diff.host_changes.len(), 1);
        assert_eq!(diff.host_changes[0].new_ports.len(), 1);
        assert_eq!(diff.host_changes[0].new_ports[0].port, 443);
    }

    #[test]
    fn test_compare_closed_port() {
        let scan1 = vec![create_test_host("192.168.1.1", vec![80, 443])];
        let scan2 = vec![create_test_host("192.168.1.1", vec![80])];

        let diff = compare_scans(scan1, scan2);
        assert_eq!(diff.host_changes.len(), 1);
        assert_eq!(diff.host_changes[0].closed_ports.len(), 1);
        assert_eq!(diff.host_changes[0].closed_ports[0].port, 443);
    }

    #[test]
    fn test_summary_statistics() {
        let scan1 = vec![create_test_host("192.168.1.1", vec![80])];
        let scan2 = vec![
            create_test_host("192.168.1.1", vec![80, 443]),
            create_test_host("192.168.1.2", vec![22]),
        ];

        let diff = compare_scans(scan1, scan2);
        assert_eq!(diff.summary.total_new_hosts, 1);
        assert_eq!(diff.summary.total_removed_hosts, 0);
        assert_eq!(diff.summary.total_hosts_changed, 1);
        assert_eq!(diff.summary.total_new_ports, 1);
    }
}
