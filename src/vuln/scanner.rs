#![allow(dead_code)]

use anyhow::Result;
use crate::cve::{CveConfig, CveScanner};
use crate::types::{HostInfo, ScanConfig, Severity, Vulnerability};
use log::debug;
use sqlx::SqlitePool;

/// Scan for vulnerabilities on a host (with database for caching)
pub async fn scan_vulnerabilities_with_db(
    host_info: &HostInfo,
    _config: &ScanConfig,
    pool: &SqlitePool,
) -> Result<Vec<Vulnerability>, anyhow::Error> {
    debug!("Scanning for vulnerabilities on {} (with CVE cache)", host_info.target.ip);

    let cve_scanner = CveScanner::new(
        pool.clone(),
        CveConfig::default(),
    );

    let mut vulnerabilities = cve_scanner.lookup_host_cves(&host_info.ports).await?;

    // Add misconfiguration checks
    vulnerabilities.extend(check_misconfigurations(host_info));

    // Add SSL/TLS vulnerabilities
    vulnerabilities.extend(check_ssl_vulnerabilities(host_info));

    Ok(vulnerabilities)
}

/// Scan for vulnerabilities on a host (offline mode, no database)
pub async fn scan_vulnerabilities(
    host_info: &HostInfo,
    _config: &ScanConfig,
) -> Result<Vec<Vulnerability>, anyhow::Error> {
    debug!("Scanning for vulnerabilities on {} (offline mode)", host_info.target.ip);

    let cve_scanner = CveScanner::offline_only();

    let mut vulnerabilities = cve_scanner.lookup_host_cves(&host_info.ports).await?;

    // Add misconfiguration checks
    vulnerabilities.extend(check_misconfigurations(host_info));

    // Add SSL/TLS vulnerabilities
    vulnerabilities.extend(check_ssl_vulnerabilities(host_info));

    Ok(vulnerabilities)
}

/// Check for common misconfigurations based on open ports
fn check_misconfigurations(host_info: &HostInfo) -> Vec<Vulnerability> {
    let mut vulns = Vec::new();

    let open_ports: Vec<u16> = host_info.ports.iter().map(|p| p.port).collect();

    // Check for SMBv1 potential (MS17-010 EternalBlue)
    if open_ports.contains(&445) {
        vulns.push(Vulnerability {
            cve_id: Some("MS17-010".to_string()),
            title: "Potential SMBv1 Enabled".to_string(),
            severity: Severity::Critical,
            description: "SMB service detected on port 445. If SMBv1 is enabled, system may be vulnerable to EternalBlue. Verify SMBv1 is disabled.".to_string(),
            affected_service: Some("smb:445".to_string()),
        });
    }

    // Check for default RDP port exposure
    if open_ports.contains(&3389) {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "RDP Service on Default Port".to_string(),
            severity: Severity::Medium,
            description: "RDP is accessible on the default port 3389. Consider using a non-standard port, VPN, or enabling Network Level Authentication (NLA).".to_string(),
            affected_service: Some("rdp:3389".to_string()),
        });
    }

    // Check for default WinRM ports (potential for lateral movement)
    if open_ports.contains(&5985) || open_ports.contains(&5986) {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "WinRM Service Exposed".to_string(),
            severity: Severity::Medium,
            description: "Windows Remote Management (WinRM) is exposed. This can be used for lateral movement if credentials are compromised.".to_string(),
            affected_service: Some(format!("winrm:{}", if open_ports.contains(&5986) { 5986 } else { 5985 })),
        });
    }

    // Check for LDAP exposure (potential for enumeration)
    if open_ports.contains(&389) || open_ports.contains(&636) {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "LDAP Service Exposed".to_string(),
            severity: Severity::Medium,
            description: "LDAP service is exposed. This could allow enumeration of Active Directory objects if anonymous bind is enabled.".to_string(),
            affected_service: Some(format!("ldap:{}", if open_ports.contains(&636) { 636 } else { 389 })),
        });
    }

    // Check for Kerberos (indicates domain controller)
    if open_ports.contains(&88) {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "Kerberos Service Detected (Domain Controller)".to_string(),
            severity: Severity::Low,
            description: "Kerberos service detected, indicating this is likely a Domain Controller. Ensure it's properly secured.".to_string(),
            affected_service: Some("kerberos:88".to_string()),
        });
    }

    // Check for MS-SQL on default port
    if open_ports.contains(&1433) {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "MSSQL on Default Port".to_string(),
            severity: Severity::Low,
            description: "Microsoft SQL Server is exposed on the default port. Verify strong authentication is required.".to_string(),
            affected_service: Some("mssql:1433".to_string()),
        });
    }

    // Check for Oracle on default port
    if open_ports.contains(&1521) {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "Oracle Database Exposed".to_string(),
            severity: Severity::Medium,
            description: "Oracle database listener is exposed. Verify authentication and TNS configuration.".to_string(),
            affected_service: Some("oracle:1521".to_string()),
        });
    }

    // Check for VNC ports
    if open_ports.iter().any(|&p| (5900..=5909).contains(&p)) {
        let vnc_port = open_ports.iter().find(|&&p| (5900..=5909).contains(&p)).unwrap();
        vulns.push(Vulnerability {
            cve_id: None,
            title: "VNC Service Exposed".to_string(),
            severity: Severity::High,
            description: "VNC remote desktop service is exposed. VNC often has weak authentication and should be accessed via VPN only.".to_string(),
            affected_service: Some(format!("vnc:{}", vnc_port)),
        });
    }

    // Check for excessive open ports (potential misconfiguration)
    if open_ports.len() > 20 {
        vulns.push(Vulnerability {
            cve_id: None,
            title: "Excessive Open Ports".to_string(),
            severity: Severity::Low,
            description: format!(
                "{} ports are open. This may indicate missing firewall rules or unnecessary services. Review and disable unnecessary services.",
                open_ports.len()
            ),
            affected_service: None,
        });
    }

    vulns
}

/// Check for SSL/TLS security issues
fn check_ssl_vulnerabilities(host_info: &HostInfo) -> Vec<Vulnerability> {
    let mut vulns = Vec::new();

    for port in &host_info.ports {
        if let Some(ref service) = port.service {
            if let Some(ref ssl) = service.ssl_info {
                let port_str = format!("{}:{}", host_info.target.ip, port.port);

                // Check for expired certificates
                if ssl.cert_expired {
                    vulns.push(Vulnerability {
                        cve_id: None,
                        title: "Expired SSL/TLS Certificate".to_string(),
                        severity: Severity::High,
                        description: format!(
                            "The SSL/TLS certificate on {} has expired on {}. This will cause browser warnings and connection failures.",
                            port_str, ssl.valid_until
                        ),
                        affected_service: Some(format!("{}:{}", service.name, port.port)),
                    });
                }

                // Check for certificates expiring soon
                if !ssl.cert_expired {
                    if let Some(days) = ssl.days_until_expiry {
                        if days < 30 && days > 0 {
                            vulns.push(Vulnerability {
                                cve_id: None,
                                title: "SSL/TLS Certificate Expiring Soon".to_string(),
                                severity: Severity::Medium,
                                description: format!(
                                    "The SSL/TLS certificate on {} will expire in {} days on {}. Plan certificate renewal.",
                                    port_str, days, ssl.valid_until
                                ),
                                affected_service: Some(format!("{}:{}", service.name, port.port)),
                            });
                        }
                    }
                }

                // Check for self-signed certificates
                if ssl.self_signed {
                    vulns.push(Vulnerability {
                        cve_id: None,
                        title: "Self-Signed SSL/TLS Certificate".to_string(),
                        severity: Severity::Medium,
                        description: format!(
                            "The SSL/TLS certificate on {} is self-signed. Use a certificate from a trusted CA for production systems.",
                            port_str
                        ),
                        affected_service: Some(format!("{}:{}", service.name, port.port)),
                    });
                }

                // Check for hostname mismatch
                if ssl.hostname_mismatch {
                    vulns.push(Vulnerability {
                        cve_id: None,
                        title: "SSL/TLS Certificate Hostname Mismatch".to_string(),
                        severity: Severity::High,
                        description: format!(
                            "The SSL/TLS certificate on {} does not match the hostname. Certificate is for: {}",
                            port_str, ssl.subject
                        ),
                        affected_service: Some(format!("{}:{}", service.name, port.port)),
                    });
                }

                // Check for weak protocols
                if !ssl.weak_protocols.is_empty() {
                    vulns.push(Vulnerability {
                        cve_id: None,
                        title: "Weak SSL/TLS Protocols Enabled".to_string(),
                        severity: Severity::High,
                        description: format!(
                            "Weak or deprecated SSL/TLS protocols detected on {}: {}. Disable SSLv3, TLS 1.0, and TLS 1.1.",
                            port_str,
                            ssl.weak_protocols.join(", ")
                        ),
                        affected_service: Some(format!("{}:{}", service.name, port.port)),
                    });
                }

                // Check for weak ciphers
                if !ssl.weak_ciphers.is_empty() {
                    vulns.push(Vulnerability {
                        cve_id: None,
                        title: "Weak SSL/TLS Cipher Suites Enabled".to_string(),
                        severity: Severity::Medium,
                        description: format!(
                            "Weak cipher suites detected on {}: {}. Disable RC4, DES, 3DES, and export ciphers.",
                            port_str,
                            ssl.weak_ciphers.join(", ")
                        ),
                        affected_service: Some(format!("{}:{}", service.name, port.port)),
                    });
                }

                // Check for missing HSTS
                if !ssl.hsts_enabled && port.port == 443 {
                    vulns.push(Vulnerability {
                        cve_id: None,
                        title: "Missing HTTP Strict Transport Security (HSTS)".to_string(),
                        severity: Severity::Low,
                        description: format!(
                            "HSTS header not detected on {}. Enable HSTS to prevent SSL stripping attacks.",
                            port_str
                        ),
                        affected_service: Some(format!("{}:{}", service.name, port.port)),
                    });
                }

                // Check for certificate chain issues
                if !ssl.chain_issues.is_empty() {
                    vulns.push(Vulnerability {
                        cve_id: None,
                        title: "SSL/TLS Certificate Chain Issues".to_string(),
                        severity: Severity::Medium,
                        description: format!(
                            "Certificate chain issues detected on {}: {}",
                            port_str,
                            ssl.chain_issues.join(", ")
                        ),
                        affected_service: Some(format!("{}:{}", service.name, port.port)),
                    });
                }
            }
        }
    }

    vulns
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{PortInfo, PortState, Protocol, ScanTarget, ServiceInfo};
    use std::net::IpAddr;
    use std::time::Duration;

    fn create_test_host(ports: Vec<u16>) -> HostInfo {
        HostInfo {
            target: ScanTarget {
                ip: "192.168.1.1".parse::<IpAddr>().unwrap(),
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
                        name: "test".to_string(),
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
    fn test_misconfig_smb() {
        let host = create_test_host(vec![445]);
        let vulns = check_misconfigurations(&host);
        assert!(vulns.iter().any(|v| v.cve_id == Some("MS17-010".to_string())));
    }

    #[test]
    fn test_misconfig_rdp() {
        let host = create_test_host(vec![3389]);
        let vulns = check_misconfigurations(&host);
        assert!(vulns.iter().any(|v| v.title.contains("RDP")));
    }

    #[test]
    fn test_misconfig_excessive_ports() {
        let host = create_test_host((1..=25).collect());
        let vulns = check_misconfigurations(&host);
        assert!(vulns.iter().any(|v| v.title.contains("Excessive")));
    }
}
