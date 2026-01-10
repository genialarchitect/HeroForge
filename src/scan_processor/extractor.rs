//! Vulnerability Extractor
//!
//! Extracts vulnerabilities from scan results and creates tracking records
//! in the vulnerability_tracking table for lifecycle management.

use anyhow::Result;
use chrono::Utc;
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::types::{HostInfo, PortInfo, Severity, SslInfo};

/// Extracted vulnerability with additional context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedVulnerability {
    pub id: String,
    pub scan_id: String,
    pub host_ip: String,
    pub hostname: Option<String>,
    pub cve_id: Option<String>,
    pub title: String,
    pub severity: Severity,
    pub description: String,
    pub affected_service: Option<String>,
    pub port: Option<u16>,
    pub protocol: Option<String>,
    pub service_name: Option<String>,
    pub service_version: Option<String>,
    pub extraction_source: ExtractionSource,
    pub raw_data: Option<String>,
}

/// Source of vulnerability extraction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExtractionSource {
    /// From HostInfo.vulnerabilities
    ScanVulnerability,
    /// From SSL/TLS analysis
    SslAnalysis,
    /// From service version correlation
    ServiceVersion,
    /// From misconfiguration detection
    Misconfiguration,
    /// From protocol issues
    ProtocolIssue,
}

/// Extract all vulnerabilities from scan hosts and store in database
pub async fn extract_vulnerabilities(
    pool: &SqlitePool,
    scan_id: &str,
    hosts: &[HostInfo],
) -> Result<Vec<ExtractedVulnerability>> {
    let mut extracted = Vec::new();

    for host in hosts {
        let ip = host.target.ip.to_string();
        let hostname = host.target.hostname.clone();

        // Extract from host vulnerabilities list
        for vuln in &host.vulnerabilities {
            let extracted_vuln = ExtractedVulnerability {
                id: Uuid::new_v4().to_string(),
                scan_id: scan_id.to_string(),
                host_ip: ip.clone(),
                hostname: hostname.clone(),
                cve_id: vuln.cve_id.clone(),
                title: vuln.title.clone(),
                severity: vuln.severity.clone(),
                description: vuln.description.clone(),
                affected_service: vuln.affected_service.clone(),
                port: None,
                protocol: None,
                service_name: None,
                service_version: None,
                extraction_source: ExtractionSource::ScanVulnerability,
                raw_data: None,
            };
            extracted.push(extracted_vuln);
        }

        // Extract vulnerabilities from services and ports
        for port_info in &host.ports {
            // Extract SSL/TLS vulnerabilities
            if let Some(ref service) = port_info.service {
                if let Some(ref ssl_info) = service.ssl_info {
                    let ssl_vulns = extract_ssl_vulnerabilities(
                        scan_id, &ip, &hostname, port_info, ssl_info
                    );
                    extracted.extend(ssl_vulns);
                }

                // Extract service-based vulnerabilities
                let service_vulns = extract_service_vulnerabilities(
                    scan_id, &ip, &hostname, port_info, service
                );
                extracted.extend(service_vulns);
            }

            // Extract protocol-based issues
            let protocol_vulns = extract_protocol_issues(
                scan_id, &ip, &hostname, port_info
            );
            extracted.extend(protocol_vulns);
        }
    }

    // Store extracted vulnerabilities
    for vuln in &extracted {
        if let Err(e) = store_extracted_vulnerability(pool, vuln).await {
            warn!("Failed to store extracted vulnerability {}: {}", vuln.id, e);
        }
    }

    info!(
        "Extracted {} total vulnerabilities from {} hosts",
        extracted.len(),
        hosts.len()
    );

    Ok(extracted)
}

/// Extract SSL/TLS vulnerabilities from SSL info
fn extract_ssl_vulnerabilities(
    scan_id: &str,
    host_ip: &str,
    hostname: &Option<String>,
    port_info: &PortInfo,
    ssl_info: &SslInfo,
) -> Vec<ExtractedVulnerability> {
    let mut vulns = Vec::new();
    let port = port_info.port;

    // Expired certificate
    if ssl_info.cert_expired {
        vulns.push(ExtractedVulnerability {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.to_string(),
            host_ip: host_ip.to_string(),
            hostname: hostname.clone(),
            cve_id: None,
            title: "Expired SSL Certificate".to_string(),
            severity: Severity::High,
            description: format!(
                "SSL certificate has expired. Valid until: {}",
                ssl_info.valid_until
            ),
            affected_service: Some(format!("ssl:{}", port)),
            port: Some(port),
            protocol: Some("TCP".to_string()),
            service_name: None,
            service_version: None,
            extraction_source: ExtractionSource::SslAnalysis,
            raw_data: serde_json::to_string(ssl_info).ok(),
        });
    }

    // Certificate expiring soon (within 30 days)
    if let Some(days) = ssl_info.days_until_expiry {
        if days > 0 && days <= 30 {
            vulns.push(ExtractedVulnerability {
                id: Uuid::new_v4().to_string(),
                scan_id: scan_id.to_string(),
                host_ip: host_ip.to_string(),
                hostname: hostname.clone(),
                cve_id: None,
                title: "SSL Certificate Expiring Soon".to_string(),
                severity: Severity::Medium,
                description: format!(
                    "SSL certificate will expire in {} days ({})",
                    days, ssl_info.valid_until
                ),
                affected_service: Some(format!("ssl:{}", port)),
                port: Some(port),
                protocol: Some("TCP".to_string()),
                service_name: None,
                service_version: None,
                extraction_source: ExtractionSource::SslAnalysis,
                raw_data: None,
            });
        }
    }

    // Self-signed certificate
    if ssl_info.self_signed {
        vulns.push(ExtractedVulnerability {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.to_string(),
            host_ip: host_ip.to_string(),
            hostname: hostname.clone(),
            cve_id: None,
            title: "Self-Signed SSL Certificate".to_string(),
            severity: Severity::Medium,
            description: "Certificate is self-signed and not trusted by default".to_string(),
            affected_service: Some(format!("ssl:{}", port)),
            port: Some(port),
            protocol: Some("TCP".to_string()),
            service_name: None,
            service_version: None,
            extraction_source: ExtractionSource::SslAnalysis,
            raw_data: None,
        });
    }

    // Hostname mismatch
    if ssl_info.hostname_mismatch {
        vulns.push(ExtractedVulnerability {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.to_string(),
            host_ip: host_ip.to_string(),
            hostname: hostname.clone(),
            cve_id: None,
            title: "SSL Certificate Hostname Mismatch".to_string(),
            severity: Severity::Medium,
            description: format!(
                "Certificate subject '{}' does not match hostname",
                ssl_info.subject
            ),
            affected_service: Some(format!("ssl:{}", port)),
            port: Some(port),
            protocol: Some("TCP".to_string()),
            service_name: None,
            service_version: None,
            extraction_source: ExtractionSource::SslAnalysis,
            raw_data: None,
        });
    }

    // Weak protocols
    for weak_proto in &ssl_info.weak_protocols {
        let severity = if weak_proto.contains("SSLv3") || weak_proto.contains("SSLv2") {
            Severity::High
        } else {
            Severity::Medium
        };

        vulns.push(ExtractedVulnerability {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.to_string(),
            host_ip: host_ip.to_string(),
            hostname: hostname.clone(),
            cve_id: if weak_proto.contains("SSLv3") {
                Some("CVE-2014-3566".to_string()) // POODLE
            } else {
                None
            },
            title: format!("Weak SSL/TLS Protocol: {}", weak_proto),
            severity,
            description: format!(
                "Server supports deprecated/insecure protocol: {}. This may be vulnerable to known attacks.",
                weak_proto
            ),
            affected_service: Some(format!("ssl:{}", port)),
            port: Some(port),
            protocol: Some("TCP".to_string()),
            service_name: None,
            service_version: None,
            extraction_source: ExtractionSource::SslAnalysis,
            raw_data: None,
        });
    }

    // Weak ciphers
    for weak_cipher in &ssl_info.weak_ciphers {
        vulns.push(ExtractedVulnerability {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.to_string(),
            host_ip: host_ip.to_string(),
            hostname: hostname.clone(),
            cve_id: None,
            title: format!("Weak SSL/TLS Cipher: {}", weak_cipher),
            severity: Severity::Medium,
            description: format!(
                "Server supports weak cipher suite: {}. Consider disabling weak ciphers.",
                weak_cipher
            ),
            affected_service: Some(format!("ssl:{}", port)),
            port: Some(port),
            protocol: Some("TCP".to_string()),
            service_name: None,
            service_version: None,
            extraction_source: ExtractionSource::SslAnalysis,
            raw_data: None,
        });
    }

    // Missing HSTS
    if !ssl_info.hsts_enabled && port == 443 {
        vulns.push(ExtractedVulnerability {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.to_string(),
            host_ip: host_ip.to_string(),
            hostname: hostname.clone(),
            cve_id: None,
            title: "Missing HTTP Strict Transport Security (HSTS)".to_string(),
            severity: Severity::Low,
            description: "HSTS header is not enabled, allowing potential downgrade attacks".to_string(),
            affected_service: Some(format!("https:{}", port)),
            port: Some(port),
            protocol: Some("TCP".to_string()),
            service_name: Some("https".to_string()),
            service_version: None,
            extraction_source: ExtractionSource::SslAnalysis,
            raw_data: None,
        });
    }

    // Chain issues
    for issue in &ssl_info.chain_issues {
        vulns.push(ExtractedVulnerability {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.to_string(),
            host_ip: host_ip.to_string(),
            hostname: hostname.clone(),
            cve_id: None,
            title: "SSL Certificate Chain Issue".to_string(),
            severity: Severity::Medium,
            description: issue.clone(),
            affected_service: Some(format!("ssl:{}", port)),
            port: Some(port),
            protocol: Some("TCP".to_string()),
            service_name: None,
            service_version: None,
            extraction_source: ExtractionSource::SslAnalysis,
            raw_data: None,
        });
    }

    vulns
}

/// Extract vulnerabilities from service detection
fn extract_service_vulnerabilities(
    scan_id: &str,
    host_ip: &str,
    hostname: &Option<String>,
    port_info: &PortInfo,
    service: &crate::types::ServiceInfo,
) -> Vec<ExtractedVulnerability> {
    let mut vulns = Vec::new();
    let port = port_info.port;
    let service_name = service.name.to_lowercase();

    // Check for commonly misconfigured/dangerous exposed services
    let exposure_check = match service_name.as_str() {
        "redis" => Some((
            Severity::High,
            "Redis Exposed to Network",
            "Redis database is exposed. Verify authentication is enabled and access is restricted.",
        )),
        "mongodb" | "mongod" => Some((
            Severity::High,
            "MongoDB Exposed to Network",
            "MongoDB is exposed. Verify authentication is enabled and access is restricted.",
        )),
        "elasticsearch" => Some((
            Severity::High,
            "Elasticsearch Exposed to Network",
            "Elasticsearch is publicly accessible. Enable authentication and restrict access.",
        )),
        "memcached" => Some((
            Severity::High,
            "Memcached Exposed to Network",
            "Memcached is exposed. Can be used for DDoS amplification attacks.",
        )),
        "telnet" => Some((
            Severity::High,
            "Telnet Service Detected",
            "Telnet transmits all data including passwords in cleartext. Use SSH instead.",
        )),
        "ftp" => Some((
            Severity::Medium,
            "FTP Service Detected",
            "FTP transmits credentials in cleartext. Consider using SFTP or FTPS.",
        )),
        "vnc" => Some((
            Severity::Medium,
            "VNC Service Exposed",
            "VNC service is accessible. Verify authentication and consider tunneling through VPN.",
        )),
        "rdp" | "ms-wbt-server" => Some((
            Severity::Medium,
            "RDP Service Exposed",
            "Remote Desktop Protocol is exposed. Use Network Level Authentication and restrict access.",
        )),
        "smb" | "microsoft-ds" | "netbios-ssn" => Some((
            Severity::Medium,
            "SMB Service Exposed",
            "SMB/CIFS service is accessible. Verify it's intentional and properly secured.",
        )),
        _ => None,
    };

    if let Some((severity, title, description)) = exposure_check {
        vulns.push(ExtractedVulnerability {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.to_string(),
            host_ip: host_ip.to_string(),
            hostname: hostname.clone(),
            cve_id: None,
            title: title.to_string(),
            severity,
            description: description.to_string(),
            affected_service: Some(format!("{}:{}", service_name, port)),
            port: Some(port),
            protocol: Some(format!("{:?}", port_info.protocol)),
            service_name: Some(service_name.clone()),
            service_version: service.version.clone(),
            extraction_source: ExtractionSource::Misconfiguration,
            raw_data: None,
        });
    }

    // Check for outdated service versions (simplified version checks)
    if let Some(ref version) = service.version {
        let version_issues = check_known_vulnerable_versions(&service_name, version);
        for (cve_id, title, description, severity) in version_issues {
            vulns.push(ExtractedVulnerability {
                id: Uuid::new_v4().to_string(),
                scan_id: scan_id.to_string(),
                host_ip: host_ip.to_string(),
                hostname: hostname.clone(),
                cve_id: Some(cve_id.to_string()),
                title: title.to_string(),
                severity,
                description: description.to_string(),
                affected_service: Some(format!("{}:{}", service_name, port)),
                port: Some(port),
                protocol: Some(format!("{:?}", port_info.protocol)),
                service_name: Some(service_name.clone()),
                service_version: Some(version.clone()),
                extraction_source: ExtractionSource::ServiceVersion,
                raw_data: None,
            });
        }
    }

    vulns
}

/// Check for known vulnerable versions
fn check_known_vulnerable_versions(
    service: &str,
    version: &str,
) -> Vec<(&'static str, &'static str, &'static str, Severity)> {
    let mut issues = Vec::new();

    match service {
        "openssh" | "ssh" => {
            // Check for older OpenSSH versions with known vulnerabilities
            if version.starts_with("7.") || version.starts_with("6.") || version.starts_with("5.") {
                issues.push((
                    "CVE-2020-15778",
                    "Outdated OpenSSH Version",
                    "OpenSSH version may be vulnerable to various security issues. Update to latest stable.",
                    Severity::Medium,
                ));
            }
        }
        "apache" | "httpd" => {
            if version.contains("2.4.49") || version.contains("2.4.50") {
                issues.push((
                    "CVE-2021-41773",
                    "Apache Path Traversal Vulnerability",
                    "Apache HTTP Server vulnerable to path traversal and remote code execution",
                    Severity::Critical,
                ));
            }
            if version.starts_with("2.2.") {
                issues.push((
                    "CVE-2017-9798",
                    "Apache Outdated Version (2.2.x)",
                    "Apache 2.2.x is end-of-life and contains multiple vulnerabilities",
                    Severity::High,
                ));
            }
        }
        "nginx" => {
            if version.starts_with("1.16.") || version.starts_with("1.14.") || version.starts_with("1.12.") {
                issues.push((
                    "CVE-2019-20372",
                    "Outdated Nginx Version",
                    "Nginx version is outdated and may be vulnerable. Update to latest stable.",
                    Severity::Medium,
                ));
            }
        }
        "mysql" | "mariadb" => {
            if version.starts_with("5.5.") || version.starts_with("5.1.") {
                issues.push((
                    "CVE-2020-14812",
                    "Outdated MySQL/MariaDB Version",
                    "MySQL/MariaDB version is outdated and contains security vulnerabilities",
                    Severity::High,
                ));
            }
        }
        "postgresql" | "postgres" => {
            if version.starts_with("9.") || version.starts_with("10.") {
                issues.push((
                    "CVE-2021-23214",
                    "Outdated PostgreSQL Version",
                    "PostgreSQL version may be end-of-life or contain known vulnerabilities",
                    Severity::Medium,
                ));
            }
        }
        _ => {}
    }

    issues
}

/// Extract protocol-based issues
fn extract_protocol_issues(
    scan_id: &str,
    host_ip: &str,
    hostname: &Option<String>,
    port_info: &PortInfo,
) -> Vec<ExtractedVulnerability> {
    let mut vulns = Vec::new();
    let port = port_info.port;

    // Check for unencrypted services on sensitive ports
    if let Some(ref service) = port_info.service {
        let service_name = service.name.to_lowercase();

        // HTTP on sensitive ports without TLS
        if (port == 80 || port == 8080 || port == 8000)
            && (service_name == "http" || service_name.contains("http"))
            && service.ssl_info.is_none()
        {
            vulns.push(ExtractedVulnerability {
                id: Uuid::new_v4().to_string(),
                scan_id: scan_id.to_string(),
                host_ip: host_ip.to_string(),
                hostname: hostname.clone(),
                cve_id: None,
                title: "Unencrypted HTTP Service".to_string(),
                severity: Severity::Medium,
                description: "HTTP service without TLS encryption. Consider enabling HTTPS.".to_string(),
                affected_service: Some(format!("http:{}", port)),
                port: Some(port),
                protocol: Some("TCP".to_string()),
                service_name: Some(service_name),
                service_version: service.version.clone(),
                extraction_source: ExtractionSource::ProtocolIssue,
                raw_data: None,
            });
        }
    }

    vulns
}

/// Store extracted vulnerability in database
async fn store_extracted_vulnerability(
    pool: &SqlitePool,
    vuln: &ExtractedVulnerability,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    let severity_str = format!("{:?}", vuln.severity).to_lowercase();

    // Check if already exists (by scan_id, host_ip, and title to avoid duplicates)
    let exists: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM vulnerability_tracking
         WHERE scan_id = ?1 AND host_ip = ?2 AND title = ?3"
    )
    .bind(&vuln.scan_id)
    .bind(&vuln.host_ip)
    .bind(&vuln.title)
    .fetch_optional(pool)
    .await?;

    if exists.is_some() {
        debug!("Vulnerability already exists, skipping: {}", vuln.title);
        return Ok(());
    }

    sqlx::query(
        "INSERT INTO vulnerability_tracking
         (id, scan_id, host_ip, cve_id, title, severity, description, affected_service,
          port, protocol, service_name, service_version, status, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 'open', ?13, ?13)"
    )
    .bind(&vuln.id)
    .bind(&vuln.scan_id)
    .bind(&vuln.host_ip)
    .bind(&vuln.cve_id)
    .bind(&vuln.title)
    .bind(&severity_str)
    .bind(&vuln.description)
    .bind(&vuln.affected_service)
    .bind(vuln.port.map(|p| p as i32))
    .bind(&vuln.protocol)
    .bind(&vuln.service_name)
    .bind(&vuln.service_version)
    .bind(&now)
    .execute(pool)
    .await?;

    debug!("Stored vulnerability: {} - {}", vuln.id, vuln.title);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_known_vulnerable_versions() {
        // Apache 2.4.49 should be flagged
        let issues = check_known_vulnerable_versions("apache", "2.4.49");
        assert!(!issues.is_empty());
        assert!(issues.iter().any(|(cve, _, _, _)| *cve == "CVE-2021-41773"));

        // Modern version should not be flagged
        let issues = check_known_vulnerable_versions("nginx", "1.24.0");
        assert!(issues.is_empty());
    }
}
