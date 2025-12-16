//! Active Compliance Check Implementations
//!
//! Direct compliance checks that can be run against hosts during scanning
//! (for integrated mode) or post-scan analysis.

use crate::compliance::types::{
    ComplianceFinding, ComplianceFramework, ControlStatus, FindingSource,
};
use crate::types::{HostInfo, PortInfo, Severity};
use chrono::Utc;
use uuid::Uuid;

/// Helper to get service name from a PortInfo
fn get_service_name(port: &PortInfo) -> Option<&str> {
    port.service.as_ref().map(|s| s.name.as_str())
}

/// Helper to get service banner from a PortInfo
fn get_service_banner(port: &PortInfo) -> Option<&str> {
    port.service.as_ref().and_then(|s| s.banner.as_deref())
}

/// Helper to get service version from a PortInfo
fn get_service_version(port: &PortInfo) -> Option<&str> {
    port.service.as_ref().and_then(|s| s.version.as_deref())
}

/// Result of running a compliance check
#[derive(Debug, Clone)]
pub struct CheckResult {
    /// Control ID this check assesses
    pub control_id: String,
    /// Framework
    pub framework: ComplianceFramework,
    /// Check name
    pub check_name: String,
    /// Status determined by the check
    pub status: ControlStatus,
    /// Severity if non-compliant
    pub severity: Severity,
    /// Evidence collected
    pub evidence: Vec<String>,
    /// Remediation guidance
    pub remediation: String,
}

/// Trait for compliance checks that can be run against hosts
pub trait ComplianceCheck: Send + Sync {
    /// Get the check ID
    fn check_id(&self) -> &str;

    /// Get the check name
    fn name(&self) -> &str;

    /// Get the control this check assesses
    fn control_id(&self) -> &str;

    /// Get the framework
    fn framework(&self) -> ComplianceFramework;

    /// Run the check against a host
    fn check(&self, host: &HostInfo) -> Option<CheckResult>;
}

/// Run all compliance checks for a host
pub fn run_compliance_checks(
    host: &HostInfo,
    frameworks: &[ComplianceFramework],
) -> Vec<CheckResult> {
    let mut results = Vec::new();
    let checks = get_all_checks();

    for check in checks {
        if frameworks.contains(&check.framework()) {
            if let Some(result) = check.check(host) {
                results.push(result);
            }
        }
    }

    results
}

/// Convert check results to compliance findings
pub fn check_results_to_findings(
    results: Vec<CheckResult>,
    scan_id: &str,
    host_ip: &str,
) -> Vec<ComplianceFinding> {
    results
        .into_iter()
        .map(|r| ComplianceFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: scan_id.to_string(),
            control_id: r.control_id.clone(),
            framework: r.framework,
            status: r.status,
            severity: r.severity,
            evidence: r.evidence,
            affected_hosts: vec![host_ip.to_string()],
            affected_ports: vec![],
            remediation: r.remediation,
            source: FindingSource::DirectCheck {
                check_id: format!("{}-{}", r.framework.id(), r.control_id),
                check_name: r.check_name,
            },
            notes: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            override_by: None,
            override_reason: None,
        })
        .collect()
}

/// Get all available compliance checks
pub fn get_all_checks() -> Vec<Box<dyn ComplianceCheck>> {
    vec![
        // Encryption checks
        Box::new(TelnetEnabledCheck),
        Box::new(FtpEnabledCheck),
        Box::new(HttpWithoutHttpsCheck),
        Box::new(WeakSshCheck),
        Box::new(SmbV1EnabledCheck),

        // Service hardening checks
        Box::new(DefaultCredentialsCheck),
        Box::new(AnonymousAccessCheck),
        Box::new(OpenDatabaseCheck),
        Box::new(RemoteDesktopExposedCheck),

        // Network security checks
        Box::new(ExcessiveOpenPortsCheck),
        Box::new(SnmpV1V2Check),
    ]
}

// ============================================================================
// Individual Check Implementations
// ============================================================================

/// Check for Telnet service (insecure protocol)
struct TelnetEnabledCheck;

impl ComplianceCheck for TelnetEnabledCheck {
    fn check_id(&self) -> &str { "telnet-enabled" }
    fn name(&self) -> &str { "Telnet Service Enabled" }
    fn control_id(&self) -> &str { "PCI-DSS-2.2.7" }
    fn framework(&self) -> ComplianceFramework { ComplianceFramework::PciDss4 }

    fn check(&self, host: &HostInfo) -> Option<CheckResult> {
        let telnet_port = host.ports.iter().find(|p| {
            p.port == 23 || get_service_name(p) == Some("telnet")
        });

        if telnet_port.is_some() {
            Some(CheckResult {
                control_id: self.control_id().to_string(),
                framework: self.framework(),
                check_name: self.name().to_string(),
                status: ControlStatus::NonCompliant,
                severity: Severity::High,
                evidence: vec!["Telnet service (port 23) is enabled".to_string()],
                remediation: "Disable Telnet and use SSH for secure remote administration.".to_string(),
            })
        } else {
            None
        }
    }
}

/// Check for unencrypted FTP service
struct FtpEnabledCheck;

impl ComplianceCheck for FtpEnabledCheck {
    fn check_id(&self) -> &str { "ftp-enabled" }
    fn name(&self) -> &str { "Unencrypted FTP Service" }
    fn control_id(&self) -> &str { "PCI-DSS-4.2" }
    fn framework(&self) -> ComplianceFramework { ComplianceFramework::PciDss4 }

    fn check(&self, host: &HostInfo) -> Option<CheckResult> {
        let ftp_port = host.ports.iter().find(|p| {
            p.port == 21 && get_service_name(p) != Some("ftps")
        });

        if ftp_port.is_some() {
            Some(CheckResult {
                control_id: self.control_id().to_string(),
                framework: self.framework(),
                check_name: self.name().to_string(),
                status: ControlStatus::NonCompliant,
                severity: Severity::Medium,
                evidence: vec!["Unencrypted FTP service (port 21) is enabled".to_string()],
                remediation: "Replace FTP with SFTP or FTPS for secure file transfers.".to_string(),
            })
        } else {
            None
        }
    }
}

/// Check for HTTP without HTTPS
struct HttpWithoutHttpsCheck;

impl ComplianceCheck for HttpWithoutHttpsCheck {
    fn check_id(&self) -> &str { "http-no-https" }
    fn name(&self) -> &str { "HTTP Without HTTPS" }
    fn control_id(&self) -> &str { "PCI-DSS-4.1" }
    fn framework(&self) -> ComplianceFramework { ComplianceFramework::PciDss4 }

    fn check(&self, host: &HostInfo) -> Option<CheckResult> {
        let has_http = host.ports.iter().any(|p| {
            p.port == 80 || get_service_name(p) == Some("http")
        });
        let has_https = host.ports.iter().any(|p| {
            p.port == 443 || get_service_name(p) == Some("https")
        });

        if has_http && !has_https {
            Some(CheckResult {
                control_id: self.control_id().to_string(),
                framework: self.framework(),
                check_name: self.name().to_string(),
                status: ControlStatus::NonCompliant,
                severity: Severity::High,
                evidence: vec!["HTTP service found without corresponding HTTPS".to_string()],
                remediation: "Enable HTTPS with TLS 1.2+ and redirect HTTP to HTTPS.".to_string(),
            })
        } else {
            None
        }
    }
}

/// Check for weak SSH configuration
struct WeakSshCheck;

impl ComplianceCheck for WeakSshCheck {
    fn check_id(&self) -> &str { "weak-ssh" }
    fn name(&self) -> &str { "Weak SSH Configuration" }
    fn control_id(&self) -> &str { "CIS-4.6" }
    fn framework(&self) -> ComplianceFramework { ComplianceFramework::CisBenchmarks }

    fn check(&self, host: &HostInfo) -> Option<CheckResult> {
        let ssh_port = host.ports.iter().find(|p| {
            p.port == 22 || get_service_name(p) == Some("ssh")
        });

        if let Some(port) = ssh_port {
            // Check for SSH version 1 in banner
            if let Some(banner) = get_service_banner(port) {
                let banner_lower = banner.to_lowercase();
                if banner_lower.contains("ssh-1") {
                    return Some(CheckResult {
                        control_id: self.control_id().to_string(),
                        framework: self.framework(),
                        check_name: self.name().to_string(),
                        status: ControlStatus::NonCompliant,
                        severity: Severity::High,
                        evidence: vec![format!("SSH version 1 detected: {}", banner)],
                        remediation: "Disable SSH protocol version 1 and use only SSH-2.".to_string(),
                    });
                }
            }
        }
        None
    }
}

/// Check for SMBv1 (vulnerable to EternalBlue, WannaCry)
struct SmbV1EnabledCheck;

impl ComplianceCheck for SmbV1EnabledCheck {
    fn check_id(&self) -> &str { "smb-v1" }
    fn name(&self) -> &str { "SMBv1 Enabled" }
    fn control_id(&self) -> &str { "NIST-CM-7" }
    fn framework(&self) -> ComplianceFramework { ComplianceFramework::Nist80053 }

    fn check(&self, host: &HostInfo) -> Option<CheckResult> {
        let smb_port = host.ports.iter().find(|p| {
            p.port == 445 || p.port == 139
        });

        if let Some(port) = smb_port {
            // Check for SMBv1 indicators in banner or version
            if let Some(version) = get_service_version(port) {
                let version_lower = version.to_lowercase();
                if version_lower.contains("smb1") || version_lower.contains("smbv1") {
                    return Some(CheckResult {
                        control_id: self.control_id().to_string(),
                        framework: self.framework(),
                        check_name: self.name().to_string(),
                        status: ControlStatus::NonCompliant,
                        severity: Severity::Critical,
                        evidence: vec![format!("SMBv1 detected: {}", version)],
                        remediation: "Disable SMBv1 and use SMBv2 or SMBv3.".to_string(),
                    });
                }
            }
        }
        None
    }
}

/// Check for default credentials
struct DefaultCredentialsCheck;

impl ComplianceCheck for DefaultCredentialsCheck {
    fn check_id(&self) -> &str { "default-creds" }
    fn name(&self) -> &str { "Default Credentials" }
    fn control_id(&self) -> &str { "PCI-DSS-2.1" }
    fn framework(&self) -> ComplianceFramework { ComplianceFramework::PciDss4 }

    fn check(&self, host: &HostInfo) -> Option<CheckResult> {
        // Check host-level vulnerabilities for default credential findings
        let has_default_creds = host.vulnerabilities.iter().any(|v| {
            let title_lower = v.title.to_lowercase();
            title_lower.contains("default password")
                || title_lower.contains("default credential")
                || title_lower.contains("factory default")
        });

        if has_default_creds {
            Some(CheckResult {
                control_id: self.control_id().to_string(),
                framework: self.framework(),
                check_name: self.name().to_string(),
                status: ControlStatus::NonCompliant,
                severity: Severity::Critical,
                evidence: vec!["Default credentials detected on one or more services".to_string()],
                remediation: "Change all default credentials immediately. Implement strong password policy.".to_string(),
            })
        } else {
            None
        }
    }
}

/// Check for anonymous access
struct AnonymousAccessCheck;

impl ComplianceCheck for AnonymousAccessCheck {
    fn check_id(&self) -> &str { "anonymous-access" }
    fn name(&self) -> &str { "Anonymous Access Enabled" }
    fn control_id(&self) -> &str { "CIS-6.1" }
    fn framework(&self) -> ComplianceFramework { ComplianceFramework::CisBenchmarks }

    fn check(&self, host: &HostInfo) -> Option<CheckResult> {
        let has_anonymous = host.ports.iter().any(|p| {
            // Check for anonymous FTP
            if p.port == 21 {
                if let Some(banner) = get_service_banner(p) {
                    if banner.to_lowercase().contains("anonymous") {
                        return true;
                    }
                }
            }
            false
        }) || host.vulnerabilities.iter().any(|v| {
            v.title.to_lowercase().contains("anonymous")
        });

        if has_anonymous {
            Some(CheckResult {
                control_id: self.control_id().to_string(),
                framework: self.framework(),
                check_name: self.name().to_string(),
                status: ControlStatus::NonCompliant,
                severity: Severity::High,
                evidence: vec!["Anonymous access is enabled on one or more services".to_string()],
                remediation: "Disable anonymous access and require authentication.".to_string(),
            })
        } else {
            None
        }
    }
}

/// Check for exposed database ports
struct OpenDatabaseCheck;

impl ComplianceCheck for OpenDatabaseCheck {
    fn check_id(&self) -> &str { "open-database" }
    fn name(&self) -> &str { "Database Port Exposed" }
    fn control_id(&self) -> &str { "PCI-DSS-1.3.6" }
    fn framework(&self) -> ComplianceFramework { ComplianceFramework::PciDss4 }

    fn check(&self, host: &HostInfo) -> Option<CheckResult> {
        let db_ports = [3306, 5432, 1433, 1521, 27017, 6379, 9200];
        let exposed_dbs: Vec<_> = host.ports.iter()
            .filter(|p| db_ports.contains(&p.port))
            .map(|p| format!("Port {} ({})", p.port, get_service_name(p).unwrap_or("unknown")))
            .collect();

        if !exposed_dbs.is_empty() {
            Some(CheckResult {
                control_id: self.control_id().to_string(),
                framework: self.framework(),
                check_name: self.name().to_string(),
                status: ControlStatus::NonCompliant,
                severity: Severity::High,
                evidence: vec![format!("Exposed database ports: {}", exposed_dbs.join(", "))],
                remediation: "Restrict database access to authorized hosts only using firewall rules.".to_string(),
            })
        } else {
            None
        }
    }
}

/// Check for exposed Remote Desktop
struct RemoteDesktopExposedCheck;

impl ComplianceCheck for RemoteDesktopExposedCheck {
    fn check_id(&self) -> &str { "rdp-exposed" }
    fn name(&self) -> &str { "Remote Desktop Exposed" }
    fn control_id(&self) -> &str { "CIS-6.4" }
    fn framework(&self) -> ComplianceFramework { ComplianceFramework::CisBenchmarks }

    fn check(&self, host: &HostInfo) -> Option<CheckResult> {
        let rdp_port = host.ports.iter().find(|p| {
            p.port == 3389 || get_service_name(p) == Some("ms-wbt-server")
        });

        if rdp_port.is_some() {
            Some(CheckResult {
                control_id: self.control_id().to_string(),
                framework: self.framework(),
                check_name: self.name().to_string(),
                status: ControlStatus::NonCompliant,
                severity: Severity::High,
                evidence: vec!["Remote Desktop (RDP) port 3389 is exposed".to_string()],
                remediation: "Restrict RDP access via VPN or implement Network Level Authentication (NLA).".to_string(),
            })
        } else {
            None
        }
    }
}

/// Check for excessive open ports
struct ExcessiveOpenPortsCheck;

impl ComplianceCheck for ExcessiveOpenPortsCheck {
    fn check_id(&self) -> &str { "excessive-ports" }
    fn name(&self) -> &str { "Excessive Open Ports" }
    fn control_id(&self) -> &str { "PCI-DSS-2.2.2" }
    fn framework(&self) -> ComplianceFramework { ComplianceFramework::PciDss4 }

    fn check(&self, host: &HostInfo) -> Option<CheckResult> {
        const EXCESSIVE_THRESHOLD: usize = 20;

        if host.ports.len() > EXCESSIVE_THRESHOLD {
            Some(CheckResult {
                control_id: self.control_id().to_string(),
                framework: self.framework(),
                check_name: self.name().to_string(),
                status: ControlStatus::NonCompliant,
                severity: Severity::Medium,
                evidence: vec![format!("{} open ports detected (threshold: {})", host.ports.len(), EXCESSIVE_THRESHOLD)],
                remediation: "Review and disable unnecessary services. Apply principle of least functionality.".to_string(),
            })
        } else {
            None
        }
    }
}

/// Check for SNMP v1/v2 (insecure versions)
struct SnmpV1V2Check;

impl ComplianceCheck for SnmpV1V2Check {
    fn check_id(&self) -> &str { "snmp-v1v2" }
    fn name(&self) -> &str { "SNMP v1/v2 Enabled" }
    fn control_id(&self) -> &str { "NIST-SC-8" }
    fn framework(&self) -> ComplianceFramework { ComplianceFramework::Nist80053 }

    fn check(&self, host: &HostInfo) -> Option<CheckResult> {
        let snmp_port = host.ports.iter().find(|p| {
            p.port == 161 || p.port == 162 || get_service_name(p) == Some("snmp")
        });

        if let Some(port) = snmp_port {
            // Check for v1/v2 indicators
            let version_info = get_service_version(port).unwrap_or("");
            let has_weak_version = version_info.contains("v1")
                || version_info.contains("v2")
                || !version_info.contains("v3");

            if has_weak_version {
                return Some(CheckResult {
                    control_id: self.control_id().to_string(),
                    framework: self.framework(),
                    check_name: self.name().to_string(),
                    status: ControlStatus::NonCompliant,
                    severity: Severity::Medium,
                    evidence: vec!["SNMP v1/v2 detected (community strings sent in cleartext)".to_string()],
                    remediation: "Upgrade to SNMPv3 with authentication and encryption.".to_string(),
                });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ScanTarget, ServiceInfo, Protocol, PortState};
    use std::net::IpAddr;
    use std::time::Duration;

    fn create_test_host_with_telnet() -> HostInfo {
        HostInfo {
            target: ScanTarget {
                ip: "192.168.1.1".parse::<IpAddr>().unwrap(),
                hostname: None,
            },
            is_alive: true,
            os_guess: None,
            ports: vec![
                PortInfo {
                    port: 23,
                    protocol: Protocol::TCP,
                    state: PortState::Open,
                    service: Some(ServiceInfo {
                        name: "telnet".to_string(),
                        version: None,
                        banner: None,
                        cpe: None,
                        enumeration: None,
                    }),
                },
            ],
            vulnerabilities: vec![],
            scan_duration: Duration::from_secs(1),
        }
    }

    #[test]
    fn test_telnet_check() {
        let host = create_test_host_with_telnet();
        let check = TelnetEnabledCheck;
        let result = check.check(&host);
        assert!(result.is_some());
        assert_eq!(result.unwrap().status, ControlStatus::NonCompliant);
    }

    #[test]
    fn test_run_all_checks() {
        let host = create_test_host_with_telnet();
        let results = run_compliance_checks(&host, &[ComplianceFramework::PciDss4]);
        assert!(!results.is_empty());
    }
}
