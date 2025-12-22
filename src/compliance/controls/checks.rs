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

        // SSL/TLS checks - NEW
        Box::new(WeakTlsProtocolCheck),
        Box::new(ExpiredCertificateCheck),
        Box::new(SelfSignedCertificateCheck),
        Box::new(CertificateExpiringSoonCheck),
        Box::new(WeakCipherSuitesCheck),
        Box::new(MissingHstsCheck),
        Box::new(SslGradeFailingCheck),
        Box::new(HostnameMismatchCheck),
        Box::new(IncompleteCertChainCheck),
        Box::new(NoPerfectForwardSecrecyCheck),

        // Authentication & Access checks - NEW
        Box::new(VncExposedCheck),
        Box::new(LdapUnencryptedCheck),
        Box::new(IkeWeakCheck),
        Box::new(RsyncExposedCheck),
        Box::new(NfsExposedCheck),
        Box::new(IpmiExposedCheck),

        // Healthcare/HIPAA specific checks - NEW
        Box::new(Hl7ExposedCheck),
        Box::new(DicomExposedCheck),

        // Web security checks - NEW
        Box::new(AdminInterfaceExposedCheck),
        Box::new(DebugEndpointsCheck),
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

// ============================================================================
// SSL/TLS Compliance Checks
// ============================================================================

/// Helper to get SSL info from any SSL-enabled port
fn get_ssl_info(host: &HostInfo) -> Option<&crate::types::SslInfo> {
    host.ports.iter()
        .filter_map(|p| p.service.as_ref().and_then(|s| s.ssl_info.as_ref()))
        .next()
}

/// Check for weak TLS protocols (TLS 1.0, TLS 1.1, SSL 2.0, SSL 3.0)
struct WeakTlsProtocolCheck;

impl ComplianceCheck for WeakTlsProtocolCheck {
    fn check_id(&self) -> &str { "weak-tls-protocol" }
    fn name(&self) -> &str { "Weak TLS/SSL Protocol Enabled" }
    fn control_id(&self) -> &str { "PCI-DSS-4.1" }
    fn framework(&self) -> ComplianceFramework { ComplianceFramework::PciDss4 }

    fn check(&self, host: &HostInfo) -> Option<CheckResult> {
        let ssl_info = get_ssl_info(host)?;

        let weak_protocols: Vec<&String> = ssl_info.protocols.iter()
            .filter(|p| {
                let lower = p.to_lowercase();
                lower.contains("ssl") || lower.contains("tls 1.0") || lower.contains("tls 1.1")
            })
            .collect();

        if !weak_protocols.is_empty() {
            let severity = if weak_protocols.iter().any(|p| p.to_lowercase().contains("ssl")) {
                Severity::Critical
            } else {
                Severity::High
            };

            Some(CheckResult {
                control_id: self.control_id().to_string(),
                framework: self.framework(),
                check_name: self.name().to_string(),
                status: ControlStatus::NonCompliant,
                severity,
                evidence: vec![format!("Weak protocols enabled: {}", weak_protocols.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "))],
                remediation: "Disable SSL 2.0, SSL 3.0, TLS 1.0, and TLS 1.1. Use only TLS 1.2 or TLS 1.3.".to_string(),
            })
        } else {
            None
        }
    }
}

/// Check for expired SSL/TLS certificate
struct ExpiredCertificateCheck;

impl ComplianceCheck for ExpiredCertificateCheck {
    fn check_id(&self) -> &str { "expired-certificate" }
    fn name(&self) -> &str { "Expired SSL/TLS Certificate" }
    fn control_id(&self) -> &str { "HIPAA-164.312(e)(1)" }
    fn framework(&self) -> ComplianceFramework { ComplianceFramework::Hipaa }

    fn check(&self, host: &HostInfo) -> Option<CheckResult> {
        let ssl_info = get_ssl_info(host)?;

        if ssl_info.cert_expired {
            Some(CheckResult {
                control_id: self.control_id().to_string(),
                framework: self.framework(),
                check_name: self.name().to_string(),
                status: ControlStatus::NonCompliant,
                severity: Severity::Critical,
                evidence: vec![format!("Certificate expired. Valid until: {}", ssl_info.valid_until)],
                remediation: "Renew the SSL/TLS certificate immediately.".to_string(),
            })
        } else {
            None
        }
    }
}

/// Check for self-signed certificate
struct SelfSignedCertificateCheck;

impl ComplianceCheck for SelfSignedCertificateCheck {
    fn check_id(&self) -> &str { "self-signed-cert" }
    fn name(&self) -> &str { "Self-Signed Certificate" }
    fn control_id(&self) -> &str { "NIST-SC-17" }
    fn framework(&self) -> ComplianceFramework { ComplianceFramework::Nist80053 }

    fn check(&self, host: &HostInfo) -> Option<CheckResult> {
        let ssl_info = get_ssl_info(host)?;

        if ssl_info.self_signed {
            Some(CheckResult {
                control_id: self.control_id().to_string(),
                framework: self.framework(),
                check_name: self.name().to_string(),
                status: ControlStatus::NonCompliant,
                severity: Severity::High,
                evidence: vec!["Certificate is self-signed and not trusted by public CAs".to_string()],
                remediation: "Use a certificate from a trusted Certificate Authority.".to_string(),
            })
        } else {
            None
        }
    }
}

/// Check for certificate expiring soon (within 30 days)
struct CertificateExpiringSoonCheck;

impl ComplianceCheck for CertificateExpiringSoonCheck {
    fn check_id(&self) -> &str { "cert-expiring-soon" }
    fn name(&self) -> &str { "Certificate Expiring Soon" }
    fn control_id(&self) -> &str { "CIS-4.5" }
    fn framework(&self) -> ComplianceFramework { ComplianceFramework::CisBenchmarks }

    fn check(&self, host: &HostInfo) -> Option<CheckResult> {
        let ssl_info = get_ssl_info(host)?;

        if let Some(days) = ssl_info.days_until_expiry {
            if days > 0 && days <= 30 {
                let severity = if days <= 7 { Severity::High } else { Severity::Medium };
                Some(CheckResult {
                    control_id: self.control_id().to_string(),
                    framework: self.framework(),
                    check_name: self.name().to_string(),
                    status: ControlStatus::PartiallyCompliant,
                    severity,
                    evidence: vec![format!("Certificate expires in {} days (on {})", days, ssl_info.valid_until)],
                    remediation: "Renew the SSL/TLS certificate before expiration.".to_string(),
                })
            } else {
                None
            }
        } else {
            None
        }
    }
}

/// Check for weak cipher suites
struct WeakCipherSuitesCheck;

impl ComplianceCheck for WeakCipherSuitesCheck {
    fn check_id(&self) -> &str { "weak-ciphers" }
    fn name(&self) -> &str { "Weak Cipher Suites Enabled" }
    fn control_id(&self) -> &str { "PCI-DSS-4.2.1" }
    fn framework(&self) -> ComplianceFramework { ComplianceFramework::PciDss4 }

    fn check(&self, host: &HostInfo) -> Option<CheckResult> {
        let ssl_info = get_ssl_info(host)?;

        if !ssl_info.weak_ciphers.is_empty() {
            let has_critical = ssl_info.weak_ciphers.iter()
                .any(|c| {
                    let upper = c.to_uppercase();
                    upper.contains("NULL") || upper.contains("EXPORT") || upper.contains("DES")
                });

            Some(CheckResult {
                control_id: self.control_id().to_string(),
                framework: self.framework(),
                check_name: self.name().to_string(),
                status: ControlStatus::NonCompliant,
                severity: if has_critical { Severity::Critical } else { Severity::High },
                evidence: vec![format!("Weak ciphers detected: {}", ssl_info.weak_ciphers.join(", "))],
                remediation: "Disable weak cipher suites. Use only modern AEAD ciphers (AES-GCM, ChaCha20-Poly1305).".to_string(),
            })
        } else {
            None
        }
    }
}

/// Check for missing HSTS header
struct MissingHstsCheck;

impl ComplianceCheck for MissingHstsCheck {
    fn check_id(&self) -> &str { "missing-hsts" }
    fn name(&self) -> &str { "Missing HSTS Header" }
    fn control_id(&self) -> &str { "OWASP-A05" }
    fn framework(&self) -> ComplianceFramework { ComplianceFramework::OwaspTop10 }

    fn check(&self, host: &HostInfo) -> Option<CheckResult> {
        // Only check if we have HTTPS
        let has_https = host.ports.iter().any(|p| p.port == 443);
        if !has_https {
            return None;
        }

        let ssl_info = get_ssl_info(host)?;

        if !ssl_info.hsts_enabled {
            Some(CheckResult {
                control_id: self.control_id().to_string(),
                framework: self.framework(),
                check_name: self.name().to_string(),
                status: ControlStatus::NonCompliant,
                severity: Severity::Medium,
                evidence: vec!["HTTP Strict Transport Security (HSTS) is not enabled".to_string()],
                remediation: "Enable HSTS with Strict-Transport-Security header and max-age of at least 31536000 (1 year).".to_string(),
            })
        } else {
            // Check if max-age is sufficient
            if let Some(max_age) = ssl_info.hsts_max_age {
                if max_age < 31536000 {
                    return Some(CheckResult {
                        control_id: self.control_id().to_string(),
                        framework: self.framework(),
                        check_name: self.name().to_string(),
                        status: ControlStatus::PartiallyCompliant,
                        severity: Severity::Low,
                        evidence: vec![format!("HSTS max-age is {} seconds (less than 1 year)", max_age)],
                        remediation: "Increase HSTS max-age to at least 31536000 (1 year).".to_string(),
                    });
                }
            }
            None
        }
    }
}

/// Check for failing SSL grade (D or F)
struct SslGradeFailingCheck;

impl ComplianceCheck for SslGradeFailingCheck {
    fn check_id(&self) -> &str { "ssl-grade-failing" }
    fn name(&self) -> &str { "Failing SSL/TLS Configuration Grade" }
    fn control_id(&self) -> &str { "SOC2-CC6.1" }
    fn framework(&self) -> ComplianceFramework { ComplianceFramework::Soc2 }

    fn check(&self, host: &HostInfo) -> Option<CheckResult> {
        let ssl_info = get_ssl_info(host)?;
        let grade = ssl_info.ssl_grade.as_ref()?;

        use crate::scanner::ssl_scanner::SslGradeLevel;
        match grade.grade {
            SslGradeLevel::F => Some(CheckResult {
                control_id: self.control_id().to_string(),
                framework: self.framework(),
                check_name: self.name().to_string(),
                status: ControlStatus::NonCompliant,
                severity: Severity::Critical,
                evidence: vec![format!("SSL/TLS grade is F (score: {}/100). {}",
                    grade.overall_score,
                    grade.cap_reason.as_deref().unwrap_or("Critical security issues detected"))],
                remediation: format!("Address the following issues: {}",
                    grade.recommendations.join("; ")).to_string(),
            }),
            SslGradeLevel::D => Some(CheckResult {
                control_id: self.control_id().to_string(),
                framework: self.framework(),
                check_name: self.name().to_string(),
                status: ControlStatus::NonCompliant,
                severity: Severity::High,
                evidence: vec![format!("SSL/TLS grade is D (score: {}/100)", grade.overall_score)],
                remediation: format!("Address the following issues: {}",
                    grade.recommendations.join("; ")).to_string(),
            }),
            SslGradeLevel::T => Some(CheckResult {
                control_id: self.control_id().to_string(),
                framework: self.framework(),
                check_name: self.name().to_string(),
                status: ControlStatus::NonCompliant,
                severity: Severity::High,
                evidence: vec!["SSL/TLS grade is T (trust issues with certificate)".to_string()],
                remediation: "Use a certificate from a trusted Certificate Authority.".to_string(),
            }),
            SslGradeLevel::M => Some(CheckResult {
                control_id: self.control_id().to_string(),
                framework: self.framework(),
                check_name: self.name().to_string(),
                status: ControlStatus::NonCompliant,
                severity: Severity::Critical,
                evidence: vec!["SSL/TLS grade is M (hostname mismatch)".to_string()],
                remediation: "Ensure certificate Subject Alternative Names (SANs) match the hostname.".to_string(),
            }),
            _ => None,
        }
    }
}

/// Check for certificate hostname mismatch
struct HostnameMismatchCheck;

impl ComplianceCheck for HostnameMismatchCheck {
    fn check_id(&self) -> &str { "hostname-mismatch" }
    fn name(&self) -> &str { "Certificate Hostname Mismatch" }
    fn control_id(&self) -> &str { "NIST-IA-5" }
    fn framework(&self) -> ComplianceFramework { ComplianceFramework::Nist80053 }

    fn check(&self, host: &HostInfo) -> Option<CheckResult> {
        let ssl_info = get_ssl_info(host)?;

        if ssl_info.hostname_mismatch {
            Some(CheckResult {
                control_id: self.control_id().to_string(),
                framework: self.framework(),
                check_name: self.name().to_string(),
                status: ControlStatus::NonCompliant,
                severity: Severity::Critical,
                evidence: vec![format!("Certificate subject '{}' does not match hostname", ssl_info.subject)],
                remediation: "Ensure certificate includes the correct hostname in Subject Alternative Names (SANs).".to_string(),
            })
        } else {
            None
        }
    }
}

/// Check for incomplete certificate chain
struct IncompleteCertChainCheck;

impl ComplianceCheck for IncompleteCertChainCheck {
    fn check_id(&self) -> &str { "incomplete-cert-chain" }
    fn name(&self) -> &str { "Incomplete Certificate Chain" }
    fn control_id(&self) -> &str { "CIS-4.4" }
    fn framework(&self) -> ComplianceFramework { ComplianceFramework::CisBenchmarks }

    fn check(&self, host: &HostInfo) -> Option<CheckResult> {
        let ssl_info = get_ssl_info(host)?;

        let has_chain_issues = ssl_info.chain_issues.iter()
            .any(|issue| issue.to_lowercase().contains("incomplete"));

        if has_chain_issues {
            Some(CheckResult {
                control_id: self.control_id().to_string(),
                framework: self.framework(),
                check_name: self.name().to_string(),
                status: ControlStatus::NonCompliant,
                severity: Severity::Medium,
                evidence: vec!["Certificate chain is incomplete. Some clients may not be able to verify the certificate.".to_string()],
                remediation: "Include all intermediate certificates in the certificate chain.".to_string(),
            })
        } else {
            None
        }
    }
}

/// Check for lack of Perfect Forward Secrecy
struct NoPerfectForwardSecrecyCheck;

impl ComplianceCheck for NoPerfectForwardSecrecyCheck {
    fn check_id(&self) -> &str { "no-pfs" }
    fn name(&self) -> &str { "No Perfect Forward Secrecy" }
    fn control_id(&self) -> &str { "NIST-SC-12" }
    fn framework(&self) -> ComplianceFramework { ComplianceFramework::Nist80053 }

    fn check(&self, host: &HostInfo) -> Option<CheckResult> {
        let ssl_info = get_ssl_info(host)?;

        // Check if any cipher supports PFS (ECDHE or DHE)
        let has_pfs = ssl_info.cipher_suites.iter()
            .any(|c| {
                let upper = c.to_uppercase();
                upper.contains("ECDHE") || upper.contains("DHE")
            });

        if !has_pfs && !ssl_info.cipher_suites.is_empty() {
            Some(CheckResult {
                control_id: self.control_id().to_string(),
                framework: self.framework(),
                check_name: self.name().to_string(),
                status: ControlStatus::NonCompliant,
                severity: Severity::Medium,
                evidence: vec!["No cipher suites with Perfect Forward Secrecy (ECDHE/DHE) enabled".to_string()],
                remediation: "Enable ECDHE or DHE key exchange cipher suites for Perfect Forward Secrecy.".to_string(),
            })
        } else {
            None
        }
    }
}

// ============================================================================
// Authentication & Access Checks
// ============================================================================

/// Check for exposed VNC service
struct VncExposedCheck;

impl ComplianceCheck for VncExposedCheck {
    fn check_id(&self) -> &str { "vnc-exposed" }
    fn name(&self) -> &str { "VNC Service Exposed" }
    fn control_id(&self) -> &str { "CIS-6.5" }
    fn framework(&self) -> ComplianceFramework { ComplianceFramework::CisBenchmarks }

    fn check(&self, host: &HostInfo) -> Option<CheckResult> {
        let vnc_ports = [5900, 5901, 5902, 5903, 5904, 5905];
        let exposed: Vec<_> = host.ports.iter()
            .filter(|p| vnc_ports.contains(&p.port) || get_service_name(p) == Some("vnc"))
            .map(|p| p.port)
            .collect();

        if !exposed.is_empty() {
            Some(CheckResult {
                control_id: self.control_id().to_string(),
                framework: self.framework(),
                check_name: self.name().to_string(),
                status: ControlStatus::NonCompliant,
                severity: Severity::High,
                evidence: vec![format!("VNC service exposed on ports: {:?}", exposed)],
                remediation: "Restrict VNC access via VPN or SSH tunneling. Disable direct remote access.".to_string(),
            })
        } else {
            None
        }
    }
}

/// Check for unencrypted LDAP
struct LdapUnencryptedCheck;

impl ComplianceCheck for LdapUnencryptedCheck {
    fn check_id(&self) -> &str { "ldap-unencrypted" }
    fn name(&self) -> &str { "Unencrypted LDAP Service" }
    fn control_id(&self) -> &str { "NIST-AC-17" }
    fn framework(&self) -> ComplianceFramework { ComplianceFramework::Nist80053 }

    fn check(&self, host: &HostInfo) -> Option<CheckResult> {
        let has_ldap = host.ports.iter().any(|p| p.port == 389);
        let has_ldaps = host.ports.iter().any(|p| p.port == 636);

        if has_ldap && !has_ldaps {
            Some(CheckResult {
                control_id: self.control_id().to_string(),
                framework: self.framework(),
                check_name: self.name().to_string(),
                status: ControlStatus::NonCompliant,
                severity: Severity::High,
                evidence: vec!["Unencrypted LDAP (port 389) detected without LDAPS (port 636)".to_string()],
                remediation: "Disable unencrypted LDAP and use LDAPS (port 636) with TLS.".to_string(),
            })
        } else {
            None
        }
    }
}

/// Check for weak IKE (VPN) configuration
struct IkeWeakCheck;

impl ComplianceCheck for IkeWeakCheck {
    fn check_id(&self) -> &str { "ike-weak" }
    fn name(&self) -> &str { "IPsec/IKE VPN Exposed" }
    fn control_id(&self) -> &str { "PCI-DSS-2.2.4" }
    fn framework(&self) -> ComplianceFramework { ComplianceFramework::PciDss4 }

    fn check(&self, host: &HostInfo) -> Option<CheckResult> {
        let ike_port = host.ports.iter().find(|p| p.port == 500 || p.port == 4500);

        if let Some(port) = ike_port {
            // Check for weak configuration in service info
            if let Some(banner) = get_service_banner(port) {
                let banner_lower = banner.to_lowercase();
                if banner_lower.contains("ikev1") || banner_lower.contains("aggressive") {
                    return Some(CheckResult {
                        control_id: self.control_id().to_string(),
                        framework: self.framework(),
                        check_name: self.name().to_string(),
                        status: ControlStatus::NonCompliant,
                        severity: Severity::High,
                        evidence: vec!["IKEv1 or aggressive mode detected - vulnerable to offline attacks".to_string()],
                        remediation: "Use IKEv2 with strong encryption. Disable aggressive mode.".to_string(),
                    });
                }
            }
        }
        None
    }
}

/// Check for exposed Rsync service
struct RsyncExposedCheck;

impl ComplianceCheck for RsyncExposedCheck {
    fn check_id(&self) -> &str { "rsync-exposed" }
    fn name(&self) -> &str { "Rsync Service Exposed" }
    fn control_id(&self) -> &str { "CIS-5.3" }
    fn framework(&self) -> ComplianceFramework { ComplianceFramework::CisBenchmarks }

    fn check(&self, host: &HostInfo) -> Option<CheckResult> {
        let rsync_port = host.ports.iter().find(|p| {
            p.port == 873 || get_service_name(p) == Some("rsync")
        });

        if rsync_port.is_some() {
            Some(CheckResult {
                control_id: self.control_id().to_string(),
                framework: self.framework(),
                check_name: self.name().to_string(),
                status: ControlStatus::NonCompliant,
                severity: Severity::High,
                evidence: vec!["Rsync service (port 873) is exposed. May allow anonymous access.".to_string()],
                remediation: "Restrict rsync access. Use SSH-based rsync instead.".to_string(),
            })
        } else {
            None
        }
    }
}

/// Check for exposed NFS service
struct NfsExposedCheck;

impl ComplianceCheck for NfsExposedCheck {
    fn check_id(&self) -> &str { "nfs-exposed" }
    fn name(&self) -> &str { "NFS Service Exposed" }
    fn control_id(&self) -> &str { "PCI-DSS-1.3.1" }
    fn framework(&self) -> ComplianceFramework { ComplianceFramework::PciDss4 }

    fn check(&self, host: &HostInfo) -> Option<CheckResult> {
        let nfs_ports = [111, 2049]; // portmapper and NFS
        let exposed: Vec<_> = host.ports.iter()
            .filter(|p| nfs_ports.contains(&p.port) || get_service_name(p) == Some("nfs"))
            .map(|p| p.port)
            .collect();

        if !exposed.is_empty() {
            Some(CheckResult {
                control_id: self.control_id().to_string(),
                framework: self.framework(),
                check_name: self.name().to_string(),
                status: ControlStatus::NonCompliant,
                severity: Severity::High,
                evidence: vec![format!("NFS service exposed on ports: {:?}", exposed)],
                remediation: "Restrict NFS access to authorized hosts only. Use NFSv4 with Kerberos authentication.".to_string(),
            })
        } else {
            None
        }
    }
}

/// Check for exposed IPMI service
struct IpmiExposedCheck;

impl ComplianceCheck for IpmiExposedCheck {
    fn check_id(&self) -> &str { "ipmi-exposed" }
    fn name(&self) -> &str { "IPMI Service Exposed" }
    fn control_id(&self) -> &str { "NIST-CM-7" }
    fn framework(&self) -> ComplianceFramework { ComplianceFramework::Nist80053 }

    fn check(&self, host: &HostInfo) -> Option<CheckResult> {
        let ipmi_port = host.ports.iter().find(|p| {
            p.port == 623 || get_service_name(p) == Some("ipmi")
        });

        if ipmi_port.is_some() {
            Some(CheckResult {
                control_id: self.control_id().to_string(),
                framework: self.framework(),
                check_name: self.name().to_string(),
                status: ControlStatus::NonCompliant,
                severity: Severity::Critical,
                evidence: vec!["IPMI service (port 623) is exposed. Vulnerable to cipher zero attack.".to_string()],
                remediation: "Restrict IPMI access to management network only. Disable IPMI if not needed.".to_string(),
            })
        } else {
            None
        }
    }
}

// ============================================================================
// Healthcare/HIPAA Specific Checks
// ============================================================================

/// Check for exposed HL7 service (healthcare data)
struct Hl7ExposedCheck;

impl ComplianceCheck for Hl7ExposedCheck {
    fn check_id(&self) -> &str { "hl7-exposed" }
    fn name(&self) -> &str { "HL7 Service Exposed" }
    fn control_id(&self) -> &str { "HIPAA-164.312(e)(1)" }
    fn framework(&self) -> ComplianceFramework { ComplianceFramework::Hipaa }

    fn check(&self, host: &HostInfo) -> Option<CheckResult> {
        // Common HL7 MLLP ports
        let hl7_ports = [2575, 2576, 6661, 6662, 7777];
        let exposed: Vec<_> = host.ports.iter()
            .filter(|p| hl7_ports.contains(&p.port) || {
                if let Some(banner) = get_service_banner(p) {
                    banner.to_lowercase().contains("hl7") || banner.contains("MSH|")
                } else {
                    false
                }
            })
            .map(|p| p.port)
            .collect();

        if !exposed.is_empty() {
            Some(CheckResult {
                control_id: self.control_id().to_string(),
                framework: self.framework(),
                check_name: self.name().to_string(),
                status: ControlStatus::NonCompliant,
                severity: Severity::Critical,
                evidence: vec![format!("HL7 healthcare data interface exposed on ports: {:?}", exposed)],
                remediation: "Encrypt HL7 traffic with TLS. Restrict access to authorized healthcare systems only.".to_string(),
            })
        } else {
            None
        }
    }
}

/// Check for exposed DICOM service (medical imaging)
struct DicomExposedCheck;

impl ComplianceCheck for DicomExposedCheck {
    fn check_id(&self) -> &str { "dicom-exposed" }
    fn name(&self) -> &str { "DICOM Service Exposed" }
    fn control_id(&self) -> &str { "HIPAA-164.312(a)(2)(iv)" }
    fn framework(&self) -> ComplianceFramework { ComplianceFramework::Hipaa }

    fn check(&self, host: &HostInfo) -> Option<CheckResult> {
        let dicom_port = host.ports.iter().find(|p| {
            p.port == 104 || p.port == 11112 || get_service_name(p) == Some("dicom")
        });

        if dicom_port.is_some() {
            Some(CheckResult {
                control_id: self.control_id().to_string(),
                framework: self.framework(),
                check_name: self.name().to_string(),
                status: ControlStatus::NonCompliant,
                severity: Severity::Critical,
                evidence: vec!["DICOM medical imaging service exposed. Contains protected health information (PHI).".to_string()],
                remediation: "Use DICOM TLS. Restrict access to authorized PACS systems only. Implement application-level authentication.".to_string(),
            })
        } else {
            None
        }
    }
}

// ============================================================================
// Web Security Checks
// ============================================================================

/// Check for exposed admin interfaces
struct AdminInterfaceExposedCheck;

impl ComplianceCheck for AdminInterfaceExposedCheck {
    fn check_id(&self) -> &str { "admin-exposed" }
    fn name(&self) -> &str { "Administrative Interface Exposed" }
    fn control_id(&self) -> &str { "OWASP-A01" }
    fn framework(&self) -> ComplianceFramework { ComplianceFramework::OwaspTop10 }

    fn check(&self, host: &HostInfo) -> Option<CheckResult> {
        let admin_ports = [
            (8080, "Tomcat Manager"),
            (8443, "Tomcat SSL"),
            (9090, "Prometheus/Webmin"),
            (9200, "Elasticsearch"),
            (10000, "Webmin"),
            (8888, "OWASP ZAP/Jupyter"),
            (8000, "Django Debug"),
            (4848, "GlassFish Admin"),
            (7001, "WebLogic Admin"),
            (9043, "WebSphere Admin"),
            (8161, "ActiveMQ Web"),
        ];

        let exposed: Vec<_> = host.ports.iter()
            .filter_map(|p| {
                admin_ports.iter()
                    .find(|(port, _)| *port == p.port)
                    .map(|(port, name)| format!("{} ({})", port, name))
            })
            .collect();

        if !exposed.is_empty() {
            Some(CheckResult {
                control_id: self.control_id().to_string(),
                framework: self.framework(),
                check_name: self.name().to_string(),
                status: ControlStatus::NonCompliant,
                severity: Severity::High,
                evidence: vec![format!("Administrative interfaces exposed: {}", exposed.join(", "))],
                remediation: "Restrict admin interfaces to internal network. Use VPN or bastion host for access.".to_string(),
            })
        } else {
            None
        }
    }
}

/// Check for debug endpoints
struct DebugEndpointsCheck;

impl ComplianceCheck for DebugEndpointsCheck {
    fn check_id(&self) -> &str { "debug-endpoints" }
    fn name(&self) -> &str { "Debug Endpoints Exposed" }
    fn control_id(&self) -> &str { "OWASP-A05" }
    fn framework(&self) -> ComplianceFramework { ComplianceFramework::OwaspTop10 }

    fn check(&self, host: &HostInfo) -> Option<CheckResult> {
        // Check vulnerability list for debug-related findings
        let debug_vulns: Vec<_> = host.vulnerabilities.iter()
            .filter(|v| {
                let title_lower = v.title.to_lowercase();
                title_lower.contains("debug")
                    || title_lower.contains("development mode")
                    || title_lower.contains("stack trace")
                    || title_lower.contains("error page disclosure")
                    || title_lower.contains("verbose error")
            })
            .map(|v| v.title.clone())
            .collect();

        if !debug_vulns.is_empty() {
            Some(CheckResult {
                control_id: self.control_id().to_string(),
                framework: self.framework(),
                check_name: self.name().to_string(),
                status: ControlStatus::NonCompliant,
                severity: Severity::Medium,
                evidence: vec![format!("Debug features detected: {}", debug_vulns.join(", "))],
                remediation: "Disable debug mode in production. Configure proper error handling.".to_string(),
            })
        } else {
            None
        }
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
                        ssl_info: None,
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
