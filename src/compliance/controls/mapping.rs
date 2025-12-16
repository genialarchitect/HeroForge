//! Vulnerability to Control Mapping Engine
//!
//! Maps discovered vulnerabilities to compliance controls across all frameworks.

use crate::compliance::types::{
    ComplianceFinding, ComplianceFramework, ControlStatus, FindingSource,
};
use crate::compliance::frameworks;
use crate::types::{HostInfo, PortInfo, Severity, Vulnerability};
use chrono::Utc;
use std::collections::HashMap;
use uuid::Uuid;

/// Result of mapping a vulnerability to controls
#[derive(Debug, Clone)]
pub struct MappingResult {
    /// Control ID
    pub control_id: String,
    /// Framework
    pub framework: ComplianceFramework,
    /// Mapped severity
    pub severity: Severity,
    /// Affected hosts
    pub affected_hosts: Vec<String>,
    /// Affected ports
    pub affected_ports: Vec<u16>,
    /// Evidence from the vulnerability
    pub evidence: Vec<String>,
}

/// Maps vulnerabilities to compliance controls
pub struct VulnerabilityMapper {
    /// Frameworks to map against
    frameworks: Vec<ComplianceFramework>,
}

impl VulnerabilityMapper {
    /// Create a new mapper for the specified frameworks
    pub fn new(frameworks: Vec<ComplianceFramework>) -> Self {
        Self { frameworks }
    }

    /// Map all vulnerabilities from scan results to compliance controls
    pub fn map_vulnerabilities(&self, hosts: &[HostInfo], scan_id: &str) -> Vec<ComplianceFinding> {
        let mut findings: HashMap<(ComplianceFramework, String), ComplianceFinding> = HashMap::new();

        for host in hosts {
            let host_ip = host.target.ip.to_string();

            // Map host-level vulnerabilities
            for vuln in &host.vulnerabilities {
                self.map_vulnerability(&mut findings, scan_id, vuln, &host_ip, None);
            }
        }

        findings.into_values().collect()
    }

    /// Map a single vulnerability to controls
    fn map_vulnerability(
        &self,
        findings: &mut HashMap<(ComplianceFramework, String), ComplianceFinding>,
        scan_id: &str,
        vuln: &Vulnerability,
        host_ip: &str,
        port: Option<&PortInfo>,
    ) {
        let port_num = port.map(|p| p.port);
        let service = port.and_then(|p| p.service.as_ref().map(|s| s.name.as_str()));
        let cve_id = vuln.cve_id.as_deref();

        for framework in &self.frameworks {
            let mappings = self.get_framework_mappings(
                *framework,
                &vuln.title,
                cve_id,
                port_num,
                service,
            );

            for (control_id, severity) in mappings {
                let key = (*framework, control_id.clone());

                if let Some(existing) = findings.get_mut(&key) {
                    // Add to existing finding
                    if !existing.affected_hosts.contains(&host_ip.to_string()) {
                        existing.affected_hosts.push(host_ip.to_string());
                    }
                    if let Some(p) = port_num {
                        if !existing.affected_ports.contains(&p) {
                            existing.affected_ports.push(p);
                        }
                    }
                    if !existing.evidence.contains(&vuln.title) {
                        existing.evidence.push(vuln.title.clone());
                    }
                    // Update severity if higher
                    if severity > existing.severity {
                        existing.severity = severity;
                    }
                    existing.updated_at = Utc::now();
                } else {
                    // Create new finding
                    let control = frameworks::find_control(*framework, &control_id);
                    let remediation = control
                        .as_ref()
                        .and_then(|c| c.remediation_guidance.clone())
                        .unwrap_or_else(|| "Review and remediate the identified vulnerability.".to_string());

                    let finding = ComplianceFinding {
                        id: Uuid::new_v4().to_string(),
                        scan_id: scan_id.to_string(),
                        control_id: control_id.clone(),
                        framework: *framework,
                        status: ControlStatus::NonCompliant,
                        severity,
                        evidence: vec![vuln.title.clone()],
                        affected_hosts: vec![host_ip.to_string()],
                        affected_ports: port_num.map(|p| vec![p]).unwrap_or_default(),
                        remediation,
                        source: FindingSource::VulnerabilityMapping {
                            cve_id: cve_id.map(String::from),
                            vuln_title: vuln.title.clone(),
                        },
                        notes: None,
                        created_at: Utc::now(),
                        updated_at: Utc::now(),
                        override_by: None,
                        override_reason: None,
                    };
                    findings.insert(key, finding);
                }
            }
        }
    }

    /// Get framework-specific vulnerability mappings
    fn get_framework_mappings(
        &self,
        framework: ComplianceFramework,
        vuln_title: &str,
        cve_id: Option<&str>,
        port: Option<u16>,
        service: Option<&str>,
    ) -> Vec<(String, Severity)> {
        match framework {
            ComplianceFramework::CisBenchmarks => {
                frameworks::cis::map_vulnerability(vuln_title, cve_id, port, service)
            }
            ComplianceFramework::Nist80053 => {
                frameworks::nist_800_53::map_vulnerability(vuln_title, cve_id, port, service)
            }
            ComplianceFramework::NistCsf => {
                frameworks::nist_csf::map_vulnerability(vuln_title, cve_id, port, service)
            }
            ComplianceFramework::PciDss4 => {
                frameworks::pci_dss::map_vulnerability(vuln_title, cve_id, port, service)
            }
            ComplianceFramework::Hipaa => {
                frameworks::hipaa::map_vulnerability(vuln_title, cve_id, port, service)
            }
            ComplianceFramework::Ferpa => {
                frameworks::ferpa::map_vulnerability(vuln_title, cve_id, port, service)
            }
            ComplianceFramework::Soc2 => {
                frameworks::soc2::map_vulnerability(vuln_title, cve_id, port, service)
            }
            ComplianceFramework::OwaspTop10 => {
                frameworks::owasp::map_vulnerability(vuln_title, cve_id, port, service)
            }
        }
    }
}

/// Common vulnerability patterns and their control mappings
/// This provides additional generic mappings beyond framework-specific ones
pub fn get_common_mappings(
    vuln_title: &str,
    _cve_id: Option<&str>,
    port: Option<u16>,
    _service: Option<&str>,
) -> Vec<(ComplianceFramework, String, Severity)> {
    let mut mappings = Vec::new();
    let title_lower = vuln_title.to_lowercase();

    // SSL/TLS vulnerabilities affect encryption controls across frameworks
    if title_lower.contains("ssl") || title_lower.contains("tls") {
        if title_lower.contains("expired")
            || title_lower.contains("self-signed")
            || title_lower.contains("weak")
        {
            mappings.push((ComplianceFramework::PciDss4, "PCI-DSS-4.1".to_string(), Severity::High));
            mappings.push((ComplianceFramework::Hipaa, "HIPAA-164.312(e)(2)(ii)".to_string(), Severity::High));
            mappings.push((ComplianceFramework::Nist80053, "NIST-SC-8".to_string(), Severity::High));
        }
    }

    // Default credentials are critical across all frameworks
    if title_lower.contains("default") && (title_lower.contains("password") || title_lower.contains("credential")) {
        mappings.push((ComplianceFramework::PciDss4, "PCI-DSS-2.1".to_string(), Severity::Critical));
        mappings.push((ComplianceFramework::CisBenchmarks, "CIS-4.7".to_string(), Severity::Critical));
        mappings.push((ComplianceFramework::Nist80053, "NIST-IA-5".to_string(), Severity::Critical));
    }

    // Telnet and other insecure protocols
    if port == Some(23) || title_lower.contains("telnet") {
        mappings.push((ComplianceFramework::PciDss4, "PCI-DSS-2.2.7".to_string(), Severity::High));
        mappings.push((ComplianceFramework::CisBenchmarks, "CIS-4.6".to_string(), Severity::High));
        mappings.push((ComplianceFramework::Nist80053, "NIST-SC-8".to_string(), Severity::High));
    }

    // FTP (unencrypted)
    if port == Some(21) && !title_lower.contains("sftp") && !title_lower.contains("ftps") {
        mappings.push((ComplianceFramework::PciDss4, "PCI-DSS-4.2".to_string(), Severity::Medium));
        mappings.push((ComplianceFramework::CisBenchmarks, "CIS-4.6".to_string(), Severity::Medium));
    }

    // Remote code execution / command injection
    if title_lower.contains("remote code execution")
        || title_lower.contains("command injection")
        || title_lower.contains("rce")
    {
        mappings.push((ComplianceFramework::PciDss4, "PCI-DSS-6.5.1".to_string(), Severity::Critical));
        mappings.push((ComplianceFramework::Nist80053, "NIST-SI-10".to_string(), Severity::Critical));
        mappings.push((ComplianceFramework::Soc2, "SOC2-PI1.2".to_string(), Severity::Critical));
    }

    // SQL injection
    if title_lower.contains("sql injection") {
        mappings.push((ComplianceFramework::PciDss4, "PCI-DSS-6.5.1".to_string(), Severity::Critical));
        mappings.push((ComplianceFramework::Nist80053, "NIST-SI-10".to_string(), Severity::Critical));
        mappings.push((ComplianceFramework::Soc2, "SOC2-PI1.2".to_string(), Severity::Critical));
    }

    // Cross-site scripting
    if title_lower.contains("xss") || title_lower.contains("cross-site scripting") {
        mappings.push((ComplianceFramework::PciDss4, "PCI-DSS-6.5.7".to_string(), Severity::High));
        mappings.push((ComplianceFramework::Nist80053, "NIST-SI-10".to_string(), Severity::High));
    }

    mappings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vulnerability_mapper_creation() {
        let mapper = VulnerabilityMapper::new(vec![
            ComplianceFramework::PciDss4,
            ComplianceFramework::CisBenchmarks,
        ]);
        assert_eq!(mapper.frameworks.len(), 2);
    }

    #[test]
    fn test_common_mappings_ssl() {
        let mappings = get_common_mappings("Weak TLS cipher detected", None, Some(443), Some("https"));
        assert!(!mappings.is_empty());
    }

    #[test]
    fn test_common_mappings_telnet() {
        let mappings = get_common_mappings("Telnet service exposed", None, Some(23), Some("telnet"));
        assert!(!mappings.is_empty());
    }
}
