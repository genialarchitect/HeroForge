use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::db::models::SecretFindingRecord;
use crate::types::{HostInfo, Severity, Vulnerability};

/// Report format options
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReportFormat {
    Pdf,
    Html,
    Json,
    Csv,
    Markdown,
    Docx,
    Pptx,
    /// DISA STIG Viewer Checklist format
    Ckl,
    /// SCAP Asset Reporting Format
    Arf,
}

impl ReportFormat {
    pub fn extension(&self) -> &'static str {
        match self {
            ReportFormat::Pdf => "pdf",
            ReportFormat::Html => "html",
            ReportFormat::Json => "json",
            ReportFormat::Csv => "csv",
            ReportFormat::Markdown => "md",
            ReportFormat::Docx => "docx",
            ReportFormat::Pptx => "pptx",
            ReportFormat::Ckl => "ckl",
            ReportFormat::Arf => "xml",
        }
    }

    pub fn content_type(&self) -> &'static str {
        match self {
            ReportFormat::Pdf => "application/pdf",
            ReportFormat::Html => "text/html",
            ReportFormat::Json => "application/json",
            ReportFormat::Csv => "text/csv",
            ReportFormat::Markdown => "text/markdown",
            ReportFormat::Docx => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ReportFormat::Pptx => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            ReportFormat::Ckl => "application/xml",
            ReportFormat::Arf => "application/xml",
        }
    }

    /// Get all available formats
    pub fn all() -> Vec<ReportFormat> {
        vec![
            ReportFormat::Pdf,
            ReportFormat::Html,
            ReportFormat::Json,
            ReportFormat::Csv,
            ReportFormat::Markdown,
            ReportFormat::Docx,
            ReportFormat::Pptx,
            ReportFormat::Ckl,
            ReportFormat::Arf,
        ]
    }

    /// Check if format supports embedded images
    pub fn supports_images(&self) -> bool {
        matches!(self, ReportFormat::Pdf | ReportFormat::Html | ReportFormat::Docx | ReportFormat::Pptx)
    }

    /// Check if format supports charts
    pub fn supports_charts(&self) -> bool {
        matches!(self, ReportFormat::Pdf | ReportFormat::Html | ReportFormat::Pptx)
    }

    /// Check if format is for compliance/audit purposes
    pub fn is_compliance_format(&self) -> bool {
        matches!(self, ReportFormat::Ckl | ReportFormat::Arf)
    }
}

impl std::str::FromStr for ReportFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pdf" => Ok(ReportFormat::Pdf),
            "html" => Ok(ReportFormat::Html),
            "json" => Ok(ReportFormat::Json),
            "csv" => Ok(ReportFormat::Csv),
            "markdown" | "md" => Ok(ReportFormat::Markdown),
            "docx" | "word" => Ok(ReportFormat::Docx),
            "pptx" | "powerpoint" => Ok(ReportFormat::Pptx),
            "ckl" | "checklist" | "stig" => Ok(ReportFormat::Ckl),
            "arf" | "scap" => Ok(ReportFormat::Arf),
            _ => Err(format!("Unknown report format: {}", s)),
        }
    }
}

/// Report sections that can be included
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReportSection {
    TableOfContents,
    ExecutiveSummary,
    RiskOverview,
    HostInventory,
    PortAnalysis,
    VulnerabilityFindings,
    SecretFindings,
    ServiceEnumeration,
    Screenshots,
    RemediationRecommendations,
    OperatorNotes,
    Appendix,
}

impl ReportSection {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "tableofcontents" | "toc" => Some(ReportSection::TableOfContents),
            "executivesummary" | "executive" => Some(ReportSection::ExecutiveSummary),
            "riskoverview" | "risk" => Some(ReportSection::RiskOverview),
            "hostinventory" | "hosts" => Some(ReportSection::HostInventory),
            "portanalysis" | "ports" => Some(ReportSection::PortAnalysis),
            "vulnerabilityfindings" | "vulnerabilities" | "vulns" => Some(ReportSection::VulnerabilityFindings),
            "secretfindings" | "secrets" => Some(ReportSection::SecretFindings),
            "serviceenumeration" | "enumeration" => Some(ReportSection::ServiceEnumeration),
            "screenshots" | "evidence" => Some(ReportSection::Screenshots),
            "remediationrecommendations" | "remediation" => Some(ReportSection::RemediationRecommendations),
            "operatornotes" | "notes" => Some(ReportSection::OperatorNotes),
            "appendix" => Some(ReportSection::Appendix),
            _ => None,
        }
    }

    pub fn title(&self) -> &'static str {
        match self {
            ReportSection::TableOfContents => "Table of Contents",
            ReportSection::ExecutiveSummary => "Executive Summary",
            ReportSection::RiskOverview => "Risk Overview",
            ReportSection::HostInventory => "Host Inventory",
            ReportSection::PortAnalysis => "Port Analysis",
            ReportSection::VulnerabilityFindings => "Vulnerability Findings",
            ReportSection::SecretFindings => "Secret Findings",
            ReportSection::ServiceEnumeration => "Service Enumeration",
            ReportSection::Screenshots => "Visual Evidence",
            ReportSection::RemediationRecommendations => "Remediation Recommendations",
            ReportSection::OperatorNotes => "Operator Notes",
            ReportSection::Appendix => "Appendix",
        }
    }
}

/// Report template definitions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportTemplate {
    pub id: String,
    pub name: String,
    pub description: String,
    pub default_sections: Vec<ReportSection>,
    pub supports_formats: Vec<ReportFormat>,
}

impl ReportTemplate {
    /// Get the executive summary template
    pub fn executive() -> Self {
        ReportTemplate {
            id: "executive".to_string(),
            name: "Executive Summary".to_string(),
            description: "High-level overview for management and stakeholders".to_string(),
            default_sections: vec![
                ReportSection::ExecutiveSummary,
                ReportSection::RiskOverview,
                ReportSection::RemediationRecommendations,
            ],
            supports_formats: vec![ReportFormat::Pdf, ReportFormat::Html],
        }
    }

    /// Get the technical report template
    pub fn technical() -> Self {
        ReportTemplate {
            id: "technical".to_string(),
            name: "Technical Report".to_string(),
            description: "Detailed technical findings for security teams".to_string(),
            default_sections: vec![
                ReportSection::TableOfContents,
                ReportSection::ExecutiveSummary,
                ReportSection::RiskOverview,
                ReportSection::HostInventory,
                ReportSection::PortAnalysis,
                ReportSection::VulnerabilityFindings,
                ReportSection::SecretFindings,
                ReportSection::ServiceEnumeration,
                ReportSection::Screenshots,
                ReportSection::RemediationRecommendations,
                ReportSection::Appendix,
            ],
            supports_formats: vec![ReportFormat::Pdf, ReportFormat::Html, ReportFormat::Json],
        }
    }

    /// Get the compliance report template
    pub fn compliance() -> Self {
        ReportTemplate {
            id: "compliance".to_string(),
            name: "Compliance Report".to_string(),
            description: "Audit-ready compliance documentation".to_string(),
            default_sections: vec![
                ReportSection::TableOfContents,
                ReportSection::ExecutiveSummary,
                ReportSection::VulnerabilityFindings,
                ReportSection::Screenshots,
                ReportSection::RemediationRecommendations,
                ReportSection::Appendix,
            ],
            supports_formats: vec![ReportFormat::Pdf, ReportFormat::Html],
        }
    }

    /// Get all available templates
    pub fn all_templates() -> Vec<ReportTemplate> {
        vec![
            Self::executive(),
            Self::technical(),
            Self::compliance(),
        ]
    }

    /// Get a template by ID
    pub fn by_id(id: &str) -> Option<ReportTemplate> {
        match id {
            "executive" => Some(Self::executive()),
            "technical" => Some(Self::technical()),
            "compliance" => Some(Self::compliance()),
            _ => None,
        }
    }
}

/// Options for report generation
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReportOptions {
    #[serde(default)]
    pub include_charts: bool,
    #[serde(default)]
    pub include_screenshots: bool,
    pub company_name: Option<String>,
    pub assessor_name: Option<String>,
    pub classification: Option<String>,
}

/// Screenshot evidence for reports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportScreenshot {
    pub id: String,
    pub url: String,
    pub title: String,
    pub description: Option<String>,
    pub file_path: String,
    pub width: u32,
    pub height: u32,
    pub captured_at: DateTime<Utc>,
    /// Base64-encoded image data for embedding in HTML/PDF
    pub data_base64: Option<String>,
    /// Associated finding ID if applicable
    pub finding_id: Option<String>,
    /// Associated host IP if applicable
    pub host_ip: Option<String>,
}

/// Complete data structure for report generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportData {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub scan_id: String,
    pub scan_name: String,
    pub created_at: DateTime<Utc>,
    pub scan_date: DateTime<Utc>,
    pub template: ReportTemplate,
    pub sections: Vec<ReportSection>,
    pub options: ReportOptions,
    pub hosts: Vec<HostInfo>,
    pub summary: ReportSummary,
    pub findings: Vec<FindingDetail>,
    pub secrets: Vec<SecretFindingRecord>,
    pub remediation: Vec<RemediationRecommendation>,
    pub screenshots: Vec<ReportScreenshot>,
    /// Operator notes for the entire report
    pub operator_notes: Option<String>,
    /// Per-finding operator notes (finding_id -> notes)
    pub finding_notes: HashMap<String, String>,
}

/// Summary statistics for the report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub total_hosts: usize,
    pub live_hosts: usize,
    pub total_ports: usize,
    pub open_ports: usize,
    pub total_vulnerabilities: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub overall_risk_score: u8,
    pub overall_risk_level: String,
    pub top_findings: Vec<String>,
    pub affected_services: Vec<String>,
}

impl ReportSummary {
    /// Calculate summary from host info
    pub fn from_hosts(hosts: &[HostInfo]) -> Self {
        let total_hosts = hosts.len();
        let live_hosts = hosts.iter().filter(|h| h.is_alive).count();

        let mut total_ports = 0;
        let mut open_ports = 0;
        let mut services_set = std::collections::HashSet::new();

        for host in hosts {
            total_ports += host.ports.len();
            for port in &host.ports {
                if port.state == crate::types::PortState::Open {
                    open_ports += 1;
                    if let Some(ref svc) = port.service {
                        services_set.insert(svc.name.clone());
                    }
                }
            }
        }

        let mut critical_count = 0;
        let mut high_count = 0;
        let mut medium_count = 0;
        let mut low_count = 0;
        let mut top_findings = Vec::new();

        for host in hosts {
            for vuln in &host.vulnerabilities {
                match vuln.severity {
                    Severity::Critical => {
                        critical_count += 1;
                        if top_findings.len() < 5 {
                            top_findings.push(vuln.title.clone());
                        }
                    }
                    Severity::High => {
                        high_count += 1;
                        if top_findings.len() < 5 {
                            top_findings.push(vuln.title.clone());
                        }
                    }
                    Severity::Medium => medium_count += 1,
                    Severity::Low => low_count += 1,
                }
            }
        }

        let total_vulnerabilities = critical_count + high_count + medium_count + low_count;

        // Calculate risk score (0-100)
        let risk_score = calculate_risk_score(critical_count, high_count, medium_count, low_count, open_ports);
        let risk_level = risk_level_from_score(risk_score);

        ReportSummary {
            total_hosts,
            live_hosts,
            total_ports,
            open_ports,
            total_vulnerabilities,
            critical_count,
            high_count,
            medium_count,
            low_count,
            overall_risk_score: risk_score,
            overall_risk_level: risk_level,
            top_findings,
            affected_services: services_set.into_iter().collect(),
        }
    }
}

/// Detailed finding for the report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingDetail {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub cvss_score: Option<f32>,
    pub cve_id: Option<String>,
    pub affected_hosts: Vec<String>,
    pub affected_service: Option<String>,
    pub description: String,
    pub impact: String,
    pub remediation: String,
    pub references: Vec<String>,
    pub evidence: Option<String>,
}

impl FindingDetail {
    /// Create finding details from vulnerabilities across hosts
    pub fn from_vulnerabilities(hosts: &[HostInfo]) -> Vec<Self> {
        let mut findings: HashMap<String, FindingDetail> = HashMap::new();

        for host in hosts {
            let host_ip = host.target.ip.to_string();

            for vuln in &host.vulnerabilities {
                let key = vuln.cve_id.clone().unwrap_or_else(|| vuln.title.clone());

                if let Some(existing) = findings.get_mut(&key) {
                    if !existing.affected_hosts.contains(&host_ip) {
                        existing.affected_hosts.push(host_ip.clone());
                    }
                } else {
                    findings.insert(key.clone(), FindingDetail {
                        id: uuid::Uuid::new_v4().to_string(),
                        title: vuln.title.clone(),
                        severity: vuln.severity.clone(),
                        cvss_score: None,
                        cve_id: vuln.cve_id.clone(),
                        affected_hosts: vec![host_ip.clone()],
                        affected_service: vuln.affected_service.clone(),
                        description: vuln.description.clone(),
                        impact: get_impact_description(&vuln.severity),
                        remediation: get_remediation_for_vuln(vuln),
                        references: get_references_for_vuln(vuln),
                        evidence: None,
                    });
                }
            }
        }

        // Sort by severity (Critical first)
        let mut result: Vec<FindingDetail> = findings.into_values().collect();
        result.sort_by(|a, b| {
            let severity_order = |s: &Severity| match s {
                Severity::Critical => 0,
                Severity::High => 1,
                Severity::Medium => 2,
                Severity::Low => 3,
            };
            severity_order(&a.severity).cmp(&severity_order(&b.severity))
        });

        result
    }
}

/// Remediation recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationRecommendation {
    pub priority: u8,
    pub title: String,
    pub description: String,
    pub affected_findings: Vec<String>,
    pub effort_estimate: String,
    pub timeline_suggestion: String,
}

impl RemediationRecommendation {
    /// Generate remediation recommendations from findings
    pub fn from_findings(findings: &[FindingDetail]) -> Vec<Self> {
        let mut recommendations: Vec<RemediationRecommendation> = Vec::new();

        // Group findings by service type for consolidated recommendations
        let mut service_findings: HashMap<String, Vec<&FindingDetail>> = HashMap::new();

        for finding in findings {
            let service = finding.affected_service.clone().unwrap_or_else(|| "General".to_string());
            service_findings.entry(service).or_default().push(finding);
        }

        let mut priority = 1u8;

        // Generate recommendations per service
        for (service, svc_findings) in service_findings {
            let critical_count = svc_findings.iter().filter(|f| f.severity == Severity::Critical).count();
            let high_count = svc_findings.iter().filter(|f| f.severity == Severity::High).count();

            if critical_count > 0 || high_count > 0 {
                let effort = if critical_count > 2 || high_count > 5 { "High" } else { "Medium" };
                let timeline = if critical_count > 0 { "Immediate (24-48 hours)" } else { "Short-term (1-2 weeks)" };

                recommendations.push(RemediationRecommendation {
                    priority,
                    title: format!("Address {} vulnerabilities", service),
                    description: format!(
                        "Remediate {} critical and {} high severity findings affecting {} service.",
                        critical_count, high_count, service
                    ),
                    affected_findings: svc_findings.iter().map(|f| f.id.clone()).collect(),
                    effort_estimate: effort.to_string(),
                    timeline_suggestion: timeline.to_string(),
                });

                priority += 1;
            }
        }

        // Sort by priority
        recommendations.sort_by_key(|r| r.priority);
        recommendations
    }
}

// Helper functions

fn calculate_risk_score(critical: usize, high: usize, medium: usize, low: usize, open_ports: usize) -> u8 {
    // Weighted scoring: Critical=10, High=7, Medium=4, Low=1
    let vuln_score = (critical * 10 + high * 7 + medium * 4 + low) as f64;

    // Port exposure factor (capped at 30)
    let port_factor = (open_ports * 2).min(30) as f64;

    // Normalize to 0-100
    let raw_score = vuln_score + port_factor;
    let normalized = (raw_score / 2.0).min(100.0);

    normalized as u8
}

fn risk_level_from_score(score: u8) -> String {
    match score {
        0..=20 => "Low".to_string(),
        21..=40 => "Medium".to_string(),
        41..=60 => "High".to_string(),
        61..=80 => "Very High".to_string(),
        _ => "Critical".to_string(),
    }
}

fn get_impact_description(severity: &Severity) -> String {
    match severity {
        Severity::Critical => "This vulnerability could allow complete system compromise, unauthorized access to sensitive data, or enable further attacks on the network.".to_string(),
        Severity::High => "This vulnerability could lead to significant data exposure, service disruption, or unauthorized access to system resources.".to_string(),
        Severity::Medium => "This vulnerability may lead to limited information disclosure or provide stepping stones for further attacks.".to_string(),
        Severity::Low => "This vulnerability has limited impact but should be addressed as part of defense-in-depth strategy.".to_string(),
    }
}

fn get_remediation_for_vuln(vuln: &Vulnerability) -> String {
    // Service-specific remediation advice
    if let Some(ref service) = vuln.affected_service {
        let service_lower = service.to_lowercase();

        if service_lower.contains("smb") {
            return "Disable SMBv1, ensure latest security patches are applied, and restrict SMB access to trusted networks only.".to_string();
        }
        if service_lower.contains("rdp") {
            return "Enable Network Level Authentication (NLA), restrict RDP access via firewall, and use VPN for remote access.".to_string();
        }
        if service_lower.contains("ssh") {
            return "Update SSH to latest version, disable weak algorithms, use key-based authentication, and restrict access by IP.".to_string();
        }
        if service_lower.contains("http") || service_lower.contains("web") {
            return "Update web server software, review and harden configuration, implement WAF, and ensure TLS 1.2+ is enforced.".to_string();
        }
        if service_lower.contains("ftp") {
            return "Disable anonymous FTP access, use SFTP instead, and ensure proper file permissions are configured.".to_string();
        }
        if service_lower.contains("sql") || service_lower.contains("mysql") || service_lower.contains("postgres") {
            return "Update database software, enforce strong authentication, restrict network access, and review user privileges.".to_string();
        }
    }

    // CVE-specific lookup would go here
    if vuln.cve_id.is_some() {
        return format!("Apply vendor patches addressing {}. Consult vendor advisory for specific remediation steps.", vuln.cve_id.as_ref().unwrap());
    }

    "Review and apply vendor security updates. Implement network segmentation and access controls.".to_string()
}

fn get_references_for_vuln(vuln: &Vulnerability) -> Vec<String> {
    let mut refs = Vec::new();

    if let Some(ref cve) = vuln.cve_id {
        refs.push(format!("https://nvd.nist.gov/vuln/detail/{}", cve));
        refs.push(format!("https://cve.mitre.org/cgi-bin/cvename.cgi?name={}", cve));
    }

    refs
}
