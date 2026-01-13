//! Core types for compliance scanning
//!
//! This module defines the fundamental types used throughout the compliance
//! scanning system, including frameworks, controls, findings, and summaries.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::types::Severity;

/// Supported compliance frameworks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceFramework {
    /// CIS Benchmarks - System hardening standards
    CisBenchmarks,
    /// NIST 800-53 - Federal information systems security controls
    Nist80053,
    /// NIST Cybersecurity Framework - Risk management framework
    NistCsf,
    /// PCI DSS 4.0 - Payment Card Industry Data Security Standard
    PciDss4,
    /// HIPAA Security Rule - Healthcare data protection
    Hipaa,
    /// FERPA - Family Educational Rights and Privacy Act
    Ferpa,
    /// SOC 2 - Service Organization Control 2 Trust Services Criteria
    Soc2,
    /// OWASP Top 10 2021 - Web Application Security Risks
    OwaspTop10,
    /// HITRUST CSF - Health Information Trust Alliance Common Security Framework
    HitrustCsf,
    /// ISO 27001:2022 - Information Security Management System
    Iso27001,
    /// GDPR - General Data Protection Regulation
    Gdpr,
    /// DoD STIG - Security Technical Implementation Guides
    DodStig,

    // ============ US Federal Frameworks ============
    /// FedRAMP - Federal Risk and Authorization Management Program
    FedRamp,
    /// CMMC 2.0 - Cybersecurity Maturity Model Certification
    Cmmc,
    /// FISMA - Federal Information Security Management Act
    Fisma,
    /// NIST 800-171 - Protecting Controlled Unclassified Information
    Nist800171,
    /// NIST 800-82 - Guide to ICS Security
    Nist80082,
    /// NIST 800-61 - Computer Security Incident Handling Guide
    Nist80061,
    /// StateRAMP - State Risk and Authorization Management Program
    StateRamp,
    /// ITAR - International Traffic in Arms Regulations
    Itar,
    /// EAR - Export Administration Regulations
    Ear,
    /// DFARS - Defense Federal Acquisition Regulation Supplement
    Dfars,
    /// ICD 503 - Intelligence Community Directive 503
    Icd503,
    /// CNSSI 1253 - Security Categorization for National Security Systems
    Cnssi1253,
    /// RMF - Risk Management Framework
    Rmf,
    /// DISA Cloud Computing SRG - Security Requirements Guide
    DisaCloudSrg,
    /// DoD Zero Trust Reference Architecture
    DodZeroTrust,
    /// NIST Privacy Framework
    NistPrivacy,

    // ============ Industry/Sector Frameworks ============
    /// CSA CCM - Cloud Security Alliance Cloud Controls Matrix
    CsaCcm,
    /// NERC CIP - Critical Infrastructure Protection
    NercCip,
    /// IEC 62443 - Industrial Automation and Control Systems Security
    Iec62443,
    /// TSA Pipeline Security Directives
    TsaPipeline,
    /// CISA Cybersecurity Performance Goals
    CisaCpgs,
    /// Executive Order 14028 - Improving the Nation's Cybersecurity
    Eo14028,
    /// SOX - Sarbanes-Oxley Act IT Controls
    Sox,
    /// GLBA - Gramm-Leach-Bliley Act
    Glba,

    // ============ International Frameworks ============
    /// Cyber Essentials - UK NCSC Certification Scheme
    CyberEssentials,
    /// ISM - Australian Information Security Manual
    IsmAustralia,
    /// IRAP - Australian InfoSec Registered Assessors Program
    Irap,
    /// NIS2 - EU Network and Information Security Directive
    Nis2,
    /// ENS - Spanish National Security Framework
    EnsSpain,
    /// BSI IT-Grundschutz - German Federal Office for Information Security
    BsiGrundschutz,
    /// C5 - German Cloud Computing Compliance Criteria Catalogue
    C5,
    /// SecNumCloud - French ANSSI Cloud Security Qualification
    SecNumCloud,
    /// NATO Cyber Defence
    NatoCyber,
}

impl ComplianceFramework {
    /// Get all available frameworks
    pub fn all() -> Vec<Self> {
        vec![
            // Original 12
            Self::CisBenchmarks,
            Self::Nist80053,
            Self::NistCsf,
            Self::PciDss4,
            Self::Hipaa,
            Self::Ferpa,
            Self::Soc2,
            Self::OwaspTop10,
            Self::HitrustCsf,
            Self::Iso27001,
            Self::Gdpr,
            Self::DodStig,
            // US Federal (16)
            Self::FedRamp,
            Self::Cmmc,
            Self::Fisma,
            Self::Nist800171,
            Self::Nist80082,
            Self::Nist80061,
            Self::StateRamp,
            Self::Itar,
            Self::Ear,
            Self::Dfars,
            Self::Icd503,
            Self::Cnssi1253,
            Self::Rmf,
            Self::DisaCloudSrg,
            Self::DodZeroTrust,
            Self::NistPrivacy,
            // Industry/Sector (8)
            Self::CsaCcm,
            Self::NercCip,
            Self::Iec62443,
            Self::TsaPipeline,
            Self::CisaCpgs,
            Self::Eo14028,
            Self::Sox,
            Self::Glba,
            // International (9)
            Self::CyberEssentials,
            Self::IsmAustralia,
            Self::Irap,
            Self::Nis2,
            Self::EnsSpain,
            Self::BsiGrundschutz,
            Self::C5,
            Self::SecNumCloud,
            Self::NatoCyber,
        ]
    }

    /// Get the framework ID string
    pub fn id(&self) -> &'static str {
        match self {
            Self::CisBenchmarks => "cis",
            Self::Nist80053 => "nist_800_53",
            Self::NistCsf => "nist_csf",
            Self::PciDss4 => "pci_dss",
            Self::Hipaa => "hipaa",
            Self::Ferpa => "ferpa",
            Self::Soc2 => "soc2",
            Self::OwaspTop10 => "owasp_top10",
            Self::HitrustCsf => "hitrust_csf",
            Self::Iso27001 => "iso_27001",
            Self::Gdpr => "gdpr",
            Self::DodStig => "dod_stig",
            // US Federal
            Self::FedRamp => "fedramp",
            Self::Cmmc => "cmmc",
            Self::Fisma => "fisma",
            Self::Nist800171 => "nist_800_171",
            Self::Nist80082 => "nist_800_82",
            Self::Nist80061 => "nist_800_61",
            Self::StateRamp => "stateramp",
            Self::Itar => "itar",
            Self::Ear => "ear",
            Self::Dfars => "dfars",
            Self::Icd503 => "icd_503",
            Self::Cnssi1253 => "cnssi_1253",
            Self::Rmf => "rmf",
            Self::DisaCloudSrg => "disa_cloud_srg",
            Self::DodZeroTrust => "dod_zero_trust",
            Self::NistPrivacy => "nist_privacy",
            // Industry/Sector
            Self::CsaCcm => "csa_ccm",
            Self::NercCip => "nerc_cip",
            Self::Iec62443 => "iec_62443",
            Self::TsaPipeline => "tsa_pipeline",
            Self::CisaCpgs => "cisa_cpgs",
            Self::Eo14028 => "eo_14028",
            Self::Sox => "sox",
            Self::Glba => "glba",
            // International
            Self::CyberEssentials => "cyber_essentials",
            Self::IsmAustralia => "ism_australia",
            Self::Irap => "irap",
            Self::Nis2 => "nis2",
            Self::EnsSpain => "ens_spain",
            Self::BsiGrundschutz => "bsi_grundschutz",
            Self::C5 => "c5",
            Self::SecNumCloud => "secnumcloud",
            Self::NatoCyber => "nato_cyber",
        }
    }

    /// Get the human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            Self::CisBenchmarks => "CIS Benchmarks",
            Self::Nist80053 => "NIST 800-53",
            Self::NistCsf => "NIST Cybersecurity Framework",
            Self::PciDss4 => "PCI DSS 4.0",
            Self::Hipaa => "HIPAA Security Rule",
            Self::Ferpa => "FERPA",
            Self::Soc2 => "SOC 2",
            Self::OwaspTop10 => "OWASP Top 10",
            Self::HitrustCsf => "HITRUST CSF",
            Self::Iso27001 => "ISO 27001:2022",
            Self::Gdpr => "GDPR",
            Self::DodStig => "DoD STIG",
            // US Federal
            Self::FedRamp => "FedRAMP",
            Self::Cmmc => "CMMC 2.0",
            Self::Fisma => "FISMA",
            Self::Nist800171 => "NIST 800-171",
            Self::Nist80082 => "NIST 800-82",
            Self::Nist80061 => "NIST 800-61",
            Self::StateRamp => "StateRAMP",
            Self::Itar => "ITAR",
            Self::Ear => "EAR",
            Self::Dfars => "DFARS 252.204-7012",
            Self::Icd503 => "ICD 503",
            Self::Cnssi1253 => "CNSSI 1253",
            Self::Rmf => "Risk Management Framework",
            Self::DisaCloudSrg => "DISA Cloud SRG",
            Self::DodZeroTrust => "DoD Zero Trust",
            Self::NistPrivacy => "NIST Privacy Framework",
            // Industry/Sector
            Self::CsaCcm => "CSA CCM",
            Self::NercCip => "NERC CIP",
            Self::Iec62443 => "IEC 62443",
            Self::TsaPipeline => "TSA Pipeline Security",
            Self::CisaCpgs => "CISA CPGs",
            Self::Eo14028 => "EO 14028",
            Self::Sox => "SOX IT Controls",
            Self::Glba => "GLBA",
            // International
            Self::CyberEssentials => "Cyber Essentials",
            Self::IsmAustralia => "Australian ISM",
            Self::Irap => "IRAP",
            Self::Nis2 => "NIS2 Directive",
            Self::EnsSpain => "ENS (Spain)",
            Self::BsiGrundschutz => "BSI IT-Grundschutz",
            Self::C5 => "C5",
            Self::SecNumCloud => "SecNumCloud",
            Self::NatoCyber => "NATO Cyber Defence",
        }
    }

    /// Get the framework version
    pub fn version(&self) -> &'static str {
        match self {
            Self::CisBenchmarks => "v8.0",
            Self::Nist80053 => "Rev 5",
            Self::NistCsf => "v2.0",
            Self::PciDss4 => "v4.0",
            Self::Hipaa => "2013",
            Self::Ferpa => "2023",
            Self::Soc2 => "2017",
            Self::OwaspTop10 => "2021",
            Self::HitrustCsf => "v11.3",
            Self::Iso27001 => "2022",
            Self::Gdpr => "2018",
            Self::DodStig => "v5",
            // US Federal
            Self::FedRamp => "Rev 5",
            Self::Cmmc => "2.0",
            Self::Fisma => "2014",
            Self::Nist800171 => "Rev 3",
            Self::Nist80082 => "Rev 3",
            Self::Nist80061 => "Rev 2",
            Self::StateRamp => "2024",
            Self::Itar => "2024",
            Self::Ear => "2024",
            Self::Dfars => "2024",
            Self::Icd503 => "2017",
            Self::Cnssi1253 => "2022",
            Self::Rmf => "2.0",
            Self::DisaCloudSrg => "v1r5",
            Self::DodZeroTrust => "v2.0",
            Self::NistPrivacy => "v1.0",
            // Industry/Sector
            Self::CsaCcm => "v4.0",
            Self::NercCip => "v7",
            Self::Iec62443 => "2024",
            Self::TsaPipeline => "2024",
            Self::CisaCpgs => "v1.0",
            Self::Eo14028 => "2021",
            Self::Sox => "2002",
            Self::Glba => "1999",
            // International
            Self::CyberEssentials => "2024",
            Self::IsmAustralia => "2024",
            Self::Irap => "2024",
            Self::Nis2 => "2022",
            Self::EnsSpain => "2022",
            Self::BsiGrundschutz => "2023",
            Self::C5 => "2020",
            Self::SecNumCloud => "v3.2",
            Self::NatoCyber => "2024",
        }
    }

    /// Get the framework description
    pub fn description(&self) -> &'static str {
        match self {
            Self::CisBenchmarks => "Center for Internet Security configuration benchmarks for system hardening",
            Self::Nist80053 => "Security and privacy controls for federal information systems and organizations",
            Self::NistCsf => "Framework for improving critical infrastructure cybersecurity",
            Self::PciDss4 => "Security standards for organizations handling payment card data",
            Self::Hipaa => "Security standards for protecting electronic health information",
            Self::Ferpa => "Federal law protecting student education records and privacy",
            Self::Soc2 => "Trust Services Criteria for service organization security, availability, and confidentiality",
            Self::OwaspTop10 => "Top 10 web application security risks identified by OWASP",
            Self::HitrustCsf => "Comprehensive healthcare security framework integrating HIPAA, NIST, PCI-DSS, and ISO 27001 controls",
            Self::Iso27001 => "International standard for information security management systems (ISMS)",
            Self::Gdpr => "EU regulation on data protection and privacy for individuals",
            Self::DodStig => "Department of Defense Security Technical Implementation Guides for hardening systems to DoD standards",
            // US Federal
            Self::FedRamp => "Federal Risk and Authorization Management Program for cloud service providers",
            Self::Cmmc => "Cybersecurity Maturity Model Certification for defense industrial base contractors",
            Self::Fisma => "Federal Information Security Management Act requirements for federal agencies",
            Self::Nist800171 => "Protecting Controlled Unclassified Information in nonfederal systems",
            Self::Nist80082 => "Guide to Industrial Control Systems (ICS) security",
            Self::Nist80061 => "Computer security incident handling guide for federal agencies",
            Self::StateRamp => "State Risk and Authorization Management Program for state government cloud services",
            Self::Itar => "International Traffic in Arms Regulations for defense-related exports",
            Self::Ear => "Export Administration Regulations for dual-use technology controls",
            Self::Dfars => "Defense Federal Acquisition Regulation Supplement cybersecurity requirements",
            Self::Icd503 => "Intelligence Community Directive for IT systems security risk management",
            Self::Cnssi1253 => "Security categorization and control selection for National Security Systems",
            Self::Rmf => "NIST Risk Management Framework for managing security and privacy risk",
            Self::DisaCloudSrg => "DISA Security Requirements Guide for DoD cloud computing",
            Self::DodZeroTrust => "DoD Zero Trust Reference Architecture for network security",
            Self::NistPrivacy => "Framework for managing privacy risks through enterprise risk management",
            // Industry/Sector
            Self::CsaCcm => "Cloud Security Alliance Cloud Controls Matrix for cloud security assurance",
            Self::NercCip => "Critical Infrastructure Protection standards for the bulk electric system",
            Self::Iec62443 => "International standard for industrial automation and control systems security",
            Self::TsaPipeline => "TSA security directives for pipeline cybersecurity",
            Self::CisaCpgs => "CISA Cybersecurity Performance Goals for critical infrastructure",
            Self::Eo14028 => "Executive Order on improving the nation's cybersecurity",
            Self::Sox => "Sarbanes-Oxley IT controls for financial reporting integrity",
            Self::Glba => "Gramm-Leach-Bliley Act requirements for financial institution data protection",
            // International
            Self::CyberEssentials => "UK NCSC certification scheme for basic cyber hygiene",
            Self::IsmAustralia => "Australian Government Information Security Manual for protecting systems",
            Self::Irap => "Australian InfoSec Registered Assessors Program for government systems",
            Self::Nis2 => "EU Network and Information Security Directive for critical infrastructure",
            Self::EnsSpain => "Spanish National Security Framework for public sector information systems",
            Self::BsiGrundschutz => "German BSI IT-Grundschutz methodology for information security management",
            Self::C5 => "German Cloud Computing Compliance Criteria Catalogue for cloud providers",
            Self::SecNumCloud => "French ANSSI security qualification for cloud service providers",
            Self::NatoCyber => "NATO Cyber Defence requirements for alliance information systems",
        }
    }

    /// Parse from string ID
    pub fn from_id(id: &str) -> Option<Self> {
        match id.to_lowercase().as_str() {
            "cis" | "cis_benchmarks" => Some(Self::CisBenchmarks),
            "nist_800_53" | "nist80053" => Some(Self::Nist80053),
            "nist_csf" | "nistcsf" => Some(Self::NistCsf),
            "pci_dss" | "pci_dss_4" | "pcidss" => Some(Self::PciDss4),
            "hipaa" => Some(Self::Hipaa),
            "ferpa" => Some(Self::Ferpa),
            "soc2" | "soc_2" => Some(Self::Soc2),
            "owasp" | "owasp_top10" | "owasp_top_10" => Some(Self::OwaspTop10),
            "hitrust" | "hitrust_csf" | "hitrustcsf" => Some(Self::HitrustCsf),
            "iso27001" | "iso_27001" | "iso27k" => Some(Self::Iso27001),
            "gdpr" => Some(Self::Gdpr),
            "dod_stig" | "dodstig" | "stig" | "dod-stig" => Some(Self::DodStig),
            // US Federal
            "fedramp" | "fed_ramp" => Some(Self::FedRamp),
            "cmmc" | "cmmc_2" | "cmmc2" => Some(Self::Cmmc),
            "fisma" => Some(Self::Fisma),
            "nist_800_171" | "nist800171" => Some(Self::Nist800171),
            "nist_800_82" | "nist80082" => Some(Self::Nist80082),
            "nist_800_61" | "nist80061" => Some(Self::Nist80061),
            "stateramp" | "state_ramp" => Some(Self::StateRamp),
            "itar" => Some(Self::Itar),
            "ear" => Some(Self::Ear),
            "dfars" => Some(Self::Dfars),
            "icd_503" | "icd503" => Some(Self::Icd503),
            "cnssi_1253" | "cnssi1253" => Some(Self::Cnssi1253),
            "rmf" => Some(Self::Rmf),
            "disa_cloud_srg" | "disa_srg" | "cloud_srg" => Some(Self::DisaCloudSrg),
            "dod_zero_trust" | "zero_trust" => Some(Self::DodZeroTrust),
            "nist_privacy" | "privacy_framework" => Some(Self::NistPrivacy),
            // Industry/Sector
            "csa_ccm" | "ccm" => Some(Self::CsaCcm),
            "nerc_cip" | "nerc" | "cip" => Some(Self::NercCip),
            "iec_62443" | "iec62443" | "62443" => Some(Self::Iec62443),
            "tsa_pipeline" | "tsa" | "pipeline" => Some(Self::TsaPipeline),
            "cisa_cpgs" | "cpgs" => Some(Self::CisaCpgs),
            "eo_14028" | "eo14028" | "executive_order" => Some(Self::Eo14028),
            "sox" | "sarbanes_oxley" => Some(Self::Sox),
            "glba" | "gramm_leach_bliley" => Some(Self::Glba),
            // International
            "cyber_essentials" | "cyberessentials" | "ce" => Some(Self::CyberEssentials),
            "ism_australia" | "ism" | "australian_ism" => Some(Self::IsmAustralia),
            "irap" => Some(Self::Irap),
            "nis2" | "nis_2" | "nis2_directive" => Some(Self::Nis2),
            "ens_spain" | "ens" => Some(Self::EnsSpain),
            "bsi_grundschutz" | "grundschutz" | "it_grundschutz" => Some(Self::BsiGrundschutz),
            "c5" => Some(Self::C5),
            "secnumcloud" | "sec_num_cloud" => Some(Self::SecNumCloud),
            "nato_cyber" | "nato" => Some(Self::NatoCyber),
            _ => None,
        }
    }
}

impl fmt::Display for ComplianceFramework {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Control priority level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ControlPriority {
    Critical,
    High,
    Medium,
    Low,
}

impl fmt::Display for ControlPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Critical => write!(f, "critical"),
            Self::High => write!(f, "high"),
            Self::Medium => write!(f, "medium"),
            Self::Low => write!(f, "low"),
        }
    }
}

/// Control status indicating compliance state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlStatus {
    /// Control requirements are fully met
    Compliant,
    /// Control requirements are not met
    NonCompliant,
    /// Some control requirements are met
    PartiallyCompliant,
    /// Control is not applicable to this environment
    NotApplicable,
    /// Control has not been assessed (requires manual review)
    NotAssessed,
    /// Control status has been manually overridden
    ManualOverride,
}

impl ControlStatus {
    /// Check if this status indicates a compliance issue
    pub fn is_issue(&self) -> bool {
        matches!(self, Self::NonCompliant | Self::PartiallyCompliant)
    }

    /// Check if this status counts toward compliance score
    pub fn counts_toward_score(&self) -> bool {
        !matches!(self, Self::NotApplicable | Self::NotAssessed)
    }
}

impl fmt::Display for ControlStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Compliant => write!(f, "Compliant"),
            Self::NonCompliant => write!(f, "Non-Compliant"),
            Self::PartiallyCompliant => write!(f, "Partially Compliant"),
            Self::NotApplicable => write!(f, "Not Applicable"),
            Self::NotAssessed => write!(f, "Not Assessed"),
            Self::ManualOverride => write!(f, "Manual Override"),
        }
    }
}

/// Source of a compliance finding
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FindingSource {
    /// Finding derived from vulnerability mapping
    VulnerabilityMapping {
        cve_id: Option<String>,
        vuln_title: String,
    },
    /// Finding from direct compliance check
    DirectCheck {
        check_id: String,
        check_name: String,
    },
    /// Finding from manual assessment
    ManualReview {
        reviewer: Option<String>,
        review_date: Option<DateTime<Utc>>,
    },
}

/// A compliance control definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceControl {
    /// Unique identifier (e.g., "AC-7", "1.1.1", "PCI-DSS-1.1.1")
    pub id: String,
    /// Control ID within the framework (e.g., "AC-7" for NIST, "1.1.1" for CIS)
    pub control_id: String,
    /// Framework this control belongs to
    pub framework: ComplianceFramework,
    /// Human-readable title
    pub title: String,
    /// Detailed description
    pub description: String,
    /// Category/family (e.g., "Access Control", "Encryption")
    pub category: String,
    /// Priority level
    pub priority: ControlPriority,
    /// Whether this control can be automatically assessed
    pub automated_check: bool,
    /// Parent control ID for hierarchical controls
    pub parent_id: Option<String>,
    /// Related controls in other frameworks
    pub cross_references: Vec<String>,
    /// Remediation guidance
    pub remediation_guidance: Option<String>,
}

/// A compliance finding from a scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceFinding {
    /// Unique finding ID
    pub id: String,
    /// Scan this finding belongs to
    pub scan_id: String,
    /// Control this finding relates to
    pub control_id: String,
    /// Framework ID
    pub framework: ComplianceFramework,
    /// Compliance status
    pub status: ControlStatus,
    /// Severity of non-compliance
    pub severity: Severity,
    /// Evidence supporting the finding
    pub evidence: Vec<String>,
    /// Affected host IPs
    pub affected_hosts: Vec<String>,
    /// Affected ports (if applicable)
    pub affected_ports: Vec<u16>,
    /// Remediation recommendation
    pub remediation: String,
    /// Source of this finding
    pub source: FindingSource,
    /// Additional notes
    pub notes: Option<String>,
    /// When the finding was created
    pub created_at: DateTime<Utc>,
    /// When the finding was last updated
    pub updated_at: DateTime<Utc>,
    /// User who manually overrode status (if applicable)
    pub override_by: Option<String>,
    /// Reason for manual override (if applicable)
    pub override_reason: Option<String>,
}

/// Summary statistics for a framework
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkSummary {
    /// Framework ID
    pub framework: ComplianceFramework,
    /// Total controls in the framework
    pub total_controls: usize,
    /// Number of compliant controls
    pub compliant: usize,
    /// Number of non-compliant controls
    pub non_compliant: usize,
    /// Number of partially compliant controls
    pub partially_compliant: usize,
    /// Number of not-applicable controls
    pub not_applicable: usize,
    /// Number of not-assessed controls
    pub not_assessed: usize,
    /// Number of manually overridden controls
    pub manual_overrides: usize,
    /// Compliance score (0-100)
    pub compliance_score: f32,
    /// Breakdown by category
    pub by_category: Vec<CategorySummary>,
}

/// Summary statistics for a control category
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategorySummary {
    /// Category name
    pub category: String,
    /// Total controls in category
    pub total: usize,
    /// Compliant controls
    pub compliant: usize,
    /// Non-compliant controls
    pub non_compliant: usize,
    /// Compliance percentage
    pub percentage: f32,
}

/// Overall compliance summary for a scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceSummary {
    /// Scan ID
    pub scan_id: String,
    /// Per-framework summaries
    pub frameworks: Vec<FrameworkSummary>,
    /// Overall compliance score across all frameworks
    pub overall_score: f32,
    /// Total findings count
    pub total_findings: usize,
    /// Critical severity findings
    pub critical_findings: usize,
    /// High severity findings
    pub high_findings: usize,
    /// Medium severity findings
    pub medium_findings: usize,
    /// Low severity findings
    pub low_findings: usize,
    /// When the summary was generated
    pub generated_at: DateTime<Utc>,
}

/// Configuration for compliance scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceScanConfig {
    /// Frameworks to assess
    pub frameworks: Vec<ComplianceFramework>,
    /// Whether to run compliance checks during scan (integrated mode)
    pub integrated_mode: bool,
    /// Categories to include (empty = all)
    pub include_categories: Vec<String>,
    /// Categories to exclude
    pub exclude_categories: Vec<String>,
    /// Minimum control priority to assess
    pub min_priority: Option<ControlPriority>,
    /// Whether to include not-assessed controls in reports
    pub include_not_assessed: bool,
}

impl Default for ComplianceScanConfig {
    fn default() -> Self {
        Self {
            frameworks: vec![ComplianceFramework::PciDss4],
            integrated_mode: false,
            include_categories: Vec::new(),
            exclude_categories: Vec::new(),
            min_priority: None,
            include_not_assessed: true,
        }
    }
}

/// Request to analyze a scan for compliance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceAnalysisRequest {
    /// Scan ID to analyze
    pub scan_id: String,
    /// Frameworks to assess
    pub frameworks: Vec<String>,
}

/// Request to manually override a finding's status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManualOverrideRequest {
    /// New status
    pub status: ControlStatus,
    /// Reason for override
    pub reason: String,
    /// Additional notes
    pub notes: Option<String>,
}

/// Response for compliance analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceAnalysisResponse {
    /// Job ID for tracking async analysis
    pub job_id: String,
    /// Status of the analysis
    pub status: String,
    /// Message
    pub message: String,
}
