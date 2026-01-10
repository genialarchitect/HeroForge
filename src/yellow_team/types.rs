//! Yellow Team types for DevSecOps operations

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

// ============================================================================
// Common Types
// ============================================================================

/// Severity levels for findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "critical"),
            Severity::High => write!(f, "high"),
            Severity::Medium => write!(f, "medium"),
            Severity::Low => write!(f, "low"),
            Severity::Info => write!(f, "info"),
        }
    }
}

/// Risk levels for assessments
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Critical,
    High,
    #[default]
    Medium,
    Low,
    None,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Critical => write!(f, "critical"),
            RiskLevel::High => write!(f, "high"),
            RiskLevel::Medium => write!(f, "medium"),
            RiskLevel::Low => write!(f, "low"),
            RiskLevel::None => write!(f, "none"),
        }
    }
}

/// Generic scan status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl std::fmt::Display for ScanStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanStatus::Pending => write!(f, "pending"),
            ScanStatus::Running => write!(f, "running"),
            ScanStatus::Completed => write!(f, "completed"),
            ScanStatus::Failed => write!(f, "failed"),
            ScanStatus::Cancelled => write!(f, "cancelled"),
        }
    }
}

// ============================================================================
// SAST Types
// ============================================================================

/// Supported programming languages for SAST
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SastLanguage {
    Rust,
    Python,
    JavaScript,
    TypeScript,
    Go,
    Java,
    CSharp,
    Ruby,
    Php,
    C,
    Cpp,
    Kotlin,
    Scala,
    Swift,
    Unknown,
}

impl std::fmt::Display for SastLanguage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SastLanguage::Rust => write!(f, "rust"),
            SastLanguage::Python => write!(f, "python"),
            SastLanguage::JavaScript => write!(f, "javascript"),
            SastLanguage::TypeScript => write!(f, "typescript"),
            SastLanguage::Go => write!(f, "go"),
            SastLanguage::Java => write!(f, "java"),
            SastLanguage::CSharp => write!(f, "csharp"),
            SastLanguage::Ruby => write!(f, "ruby"),
            SastLanguage::Php => write!(f, "php"),
            SastLanguage::C => write!(f, "c"),
            SastLanguage::Cpp => write!(f, "cpp"),
            SastLanguage::Kotlin => write!(f, "kotlin"),
            SastLanguage::Scala => write!(f, "scala"),
            SastLanguage::Swift => write!(f, "swift"),
            SastLanguage::Unknown => write!(f, "unknown"),
        }
    }
}

impl SastLanguage {
    pub fn from_extension(ext: &str) -> Self {
        match ext.to_lowercase().as_str() {
            "rs" => SastLanguage::Rust,
            "py" => SastLanguage::Python,
            "js" | "mjs" | "cjs" => SastLanguage::JavaScript,
            "ts" | "tsx" => SastLanguage::TypeScript,
            "go" => SastLanguage::Go,
            "java" => SastLanguage::Java,
            "cs" => SastLanguage::CSharp,
            "rb" => SastLanguage::Ruby,
            "php" => SastLanguage::Php,
            "c" | "h" => SastLanguage::C,
            "cpp" | "cc" | "cxx" | "hpp" => SastLanguage::Cpp,
            "kt" | "kts" => SastLanguage::Kotlin,
            "scala" | "sc" => SastLanguage::Scala,
            "swift" => SastLanguage::Swift,
            _ => SastLanguage::Unknown,
        }
    }
}

/// SAST finding categories (aligned with OWASP Top 10)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SastCategory {
    Injection,
    BrokenAuth,
    SensitiveDataExposure,
    Xxe,
    BrokenAccessControl,
    SecurityMisconfiguration,
    Xss,
    InsecureDeserialization,
    VulnerableComponents,
    InsufficientLogging,
    Cryptography,
    PathTraversal,
    CommandInjection,
    SqlInjection,
    HardcodedSecrets,
    BufferOverflow,
    RaceCondition,
    UseAfterFree,
    NullPointerDereference,
    IntegerOverflow,
    Ssrf,
    SecurityHotspot,
    TaintedDataFlow,
    Other,
}

impl std::fmt::Display for SastCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SastCategory::Injection => write!(f, "injection"),
            SastCategory::BrokenAuth => write!(f, "broken_auth"),
            SastCategory::SensitiveDataExposure => write!(f, "sensitive_data_exposure"),
            SastCategory::Xxe => write!(f, "xxe"),
            SastCategory::BrokenAccessControl => write!(f, "broken_access_control"),
            SastCategory::SecurityMisconfiguration => write!(f, "security_misconfiguration"),
            SastCategory::Xss => write!(f, "xss"),
            SastCategory::InsecureDeserialization => write!(f, "insecure_deserialization"),
            SastCategory::VulnerableComponents => write!(f, "vulnerable_components"),
            SastCategory::InsufficientLogging => write!(f, "insufficient_logging"),
            SastCategory::Cryptography => write!(f, "cryptography"),
            SastCategory::PathTraversal => write!(f, "path_traversal"),
            SastCategory::CommandInjection => write!(f, "command_injection"),
            SastCategory::SqlInjection => write!(f, "sql_injection"),
            SastCategory::HardcodedSecrets => write!(f, "hardcoded_secrets"),
            SastCategory::BufferOverflow => write!(f, "buffer_overflow"),
            SastCategory::RaceCondition => write!(f, "race_condition"),
            SastCategory::UseAfterFree => write!(f, "use_after_free"),
            SastCategory::NullPointerDereference => write!(f, "null_pointer_dereference"),
            SastCategory::IntegerOverflow => write!(f, "integer_overflow"),
            SastCategory::Ssrf => write!(f, "ssrf"),
            SastCategory::SecurityHotspot => write!(f, "security_hotspot"),
            SastCategory::TaintedDataFlow => write!(f, "tainted_data_flow"),
            SastCategory::Other => write!(f, "other"),
        }
    }
}

/// Source type for SAST scans
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SastSourceType {
    GitRepo,
    Upload,
    Directory,
}

/// Pattern type for SAST rules
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatternType {
    Regex,
    Ast,
    Semantic,
}

/// Code location for a finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeLocation {
    pub line_start: u32,
    pub line_end: Option<u32>,
    pub column_start: Option<u32>,
    pub column_end: Option<u32>,
}

/// SAST scan configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SastScan {
    pub id: String,
    pub user_id: String,
    pub project_name: String,
    pub language: SastLanguage,
    pub source_type: SastSourceType,
    pub source_path: String,
    pub status: ScanStatus,
    pub total_findings: i32,
    pub critical_count: i32,
    pub high_count: i32,
    pub medium_count: i32,
    pub low_count: i32,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// SAST finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SastFinding {
    pub id: String,
    pub scan_id: String,
    pub rule_id: String,
    pub severity: Severity,
    pub category: SastCategory,
    pub file_path: String,
    pub location: CodeLocation,
    pub code_snippet: Option<String>,
    pub message: String,
    pub cwe_id: Option<String>,
    pub remediation: Option<String>,
    pub false_positive: bool,
    pub suppressed: bool,
    pub created_at: DateTime<Utc>,
}

/// SAST rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SastRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub language: SastLanguage,
    pub severity: Severity,
    pub category: SastCategory,
    pub pattern: String,
    pub pattern_type: PatternType,
    pub cwe_id: Option<String>,
    pub remediation_guidance: Option<String>,
    pub enabled: bool,
    pub custom: bool,
    pub created_by: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Request to start a SAST scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartSastScanRequest {
    pub name: String,               // Scan name
    pub project_name: String,
    pub source_type: SastSourceType,
    pub source_path: String,
    pub code: Option<String>,       // Inline code to scan (alternative to source_path)
    pub language: Option<SastLanguage>, // Auto-detect if not specified
    pub languages: Option<Vec<SastLanguage>>, // Multiple languages to scan
    pub rule_ids: Option<Vec<String>>,  // Use all if not specified
    pub enabled_rules: Option<Vec<String>>,   // Rules to enable
    pub disabled_rules: Option<Vec<String>>,  // Rules to disable
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
}

/// Request to create a custom SAST rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSastRuleRequest {
    pub name: String,
    pub description: String,
    pub language: SastLanguage,
    pub severity: Severity,
    pub category: SastCategory,
    pub pattern: String,
    pub pattern_type: PatternType,
    pub cwe_id: Option<String>,
    pub remediation_guidance: Option<String>,
}

/// Update a SAST finding (suppress, mark false positive)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSastFindingRequest {
    pub false_positive: Option<bool>,
    pub suppressed: Option<bool>,
}

// ============================================================================
// SBOM Types
// ============================================================================

/// License risk levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LicenseRisk {
    Low,           // MIT, Apache-2.0, BSD
    Medium,        // LGPL, MPL
    High,          // GPL, AGPL
    Critical,      // Proprietary, unknown
    Permissive,    // MIT, Apache, BSD (alias for Low)
    Copyleft,      // GPL, AGPL (strong copyleft)
    WeakCopyleft,  // LGPL, MPL (weak copyleft)
    Proprietary,   // Commercial/proprietary
    PublicDomain,  // CC0, Unlicense
    #[default]
    Unknown,
}

impl std::fmt::Display for LicenseRisk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LicenseRisk::Low => write!(f, "low"),
            LicenseRisk::Medium => write!(f, "medium"),
            LicenseRisk::High => write!(f, "high"),
            LicenseRisk::Critical => write!(f, "critical"),
            LicenseRisk::Permissive => write!(f, "permissive"),
            LicenseRisk::Copyleft => write!(f, "copyleft"),
            LicenseRisk::WeakCopyleft => write!(f, "weakcopyleft"),
            LicenseRisk::Proprietary => write!(f, "proprietary"),
            LicenseRisk::PublicDomain => write!(f, "publicdomain"),
            LicenseRisk::Unknown => write!(f, "unknown"),
        }
    }
}

impl LicenseRisk {
    pub fn from_license(license: &str) -> Self {
        let license_lower = license.to_lowercase();
        if license_lower.contains("mit")
            || license_lower.contains("apache")
            || license_lower.contains("bsd")
            || license_lower.contains("isc")
        {
            LicenseRisk::Permissive
        } else if license_lower.contains("unlicense") || license_lower.contains("cc0") {
            LicenseRisk::PublicDomain
        } else if license_lower.contains("lgpl") || license_lower.contains("mpl") {
            LicenseRisk::WeakCopyleft
        } else if license_lower.contains("gpl") || license_lower.contains("agpl") {
            LicenseRisk::Copyleft
        } else if license_lower.contains("proprietary") || license_lower.is_empty() {
            LicenseRisk::Proprietary
        } else {
            LicenseRisk::Unknown
        }
    }
}

/// SBOM export format
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SbomFormat {
    #[default]
    CycloneDx,
    #[serde(alias = "CycloneDX")]
    CycloneDX, // Alias for compatibility
    Spdx,
    Json,
}

impl std::fmt::Display for SbomFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SbomFormat::CycloneDx | SbomFormat::CycloneDX => write!(f, "cyclone_dx"),
            SbomFormat::Spdx => write!(f, "spdx"),
            SbomFormat::Json => write!(f, "json"),
        }
    }
}

impl std::str::FromStr for SbomFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "cyclonedx" | "cyclone_dx" => Ok(SbomFormat::CycloneDx),
            "spdx" => Ok(SbomFormat::Spdx),
            "json" => Ok(SbomFormat::Json),
            _ => Err(format!("Unknown SBOM format: {}", s)),
        }
    }
}

/// SBOM project
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomProject {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub version: Option<String>,
    pub source_type: SastSourceType,
    pub source_path: String,
    pub last_scan_at: Option<DateTime<Utc>>,
    pub component_count: i32,
    pub vulnerability_count: i32,
    pub license_risk: LicenseRisk,
    pub created_at: DateTime<Utc>,
}

/// SBOM component (dependency)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomComponent {
    pub id: String,
    pub project_id: String,
    pub name: String,
    pub version: String,
    pub purl: String,               // Package URL (required)
    pub cpe: Option<String>,        // CPE identifier
    pub component_type: ComponentType,
    pub supplier: Option<String>,
    pub licenses: Vec<LicenseInfo>,
    pub hashes: std::collections::HashMap<String, String>,
    pub description: Option<String>,
    pub dependency_type: DependencyType,
    pub external_refs: Vec<ExternalReference>,
    pub vulnerabilities: Vec<String>, // CVE IDs
    pub created_at: DateTime<Utc>,
}

impl SbomComponent {
    /// Get the primary license as a single string
    pub fn license(&self) -> Option<String> {
        self.licenses.first().map(|l| l.spdx_id.clone())
    }

    /// Check if this is a direct dependency
    pub fn is_direct(&self) -> bool {
        matches!(self.dependency_type, DependencyType::Direct)
    }
}

/// Request to generate SBOM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateSbomRequest {
    pub project_name: String,
    pub source_type: SastSourceType,
    pub source_path: String,
    pub version: Option<String>,
}

/// SBOM export response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomExportResponse {
    pub format: SbomFormat,
    pub content: String,
    pub filename: String,
}

// ============================================================================
// API Security Types
// ============================================================================

/// API spec format
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ApiSpecFormat {
    #[default]
    OpenApi3,
    OpenApi2,
    Swagger2,  // Alias for OpenApi2
    GraphQL,
    Raml,
    Wadl,
    AsyncApi,
    Unknown,
}

impl std::fmt::Display for ApiSpecFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiSpecFormat::OpenApi3 => write!(f, "OpenAPI 3.x"),
            ApiSpecFormat::OpenApi2 => write!(f, "OpenAPI 2.x"),
            ApiSpecFormat::Swagger2 => write!(f, "Swagger 2.0"),
            ApiSpecFormat::GraphQL => write!(f, "GraphQL"),
            ApiSpecFormat::Raml => write!(f, "RAML"),
            ApiSpecFormat::Wadl => write!(f, "WADL"),
            ApiSpecFormat::AsyncApi => write!(f, "AsyncAPI"),
            ApiSpecFormat::Unknown => write!(f, "Unknown"),
        }
    }
}

/// API security finding type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiSecurityFindingType {
    NoAuth,
    #[serde(alias = "missing_authentication")]
    MissingAuthentication, // Alias for NoAuth
    WeakAuth,
    #[serde(alias = "weak_authentication")]
    WeakAuthentication, // Alias for WeakAuth
    MissingRateLimit,
    SensitiveDataExposure,
    ExcessiveDataExposure,
    InjectionRisk,
    BrokenObjectLevelAuth,
    MassAssignment,
    SecurityMisconfiguration,
    ImproperAssetManagement,
    InsufficientLogging,
    ServerSideRequestForgery,
    InsecureTransport,
    Other,
}

/// API security scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSecurityScan {
    pub id: String,
    pub user_id: String,
    pub api_name: String,
    pub spec_format: ApiSpecFormat,
    pub spec_content: String,
    pub base_url: Option<String>,
    pub status: ScanStatus,
    pub total_findings: i32,
    pub auth_issues: i32,
    pub injection_risks: i32,
    pub created_at: DateTime<Utc>,
}

/// API security finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSecurityFinding {
    pub id: String,
    pub scan_id: String,
    pub endpoint: String,
    pub method: Option<HttpMethod>,
    pub finding_type: ApiSecurityFindingType,
    pub category: ApiSecurityCategory,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub recommendation: Option<String>,
    pub cwe_id: Option<String>,
    pub owasp_api_id: Option<String>,
    pub evidence: Option<String>,
    pub affected_parameters: Vec<String>,
    pub remediation_effort: RemediationEffort,
    pub remediation: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Request to scan API spec
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanApiRequest {
    pub api_name: String,
    pub spec_format: ApiSpecFormat,
    pub spec_content: String,
    pub base_url: Option<String>,
}

// ============================================================================
// Architecture Review Types
// ============================================================================

/// STRIDE threat categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum StrideCategory {
    #[default]
    Spoofing,
    Tampering,
    Repudiation,
    InformationDisclosure,
    DenialOfService,
    ElevationOfPrivilege,
}

impl std::fmt::Display for StrideCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StrideCategory::Spoofing => write!(f, "Spoofing"),
            StrideCategory::Tampering => write!(f, "Tampering"),
            StrideCategory::Repudiation => write!(f, "Repudiation"),
            StrideCategory::InformationDisclosure => write!(f, "Information Disclosure"),
            StrideCategory::DenialOfService => write!(f, "Denial of Service"),
            StrideCategory::ElevationOfPrivilege => write!(f, "Elevation of Privilege"),
        }
    }
}

impl StrideCategory {
    pub fn from_str(s: &str) -> Self {
        match s {
            "spoofing" | "Spoofing" => StrideCategory::Spoofing,
            "tampering" | "Tampering" => StrideCategory::Tampering,
            "repudiation" | "Repudiation" => StrideCategory::Repudiation,
            "information_disclosure" | "InformationDisclosure" => StrideCategory::InformationDisclosure,
            "denial_of_service" | "DenialOfService" => StrideCategory::DenialOfService,
            "elevation_of_privilege" | "ElevationOfPrivilege" => StrideCategory::ElevationOfPrivilege,
            _ => StrideCategory::default(),
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            StrideCategory::Spoofing => "Threat actor pretending to be something/someone else",
            StrideCategory::Tampering => "Threat actor modifying data or code",
            StrideCategory::Repudiation => "Threat actor denying having performed an action",
            StrideCategory::InformationDisclosure => "Threat actor accessing unauthorized information",
            StrideCategory::DenialOfService => "Threat actor causing service unavailability",
            StrideCategory::ElevationOfPrivilege => "Threat actor gaining unauthorized access levels",
        }
    }
}

/// Architecture review status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewStatus {
    Draft,
    InProgress,
    Completed,
    Approved,
    Archived,
}

impl std::fmt::Display for ReviewStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReviewStatus::Draft => write!(f, "draft"),
            ReviewStatus::InProgress => write!(f, "in_progress"),
            ReviewStatus::Completed => write!(f, "completed"),
            ReviewStatus::Approved => write!(f, "approved"),
            ReviewStatus::Archived => write!(f, "archived"),
        }
    }
}

/// Threat status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ThreatStatus {
    #[default]
    Identified,
    Open,
    InProgress,
    Mitigated,
    Accepted,
    Transferred,
    Closed,
}

impl std::fmt::Display for ThreatStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatStatus::Identified => write!(f, "identified"),
            ThreatStatus::Open => write!(f, "open"),
            ThreatStatus::InProgress => write!(f, "in_progress"),
            ThreatStatus::Mitigated => write!(f, "mitigated"),
            ThreatStatus::Accepted => write!(f, "accepted"),
            ThreatStatus::Transferred => write!(f, "transferred"),
            ThreatStatus::Closed => write!(f, "closed"),
        }
    }
}

impl std::str::FromStr for ThreatStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "identified" => Ok(ThreatStatus::Identified),
            "open" => Ok(ThreatStatus::Open),
            "in_progress" => Ok(ThreatStatus::InProgress),
            "mitigated" => Ok(ThreatStatus::Mitigated),
            "accepted" => Ok(ThreatStatus::Accepted),
            "transferred" => Ok(ThreatStatus::Transferred),
            "closed" => Ok(ThreatStatus::Closed),
            _ => Err(format!("Unknown threat status: {}", s)),
        }
    }
}

impl ThreatStatus {
    pub fn from_str(s: &str) -> Self {
        match s {
            "identified" => ThreatStatus::Identified,
            "open" => ThreatStatus::Open,
            "in_progress" => ThreatStatus::InProgress,
            "mitigated" => ThreatStatus::Mitigated,
            "accepted" => ThreatStatus::Accepted,
            "transferred" => ThreatStatus::Transferred,
            "closed" => ThreatStatus::Closed,
            _ => ThreatStatus::default(),
        }
    }
}

/// Architecture review
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchitectureReview {
    pub id: String,
    pub user_id: String,
    pub project_name: String,
    pub description: Option<String>,
    pub diagram_data: Option<serde_json::Value>, // JSON representation
    pub status: ReviewStatus,
    pub threat_count: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Architecture threat
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchitectureThreat {
    pub id: String,
    pub review_id: String,
    pub stride_category: StrideCategory,
    pub component: String,
    pub threat_description: String,
    pub severity: Severity,
    pub likelihood: RiskLevel,
    pub impact: RiskLevel,
    pub mitigations: Vec<String>,
    pub status: ThreatStatus,
    pub created_at: DateTime<Utc>,
}

/// Architecture component for diagram
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchitectureComponent {
    pub id: String,
    pub name: String,
    pub component_type: String, // 'service', 'database', 'external', 'user', etc.
    pub trust_level: String,    // 'trusted', 'semi-trusted', 'untrusted'
    pub data_classification: Option<String>,
    pub position: ComponentPosition,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentPosition {
    pub x: f64,
    pub y: f64,
}

/// Data flow between components
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlow {
    pub id: Uuid,
    pub threat_model_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub source_id: Uuid,
    pub destination_id: Uuid,
    pub data_classification: DataClassification,
    pub protocol: Option<String>,
    pub port: Option<u16>,
    pub encrypted: bool,
    pub authenticated: bool,
    pub bidirectional: bool,
    pub crosses_trust_boundary: bool,
    pub data_types: Vec<String>,
}

/// Request to create architecture review
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateArchitectureReviewRequest {
    pub project_name: String,
    pub description: Option<String>,
    pub components: Option<Vec<ArchitectureComponent>>,
    pub data_flows: Option<Vec<DataFlow>>,
}

/// Request to add a threat
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddThreatRequest {
    pub stride_category: StrideCategory,
    pub affected_component_id: Uuid,
    pub affected_dataflow_id: Option<Uuid>,
    pub title: String,
    pub description: String,
    pub attack_scenario: Option<String>,
    pub prerequisites: Option<Vec<String>>,
    pub likelihood: Option<Likelihood>,
    pub impact: Option<Impact>,
    pub mitigations: Option<Vec<String>>,
    pub cwe_ids: Option<Vec<String>>,
    pub capec_ids: Option<Vec<String>>,
    pub notes: Option<String>,
}

/// Request to update a threat
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateThreatRequest {
    pub title: Option<String>,
    pub description: Option<String>,
    pub attack_scenario: Option<String>,
    pub prerequisites: Option<Vec<String>>,
    pub severity: Option<Severity>,
    pub likelihood: Option<Likelihood>,
    pub impact: Option<Impact>,
    pub mitigations: Option<Vec<String>>,
    pub cwe_ids: Option<Vec<String>>,
    pub capec_ids: Option<Vec<String>>,
    pub notes: Option<String>,
    pub status: Option<ThreatStatus>,
}

// ============================================================================
// DevSecOps Dashboard Types
// ============================================================================

/// Pipeline type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineType {
    GithubActions,
    GitlabCi,
    Jenkins,
    AzureDevops,
    CircleCi,
    Other,
}

/// Build status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildStatus {
    Success,
    Failed,
    Running,
    Pending,
    Cancelled,
}

/// DevSecOps project
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevSecOpsProject {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub repo_url: Option<String>,
    pub pipeline_type: Option<PipelineType>,
    pub security_gate_enabled: bool,
    pub last_build_status: Option<BuildStatus>,
    pub last_build_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// DevSecOps metrics for a project
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevSecOpsMetrics {
    pub id: String,
    pub project_id: String,
    pub metric_date: NaiveDate,
    pub new_findings: i32,
    pub fixed_findings: i32,
    pub mttr_hours: Option<f64>, // Mean time to remediate
    pub security_gate_passed: bool,
    pub build_blocked: bool,
    pub created_at: DateTime<Utc>,
}

/// Dashboard overview
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevSecOpsDashboard {
    pub total_projects: i32,
    pub total_scans: i32,
    pub total_findings: i32,
    pub critical_findings: i32,
    pub high_findings: i32,
    pub avg_mttr_hours: Option<f64>,
    pub security_gate_pass_rate: f64,
    pub findings_by_category: HashMap<String, i32>,
    pub findings_trend: Vec<FindingsTrendPoint>,
    pub recent_scans: Vec<RecentScan>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingsTrendPoint {
    pub date: NaiveDate,
    pub new_findings: i32,
    pub fixed_findings: i32,
    pub total_open: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentScan {
    pub scan_id: String,
    pub scan_type: String, // 'sast', 'sbom', 'api'
    pub project_name: String,
    pub status: ScanStatus,
    pub findings_count: i32,
    pub created_at: DateTime<Utc>,
}

/// Request to create DevSecOps project
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDevSecOpsProjectRequest {
    pub name: String,
    pub repo_url: Option<String>,
    pub pipeline_type: Option<PipelineType>,
    pub security_gate_enabled: Option<bool>,
}

// ============================================================================
// SARIF Output Types
// ============================================================================

/// SARIF (Static Analysis Results Interchange Format) output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifReport {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    pub rules: Vec<SarifRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRule {
    pub id: String,
    pub name: String,
    #[serde(rename = "shortDescription")]
    pub short_description: SarifMessage,
    #[serde(rename = "fullDescription")]
    pub full_description: Option<SarifMessage>,
    #[serde(rename = "defaultConfiguration")]
    pub default_configuration: Option<SarifConfiguration>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifConfiguration {
    pub level: String, // "error", "warning", "note"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub level: String,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
    pub region: Option<SarifRegion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRegion {
    #[serde(rename = "startLine")]
    pub start_line: u32,
    #[serde(rename = "endLine")]
    pub end_line: Option<u32>,
    #[serde(rename = "startColumn")]
    pub start_column: Option<u32>,
    #[serde(rename = "endColumn")]
    pub end_column: Option<u32>,
}

// ============================================================================
// Threat Modeling Types
// ============================================================================

/// Threat model for architecture security review
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatModel {
    pub id: Uuid,
    pub user_id: Uuid,
    pub org_id: Option<Uuid>,
    pub name: String,
    pub system_description: String,
    pub components: Vec<SystemComponent>,
    pub data_flows: Vec<DataFlow>,
    pub trust_boundaries: Vec<TrustBoundary>,
    pub threats: Vec<StrideTheat>,
    pub mitigations: Vec<Mitigation>,
    pub risk_score: f64,
    pub status: ThreatModelStatus,
    pub version: u32,
    pub tags: Vec<String>,
    pub created_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// System component in threat model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemComponent {
    pub id: Uuid,
    pub threat_model_id: Uuid,
    pub name: String,
    pub component_type: ArchComponentType,
    pub description: Option<String>,
    pub trust_level: TrustLevel,
    pub data_classification: DataClassification,
    pub technologies: Vec<String>,
    pub external: bool,
    pub position_x: Option<f64>,
    pub position_y: Option<f64>,
    pub metadata: HashMap<String, String>,
}

/// Architecture component type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ArchComponentType {
    #[default]
    WebApplication,
    ApiGateway,
    Microservice,
    Database,
    MessageQueue,
    Cache,
    LoadBalancer,
    FileStorage,
    IdentityProvider,
    ExternalService,
    MobileApp,
    IoTDevice,
    Container,
    ServerlessFunction,
    DataWarehouse,
}

impl std::fmt::Display for ArchComponentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArchComponentType::WebApplication => write!(f, "web_application"),
            ArchComponentType::ApiGateway => write!(f, "api_gateway"),
            ArchComponentType::Microservice => write!(f, "microservice"),
            ArchComponentType::Database => write!(f, "database"),
            ArchComponentType::MessageQueue => write!(f, "message_queue"),
            ArchComponentType::Cache => write!(f, "cache"),
            ArchComponentType::LoadBalancer => write!(f, "load_balancer"),
            ArchComponentType::FileStorage => write!(f, "file_storage"),
            ArchComponentType::IdentityProvider => write!(f, "identity_provider"),
            ArchComponentType::ExternalService => write!(f, "external_service"),
            ArchComponentType::MobileApp => write!(f, "mobile_app"),
            ArchComponentType::IoTDevice => write!(f, "iot_device"),
            ArchComponentType::Container => write!(f, "container"),
            ArchComponentType::ServerlessFunction => write!(f, "serverless_function"),
            ArchComponentType::DataWarehouse => write!(f, "data_warehouse"),
        }
    }
}

impl std::str::FromStr for ArchComponentType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "web_application" => Ok(ArchComponentType::WebApplication),
            "api_gateway" => Ok(ArchComponentType::ApiGateway),
            "microservice" => Ok(ArchComponentType::Microservice),
            "database" => Ok(ArchComponentType::Database),
            "message_queue" => Ok(ArchComponentType::MessageQueue),
            "cache" => Ok(ArchComponentType::Cache),
            "load_balancer" => Ok(ArchComponentType::LoadBalancer),
            "file_storage" => Ok(ArchComponentType::FileStorage),
            "identity_provider" => Ok(ArchComponentType::IdentityProvider),
            "external_service" => Ok(ArchComponentType::ExternalService),
            "mobile_app" => Ok(ArchComponentType::MobileApp),
            "iot_device" => Ok(ArchComponentType::IoTDevice),
            "container" => Ok(ArchComponentType::Container),
            "serverless_function" => Ok(ArchComponentType::ServerlessFunction),
            "data_warehouse" => Ok(ArchComponentType::DataWarehouse),
            _ => Err(format!("Unknown component type: {}", s)),
        }
    }
}

impl ArchComponentType {
    pub fn from_str(s: &str) -> Self {
        match s {
            "web_application" => ArchComponentType::WebApplication,
            "api_gateway" => ArchComponentType::ApiGateway,
            "microservice" => ArchComponentType::Microservice,
            "database" => ArchComponentType::Database,
            "message_queue" => ArchComponentType::MessageQueue,
            "cache" => ArchComponentType::Cache,
            "load_balancer" => ArchComponentType::LoadBalancer,
            "file_storage" => ArchComponentType::FileStorage,
            "identity_provider" => ArchComponentType::IdentityProvider,
            "external_service" => ArchComponentType::ExternalService,
            "mobile_app" => ArchComponentType::MobileApp,
            "iot_device" => ArchComponentType::IoTDevice,
            "container" => ArchComponentType::Container,
            "serverless_function" => ArchComponentType::ServerlessFunction,
            "data_warehouse" => ArchComponentType::DataWarehouse,
            _ => ArchComponentType::default(),
        }
    }
}

/// Trust level for components
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    Untrusted,
    External,
    Dmz,
    #[default]
    Internal,
    Trusted,
    HighlyTrusted,
}

impl std::fmt::Display for TrustLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrustLevel::Untrusted => write!(f, "untrusted"),
            TrustLevel::External => write!(f, "external"),
            TrustLevel::Dmz => write!(f, "dmz"),
            TrustLevel::Internal => write!(f, "internal"),
            TrustLevel::Trusted => write!(f, "trusted"),
            TrustLevel::HighlyTrusted => write!(f, "highly_trusted"),
        }
    }
}

impl std::str::FromStr for TrustLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "untrusted" => Ok(TrustLevel::Untrusted),
            "external" => Ok(TrustLevel::External),
            "dmz" => Ok(TrustLevel::Dmz),
            "internal" => Ok(TrustLevel::Internal),
            "trusted" => Ok(TrustLevel::Trusted),
            "highly_trusted" | "semi_trusted" => Ok(TrustLevel::HighlyTrusted),
            _ => Err(format!("Unknown trust level: {}", s)),
        }
    }
}

impl TrustLevel {
    pub fn from_str(s: &str) -> Self {
        match s {
            "untrusted" => TrustLevel::Untrusted,
            "external" => TrustLevel::External,
            "dmz" => TrustLevel::Dmz,
            "internal" => TrustLevel::Internal,
            "trusted" => TrustLevel::Trusted,
            "highly_trusted" | "semi_trusted" => TrustLevel::HighlyTrusted,
            _ => TrustLevel::default(),
        }
    }
}

/// Data classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DataClassification {
    Public,
    #[default]
    Internal,
    Confidential,
    Restricted,
    TopSecret,
}

impl std::fmt::Display for DataClassification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DataClassification::Public => write!(f, "public"),
            DataClassification::Internal => write!(f, "internal"),
            DataClassification::Confidential => write!(f, "confidential"),
            DataClassification::Restricted => write!(f, "restricted"),
            DataClassification::TopSecret => write!(f, "top_secret"),
        }
    }
}

impl std::str::FromStr for DataClassification {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "public" => Ok(DataClassification::Public),
            "internal" => Ok(DataClassification::Internal),
            "confidential" => Ok(DataClassification::Confidential),
            "restricted" => Ok(DataClassification::Restricted),
            "top_secret" => Ok(DataClassification::TopSecret),
            _ => Err(format!("Unknown data classification: {}", s)),
        }
    }
}

impl DataClassification {
    pub fn from_str(s: &str) -> Self {
        match s {
            "public" => DataClassification::Public,
            "internal" => DataClassification::Internal,
            "confidential" => DataClassification::Confidential,
            "restricted" => DataClassification::Restricted,
            "top_secret" => DataClassification::TopSecret,
            _ => DataClassification::default(),
        }
    }
}

/// Trust boundary in threat model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustBoundary {
    pub id: Uuid,
    pub threat_model_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub boundary_type: BoundaryType,
    pub components: Vec<Uuid>,
    pub color: Option<String>,
    pub position_x: Option<f64>,
    pub position_y: Option<f64>,
    pub width: Option<f64>,
    pub height: Option<f64>,
}

impl TrustBoundary {
    /// Alias for components field (for compatibility)
    pub fn components_inside(&self) -> &Vec<Uuid> {
        &self.components
    }
}

/// Boundary type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryType {
    #[default]
    Network,
    Process,
    Machine,
    Container,
    Zone,
    Cloud,
    Vpc,
}

impl std::fmt::Display for BoundaryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BoundaryType::Network => write!(f, "network"),
            BoundaryType::Process => write!(f, "process"),
            BoundaryType::Machine => write!(f, "machine"),
            BoundaryType::Container => write!(f, "container"),
            BoundaryType::Zone => write!(f, "zone"),
            BoundaryType::Cloud => write!(f, "cloud"),
            BoundaryType::Vpc => write!(f, "vpc"),
        }
    }
}

impl std::str::FromStr for BoundaryType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "network" => Ok(BoundaryType::Network),
            "process" => Ok(BoundaryType::Process),
            "machine" => Ok(BoundaryType::Machine),
            "container" => Ok(BoundaryType::Container),
            "zone" => Ok(BoundaryType::Zone),
            "cloud" => Ok(BoundaryType::Cloud),
            "vpc" => Ok(BoundaryType::Vpc),
            _ => Err(format!("Unknown boundary type: {}", s)),
        }
    }
}

impl BoundaryType {
    pub fn from_str(s: &str) -> Self {
        match s {
            "network" => BoundaryType::Network,
            "process" => BoundaryType::Process,
            "machine" => BoundaryType::Machine,
            "container" => BoundaryType::Container,
            "zone" => BoundaryType::Zone,
            "cloud" => BoundaryType::Cloud,
            "vpc" => BoundaryType::Vpc,
            _ => BoundaryType::default(),
        }
    }
}

/// STRIDE threat
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrideTheat {
    pub id: Uuid,
    pub threat_model_id: Uuid,
    pub category: StrideCategory,
    pub affected_component_id: Uuid,
    pub affected_dataflow_id: Option<Uuid>,
    pub title: String,
    pub description: String,
    pub attack_scenario: String,
    pub prerequisites: Vec<String>,
    pub likelihood: Likelihood,
    pub impact: Impact,
    pub risk_rating: RiskRating,
    pub mitigations: Vec<Uuid>,
    pub status: ThreatStatus,
    pub priority: u32,
    pub cwe_ids: Vec<String>,
    pub capec_ids: Vec<String>,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Mitigation for a threat
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mitigation {
    pub id: Uuid,
    pub threat_model_id: Uuid,
    pub title: String,
    pub description: String,
    pub control_type: ControlType,
    pub implementation_status: ImplementationStatus,
    pub implementation_notes: Option<String>,
    pub linked_controls: Vec<String>,
    pub effort_estimate: Option<String>,
    pub cost_estimate: Option<String>,
    pub effectiveness: Option<u32>,
    pub owner: Option<String>,
    pub due_date: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Control type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ControlType {
    #[default]
    Preventive,
    Detective,
    Corrective,
    Compensating,
    Directive,
}

impl std::fmt::Display for ControlType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ControlType::Preventive => write!(f, "preventive"),
            ControlType::Detective => write!(f, "detective"),
            ControlType::Corrective => write!(f, "corrective"),
            ControlType::Compensating => write!(f, "compensating"),
            ControlType::Directive => write!(f, "directive"),
        }
    }
}

impl ControlType {
    pub fn from_str(s: &str) -> Self {
        match s {
            "preventive" => ControlType::Preventive,
            "detective" => ControlType::Detective,
            "corrective" => ControlType::Corrective,
            "compensating" => ControlType::Compensating,
            "directive" => ControlType::Directive,
            _ => ControlType::default(),
        }
    }
}

/// Implementation status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ImplementationStatus {
    #[default]
    NotStarted,
    InProgress,
    Implemented,
    Verified,
    NotApplicable,
}

impl std::fmt::Display for ImplementationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImplementationStatus::NotStarted => write!(f, "not_started"),
            ImplementationStatus::InProgress => write!(f, "in_progress"),
            ImplementationStatus::Implemented => write!(f, "implemented"),
            ImplementationStatus::Verified => write!(f, "verified"),
            ImplementationStatus::NotApplicable => write!(f, "not_applicable"),
        }
    }
}

impl ImplementationStatus {
    pub fn from_str(s: &str) -> Self {
        match s {
            "not_started" => ImplementationStatus::NotStarted,
            "in_progress" => ImplementationStatus::InProgress,
            "implemented" => ImplementationStatus::Implemented,
            "verified" => ImplementationStatus::Verified,
            "not_applicable" => ImplementationStatus::NotApplicable,
            _ => ImplementationStatus::default(),
        }
    }
}

/// Threat model status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ThreatModelStatus {
    #[default]
    Draft,
    InReview,
    Approved,
    Archived,
}

impl std::fmt::Display for ThreatModelStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatModelStatus::Draft => write!(f, "draft"),
            ThreatModelStatus::InReview => write!(f, "in_review"),
            ThreatModelStatus::Approved => write!(f, "approved"),
            ThreatModelStatus::Archived => write!(f, "archived"),
        }
    }
}

impl ThreatModelStatus {
    pub fn from_str(s: &str) -> Self {
        match s {
            "draft" => ThreatModelStatus::Draft,
            "in_review" => ThreatModelStatus::InReview,
            "approved" => ThreatModelStatus::Approved,
            "archived" => ThreatModelStatus::Archived,
            _ => ThreatModelStatus::Draft,
        }
    }
}

/// Likelihood rating
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Likelihood {
    VeryLow,
    Low,
    #[default]
    Medium,
    High,
    VeryHigh,
}

impl std::fmt::Display for Likelihood {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Likelihood::VeryLow => write!(f, "very_low"),
            Likelihood::Low => write!(f, "low"),
            Likelihood::Medium => write!(f, "medium"),
            Likelihood::High => write!(f, "high"),
            Likelihood::VeryHigh => write!(f, "very_high"),
        }
    }
}

impl std::str::FromStr for Likelihood {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "very_low" => Ok(Likelihood::VeryLow),
            "low" => Ok(Likelihood::Low),
            "medium" => Ok(Likelihood::Medium),
            "high" => Ok(Likelihood::High),
            "very_high" => Ok(Likelihood::VeryHigh),
            _ => Err(format!("Unknown likelihood: {}", s)),
        }
    }
}

impl Likelihood {
    pub fn from_str(s: &str) -> Self {
        match s {
            "very_low" => Likelihood::VeryLow,
            "low" => Likelihood::Low,
            "medium" => Likelihood::Medium,
            "high" => Likelihood::High,
            "very_high" => Likelihood::VeryHigh,
            _ => Likelihood::Medium,
        }
    }
}

/// Impact rating
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Impact {
    Negligible,
    Minor,
    #[default]
    Moderate,
    Major,
    Catastrophic,
}

impl std::fmt::Display for Impact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Impact::Negligible => write!(f, "negligible"),
            Impact::Minor => write!(f, "minor"),
            Impact::Moderate => write!(f, "moderate"),
            Impact::Major => write!(f, "major"),
            Impact::Catastrophic => write!(f, "catastrophic"),
        }
    }
}

impl std::str::FromStr for Impact {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "negligible" => Ok(Impact::Negligible),
            "minor" => Ok(Impact::Minor),
            "moderate" => Ok(Impact::Moderate),
            "major" => Ok(Impact::Major),
            "catastrophic" => Ok(Impact::Catastrophic),
            _ => Err(format!("Unknown impact: {}", s)),
        }
    }
}

impl Impact {
    pub fn from_str(s: &str) -> Self {
        match s {
            "negligible" => Impact::Negligible,
            "minor" => Impact::Minor,
            "moderate" => Impact::Moderate,
            "major" => Impact::Major,
            "catastrophic" => Impact::Catastrophic,
            _ => Impact::Moderate,
        }
    }
}

/// Risk rating
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RiskRating {
    VeryLow,
    Low,
    #[default]
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for RiskRating {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskRating::VeryLow => write!(f, "very_low"),
            RiskRating::Low => write!(f, "low"),
            RiskRating::Medium => write!(f, "medium"),
            RiskRating::High => write!(f, "high"),
            RiskRating::Critical => write!(f, "critical"),
        }
    }
}

impl std::str::FromStr for RiskRating {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "very_low" => Ok(RiskRating::VeryLow),
            "low" => Ok(RiskRating::Low),
            "medium" => Ok(RiskRating::Medium),
            "high" => Ok(RiskRating::High),
            "critical" => Ok(RiskRating::Critical),
            _ => Err(format!("Unknown risk rating: {}", s)),
        }
    }
}

impl RiskRating {
    pub fn from_str(s: &str) -> Self {
        match s {
            "very_low" => RiskRating::VeryLow,
            "low" => RiskRating::Low,
            "medium" => RiskRating::Medium,
            "high" => RiskRating::High,
            "critical" => RiskRating::Critical,
            _ => RiskRating::default(),
        }
    }

    pub fn calculate(likelihood: Likelihood, impact: Impact) -> Self {
        let l_score = match likelihood {
            Likelihood::VeryLow => 1,
            Likelihood::Low => 2,
            Likelihood::Medium => 3,
            Likelihood::High => 4,
            Likelihood::VeryHigh => 5,
        };
        let i_score = match impact {
            Impact::Negligible => 1,
            Impact::Minor => 2,
            Impact::Moderate => 3,
            Impact::Major => 4,
            Impact::Catastrophic => 5,
        };
        let combined = l_score * i_score;
        match combined {
            1..=4 => RiskRating::VeryLow,
            5..=8 => RiskRating::Low,
            9..=12 => RiskRating::Medium,
            13..=19 => RiskRating::High,
            _ => RiskRating::Critical,
        }
    }

    pub fn score(&self) -> u32 {
        match self {
            RiskRating::VeryLow => 1,
            RiskRating::Low => 2,
            RiskRating::Medium => 3,
            RiskRating::High => 4,
            RiskRating::Critical => 5,
        }
    }
}

/// Request to create a threat model
#[derive(Debug, Clone, Deserialize)]
pub struct CreateThreatModelRequest {
    pub name: String,
    pub system_description: String,
    pub org_id: Option<Uuid>,
    pub tags: Option<Vec<String>>,
}

/// Request to update a threat model
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateThreatModelRequest {
    pub name: Option<String>,
    pub system_description: Option<String>,
    pub status: Option<ThreatModelStatus>,
    pub tags: Option<Vec<String>>,
}

/// Request to add a component
#[derive(Debug, Clone, Deserialize)]
pub struct AddComponentRequest {
    pub name: String,
    pub component_type: ArchComponentType,
    pub description: Option<String>,
    pub trust_level: Option<TrustLevel>,
    pub data_classification: Option<DataClassification>,
    pub technologies: Option<Vec<String>>,
    pub external: Option<bool>,
    pub position_x: Option<f64>,
    pub position_y: Option<f64>,
    pub metadata: Option<HashMap<String, String>>,
}

/// Request to add a data flow
#[derive(Debug, Clone, Deserialize)]
pub struct AddDataFlowRequest {
    pub name: String,
    pub source_id: Uuid,
    pub destination_id: Uuid,
    pub protocol: Option<String>,
    pub port: Option<u16>,
    pub data_classification: Option<DataClassification>,
    pub encrypted: Option<bool>,
    pub authenticated: Option<bool>,
    pub bidirectional: Option<bool>,
    pub description: Option<String>,
    pub data_types: Option<Vec<String>>,
}

/// Request to add a trust boundary
#[derive(Debug, Clone, Deserialize)]
pub struct AddTrustBoundaryRequest {
    pub name: String,
    pub boundary_type: Option<BoundaryType>,
    pub description: Option<String>,
    pub components: Option<Vec<Uuid>>,
    pub color: Option<String>,
    pub position_x: Option<f64>,
    pub position_y: Option<f64>,
    pub width: Option<f64>,
    pub height: Option<f64>,
}

/// Request to add a mitigation
#[derive(Debug, Clone, Deserialize)]
pub struct AddMitigationRequest {
    pub title: String,
    pub description: String,
    pub control_type: Option<ControlType>,
    pub implementation_status: Option<ImplementationStatus>,
    pub implementation_notes: Option<String>,
    pub linked_controls: Option<Vec<String>>,
    pub effort_estimate: Option<String>,
    pub cost_estimate: Option<String>,
    pub effectiveness: Option<u32>,
    pub owner: Option<String>,
    pub due_date: Option<DateTime<Utc>>,
}

/// Request to update threat status
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateThreatStatusRequest {
    pub status: ThreatStatus,
    pub mitigation_ids: Option<Vec<Uuid>>,
    pub notes: Option<String>,
}

/// Threat model summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatModelSummary {
    pub id: String,
    pub name: String,
    pub status: ThreatModelStatus,
    pub risk_score: f64,
    pub component_count: u32,
    pub data_flow_count: u32,
    pub trust_boundary_count: u32,
    pub threat_count: u32,
    pub open_threat_count: u32,
    pub mitigation_count: u32,
    pub threats_by_status: HashMap<String, u32>,
    pub threats_by_category: HashMap<String, u32>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Threat model analyzer for STRIDE analysis
pub struct ThreatModelAnalyzer {
    pub model: ThreatModel,
    pub components: Vec<SystemComponent>,
    pub data_flows: Vec<ThreatModelDataFlow>,
    pub trust_boundaries: Vec<TrustBoundary>,
    pub threats: Vec<StrideTheat>,
}

/// Data flow in threat model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatModelDataFlow {
    pub id: String,
    pub model_id: String,
    pub name: String,
    pub source_id: String,
    pub destination_id: String,
    pub protocol: Option<String>,
    pub data_classification: DataClassification,
    pub encrypted: bool,
    pub authenticated: bool,
    pub description: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl ThreatModelAnalyzer {
    /// Create a new analyzer
    pub fn new(model: ThreatModel) -> Self {
        Self {
            model,
            components: Vec::new(),
            data_flows: Vec::new(),
            trust_boundaries: Vec::new(),
            threats: Vec::new(),
        }
    }

    /// Perform STRIDE analysis
    pub fn analyze(&mut self) {
        self.threats.clear();
        self.analyze_components();
        self.analyze_data_flows();
        self.analyze_trust_boundaries();
    }

    fn analyze_components(&mut self) {
        // Collect threats first to avoid borrow issues
        let mut new_threats: Vec<(Option<String>, StrideCategory, String, String)> = Vec::new();

        for component in &self.components {
            let comp_id = component.id.to_string();

            // Spoofing - identity verification
            if matches!(component.component_type,
                ArchComponentType::WebApplication |
                ArchComponentType::ApiGateway |
                ArchComponentType::ExternalService
            ) {
                new_threats.push((
                    Some(comp_id.clone()),
                    StrideCategory::Spoofing,
                    "Identity Spoofing Risk".to_string(),
                    format!("Component '{}' may be vulnerable to identity spoofing", component.name),
                ));
            }

            // Information Disclosure - data classification
            if matches!(component.data_classification,
                DataClassification::Confidential |
                DataClassification::Restricted |
                DataClassification::TopSecret
            ) {
                new_threats.push((
                    Some(comp_id.clone()),
                    StrideCategory::InformationDisclosure,
                    "Sensitive Data Exposure Risk".to_string(),
                    format!("Component '{}' handles {} data that may be exposed",
                        component.name,
                        format!("{:?}", component.data_classification).to_lowercase()
                    ),
                ));
            }
        }

        // Add collected threats
        for (comp_id, category, title, desc) in new_threats {
            self.add_threat(
                comp_id.as_deref(),
                None,
                category,
                &title,
                &desc,
            );
        }
    }

    fn analyze_data_flows(&mut self) {
        // Collect threats first to avoid borrow issues
        let mut new_threats: Vec<(Option<String>, Option<String>, StrideCategory, String, String)> = Vec::new();

        for flow in &self.data_flows {
            // Tampering - unencrypted data
            if !flow.encrypted {
                new_threats.push((
                    None,
                    Some(flow.id.clone()),
                    StrideCategory::Tampering,
                    "Data Tampering Risk".to_string(),
                    format!("Data flow '{}' is not encrypted and may be tampered with", flow.name),
                ));
            }

            // Information Disclosure - sensitive data in transit
            if !flow.encrypted && matches!(flow.data_classification,
                DataClassification::Confidential |
                DataClassification::Restricted |
                DataClassification::TopSecret
            ) {
                new_threats.push((
                    None,
                    Some(flow.id.clone()),
                    StrideCategory::InformationDisclosure,
                    "Sensitive Data in Transit".to_string(),
                    format!("Flow '{}' transmits {} data without encryption",
                        flow.name,
                        format!("{:?}", flow.data_classification).to_lowercase()
                    ),
                ));
            }
        }

        // Add the threats
        for (comp_id, flow_id, category, title, desc) in new_threats {
            self.add_threat(
                comp_id.as_deref(),
                flow_id.as_deref(),
                category,
                &title,
                &desc,
            );
        }
    }

    fn analyze_trust_boundaries(&mut self) {
        // Collect threats to avoid borrow issues
        let mut new_threats = Vec::new();

        for boundary in &self.trust_boundaries {
            let boundary_components = boundary.components_inside();

            for flow in &self.data_flows {
                // Parse source and destination IDs as UUIDs for comparison
                let source_uuid = Uuid::parse_str(&flow.source_id).ok();
                let dest_uuid = Uuid::parse_str(&flow.destination_id).ok();

                let source_inside = source_uuid.map(|u| boundary_components.contains(&u)).unwrap_or(false);
                let dest_inside = dest_uuid.map(|u| boundary_components.contains(&u)).unwrap_or(false);

                if source_inside != dest_inside && !flow.authenticated {
                    new_threats.push((
                        flow.id.clone(),
                        flow.name.clone(),
                        boundary.name.clone(),
                    ));
                }
            }
        }

        // Add collected threats
        for (flow_id, flow_name, boundary_name) in new_threats {
            self.add_threat(
                None,
                Some(&flow_id),
                StrideCategory::Spoofing,
                "Unauthenticated Boundary Crossing",
                &format!("Flow '{}' crosses trust boundary '{}' without authentication",
                    flow_name, boundary_name
                ),
            );
        }
    }

    fn add_threat(
        &mut self,
        component_id: Option<&str>,
        data_flow_id: Option<&str>,
        category: StrideCategory,
        title: &str,
        description: &str,
    ) {
        // Need a default component_id if none provided
        let affected_component_id = component_id
            .and_then(|s| Uuid::parse_str(s).ok())
            .unwrap_or_else(Uuid::nil);

        let threat = StrideTheat {
            id: Uuid::new_v4(),
            threat_model_id: self.model.id,
            category,
            affected_component_id,
            affected_dataflow_id: data_flow_id.and_then(|s| Uuid::parse_str(s).ok()),
            title: title.to_string(),
            description: description.to_string(),
            attack_scenario: String::new(),
            prerequisites: Vec::new(),
            likelihood: Likelihood::Medium,
            impact: Impact::Moderate,
            risk_rating: RiskRating::Medium,
            mitigations: Vec::new(),
            status: ThreatStatus::Open,
            priority: 0,
            cwe_ids: Vec::new(),
            capec_ids: Vec::new(),
            notes: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        self.threats.push(threat);
    }

    /// Calculate risk score based on threats
    pub fn calculate_risk_score(&self) -> f64 {
        if self.threats.is_empty() {
            return 0.0;
        }

        let total_risk: f64 = self.threats.iter()
            .map(|t| {
                let likelihood_score = match t.likelihood {
                    Likelihood::VeryLow => 1.0,
                    Likelihood::Low => 2.0,
                    Likelihood::Medium => 3.0,
                    Likelihood::High => 4.0,
                    Likelihood::VeryHigh => 5.0,
                };
                let impact_score = match t.impact {
                    Impact::Negligible => 1.0,
                    Impact::Minor => 2.0,
                    Impact::Moderate => 3.0,
                    Impact::Major => 4.0,
                    Impact::Catastrophic => 5.0,
                };
                likelihood_score * impact_score
            })
            .sum();

        // Normalize to 0-100 scale
        (total_risk / (self.threats.len() as f64 * 25.0)) * 100.0
    }

    /// Static method to analyze a threat model and return a StrideAnalysisResult
    /// This is the method expected by the API
    pub fn analyze_model(model: &ThreatModel) -> crate::yellow_team::architecture::StrideAnalysisResult {
        use crate::yellow_team::architecture::StrideAnalysisResult;
        use std::collections::HashMap;

        // Create a dummy ArchitectureReviewEngine to generate the result
        let threats_by_category: HashMap<String, u32> = HashMap::new();
        let threats_by_risk: HashMap<String, u32> = HashMap::new();

        // For now, return an empty analysis result
        // Full implementation would analyze the model's components, data flows, etc.
        StrideAnalysisResult {
            review_id: model.id.to_string(),
            threats: Vec::new(),
            threats_by_category,
            threats_by_risk,
            recommendations: Vec::new(),
            risk_score: 0.0,
            analyzed_at: chrono::Utc::now(),
        }
    }

    /// Generate a markdown report from the threat model
    pub fn generate_markdown_report(model: &ThreatModel) -> String {
        let mut report = String::new();

        report.push_str(&format!("# Threat Model Report: {}\n\n", model.name));
        report.push_str(&format!("**Generated:** {}\n\n", chrono::Utc::now().format("%Y-%m-%d %H:%M UTC")));
        report.push_str(&format!("## System Description\n\n{}\n\n", model.system_description));
        report.push_str(&format!("**Status:** {:?}\n\n", model.status));
        report.push_str(&format!("**Risk Score:** {:.1}\n\n", model.risk_score));

        if !model.tags.is_empty() {
            report.push_str(&format!("**Tags:** {}\n\n", model.tags.join(", ")));
        }

        report.push_str("## Analysis Summary\n\n");
        report.push_str("*Full analysis details would be included here based on components, data flows, and identified threats.*\n\n");

        report
    }
}

/// Get architecture templates for common patterns
pub fn get_architecture_templates() -> Vec<ArchitectureTemplate> {
    vec![
        ArchitectureTemplate {
            id: "three-tier".to_string(),
            name: "Three-Tier Web Application".to_string(),
            description: "Classic three-tier architecture with web, app, and database tiers".to_string(),
            components: vec![
                TemplateComponent {
                    name: "Web Server".to_string(),
                    component_type: ArchComponentType::WebApplication,
                    trust_level: TrustLevel::Dmz,
                },
                TemplateComponent {
                    name: "Application Server".to_string(),
                    component_type: ArchComponentType::Microservice,
                    trust_level: TrustLevel::Internal,
                },
                TemplateComponent {
                    name: "Database".to_string(),
                    component_type: ArchComponentType::Database,
                    trust_level: TrustLevel::Trusted,
                },
            ],
        },
        ArchitectureTemplate {
            id: "microservices".to_string(),
            name: "Microservices Architecture".to_string(),
            description: "Distributed microservices with API gateway".to_string(),
            components: vec![
                TemplateComponent {
                    name: "API Gateway".to_string(),
                    component_type: ArchComponentType::ApiGateway,
                    trust_level: TrustLevel::Dmz,
                },
                TemplateComponent {
                    name: "Auth Service".to_string(),
                    component_type: ArchComponentType::IdentityProvider,
                    trust_level: TrustLevel::Internal,
                },
                TemplateComponent {
                    name: "User Service".to_string(),
                    component_type: ArchComponentType::Microservice,
                    trust_level: TrustLevel::Internal,
                },
                TemplateComponent {
                    name: "Message Queue".to_string(),
                    component_type: ArchComponentType::MessageQueue,
                    trust_level: TrustLevel::Internal,
                },
                TemplateComponent {
                    name: "Database".to_string(),
                    component_type: ArchComponentType::Database,
                    trust_level: TrustLevel::Trusted,
                },
            ],
        },
    ]
}

/// Architecture template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchitectureTemplate {
    pub id: String,
    pub name: String,
    pub description: String,
    pub components: Vec<TemplateComponent>,
}

/// Template component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateComponent {
    pub name: String,
    pub component_type: ArchComponentType,
    pub trust_level: TrustLevel,
}

// ============================================================================
// Additional SBOM Types (for DB layer)
// ============================================================================

/// SBOM source type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SbomSourceType {
    #[default]
    Directory,
    GitRepo,
    Upload,
    Archive,
}

impl std::fmt::Display for SbomSourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SbomSourceType::Directory => write!(f, "directory"),
            SbomSourceType::GitRepo => write!(f, "git_repo"),
            SbomSourceType::Upload => write!(f, "upload"),
            SbomSourceType::Archive => write!(f, "archive"),
        }
    }
}

/// SBOM component type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ComponentType {
    #[default]
    Library,
    Framework,
    Application,
    Container,
    OperatingSystem,
    Device,
    Firmware,
    File,
}

impl std::fmt::Display for ComponentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComponentType::Library => write!(f, "library"),
            ComponentType::Framework => write!(f, "framework"),
            ComponentType::Application => write!(f, "application"),
            ComponentType::Container => write!(f, "container"),
            ComponentType::OperatingSystem => write!(f, "operating_system"),
            ComponentType::Device => write!(f, "device"),
            ComponentType::Firmware => write!(f, "firmware"),
            ComponentType::File => write!(f, "file"),
        }
    }
}

/// Dependency type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DependencyType {
    #[default]
    Direct,
    Transitive,
    Dev,
    Development,
    Build,
    Optional,
    Peer,
}

impl std::fmt::Display for DependencyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DependencyType::Direct => write!(f, "direct"),
            DependencyType::Transitive => write!(f, "transitive"),
            DependencyType::Dev => write!(f, "dev"),
            DependencyType::Development => write!(f, "development"),
            DependencyType::Build => write!(f, "build"),
            DependencyType::Optional => write!(f, "optional"),
            DependencyType::Peer => write!(f, "peer"),
        }
    }
}

/// Vulnerability severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum VulnSeverity {
    #[default]
    Unknown,
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for VulnSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VulnSeverity::Unknown => write!(f, "unknown"),
            VulnSeverity::None => write!(f, "none"),
            VulnSeverity::Low => write!(f, "low"),
            VulnSeverity::Medium => write!(f, "medium"),
            VulnSeverity::High => write!(f, "high"),
            VulnSeverity::Critical => write!(f, "critical"),
        }
    }
}

/// Complete SBOM structure for database storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sbom {
    pub id: String,
    pub user_id: String,
    pub project_name: String,
    pub project_version: Option<String>,
    pub format: SbomFormat,
    pub stats: SbomStats,
    pub source_files: Vec<SourceFile>,
    pub components: Vec<SbomComponent>,
    pub vulnerabilities: Vec<ComponentVuln>,
    pub licenses: Vec<LicenseInfo>,
    pub dependencies: Vec<DependencyRelation>,
    pub generated_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// Type alias for FullSbom (compatibility)
pub type FullSbom = Sbom;

/// SBOM statistics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SbomStats {
    pub total_components: i32,
    pub direct_dependencies: i32,
    pub transitive_dependencies: i32,
    pub vulnerabilities_found: i32,
    pub critical_vulns: i32,
    pub high_vulns: i32,
    pub medium_vulns: i32,
    pub low_vulns: i32,
    pub copyleft_licenses: i32,
    pub permissive_licenses: i32,
    pub unknown_licenses: i32,
}

/// Source file information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceFile {
    pub path: String,
    pub file_type: String,
    pub checksum: Option<String>,
}

/// Component vulnerability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentVuln {
    pub cve_id: String,
    pub component_purl: String,
    pub cvss_score: Option<f64>,
    pub severity: VulnSeverity,
    pub description: String,
    pub fixed_version: Option<String>,
    pub references: Vec<String>,
}

/// License information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseInfo {
    pub spdx_id: String,
    pub name: String,
    pub risk_level: LicenseRisk,
    pub url: Option<String>,
    pub component_count: u32,
}

/// Dependency relationship
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyRelation {
    pub parent: String,
    pub child: String,
    pub dependency_type: DependencyType,
}

/// External reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalReference {
    pub ref_type: String,
    pub url: String,
    pub comment: Option<String>,
}

// ============================================================================
// Additional API Security Types (for DB layer)
// ============================================================================

/// API Security Category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ApiSecurityCategory {
    #[default]
    Authentication,
    Authorization,
    Injection,
    SensitiveData,
    RateLimiting,
    Transport,
    Configuration,
    InputValidation,
    Other,
}

impl std::fmt::Display for ApiSecurityCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiSecurityCategory::Authentication => write!(f, "authentication"),
            ApiSecurityCategory::Authorization => write!(f, "authorization"),
            ApiSecurityCategory::Injection => write!(f, "injection"),
            ApiSecurityCategory::SensitiveData => write!(f, "sensitive_data"),
            ApiSecurityCategory::RateLimiting => write!(f, "rate_limiting"),
            ApiSecurityCategory::Transport => write!(f, "transport"),
            ApiSecurityCategory::Configuration => write!(f, "configuration"),
            ApiSecurityCategory::InputValidation => write!(f, "input_validation"),
            ApiSecurityCategory::Other => write!(f, "other"),
        }
    }
}

/// API Spec Type (alias for ApiSpecFormat)
pub type ApiSpecType = ApiSpecFormat;

/// HTTP Method
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HttpMethod {
    #[default]
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
    Options,
    Trace,
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpMethod::Get => write!(f, "GET"),
            HttpMethod::Post => write!(f, "POST"),
            HttpMethod::Put => write!(f, "PUT"),
            HttpMethod::Patch => write!(f, "PATCH"),
            HttpMethod::Delete => write!(f, "DELETE"),
            HttpMethod::Head => write!(f, "HEAD"),
            HttpMethod::Options => write!(f, "OPTIONS"),
            HttpMethod::Trace => write!(f, "TRACE"),
        }
    }
}

impl std::str::FromStr for HttpMethod {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "GET" => Ok(HttpMethod::Get),
            "POST" => Ok(HttpMethod::Post),
            "PUT" => Ok(HttpMethod::Put),
            "PATCH" => Ok(HttpMethod::Patch),
            "DELETE" => Ok(HttpMethod::Delete),
            "HEAD" => Ok(HttpMethod::Head),
            "OPTIONS" => Ok(HttpMethod::Options),
            "TRACE" => Ok(HttpMethod::Trace),
            _ => Err(format!("Unknown HTTP method: {}", s)),
        }
    }
}

/// Parameter location
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ParameterLocation {
    #[default]
    Query,
    Header,
    Path,
    Cookie,
    Body,
}

impl std::fmt::Display for ParameterLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParameterLocation::Query => write!(f, "query"),
            ParameterLocation::Header => write!(f, "header"),
            ParameterLocation::Path => write!(f, "path"),
            ParameterLocation::Cookie => write!(f, "cookie"),
            ParameterLocation::Body => write!(f, "body"),
        }
    }
}

/// Remediation effort
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RemediationEffort {
    #[default]
    Low,
    Medium,
    High,
}

impl std::fmt::Display for RemediationEffort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RemediationEffort::Low => write!(f, "low"),
            RemediationEffort::Medium => write!(f, "medium"),
            RemediationEffort::High => write!(f, "high"),
        }
    }
}

/// API Endpoint for DB
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiEndpoint {
    pub id: String,
    pub scan_id: String,
    pub path: String,
    pub method: HttpMethod,
    pub operation_id: Option<String>,
    pub summary: Option<String>,
    pub description: Option<String>,
    pub security_requirements: Vec<String>,
    pub parameters: Vec<ApiParameter>,
    pub request_body: Option<String>,
    pub responses: Vec<String>,
    pub has_auth: bool,
    pub tags: Vec<String>,
    pub deprecated: bool,
    pub created_at: DateTime<Utc>,
}

/// API Parameter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiParameter {
    pub name: String,
    pub location: ParameterLocation,
    pub required: bool,
    pub param_type: String,
    pub description: Option<String>,
}
