//! Core types for the compliance evidence collection system
//!
//! This module defines the data structures used for automated evidence collection,
//! including evidence types, storage models, and collection sources.

#![allow(dead_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Type of evidence that can be collected
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EvidenceType {
    /// Evidence derived from a security scan
    ScanResult {
        scan_id: String,
    },
    /// Evidence from vulnerability scan findings
    VulnerabilityScan {
        scan_id: String,
        finding_count: Option<i32>,
    },
    /// Policy or procedure document
    PolicyDocument {
        document_type: String,
        document_name: Option<String>,
    },
    /// Screenshot evidence
    Screenshot {
        url: String,
        description: Option<String>,
    },
    /// Manually uploaded file
    ManualUpload {
        file_path: String,
        original_filename: Option<String>,
    },
    /// Configuration export
    ConfigurationExport {
        system_name: String,
        config_type: String,
    },
    /// Log file or audit trail
    AuditLog {
        log_source: String,
        time_range_start: DateTime<Utc>,
        time_range_end: DateTime<Utc>,
    },
    /// API response snapshot
    ApiSnapshot {
        endpoint: String,
        method: String,
    },
    /// Container scan results
    ContainerScan {
        scan_id: String,
        image_count: Option<i32>,
    },
    /// Cloud security posture results
    CloudSecurityPosture {
        provider: String,
        scan_id: String,
    },
    /// Compliance assessment report
    ComplianceReport {
        framework_id: String,
        scan_id: String,
    },
}

impl EvidenceType {
    /// Get a human-readable label for the evidence type
    pub fn label(&self) -> &'static str {
        match self {
            Self::ScanResult { .. } => "Scan Result",
            Self::VulnerabilityScan { .. } => "Vulnerability Scan",
            Self::PolicyDocument { .. } => "Policy Document",
            Self::Screenshot { .. } => "Screenshot",
            Self::ManualUpload { .. } => "Manual Upload",
            Self::ConfigurationExport { .. } => "Configuration Export",
            Self::AuditLog { .. } => "Audit Log",
            Self::ApiSnapshot { .. } => "API Snapshot",
            Self::ContainerScan { .. } => "Container Scan",
            Self::CloudSecurityPosture { .. } => "Cloud Security Posture",
            Self::ComplianceReport { .. } => "Compliance Report",
        }
    }

    /// Get the type identifier string
    pub fn type_id(&self) -> &'static str {
        match self {
            Self::ScanResult { .. } => "scan_result",
            Self::VulnerabilityScan { .. } => "vulnerability_scan",
            Self::PolicyDocument { .. } => "policy_document",
            Self::Screenshot { .. } => "screenshot",
            Self::ManualUpload { .. } => "manual_upload",
            Self::ConfigurationExport { .. } => "configuration_export",
            Self::AuditLog { .. } => "audit_log",
            Self::ApiSnapshot { .. } => "api_snapshot",
            Self::ContainerScan { .. } => "container_scan",
            Self::CloudSecurityPosture { .. } => "cloud_security_posture",
            Self::ComplianceReport { .. } => "compliance_report",
        }
    }
}

/// Content stored with the evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "content_type", rename_all = "snake_case")]
pub enum EvidenceContent {
    /// JSON data
    Json {
        data: serde_json::Value,
    },
    /// Plain text content
    Text {
        text: String,
    },
    /// Binary file reference
    File {
        file_path: String,
        mime_type: String,
        size_bytes: i64,
    },
    /// External URL reference
    ExternalUrl {
        url: String,
    },
    /// No content (metadata only)
    None,
}

impl EvidenceContent {
    /// Check if this content is empty
    pub fn is_empty(&self) -> bool {
        matches!(self, Self::None)
    }

    /// Get the approximate size of the content in bytes
    pub fn size_bytes(&self) -> i64 {
        match self {
            Self::Json { data } => serde_json::to_string(data)
                .map(|s| s.len() as i64)
                .unwrap_or(0),
            Self::Text { text } => text.len() as i64,
            Self::File { size_bytes, .. } => *size_bytes,
            Self::ExternalUrl { url } => url.len() as i64,
            Self::None => 0,
        }
    }
}

/// Source of evidence collection
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CollectionSource {
    /// Automatically collected from scan results
    AutomatedScan,
    /// Collected via scheduled job
    ScheduledCollection,
    /// Manually uploaded by user
    ManualUpload,
    /// Imported from external system
    ExternalImport,
    /// Generated by API integration
    ApiIntegration,
    /// Derived from other evidence
    Derived,
}

impl CollectionSource {
    /// Get a human-readable label
    pub fn label(&self) -> &'static str {
        match self {
            Self::AutomatedScan => "Automated Scan",
            Self::ScheduledCollection => "Scheduled Collection",
            Self::ManualUpload => "Manual Upload",
            Self::ExternalImport => "External Import",
            Self::ApiIntegration => "API Integration",
            Self::Derived => "Derived",
        }
    }
}

/// Status of evidence
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    /// Evidence is active and current
    #[default]
    Active,
    /// Evidence is superseded by a newer version
    Superseded,
    /// Evidence has been archived
    Archived,
    /// Evidence is pending review
    PendingReview,
    /// Evidence has been approved
    Approved,
    /// Evidence has been rejected
    Rejected,
}

impl EvidenceStatus {
    /// Check if evidence is in an active state
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active | Self::Approved | Self::PendingReview)
    }
}

/// Retention policy for evidence
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RetentionPolicy {
    /// Keep indefinitely
    Indefinite,
    /// Retain for specified number of days
    Days(i32),
    /// Retain until a specific date
    UntilDate(DateTime<Utc>),
    /// Follow framework-specific retention requirements
    FrameworkDefault,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self::FrameworkDefault
    }
}

/// Evidence metadata
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EvidenceMetadata {
    /// Additional key-value tags
    #[serde(default)]
    pub tags: std::collections::HashMap<String, String>,
    /// Related evidence IDs
    #[serde(default)]
    pub related_evidence_ids: Vec<String>,
    /// Custom fields
    #[serde(default)]
    pub custom_fields: std::collections::HashMap<String, serde_json::Value>,
    /// Assessment period start
    pub period_start: Option<DateTime<Utc>>,
    /// Assessment period end
    pub period_end: Option<DateTime<Utc>>,
}

/// A complete evidence record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// Unique identifier
    pub id: String,
    /// Type of evidence
    pub evidence_type: EvidenceType,
    /// Control IDs this evidence supports
    pub control_ids: Vec<String>,
    /// Framework IDs this evidence applies to
    pub framework_ids: Vec<String>,
    /// Title of the evidence
    pub title: String,
    /// Description of what this evidence demonstrates
    pub description: Option<String>,
    /// SHA-256 hash of the content for integrity verification
    pub content_hash: String,
    /// Actual content or reference
    pub content: EvidenceContent,
    /// Source of collection
    pub collection_source: CollectionSource,
    /// Current status
    pub status: EvidenceStatus,
    /// Version number (1-based)
    pub version: i32,
    /// ID of the previous version (if any)
    pub previous_version_id: Option<String>,
    /// When the evidence was collected
    pub collected_at: DateTime<Utc>,
    /// User who collected/uploaded the evidence
    pub collected_by: String,
    /// When the evidence expires (if applicable)
    pub expires_at: Option<DateTime<Utc>>,
    /// Retention policy
    pub retention_policy: RetentionPolicy,
    /// Additional metadata
    pub metadata: EvidenceMetadata,
    /// When this record was created
    pub created_at: DateTime<Utc>,
    /// When this record was last updated
    pub updated_at: DateTime<Utc>,
}

impl Evidence {
    /// Create a new evidence record with default values
    pub fn new(
        evidence_type: EvidenceType,
        title: String,
        collected_by: String,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            evidence_type,
            control_ids: Vec::new(),
            framework_ids: Vec::new(),
            title,
            description: None,
            content_hash: String::new(),
            content: EvidenceContent::None,
            collection_source: CollectionSource::ManualUpload,
            status: EvidenceStatus::Active,
            version: 1,
            previous_version_id: None,
            collected_at: now,
            collected_by,
            expires_at: None,
            retention_policy: RetentionPolicy::default(),
            metadata: EvidenceMetadata::default(),
            created_at: now,
            updated_at: now,
        }
    }

    /// Check if this evidence is expired
    pub fn is_expired(&self) -> bool {
        match &self.expires_at {
            Some(expires) => Utc::now() > *expires,
            None => false,
        }
    }

    /// Check if this evidence is the latest version
    pub fn is_latest_version(&self) -> bool {
        self.status != EvidenceStatus::Superseded
    }
}

/// A control-to-evidence mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceControlMapping {
    /// Unique mapping ID
    pub id: String,
    /// Evidence ID
    pub evidence_id: String,
    /// Control ID
    pub control_id: String,
    /// Framework ID
    pub framework_id: String,
    /// How well the evidence supports the control (0.0 to 1.0)
    pub coverage_score: f32,
    /// Notes about the mapping
    pub notes: Option<String>,
    /// When this mapping was created
    pub created_at: DateTime<Utc>,
    /// Who created this mapping
    pub created_by: String,
}

/// Schedule for automated evidence collection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceCollectionSchedule {
    /// Unique schedule ID
    pub id: String,
    /// User who created the schedule
    pub user_id: String,
    /// Name of the schedule
    pub name: String,
    /// Description
    pub description: Option<String>,
    /// Collection source type
    pub collection_source: CollectionSource,
    /// Cron expression for scheduling
    pub cron_expression: String,
    /// Control IDs to collect evidence for
    pub control_ids: Vec<String>,
    /// Framework IDs to target
    pub framework_ids: Vec<String>,
    /// Whether the schedule is enabled
    pub enabled: bool,
    /// Last time collection was run
    pub last_run_at: Option<DateTime<Utc>>,
    /// Next scheduled run time
    pub next_run_at: Option<DateTime<Utc>>,
    /// Configuration for the collection job
    pub config: serde_json::Value,
    /// When the schedule was created
    pub created_at: DateTime<Utc>,
    /// When the schedule was last updated
    pub updated_at: DateTime<Utc>,
}

/// Summary of evidence for a control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlEvidenceSummary {
    /// Control ID
    pub control_id: String,
    /// Framework ID
    pub framework_id: String,
    /// Total evidence items
    pub total_evidence: i32,
    /// Active evidence items
    pub active_evidence: i32,
    /// Most recent evidence collection date
    pub latest_collection: Option<DateTime<Utc>>,
    /// Overall coverage score (0.0 to 1.0)
    pub coverage_score: f32,
    /// Whether evidence is current or stale
    pub is_current: bool,
    /// Days since last collection
    pub days_since_collection: Option<i32>,
}

/// Request to collect evidence
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CollectEvidenceRequest {
    /// Type of evidence to collect
    pub evidence_type: String,
    /// Control IDs to associate with
    #[serde(default)]
    pub control_ids: Vec<String>,
    /// Framework IDs to associate with
    #[serde(default)]
    pub framework_ids: Vec<String>,
    /// Title for the evidence
    pub title: String,
    /// Description
    pub description: Option<String>,
    /// Additional parameters for collection
    #[serde(default)]
    #[schema(value_type = Object)]
    pub params: serde_json::Value,
}

/// Response from evidence collection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectEvidenceResponse {
    /// Whether collection was successful
    pub success: bool,
    /// Evidence ID if created
    pub evidence_id: Option<String>,
    /// Message describing the result
    pub message: String,
    /// Collection job ID for async operations
    pub job_id: Option<String>,
}

/// Query parameters for listing evidence
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EvidenceListQuery {
    /// Filter by control ID
    pub control_id: Option<String>,
    /// Filter by framework ID
    pub framework_id: Option<String>,
    /// Filter by evidence type
    pub evidence_type: Option<String>,
    /// Filter by status
    pub status: Option<String>,
    /// Filter by collection source
    pub collection_source: Option<String>,
    /// Include expired evidence
    #[serde(default)]
    pub include_expired: bool,
    /// Include superseded versions
    #[serde(default)]
    pub include_superseded: bool,
    /// Maximum results to return
    pub limit: Option<i32>,
    /// Offset for pagination
    pub offset: Option<i32>,
}

/// Paginated list of evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceListResponse {
    /// Evidence items
    pub evidence: Vec<Evidence>,
    /// Total count (before pagination)
    pub total: i64,
    /// Current offset
    pub offset: i64,
    /// Limit applied
    pub limit: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_type_label() {
        let et = EvidenceType::ScanResult {
            scan_id: "test".to_string(),
        };
        assert_eq!(et.label(), "Scan Result");
        assert_eq!(et.type_id(), "scan_result");
    }

    #[test]
    fn test_evidence_content_size() {
        let content = EvidenceContent::Text {
            text: "Hello, World!".to_string(),
        };
        assert_eq!(content.size_bytes(), 13);

        let empty = EvidenceContent::None;
        assert!(empty.is_empty());
        assert_eq!(empty.size_bytes(), 0);
    }

    #[test]
    fn test_evidence_new() {
        let evidence = Evidence::new(
            EvidenceType::ManualUpload {
                file_path: "/test/file.pdf".to_string(),
                original_filename: Some("document.pdf".to_string()),
            },
            "Test Evidence".to_string(),
            "user123".to_string(),
        );

        assert_eq!(evidence.version, 1);
        assert!(!evidence.is_expired());
        assert!(evidence.is_latest_version());
        assert_eq!(evidence.status, EvidenceStatus::Active);
    }

    #[test]
    fn test_evidence_status() {
        assert!(EvidenceStatus::Active.is_active());
        assert!(EvidenceStatus::Approved.is_active());
        assert!(EvidenceStatus::PendingReview.is_active());
        assert!(!EvidenceStatus::Superseded.is_active());
        assert!(!EvidenceStatus::Archived.is_active());
    }

    #[test]
    fn test_retention_policy_default() {
        let policy: RetentionPolicy = Default::default();
        assert_eq!(policy, RetentionPolicy::FrameworkDefault);
    }
}
