//! Detection-as-Code Implementation
//!
//! This module provides detection definitions with:
//! - YAML-like detection format with logic, data sources, and severity
//! - Version history (git-like versioning)
//! - Validation and linting
//! - Deployment status management (draft, testing, production, deprecated)
//! - Rich metadata (author, created, updated, references)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Detection severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "TEXT")]
#[serde(rename_all = "lowercase")]
pub enum DetectionSeverity {
    /// Informational - low priority observations
    Informational,
    /// Low severity - minor security issues
    Low,
    /// Medium severity - moderate security concerns
    Medium,
    /// High severity - significant security threats
    High,
    /// Critical severity - requires immediate attention
    Critical,
}

impl Default for DetectionSeverity {
    fn default() -> Self {
        Self::Medium
    }
}

impl std::fmt::Display for DetectionSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Informational => write!(f, "informational"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

impl std::str::FromStr for DetectionSeverity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "informational" | "info" => Ok(Self::Informational),
            "low" => Ok(Self::Low),
            "medium" | "med" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" | "crit" => Ok(Self::Critical),
            _ => Err(format!("Invalid severity: {}", s)),
        }
    }
}

/// Detection deployment status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "TEXT")]
#[serde(rename_all = "lowercase")]
pub enum DetectionStatus {
    /// Draft - detection is being developed
    Draft,
    /// Testing - detection is being validated
    Testing,
    /// Production - detection is actively deployed
    Production,
    /// Deprecated - detection is no longer maintained
    Deprecated,
    /// Disabled - detection is temporarily disabled
    Disabled,
}

impl Default for DetectionStatus {
    fn default() -> Self {
        Self::Draft
    }
}

impl std::fmt::Display for DetectionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Draft => write!(f, "draft"),
            Self::Testing => write!(f, "testing"),
            Self::Production => write!(f, "production"),
            Self::Deprecated => write!(f, "deprecated"),
            Self::Disabled => write!(f, "disabled"),
        }
    }
}

impl std::str::FromStr for DetectionStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "draft" => Ok(Self::Draft),
            "testing" | "test" => Ok(Self::Testing),
            "production" | "prod" => Ok(Self::Production),
            "deprecated" | "depr" => Ok(Self::Deprecated),
            "disabled" => Ok(Self::Disabled),
            _ => Err(format!("Invalid status: {}", s)),
        }
    }
}

/// Data source required by a detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSource {
    /// Data source name (e.g., "windows_security_logs", "sysmon", "network_traffic")
    pub name: String,
    /// Specific event IDs or log types needed
    #[serde(default)]
    pub event_ids: Vec<String>,
    /// Whether this data source is required or optional
    #[serde(default = "default_true")]
    pub required: bool,
    /// Description of how this data source is used
    pub description: Option<String>,
}

fn default_true() -> bool {
    true
}

/// Detection logic definition (YAML-like structure)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionLogic {
    /// Detection query/rule language (e.g., "sigma", "splunk_spl", "elastic_eql", "kql")
    pub language: String,
    /// The actual detection query/rule
    pub query: String,
    /// Field mappings for normalization
    #[serde(default)]
    pub field_mappings: HashMap<String, String>,
    /// Aggregation settings (if applicable)
    pub aggregation: Option<AggregationSettings>,
    /// Threshold for alerting
    pub threshold: Option<ThresholdSettings>,
    /// Time window for correlation
    pub timeframe: Option<String>,
    /// Condition logic (and, or, not combinations)
    pub condition: Option<String>,
}

/// Aggregation settings for detections
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationSettings {
    /// Field to group by
    pub group_by: Vec<String>,
    /// Aggregation function (count, sum, avg, etc.)
    pub function: String,
    /// Time bucket for aggregation
    pub time_bucket: Option<String>,
}

/// Threshold settings for alerting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdSettings {
    /// Threshold value
    pub value: i64,
    /// Comparison operator (>, <, >=, <=, ==, !=)
    pub operator: String,
    /// Time window for threshold evaluation
    pub window: Option<String>,
}

/// Detection metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionMetadata {
    /// Detection author
    pub author: String,
    /// Author's email (optional)
    pub author_email: Option<String>,
    /// Detection creation date
    pub created_at: DateTime<Utc>,
    /// Last modification date
    pub updated_at: DateTime<Utc>,
    /// External references (URLs, CVEs, etc.)
    #[serde(default)]
    pub references: Vec<String>,
    /// Related detections
    #[serde(default)]
    pub related_detections: Vec<String>,
    /// Tags for categorization
    #[serde(default)]
    pub tags: Vec<String>,
    /// License information
    pub license: Option<String>,
    /// Source of the detection (internal, community, vendor)
    pub source: Option<String>,
}

/// Main detection definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    /// Unique detection ID
    pub id: String,
    /// Detection name
    pub name: String,
    /// Detailed description
    pub description: String,
    /// Detection severity
    pub severity: DetectionSeverity,
    /// Deployment status
    pub status: DetectionStatus,
    /// Detection logic (the actual rule)
    pub logic: DetectionLogic,
    /// Required data sources
    #[serde(default)]
    pub data_sources: Vec<DataSource>,
    /// MITRE ATT&CK techniques covered
    #[serde(default)]
    pub mitre_techniques: Vec<String>,
    /// MITRE ATT&CK tactics
    #[serde(default)]
    pub mitre_tactics: Vec<String>,
    /// Metadata
    pub metadata: DetectionMetadata,
    /// Current version number
    pub version: u32,
    /// False positive rate (0.0 - 1.0, updated from historical data)
    pub fp_rate: Option<f64>,
    /// Confidence score (0.0 - 1.0)
    pub confidence: Option<f64>,
    /// Enabled flag
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// Detection version history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionVersion {
    /// Version ID
    pub id: String,
    /// Detection ID this version belongs to
    pub detection_id: String,
    /// Version number
    pub version: u32,
    /// Complete detection logic at this version
    pub logic_yaml: String,
    /// Change notes describing what changed
    pub change_notes: String,
    /// Who created this version
    pub created_by: String,
    /// When this version was created
    pub created_at: DateTime<Utc>,
    /// Diff from previous version (optional)
    pub diff: Option<String>,
}

/// Validation error for detection linting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationError {
    /// Error severity (error, warning, info)
    pub severity: ValidationSeverity,
    /// Error code
    pub code: String,
    /// Error message
    pub message: String,
    /// Location in the detection (field path)
    pub location: Option<String>,
    /// Suggested fix
    pub suggestion: Option<String>,
}

/// Validation error severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ValidationSeverity {
    Error,
    Warning,
    Info,
}

/// Result of detection validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// Whether the detection is valid (no errors)
    pub valid: bool,
    /// List of validation errors/warnings
    pub errors: Vec<ValidationError>,
    /// Detection parsed successfully
    pub parsed: bool,
}

impl Detection {
    /// Create a new detection with default values
    pub fn new(id: String, name: String, author: String) -> Self {
        let now = Utc::now();
        Self {
            id,
            name: name.clone(),
            description: String::new(),
            severity: DetectionSeverity::Medium,
            status: DetectionStatus::Draft,
            logic: DetectionLogic {
                language: "sigma".to_string(),
                query: String::new(),
                field_mappings: HashMap::new(),
                aggregation: None,
                threshold: None,
                timeframe: None,
                condition: None,
            },
            data_sources: Vec::new(),
            mitre_techniques: Vec::new(),
            mitre_tactics: Vec::new(),
            metadata: DetectionMetadata {
                author,
                author_email: None,
                created_at: now,
                updated_at: now,
                references: Vec::new(),
                related_detections: Vec::new(),
                tags: Vec::new(),
                license: None,
                source: Some("internal".to_string()),
            },
            version: 1,
            fp_rate: None,
            confidence: None,
            enabled: true,
        }
    }

    /// Validate the detection and return any errors
    pub fn validate(&self) -> ValidationResult {
        let mut errors = Vec::new();

        // Check required fields
        if self.name.is_empty() {
            errors.push(ValidationError {
                severity: ValidationSeverity::Error,
                code: "E001".to_string(),
                message: "Detection name is required".to_string(),
                location: Some("name".to_string()),
                suggestion: Some("Add a descriptive name for the detection".to_string()),
            });
        }

        if self.description.is_empty() {
            errors.push(ValidationError {
                severity: ValidationSeverity::Warning,
                code: "W001".to_string(),
                message: "Detection description is empty".to_string(),
                location: Some("description".to_string()),
                suggestion: Some("Add a detailed description explaining what this detection identifies".to_string()),
            });
        }

        if self.logic.query.is_empty() {
            errors.push(ValidationError {
                severity: ValidationSeverity::Error,
                code: "E002".to_string(),
                message: "Detection query is required".to_string(),
                location: Some("logic.query".to_string()),
                suggestion: Some("Add the detection logic query".to_string()),
            });
        }

        // Validate detection logic language
        let valid_languages = ["sigma", "splunk_spl", "elastic_eql", "kql", "yara-l", "chronicle", "custom"];
        if !valid_languages.contains(&self.logic.language.as_str()) {
            errors.push(ValidationError {
                severity: ValidationSeverity::Warning,
                code: "W002".to_string(),
                message: format!("Unknown detection language: {}", self.logic.language),
                location: Some("logic.language".to_string()),
                suggestion: Some(format!("Use one of: {}", valid_languages.join(", "))),
            });
        }

        // Check MITRE ATT&CK mapping
        if self.mitre_techniques.is_empty() {
            errors.push(ValidationError {
                severity: ValidationSeverity::Warning,
                code: "W003".to_string(),
                message: "No MITRE ATT&CK techniques mapped".to_string(),
                location: Some("mitre_techniques".to_string()),
                suggestion: Some("Map this detection to relevant MITRE ATT&CK techniques (e.g., T1059)".to_string()),
            });
        }

        // Validate MITRE technique format
        for technique in &self.mitre_techniques {
            if !technique.starts_with('T') || technique.len() < 5 {
                errors.push(ValidationError {
                    severity: ValidationSeverity::Warning,
                    code: "W004".to_string(),
                    message: format!("Invalid MITRE technique format: {}", technique),
                    location: Some("mitre_techniques".to_string()),
                    suggestion: Some("Use format like T1059 or T1059.001".to_string()),
                });
            }
        }

        // Check data sources
        if self.data_sources.is_empty() {
            errors.push(ValidationError {
                severity: ValidationSeverity::Warning,
                code: "W005".to_string(),
                message: "No data sources specified".to_string(),
                location: Some("data_sources".to_string()),
                suggestion: Some("Specify required data sources for this detection".to_string()),
            });
        }

        // Check for production status requirements
        if self.status == DetectionStatus::Production {
            if self.mitre_techniques.is_empty() {
                errors.push(ValidationError {
                    severity: ValidationSeverity::Error,
                    code: "E003".to_string(),
                    message: "Production detections must have MITRE ATT&CK mapping".to_string(),
                    location: Some("mitre_techniques".to_string()),
                    suggestion: Some("Add MITRE ATT&CK technique mappings before deploying to production".to_string()),
                });
            }

            if self.data_sources.is_empty() {
                errors.push(ValidationError {
                    severity: ValidationSeverity::Error,
                    code: "E004".to_string(),
                    message: "Production detections must specify data sources".to_string(),
                    location: Some("data_sources".to_string()),
                    suggestion: Some("Specify required data sources before deploying to production".to_string()),
                });
            }
        }

        // Validate threshold if present
        if let Some(ref threshold) = self.logic.threshold {
            let valid_operators = [">", "<", ">=", "<=", "==", "!="];
            if !valid_operators.contains(&threshold.operator.as_str()) {
                errors.push(ValidationError {
                    severity: ValidationSeverity::Error,
                    code: "E005".to_string(),
                    message: format!("Invalid threshold operator: {}", threshold.operator),
                    location: Some("logic.threshold.operator".to_string()),
                    suggestion: Some(format!("Use one of: {}", valid_operators.join(", "))),
                });
            }
        }

        let has_errors = errors.iter().any(|e| e.severity == ValidationSeverity::Error);

        ValidationResult {
            valid: !has_errors,
            errors,
            parsed: true,
        }
    }

    /// Convert detection to YAML format
    pub fn to_yaml(&self) -> Result<String, serde_yaml::Error> {
        serde_yaml::to_string(self)
    }

    /// Parse detection from YAML format
    pub fn from_yaml(yaml: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(yaml)
    }

    /// Convert detection logic to a specific format
    pub fn convert_to_format(&self, target_format: &str) -> Result<String, String> {
        match target_format {
            "sigma" => {
                // If already Sigma, return as-is
                if self.logic.language == "sigma" {
                    return Ok(self.logic.query.clone());
                }
                // Basic conversion scaffold
                let sigma = format!(
                    r#"title: {}
id: {}
status: {}
description: {}
author: {}
date: {}
references: {}
tags: {}
logsource:
    product: {}
detection:
    selection:
        {}
    condition: selection
falsepositives:
    - Unknown
level: {}
"#,
                    self.name,
                    self.id,
                    self.status,
                    self.description,
                    self.metadata.author,
                    self.metadata.created_at.format("%Y/%m/%d"),
                    self.metadata.references.join("\n    - "),
                    self.mitre_techniques.iter()
                        .map(|t| format!("attack.{}", t.to_lowercase()))
                        .collect::<Vec<_>>()
                        .join("\n    - "),
                    self.data_sources.first().map(|d| d.name.as_str()).unwrap_or("windows"),
                    self.logic.query.replace('\n', "\n        "),
                    self.severity,
                );
                Ok(sigma)
            }
            "splunk_spl" => {
                // Basic SPL conversion
                let spl = format!(
                    "index=* {} | stats count by host",
                    self.logic.query
                );
                Ok(spl)
            }
            "elastic_eql" => {
                // Basic EQL conversion
                let eql = format!(
                    "any where {}",
                    self.logic.query
                );
                Ok(eql)
            }
            _ => Err(format!("Unsupported target format: {}", target_format)),
        }
    }

    /// Calculate a quality score for the detection
    pub fn quality_score(&self) -> f64 {
        let mut score = 0.0;
        let mut max_score = 0.0;

        // Name and description (20%)
        max_score += 20.0;
        if !self.name.is_empty() {
            score += 10.0;
        }
        if !self.description.is_empty() {
            score += 5.0;
            if self.description.len() > 100 {
                score += 5.0;
            }
        }

        // MITRE ATT&CK mapping (25%)
        max_score += 25.0;
        if !self.mitre_techniques.is_empty() {
            score += 15.0;
            if self.mitre_techniques.len() >= 2 {
                score += 5.0;
            }
        }
        if !self.mitre_tactics.is_empty() {
            score += 5.0;
        }

        // Data sources (20%)
        max_score += 20.0;
        if !self.data_sources.is_empty() {
            score += 15.0;
            if self.data_sources.iter().any(|ds| ds.description.is_some()) {
                score += 5.0;
            }
        }

        // References and tags (15%)
        max_score += 15.0;
        if !self.metadata.references.is_empty() {
            score += 10.0;
        }
        if !self.metadata.tags.is_empty() {
            score += 5.0;
        }

        // Confidence and FP tracking (20%)
        max_score += 20.0;
        if self.confidence.is_some() {
            score += 10.0;
        }
        if self.fp_rate.is_some() {
            score += 10.0;
        }

        (score / max_score) * 100.0
    }
}

/// Lint a detection YAML string
pub fn lint_detection_yaml(yaml: &str) -> ValidationResult {
    match Detection::from_yaml(yaml) {
        Ok(detection) => detection.validate(),
        Err(e) => ValidationResult {
            valid: false,
            errors: vec![ValidationError {
                severity: ValidationSeverity::Error,
                code: "E000".to_string(),
                message: format!("Failed to parse detection YAML: {}", e),
                location: None,
                suggestion: Some("Check YAML syntax and required fields".to_string()),
            }],
            parsed: false,
        },
    }
}

/// Compare two detection versions and generate a diff
pub fn diff_versions(old: &Detection, new: &Detection) -> Vec<String> {
    let mut changes = Vec::new();

    if old.name != new.name {
        changes.push(format!("Name changed: '{}' -> '{}'", old.name, new.name));
    }
    if old.description != new.description {
        changes.push("Description modified".to_string());
    }
    if old.severity != new.severity {
        changes.push(format!("Severity changed: {} -> {}", old.severity, new.severity));
    }
    if old.status != new.status {
        changes.push(format!("Status changed: {} -> {}", old.status, new.status));
    }
    if old.logic.query != new.logic.query {
        changes.push("Detection logic query modified".to_string());
    }
    if old.logic.language != new.logic.language {
        changes.push(format!("Query language changed: {} -> {}", old.logic.language, new.logic.language));
    }
    if old.mitre_techniques != new.mitre_techniques {
        let added: Vec<_> = new.mitre_techniques.iter()
            .filter(|t| !old.mitre_techniques.contains(t))
            .collect();
        let removed: Vec<_> = old.mitre_techniques.iter()
            .filter(|t| !new.mitre_techniques.contains(t))
            .collect();
        if !added.is_empty() {
            changes.push(format!("MITRE techniques added: {:?}", added));
        }
        if !removed.is_empty() {
            changes.push(format!("MITRE techniques removed: {:?}", removed));
        }
    }
    if old.data_sources.len() != new.data_sources.len() {
        changes.push("Data sources modified".to_string());
    }
    if old.enabled != new.enabled {
        changes.push(format!("Enabled changed: {} -> {}", old.enabled, new.enabled));
    }

    changes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detection_creation() {
        let detection = Detection::new(
            "DET-001".to_string(),
            "Suspicious PowerShell Execution".to_string(),
            "Security Team".to_string(),
        );

        assert_eq!(detection.id, "DET-001");
        assert_eq!(detection.status, DetectionStatus::Draft);
        assert_eq!(detection.severity, DetectionSeverity::Medium);
        assert_eq!(detection.version, 1);
        assert!(detection.enabled);
    }

    #[test]
    fn test_detection_validation() {
        let mut detection = Detection::new(
            "DET-001".to_string(),
            "Test Detection".to_string(),
            "Test Author".to_string(),
        );

        // Should have warnings but be valid (no query)
        let result = detection.validate();
        assert!(!result.valid); // Invalid because query is empty

        // Add required fields
        detection.logic.query = "process.name: powershell.exe".to_string();
        detection.description = "Detects suspicious PowerShell execution".to_string();
        detection.mitre_techniques = vec!["T1059.001".to_string()];
        detection.data_sources = vec![DataSource {
            name: "windows_process_creation".to_string(),
            event_ids: vec!["1".to_string()],
            required: true,
            description: Some("Sysmon Process Creation".to_string()),
        }];

        let result = detection.validate();
        assert!(result.valid);
    }

    #[test]
    fn test_severity_parsing() {
        assert_eq!("high".parse::<DetectionSeverity>().unwrap(), DetectionSeverity::High);
        assert_eq!("crit".parse::<DetectionSeverity>().unwrap(), DetectionSeverity::Critical);
        assert_eq!("info".parse::<DetectionSeverity>().unwrap(), DetectionSeverity::Informational);
    }

    #[test]
    fn test_status_parsing() {
        assert_eq!("draft".parse::<DetectionStatus>().unwrap(), DetectionStatus::Draft);
        assert_eq!("prod".parse::<DetectionStatus>().unwrap(), DetectionStatus::Production);
        assert_eq!("test".parse::<DetectionStatus>().unwrap(), DetectionStatus::Testing);
    }

    #[test]
    fn test_quality_score() {
        let mut detection = Detection::new(
            "DET-001".to_string(),
            "Complete Detection".to_string(),
            "Author".to_string(),
        );

        // Minimal detection should have low score
        let low_score = detection.quality_score();
        assert!(low_score < 50.0);

        // Add all recommended fields
        detection.description = "A complete detection with all recommended fields filled in properly for best practices.".to_string();
        detection.mitre_techniques = vec!["T1059.001".to_string(), "T1059.003".to_string()];
        detection.mitre_tactics = vec!["TA0002".to_string()];
        detection.data_sources = vec![DataSource {
            name: "sysmon".to_string(),
            event_ids: vec!["1".to_string()],
            required: true,
            description: Some("Process creation events".to_string()),
        }];
        detection.metadata.references = vec!["https://attack.mitre.org/techniques/T1059/001/".to_string()];
        detection.metadata.tags = vec!["persistence".to_string(), "powershell".to_string()];
        detection.confidence = Some(0.85);
        detection.fp_rate = Some(0.05);

        let high_score = detection.quality_score();
        assert!(high_score > 80.0);
    }

    #[test]
    fn test_yaml_serialization() {
        let detection = Detection::new(
            "DET-001".to_string(),
            "Test Detection".to_string(),
            "Test Author".to_string(),
        );

        let yaml = detection.to_yaml().unwrap();
        assert!(yaml.contains("DET-001"));
        assert!(yaml.contains("Test Detection"));

        let parsed = Detection::from_yaml(&yaml).unwrap();
        assert_eq!(parsed.id, detection.id);
        assert_eq!(parsed.name, detection.name);
    }

    #[test]
    fn test_diff_versions() {
        let mut old = Detection::new(
            "DET-001".to_string(),
            "Old Name".to_string(),
            "Author".to_string(),
        );
        old.severity = DetectionSeverity::Low;

        let mut new = old.clone();
        new.name = "New Name".to_string();
        new.severity = DetectionSeverity::High;
        new.mitre_techniques = vec!["T1059".to_string()];

        let diff = diff_versions(&old, &new);
        assert!(diff.iter().any(|d| d.contains("Name changed")));
        assert!(diff.iter().any(|d| d.contains("Severity changed")));
        assert!(diff.iter().any(|d| d.contains("MITRE techniques added")));
    }
}
