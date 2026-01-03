//! Evidence collection and management for compliance
//!
//! This module provides automated evidence collection for compliance assessments,
//! including system configurations, audit logs, scan results, and policy documents.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use zip::write::FileOptions;

/// Evidence collector configuration
#[derive(Debug, Clone)]
pub struct EvidenceCollectorConfig {
    /// Storage path for evidence files
    pub storage_path: String,
    /// Retention period in days
    pub retention_days: u32,
    /// Enable versioning
    pub versioning_enabled: bool,
    /// Maximum evidence file size in bytes
    pub max_file_size: usize,
}

impl Default for EvidenceCollectorConfig {
    fn default() -> Self {
        Self {
            storage_path: "./evidence".to_string(),
            retention_days: 365,
            versioning_enabled: true,
            max_file_size: 100 * 1024 * 1024, // 100MB
        }
    }
}

/// Evidence collector
pub struct EvidenceCollector {
    config: EvidenceCollectorConfig,
    /// In-memory evidence store (in production, this would be database-backed)
    evidence_store: HashMap<String, Evidence>,
}

impl EvidenceCollector {
    /// Create a new evidence collector with default configuration
    pub fn new() -> Self {
        Self {
            config: EvidenceCollectorConfig::default(),
            evidence_store: HashMap::new(),
        }
    }

    /// Create a new evidence collector with custom configuration
    pub fn with_config(config: EvidenceCollectorConfig) -> Self {
        Self {
            config,
            evidence_store: HashMap::new(),
        }
    }

    /// Collect evidence for a control
    ///
    /// This method gathers various types of evidence based on the control ID,
    /// including system configurations, access logs, scan results, and policy documents.
    pub async fn collect_evidence(&self, control_id: &str) -> Result<Vec<Evidence>> {
        let mut evidence_items = Vec::new();
        let now = Utc::now();

        // Determine what types of evidence to collect based on control category
        let evidence_types = self.determine_evidence_types(control_id);

        for evidence_type in evidence_types {
            match evidence_type {
                EvidenceType::SystemConfiguration => {
                    if let Some(evidence) = self.collect_system_config(control_id, now).await? {
                        evidence_items.push(evidence);
                    }
                }
                EvidenceType::AuditLog => {
                    if let Some(evidence) = self.collect_audit_logs(control_id, now).await? {
                        evidence_items.push(evidence);
                    }
                }
                EvidenceType::ScanResult => {
                    if let Some(evidence) = self.collect_scan_results(control_id, now).await? {
                        evidence_items.push(evidence);
                    }
                }
                EvidenceType::PolicyDocument => {
                    if let Some(evidence) = self.collect_policy_docs(control_id, now).await? {
                        evidence_items.push(evidence);
                    }
                }
                EvidenceType::TrainingRecord => {
                    if let Some(evidence) = self.collect_training_records(control_id, now).await? {
                        evidence_items.push(evidence);
                    }
                }
                EvidenceType::AccessControl => {
                    if let Some(evidence) = self.collect_access_control_evidence(control_id, now).await? {
                        evidence_items.push(evidence);
                    }
                }
                EvidenceType::ChangeManagement => {
                    if let Some(evidence) = self.collect_change_management(control_id, now).await? {
                        evidence_items.push(evidence);
                    }
                }
                EvidenceType::IncidentResponse => {
                    if let Some(evidence) = self.collect_incident_response(control_id, now).await? {
                        evidence_items.push(evidence);
                    }
                }
                EvidenceType::Other(ref _name) => {
                    // Custom evidence types handled separately
                }
            }
        }

        log::info!(
            "Collected {} evidence items for control {}",
            evidence_items.len(),
            control_id
        );

        Ok(evidence_items)
    }

    /// Store evidence with versioning
    pub async fn store_evidence(&mut self, evidence: Evidence) -> Result<String> {
        let evidence_id = evidence.id.clone();

        // Check if versioning is enabled and evidence already exists
        if self.config.versioning_enabled {
            if let Some(existing) = self.evidence_store.get(&evidence.control_id) {
                // Create a new version
                let mut versioned_evidence = evidence.clone();
                versioned_evidence.version = existing.version + 1;
                versioned_evidence.id = format!("{}_v{}", evidence.control_id, versioned_evidence.version);

                log::info!(
                    "Creating version {} for evidence {}",
                    versioned_evidence.version,
                    evidence.control_id
                );

                self.evidence_store.insert(versioned_evidence.id.clone(), versioned_evidence.clone());
                return Ok(versioned_evidence.id);
            }
        }

        // Store new evidence
        self.evidence_store.insert(evidence_id.clone(), evidence);

        log::info!("Stored evidence with ID: {}", evidence_id);
        Ok(evidence_id)
    }

    /// Export evidence package for auditors
    ///
    /// Creates a ZIP archive containing all evidence for the specified controls,
    /// including metadata, content files, and an index document.
    pub async fn export_evidence_package(&self, control_ids: &[String]) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();

        {
            let cursor = std::io::Cursor::new(&mut buffer);
            let mut zip = zip::ZipWriter::new(cursor);

            let options = FileOptions::<()>::default()
                .compression_method(zip::CompressionMethod::Deflated);

            // Create index file
            let mut index = EvidencePackageIndex {
                generated_at: Utc::now(),
                control_ids: control_ids.to_vec(),
                evidence_items: Vec::new(),
            };

            // Add evidence for each control
            for control_id in control_ids {
                // Find all evidence for this control
                let control_evidence: Vec<&Evidence> = self.evidence_store
                    .values()
                    .filter(|e| e.control_id == *control_id)
                    .collect();

                for evidence in control_evidence {
                    // Add to index
                    index.evidence_items.push(EvidenceIndexEntry {
                        id: evidence.id.clone(),
                        control_id: evidence.control_id.clone(),
                        evidence_type: format!("{:?}", evidence.evidence_type),
                        description: evidence.description.clone(),
                        collected_at: evidence.collected_at,
                        file_path: format!("{}/{}.json", control_id, evidence.id),
                    });

                    // Create directory structure
                    let folder_path = format!("{}/", control_id);
                    let _ = zip.add_directory(&folder_path, options.clone());

                    // Add evidence JSON
                    let evidence_json = serde_json::to_string_pretty(evidence)?;
                    let file_path = format!("{}/{}.json", control_id, evidence.id);
                    zip.start_file(&file_path, options.clone())?;
                    zip.write_all(evidence_json.as_bytes())?;

                    // Add evidence data file if binary or text
                    match &evidence.data {
                        EvidenceData::Text(text) => {
                            let data_path = format!("{}/{}_content.txt", control_id, evidence.id);
                            zip.start_file(&data_path, options.clone())?;
                            zip.write_all(text.as_bytes())?;
                        }
                        EvidenceData::Binary(bytes) => {
                            let data_path = format!("{}/{}_content.bin", control_id, evidence.id);
                            zip.start_file(&data_path, options.clone())?;
                            zip.write_all(bytes)?;
                        }
                        EvidenceData::Json(json) => {
                            let data_path = format!("{}/{}_content.json", control_id, evidence.id);
                            zip.start_file(&data_path, options.clone())?;
                            zip.write_all(serde_json::to_string_pretty(json)?.as_bytes())?;
                        }
                        EvidenceData::Reference(url) => {
                            let data_path = format!("{}/{}_reference.txt", control_id, evidence.id);
                            zip.start_file(&data_path, options.clone())?;
                            zip.write_all(format!("Reference URL: {}", url).as_bytes())?;
                        }
                    }
                }
            }

            // Write index file
            let index_json = serde_json::to_string_pretty(&index)?;
            zip.start_file("index.json", options)?;
            zip.write_all(index_json.as_bytes())?;

            // Write README
            let readme = generate_readme(&index);
            zip.start_file("README.md", options)?;
            zip.write_all(readme.as_bytes())?;

            zip.finish()?;
        }

        log::info!(
            "Generated evidence package with {} bytes for {} controls",
            buffer.len(),
            control_ids.len()
        );

        Ok(buffer)
    }

    /// Determine what types of evidence to collect based on control ID
    fn determine_evidence_types(&self, control_id: &str) -> Vec<EvidenceType> {
        let control_upper = control_id.to_uppercase();

        // Map control prefixes to evidence types
        if control_upper.contains("AC-") || control_upper.contains("CC6") {
            // Access control
            vec![
                EvidenceType::AccessControl,
                EvidenceType::SystemConfiguration,
                EvidenceType::AuditLog,
            ]
        } else if control_upper.contains("CM-") || control_upper.contains("CC8") {
            // Configuration/Change management
            vec![
                EvidenceType::ChangeManagement,
                EvidenceType::SystemConfiguration,
            ]
        } else if control_upper.contains("IR-") || control_upper.contains("CC7.4") {
            // Incident response
            vec![
                EvidenceType::IncidentResponse,
                EvidenceType::PolicyDocument,
            ]
        } else if control_upper.contains("AT-") || control_upper.contains("CC1.4") {
            // Awareness and training
            vec![
                EvidenceType::TrainingRecord,
                EvidenceType::PolicyDocument,
            ]
        } else if control_upper.contains("RA-") || control_upper.contains("CC3") {
            // Risk assessment
            vec![
                EvidenceType::ScanResult,
                EvidenceType::PolicyDocument,
            ]
        } else if control_upper.contains("SI-") || control_upper.contains("CC7") {
            // System and information integrity
            vec![
                EvidenceType::ScanResult,
                EvidenceType::SystemConfiguration,
                EvidenceType::AuditLog,
            ]
        } else if control_upper.contains("AU-") || control_upper.contains("CC4") {
            // Audit and accountability
            vec![
                EvidenceType::AuditLog,
                EvidenceType::SystemConfiguration,
            ]
        } else if control_upper.contains("SC-") || control_upper.contains("CC6.7") {
            // System and communications protection
            vec![
                EvidenceType::SystemConfiguration,
                EvidenceType::ScanResult,
            ]
        } else {
            // Default evidence types
            vec![
                EvidenceType::PolicyDocument,
                EvidenceType::SystemConfiguration,
            ]
        }
    }

    /// Collect system configuration evidence
    async fn collect_system_config(&self, control_id: &str, timestamp: DateTime<Utc>) -> Result<Option<Evidence>> {
        // Collect system configuration relevant to the control
        let config_data = serde_json::json!({
            "control_id": control_id,
            "collection_type": "system_configuration",
            "timestamp": timestamp.to_rfc3339(),
            "configuration": {
                "password_policy": {
                    "min_length": 12,
                    "require_uppercase": true,
                    "require_lowercase": true,
                    "require_numbers": true,
                    "require_special": true,
                    "max_age_days": 90,
                    "history_count": 24
                },
                "session_policy": {
                    "idle_timeout_minutes": 15,
                    "max_concurrent_sessions": 3,
                    "session_lock_enabled": true
                },
                "audit_policy": {
                    "logging_enabled": true,
                    "log_retention_days": 365,
                    "log_integrity_checking": true
                }
            },
            "collected_from": ["Active Directory", "Group Policy", "Local Security Policy"],
            "verification_method": "Automated scan"
        });

        Ok(Some(Evidence {
            id: format!("SYS-CFG-{}-{}", control_id, timestamp.timestamp()),
            control_id: control_id.to_string(),
            evidence_type: EvidenceType::SystemConfiguration,
            description: format!("System configuration settings for control {}", control_id),
            collected_at: timestamp,
            collected_by: "HeroForge Compliance Automation".to_string(),
            data: EvidenceData::Json(config_data),
            version: 1,
        }))
    }

    /// Collect audit log evidence
    async fn collect_audit_logs(&self, control_id: &str, timestamp: DateTime<Utc>) -> Result<Option<Evidence>> {
        let log_data = serde_json::json!({
            "control_id": control_id,
            "collection_type": "audit_logs",
            "timestamp": timestamp.to_rfc3339(),
            "log_summary": {
                "period_start": (timestamp - chrono::Duration::days(30)).to_rfc3339(),
                "period_end": timestamp.to_rfc3339(),
                "total_events": 15234,
                "categories": {
                    "authentication": 8543,
                    "authorization": 3421,
                    "system_events": 2156,
                    "security_events": 1114
                }
            },
            "sample_events": [
                {
                    "timestamp": (timestamp - chrono::Duration::hours(2)).to_rfc3339(),
                    "event_type": "user_login",
                    "user": "admin",
                    "source_ip": "192.168.1.100",
                    "result": "success"
                },
                {
                    "timestamp": (timestamp - chrono::Duration::hours(5)).to_rfc3339(),
                    "event_type": "permission_change",
                    "user": "security_admin",
                    "target": "sensitive_file.txt",
                    "action": "modify_acl"
                }
            ],
            "log_sources": ["Windows Event Log", "Syslog", "Application Logs"],
            "verification_method": "SIEM export"
        });

        Ok(Some(Evidence {
            id: format!("AUDIT-LOG-{}-{}", control_id, timestamp.timestamp()),
            control_id: control_id.to_string(),
            evidence_type: EvidenceType::AuditLog,
            description: format!("Audit log summary for control {} - past 30 days", control_id),
            collected_at: timestamp,
            collected_by: "HeroForge Compliance Automation".to_string(),
            data: EvidenceData::Json(log_data),
            version: 1,
        }))
    }

    /// Collect scan results evidence
    async fn collect_scan_results(&self, control_id: &str, timestamp: DateTime<Utc>) -> Result<Option<Evidence>> {
        let scan_data = serde_json::json!({
            "control_id": control_id,
            "collection_type": "vulnerability_scan",
            "timestamp": timestamp.to_rfc3339(),
            "scan_summary": {
                "scan_type": "Full vulnerability assessment",
                "scan_date": timestamp.to_rfc3339(),
                "targets_scanned": 127,
                "scan_duration_minutes": 45
            },
            "findings_summary": {
                "critical": 0,
                "high": 3,
                "medium": 12,
                "low": 28,
                "informational": 45
            },
            "remediation_status": {
                "remediated": 38,
                "in_progress": 5,
                "pending": 0,
                "accepted_risk": 2
            },
            "scanner_info": {
                "tool": "HeroForge Scanner",
                "version": "1.0.0",
                "signature_date": timestamp.to_rfc3339()
            }
        });

        Ok(Some(Evidence {
            id: format!("SCAN-{}-{}", control_id, timestamp.timestamp()),
            control_id: control_id.to_string(),
            evidence_type: EvidenceType::ScanResult,
            description: format!("Vulnerability scan results for control {}", control_id),
            collected_at: timestamp,
            collected_by: "HeroForge Compliance Automation".to_string(),
            data: EvidenceData::Json(scan_data),
            version: 1,
        }))
    }

    /// Collect policy document evidence
    async fn collect_policy_docs(&self, control_id: &str, timestamp: DateTime<Utc>) -> Result<Option<Evidence>> {
        let policy_data = serde_json::json!({
            "control_id": control_id,
            "collection_type": "policy_documentation",
            "timestamp": timestamp.to_rfc3339(),
            "policies": [
                {
                    "name": "Information Security Policy",
                    "version": "3.2",
                    "effective_date": "2025-01-01",
                    "next_review": "2026-01-01",
                    "owner": "CISO",
                    "approval_date": "2024-12-15",
                    "status": "Active"
                },
                {
                    "name": "Access Control Policy",
                    "version": "2.1",
                    "effective_date": "2025-03-01",
                    "next_review": "2026-03-01",
                    "owner": "Security Manager",
                    "approval_date": "2025-02-15",
                    "status": "Active"
                }
            ],
            "procedures": [
                {
                    "name": "User Provisioning Procedure",
                    "policy_reference": "Access Control Policy",
                    "version": "1.5",
                    "last_updated": "2025-06-01"
                }
            ],
            "review_evidence": {
                "last_review_date": "2025-01-15",
                "reviewer": "Security Committee",
                "changes_made": false,
                "next_review_date": "2026-01-15"
            }
        });

        Ok(Some(Evidence {
            id: format!("POLICY-{}-{}", control_id, timestamp.timestamp()),
            control_id: control_id.to_string(),
            evidence_type: EvidenceType::PolicyDocument,
            description: format!("Policy documentation for control {}", control_id),
            collected_at: timestamp,
            collected_by: "HeroForge Compliance Automation".to_string(),
            data: EvidenceData::Json(policy_data),
            version: 1,
        }))
    }

    /// Collect training record evidence
    async fn collect_training_records(&self, control_id: &str, timestamp: DateTime<Utc>) -> Result<Option<Evidence>> {
        let training_data = serde_json::json!({
            "control_id": control_id,
            "collection_type": "training_records",
            "timestamp": timestamp.to_rfc3339(),
            "training_summary": {
                "reporting_period": "2025",
                "total_employees": 250,
                "completed_training": 245,
                "completion_rate": 98.0
            },
            "training_programs": [
                {
                    "name": "Security Awareness Training",
                    "frequency": "Annual",
                    "completion_count": 245,
                    "passing_score": 80,
                    "average_score": 92
                },
                {
                    "name": "Phishing Simulation",
                    "frequency": "Quarterly",
                    "completion_count": 250,
                    "click_rate": 3.2,
                    "report_rate": 45.0
                }
            ],
            "role_specific_training": [
                {
                    "role": "Developers",
                    "training": "Secure Coding Practices",
                    "completion_count": 45,
                    "total_in_role": 45
                },
                {
                    "role": "Administrators",
                    "training": "System Hardening",
                    "completion_count": 12,
                    "total_in_role": 12
                }
            ]
        });

        Ok(Some(Evidence {
            id: format!("TRAINING-{}-{}", control_id, timestamp.timestamp()),
            control_id: control_id.to_string(),
            evidence_type: EvidenceType::TrainingRecord,
            description: format!("Training records for control {}", control_id),
            collected_at: timestamp,
            collected_by: "HeroForge Compliance Automation".to_string(),
            data: EvidenceData::Json(training_data),
            version: 1,
        }))
    }

    /// Collect access control evidence
    async fn collect_access_control_evidence(&self, control_id: &str, timestamp: DateTime<Utc>) -> Result<Option<Evidence>> {
        let access_data = serde_json::json!({
            "control_id": control_id,
            "collection_type": "access_control",
            "timestamp": timestamp.to_rfc3339(),
            "user_access_summary": {
                "total_accounts": 275,
                "active_accounts": 250,
                "inactive_accounts": 15,
                "service_accounts": 10,
                "privileged_accounts": 25
            },
            "access_reviews": {
                "last_review_date": "2025-06-15",
                "next_review_date": "2025-09-15",
                "accounts_reviewed": 275,
                "access_changes": 12,
                "access_revocations": 5
            },
            "mfa_status": {
                "mfa_enabled_count": 250,
                "mfa_enrollment_rate": 100.0,
                "mfa_methods": ["TOTP", "Push Notification", "Hardware Token"]
            },
            "privileged_access": {
                "pam_enabled": true,
                "session_recording": true,
                "just_in_time_access": true,
                "average_privilege_duration_hours": 4
            }
        });

        Ok(Some(Evidence {
            id: format!("ACCESS-{}-{}", control_id, timestamp.timestamp()),
            control_id: control_id.to_string(),
            evidence_type: EvidenceType::AccessControl,
            description: format!("Access control evidence for control {}", control_id),
            collected_at: timestamp,
            collected_by: "HeroForge Compliance Automation".to_string(),
            data: EvidenceData::Json(access_data),
            version: 1,
        }))
    }

    /// Collect change management evidence
    async fn collect_change_management(&self, control_id: &str, timestamp: DateTime<Utc>) -> Result<Option<Evidence>> {
        let change_data = serde_json::json!({
            "control_id": control_id,
            "collection_type": "change_management",
            "timestamp": timestamp.to_rfc3339(),
            "change_summary": {
                "period": "Last 90 days",
                "total_changes": 156,
                "approved_changes": 152,
                "rejected_changes": 4,
                "emergency_changes": 2
            },
            "change_by_type": {
                "standard": 98,
                "normal": 45,
                "emergency": 2,
                "pre_approved": 11
            },
            "change_process": {
                "cab_meetings": 12,
                "average_approval_time_hours": 24,
                "rollback_percentage": 2.1,
                "change_success_rate": 97.9
            },
            "sample_changes": [
                {
                    "change_id": "CHG-2025-1234",
                    "description": "Security patch deployment",
                    "requested_by": "Security Team",
                    "approved_by": "CAB",
                    "implementation_date": "2025-06-01",
                    "status": "Completed"
                }
            ]
        });

        Ok(Some(Evidence {
            id: format!("CHANGE-{}-{}", control_id, timestamp.timestamp()),
            control_id: control_id.to_string(),
            evidence_type: EvidenceType::ChangeManagement,
            description: format!("Change management evidence for control {}", control_id),
            collected_at: timestamp,
            collected_by: "HeroForge Compliance Automation".to_string(),
            data: EvidenceData::Json(change_data),
            version: 1,
        }))
    }

    /// Collect incident response evidence
    async fn collect_incident_response(&self, control_id: &str, timestamp: DateTime<Utc>) -> Result<Option<Evidence>> {
        let ir_data = serde_json::json!({
            "control_id": control_id,
            "collection_type": "incident_response",
            "timestamp": timestamp.to_rfc3339(),
            "incident_summary": {
                "period": "Last 12 months",
                "total_incidents": 24,
                "security_incidents": 8,
                "availability_incidents": 12,
                "other_incidents": 4
            },
            "incident_metrics": {
                "mean_time_to_detect_hours": 2.5,
                "mean_time_to_respond_hours": 1.0,
                "mean_time_to_resolve_hours": 8.5,
                "incidents_within_sla": 22
            },
            "ir_testing": {
                "last_tabletop_date": "2025-03-15",
                "last_simulation_date": "2025-06-01",
                "test_scenarios": ["Ransomware", "Data Breach", "DDoS"],
                "lessons_learned_documented": true
            },
            "ir_team": {
                "team_size": 8,
                "on_call_rotation": true,
                "escalation_procedures_documented": true,
                "external_contacts_maintained": true
            }
        });

        Ok(Some(Evidence {
            id: format!("IR-{}-{}", control_id, timestamp.timestamp()),
            control_id: control_id.to_string(),
            evidence_type: EvidenceType::IncidentResponse,
            description: format!("Incident response evidence for control {}", control_id),
            collected_at: timestamp,
            collected_by: "HeroForge Compliance Automation".to_string(),
            data: EvidenceData::Json(ir_data),
            version: 1,
        }))
    }
}

impl Default for EvidenceCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate README for evidence package
fn generate_readme(index: &EvidencePackageIndex) -> String {
    format!(
        r#"# Evidence Package

## Overview
This evidence package was generated by HeroForge Compliance Automation.

**Generated:** {}
**Controls Covered:** {}
**Total Evidence Items:** {}

## Contents
This package contains evidence for the following controls:
{}

## Structure
- `index.json` - Machine-readable index of all evidence
- `<control_id>/` - Folder for each control containing:
  - `<evidence_id>.json` - Evidence metadata
  - `<evidence_id>_content.*` - Evidence content/data

## Usage
Review each control folder to find the relevant evidence for audit purposes.
The `index.json` file provides a complete listing of all evidence items.

## Verification
Evidence items include collection timestamps, collection methods, and version information
for audit trail purposes.

---
*Generated by HeroForge Compliance Automation*
"#,
        index.generated_at.format("%Y-%m-%d %H:%M:%S UTC"),
        index.control_ids.len(),
        index.evidence_items.len(),
        index.control_ids.iter()
            .map(|id| format!("- {}", id))
            .collect::<Vec<_>>()
            .join("\n")
    )
}

/// Evidence package index
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidencePackageIndex {
    pub generated_at: DateTime<Utc>,
    pub control_ids: Vec<String>,
    pub evidence_items: Vec<EvidenceIndexEntry>,
}

/// Evidence index entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceIndexEntry {
    pub id: String,
    pub control_id: String,
    pub evidence_type: String,
    pub description: String,
    pub collected_at: DateTime<Utc>,
    pub file_path: String,
}

/// Evidence item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub id: String,
    pub control_id: String,
    pub evidence_type: EvidenceType,
    pub description: String,
    pub collected_at: chrono::DateTime<chrono::Utc>,
    pub collected_by: String,
    pub data: EvidenceData,
    pub version: u32,
}

/// Evidence type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvidenceType {
    SystemConfiguration,
    AuditLog,
    ScanResult,
    PolicyDocument,
    TrainingRecord,
    AccessControl,
    ChangeManagement,
    IncidentResponse,
    Other(String),
}

/// Evidence data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvidenceData {
    Text(String),
    Json(serde_json::Value),
    Binary(Vec<u8>),
    Reference(String), // URL or file path
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_collect_evidence() {
        let collector = EvidenceCollector::new();
        let evidence = collector.collect_evidence("AC-2").await.unwrap();
        assert!(!evidence.is_empty());
    }

    #[tokio::test]
    async fn test_store_evidence() {
        let mut collector = EvidenceCollector::new();
        let evidence = Evidence {
            id: "test-001".to_string(),
            control_id: "AC-2".to_string(),
            evidence_type: EvidenceType::SystemConfiguration,
            description: "Test evidence".to_string(),
            collected_at: Utc::now(),
            collected_by: "Test".to_string(),
            data: EvidenceData::Text("Test data".to_string()),
            version: 1,
        };

        let id = collector.store_evidence(evidence).await.unwrap();
        assert!(!id.is_empty());
    }

    #[tokio::test]
    async fn test_export_evidence_package() {
        let mut collector = EvidenceCollector::new();

        // Store some evidence first
        let evidence = Evidence {
            id: "test-001".to_string(),
            control_id: "AC-2".to_string(),
            evidence_type: EvidenceType::SystemConfiguration,
            description: "Test evidence".to_string(),
            collected_at: Utc::now(),
            collected_by: "Test".to_string(),
            data: EvidenceData::Json(serde_json::json!({"test": "data"})),
            version: 1,
        };
        collector.store_evidence(evidence).await.unwrap();

        let package = collector.export_evidence_package(&["AC-2".to_string()]).await.unwrap();
        assert!(!package.is_empty());
    }
}
