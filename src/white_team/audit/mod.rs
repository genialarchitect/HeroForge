// Audit Management Module
//
// Provides comprehensive audit management capabilities:
// - Audit planning and scheduling
// - Audit execution and fieldwork
// - Finding management
// - Evidence collection
// - Audit reporting

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::types::{
    Audit, AuditEvidence, AuditFinding, AuditStatus, AuditType, ComplianceFramework,
    EvidenceType, FindingSeverity, FindingStatus,
};

/// Audit management engine
pub struct AuditManager {
    audits: HashMap<String, Audit>,
    findings: HashMap<String, Vec<AuditFinding>>,
    evidence: HashMap<String, Vec<AuditEvidence>>,
    audit_counter: u32,
}

impl AuditManager {
    pub fn new() -> Self {
        Self {
            audits: HashMap::new(),
            findings: HashMap::new(),
            evidence: HashMap::new(),
            audit_counter: 0,
        }
    }

    /// Create a new audit
    pub fn create_audit(
        &mut self,
        title: String,
        audit_type: AuditType,
        scope: String,
        objectives: Option<String>,
        lead_auditor_id: String,
        planned_start_date: Option<NaiveDate>,
        planned_end_date: Option<NaiveDate>,
        frameworks: Vec<ComplianceFramework>,
    ) -> Audit {
        self.audit_counter += 1;
        let id = uuid::Uuid::new_v4().to_string();
        let audit_number = format!("AUD-{:04}", self.audit_counter);
        let now = Utc::now();

        let audit = Audit {
            id: id.clone(),
            audit_number,
            title,
            audit_type,
            scope,
            objectives,
            status: AuditStatus::Planning,
            lead_auditor_id,
            auditee_id: None,
            planned_start_date,
            planned_end_date,
            actual_start_date: None,
            actual_end_date: None,
            frameworks,
            controls_in_scope: Vec::new(),
            created_at: now,
            updated_at: now,
        };

        self.audits.insert(id, audit.clone());
        audit
    }

    /// Start audit fieldwork
    pub fn start_fieldwork(&mut self, audit_id: &str) -> Result<(), AuditError> {
        let audit = self.audits.get_mut(audit_id).ok_or(AuditError::NotFound)?;

        if audit.status != AuditStatus::Planning {
            return Err(AuditError::InvalidStatus("Audit must be in planning status".to_string()));
        }

        audit.status = AuditStatus::Fieldwork;
        audit.actual_start_date = Some(Utc::now().date_naive());
        audit.updated_at = Utc::now();

        Ok(())
    }

    /// Complete fieldwork and move to reporting
    pub fn complete_fieldwork(&mut self, audit_id: &str) -> Result<(), AuditError> {
        let audit = self.audits.get_mut(audit_id).ok_or(AuditError::NotFound)?;

        if audit.status != AuditStatus::Fieldwork {
            return Err(AuditError::InvalidStatus("Audit must be in fieldwork status".to_string()));
        }

        audit.status = AuditStatus::Reporting;
        audit.updated_at = Utc::now();

        Ok(())
    }

    /// Finalize report and move to follow-up
    pub fn finalize_report(&mut self, audit_id: &str) -> Result<(), AuditError> {
        let audit = self.audits.get_mut(audit_id).ok_or(AuditError::NotFound)?;

        if audit.status != AuditStatus::Reporting {
            return Err(AuditError::InvalidStatus("Audit must be in reporting status".to_string()));
        }

        audit.status = AuditStatus::FollowUp;
        audit.updated_at = Utc::now();

        Ok(())
    }

    /// Close audit
    pub fn close_audit(&mut self, audit_id: &str) -> Result<(), AuditError> {
        let audit = self.audits.get_mut(audit_id).ok_or(AuditError::NotFound)?;

        // Can close from follow-up or reporting
        if audit.status != AuditStatus::FollowUp && audit.status != AuditStatus::Reporting {
            return Err(AuditError::InvalidStatus("Audit must be in follow-up or reporting status".to_string()));
        }

        audit.status = AuditStatus::Closed;
        audit.actual_end_date = Some(Utc::now().date_naive());
        audit.updated_at = Utc::now();

        Ok(())
    }

    /// Add controls to audit scope
    pub fn add_controls_to_scope(
        &mut self,
        audit_id: &str,
        control_ids: Vec<String>,
    ) -> Result<(), AuditError> {
        let audit = self.audits.get_mut(audit_id).ok_or(AuditError::NotFound)?;
        audit.controls_in_scope.extend(control_ids);
        audit.controls_in_scope.sort();
        audit.controls_in_scope.dedup();
        audit.updated_at = Utc::now();
        Ok(())
    }

    /// Create a finding
    pub fn create_finding(
        &mut self,
        audit_id: &str,
        title: String,
        description: String,
        severity: FindingSeverity,
        recommendation: String,
        control_id: Option<String>,
    ) -> Result<AuditFinding, AuditError> {
        let audit = self.audits.get(audit_id).ok_or(AuditError::NotFound)?;

        if audit.status != AuditStatus::Fieldwork && audit.status != AuditStatus::Reporting {
            return Err(AuditError::InvalidStatus("Can only create findings during fieldwork or reporting".to_string()));
        }

        let finding_count = self.findings.get(audit_id).map(|f| f.len()).unwrap_or(0);
        let finding_number = format!("{}-F{:02}", audit.audit_number, finding_count + 1);

        let now = Utc::now();
        let finding = AuditFinding {
            id: uuid::Uuid::new_v4().to_string(),
            audit_id: audit_id.to_string(),
            finding_number,
            title,
            description,
            severity,
            status: FindingStatus::Open,
            control_id,
            root_cause: None,
            recommendation,
            management_response: None,
            remediation_owner_id: None,
            remediation_due_date: None,
            remediation_completed_date: None,
            evidence_refs: Vec::new(),
            created_at: now,
            updated_at: now,
        };

        self.findings
            .entry(audit_id.to_string())
            .or_default()
            .push(finding.clone());

        Ok(finding)
    }

    /// Update finding
    pub fn update_finding(
        &mut self,
        finding_id: &str,
        root_cause: Option<String>,
        management_response: Option<String>,
        remediation_owner_id: Option<String>,
        remediation_due_date: Option<NaiveDate>,
    ) -> Result<AuditFinding, AuditError> {
        for findings in self.findings.values_mut() {
            if let Some(finding) = findings.iter_mut().find(|f| f.id == finding_id) {
                if let Some(rc) = root_cause {
                    finding.root_cause = Some(rc);
                }
                if let Some(mr) = management_response {
                    finding.management_response = Some(mr);
                }
                if let Some(owner) = remediation_owner_id {
                    finding.remediation_owner_id = Some(owner);
                }
                if let Some(due) = remediation_due_date {
                    finding.remediation_due_date = Some(due);
                }
                finding.updated_at = Utc::now();
                return Ok(finding.clone());
            }
        }
        Err(AuditError::FindingNotFound)
    }

    /// Update finding status
    pub fn update_finding_status(
        &mut self,
        finding_id: &str,
        status: FindingStatus,
    ) -> Result<(), AuditError> {
        for findings in self.findings.values_mut() {
            if let Some(finding) = findings.iter_mut().find(|f| f.id == finding_id) {
                finding.status = status.clone();

                if status == FindingStatus::Closed {
                    finding.remediation_completed_date = Some(Utc::now().date_naive());
                }

                finding.updated_at = Utc::now();
                return Ok(());
            }
        }
        Err(AuditError::FindingNotFound)
    }

    /// Add evidence
    pub fn add_evidence(
        &mut self,
        audit_id: &str,
        finding_id: Option<String>,
        name: String,
        description: Option<String>,
        evidence_type: EvidenceType,
        file_path: Option<String>,
        file_hash: Option<String>,
        collected_by: String,
    ) -> Result<AuditEvidence, AuditError> {
        if !self.audits.contains_key(audit_id) {
            return Err(AuditError::NotFound);
        }

        let evidence = AuditEvidence {
            id: uuid::Uuid::new_v4().to_string(),
            audit_id: audit_id.to_string(),
            finding_id,
            name,
            description,
            evidence_type,
            file_path,
            file_hash,
            collected_by,
            collected_at: Utc::now(),
        };

        self.evidence
            .entry(audit_id.to_string())
            .or_default()
            .push(evidence.clone());

        Ok(evidence)
    }

    /// Link evidence to finding
    pub fn link_evidence_to_finding(
        &mut self,
        evidence_id: &str,
        finding_id: &str,
    ) -> Result<(), AuditError> {
        // Update evidence
        for evidence_list in self.evidence.values_mut() {
            if let Some(evidence) = evidence_list.iter_mut().find(|e| e.id == evidence_id) {
                evidence.finding_id = Some(finding_id.to_string());
            }
        }

        // Update finding
        for findings in self.findings.values_mut() {
            if let Some(finding) = findings.iter_mut().find(|f| f.id == finding_id) {
                if !finding.evidence_refs.contains(&evidence_id.to_string()) {
                    finding.evidence_refs.push(evidence_id.to_string());
                }
                finding.updated_at = Utc::now();
                return Ok(());
            }
        }

        Err(AuditError::FindingNotFound)
    }

    /// Get audit by ID
    pub fn get_audit(&self, audit_id: &str) -> Option<&Audit> {
        self.audits.get(audit_id)
    }

    /// List all audits
    pub fn list_audits(
        &self,
        audit_type: Option<AuditType>,
        status: Option<AuditStatus>,
    ) -> Vec<&Audit> {
        self.audits
            .values()
            .filter(|a| {
                audit_type.as_ref().map_or(true, |t| &a.audit_type == t)
                    && status.as_ref().map_or(true, |s| &a.status == s)
            })
            .collect()
    }

    /// Get findings for an audit
    pub fn get_findings(&self, audit_id: &str) -> Vec<&AuditFinding> {
        self.findings
            .get(audit_id)
            .map(|f| f.iter().collect())
            .unwrap_or_default()
    }

    /// Get evidence for an audit
    pub fn get_evidence(&self, audit_id: &str) -> Vec<&AuditEvidence> {
        self.evidence
            .get(audit_id)
            .map(|e| e.iter().collect())
            .unwrap_or_default()
    }

    /// Get overdue remediations
    pub fn get_overdue_remediations(&self) -> Vec<&AuditFinding> {
        let today = Utc::now().date_naive();
        self.findings
            .values()
            .flatten()
            .filter(|f| {
                f.status != FindingStatus::Closed
                    && f.remediation_due_date.map_or(false, |d| d < today)
            })
            .collect()
    }

    /// Get audit statistics
    pub fn get_statistics(&self) -> AuditStatistics {
        let total = self.audits.len() as u32;
        let active = self.audits
            .values()
            .filter(|a| a.status != AuditStatus::Closed)
            .count() as u32;

        let mut open_findings = 0;
        let mut critical_findings = 0;
        let mut high_findings = 0;
        let mut overdue = 0;
        let mut total_remediation_days = 0.0;
        let mut closed_findings = 0;

        let today = Utc::now().date_naive();

        for finding in self.findings.values().flatten() {
            if finding.status != FindingStatus::Closed {
                open_findings += 1;

                match finding.severity {
                    FindingSeverity::Critical => critical_findings += 1,
                    FindingSeverity::High => high_findings += 1,
                    _ => {}
                }

                if finding.remediation_due_date.map_or(false, |d| d < today) {
                    overdue += 1;
                }
            } else {
                closed_findings += 1;

                // Calculate remediation time
                if let (Some(due), Some(completed)) = (finding.remediation_due_date, finding.remediation_completed_date) {
                    let days = (completed - due).num_days();
                    total_remediation_days += days as f64;
                }
            }
        }

        let avg_remediation_days = if closed_findings > 0 {
            total_remediation_days / closed_findings as f64
        } else {
            0.0
        };

        AuditStatistics {
            total_audits: total,
            active_audits: active,
            open_findings,
            critical_findings,
            high_findings,
            overdue_remediations: overdue,
            avg_remediation_days,
        }
    }
}

impl Default for AuditManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditStatistics {
    pub total_audits: u32,
    pub active_audits: u32,
    pub open_findings: u32,
    pub critical_findings: u32,
    pub high_findings: u32,
    pub overdue_remediations: u32,
    pub avg_remediation_days: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditError {
    NotFound,
    FindingNotFound,
    InvalidStatus(String),
    ValidationError(String),
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "Audit not found"),
            Self::FindingNotFound => write!(f, "Finding not found"),
            Self::InvalidStatus(msg) => write!(f, "Invalid status: {}", msg),
            Self::ValidationError(msg) => write!(f, "Validation error: {}", msg),
        }
    }
}

impl std::error::Error for AuditError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_lifecycle() {
        let mut manager = AuditManager::new();

        // Create audit
        let audit = manager.create_audit(
            "Q1 2025 Internal Audit".to_string(),
            AuditType::Internal,
            "Access control and authentication systems".to_string(),
            Some("Verify effectiveness of access controls".to_string()),
            "auditor-1".to_string(),
            Some(NaiveDate::from_ymd_opt(2025, 1, 15).unwrap()),
            Some(NaiveDate::from_ymd_opt(2025, 2, 15).unwrap()),
            vec![ComplianceFramework::Nist80053, ComplianceFramework::Soc2],
        );

        assert_eq!(audit.status, AuditStatus::Planning);

        // Start fieldwork
        manager.start_fieldwork(&audit.id).unwrap();
        let updated = manager.get_audit(&audit.id).unwrap();
        assert_eq!(updated.status, AuditStatus::Fieldwork);

        // Create finding
        let finding = manager.create_finding(
            &audit.id,
            "Weak Password Policy".to_string(),
            "Password policy does not enforce complexity requirements".to_string(),
            FindingSeverity::High,
            "Implement password complexity requirements".to_string(),
            Some("CTRL-AC-001".to_string()),
        ).unwrap();

        assert_eq!(finding.severity, FindingSeverity::High);
        assert_eq!(finding.status, FindingStatus::Open);

        // Complete fieldwork
        manager.complete_fieldwork(&audit.id).unwrap();
        let updated = manager.get_audit(&audit.id).unwrap();
        assert_eq!(updated.status, AuditStatus::Reporting);
    }

    #[test]
    fn test_evidence_management() {
        let mut manager = AuditManager::new();

        let audit = manager.create_audit(
            "Test Audit".to_string(),
            AuditType::Internal,
            "Scope".to_string(),
            None,
            "auditor-1".to_string(),
            None,
            None,
            vec![],
        );

        manager.start_fieldwork(&audit.id).unwrap();

        // Add evidence
        let evidence = manager.add_evidence(
            &audit.id,
            None,
            "Password Policy Screenshot".to_string(),
            Some("Screenshot of AD password policy".to_string()),
            EvidenceType::Screenshot,
            Some("/evidence/password-policy.png".to_string()),
            Some("abc123hash".to_string()),
            "auditor-1".to_string(),
        ).unwrap();

        assert_eq!(evidence.evidence_type, EvidenceType::Screenshot);

        // Create finding
        let finding = manager.create_finding(
            &audit.id,
            "Test Finding".to_string(),
            "Description".to_string(),
            FindingSeverity::Medium,
            "Recommendation".to_string(),
            None,
        ).unwrap();

        // Link evidence to finding
        manager.link_evidence_to_finding(&evidence.id, &finding.id).unwrap();

        // Verify link
        let findings = manager.get_findings(&audit.id);
        assert_eq!(findings[0].evidence_refs.len(), 1);
        assert_eq!(findings[0].evidence_refs[0], evidence.id);
    }
}
