//! Bridge between SCAP and existing compliance module

use anyhow::Result;
use sqlx::SqlitePool;

use crate::compliance::types::{ComplianceFinding, ControlStatus, ComplianceFramework, FindingSource};
use crate::types::Severity;
use crate::scap::xccdf::{XccdfResultType, RuleResult};
use crate::scap::ScapSeverity;

/// Bridge for converting SCAP results to compliance findings
pub struct ScapComplianceBridge {
    pool: SqlitePool,
}

impl ScapComplianceBridge {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Convert XCCDF rule results to compliance findings
    pub fn xccdf_to_compliance_findings(
        &self,
        rule_results: &[RuleResult],
        scan_id: &str,
        target_host: &str,
    ) -> Vec<ComplianceFinding> {
        rule_results
            .iter()
            .map(|result| {
                let status = Self::xccdf_to_control_status(result.result);
                let severity = Self::scap_to_compliance_severity(result.severity);

                ComplianceFinding {
                    id: uuid::Uuid::new_v4().to_string(),
                    scan_id: scan_id.to_string(),
                    control_id: result.rule_id.clone(),
                    framework: ComplianceFramework::DodStig,
                    status,
                    severity,
                    evidence: result.check_results
                        .iter()
                        .filter_map(|cr| cr.message.clone())
                        .collect(),
                    affected_hosts: vec![target_host.to_string()],
                    affected_ports: vec![],
                    remediation: result.fix.as_ref()
                        .map(|f| f.content.clone())
                        .unwrap_or_default(),
                    source: FindingSource::DirectCheck {
                        check_id: format!("scap:{}", result.rule_id),
                        check_name: result.rule_id.clone(),
                    },
                    notes: result.message.clone(),
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                    override_by: None,
                    override_reason: None,
                }
            })
            .collect()
    }

    /// Convert XCCDF result type to control status
    fn xccdf_to_control_status(result: XccdfResultType) -> ControlStatus {
        match result {
            XccdfResultType::Pass => ControlStatus::Compliant,
            XccdfResultType::Fail => ControlStatus::NonCompliant,
            XccdfResultType::Error => ControlStatus::NotAssessed,
            XccdfResultType::Unknown => ControlStatus::NotAssessed,
            XccdfResultType::NotApplicable => ControlStatus::NotApplicable,
            XccdfResultType::NotChecked => ControlStatus::NotAssessed,
            XccdfResultType::NotSelected => ControlStatus::NotApplicable,
            XccdfResultType::Informational => ControlStatus::Compliant,
            XccdfResultType::Fixed => ControlStatus::Compliant,
        }
    }

    /// Convert SCAP severity to compliance severity
    fn scap_to_compliance_severity(severity: ScapSeverity) -> Severity {
        match severity {
            ScapSeverity::Critical => Severity::Critical,
            ScapSeverity::High => Severity::High,
            ScapSeverity::Medium => Severity::Medium,
            ScapSeverity::Low => Severity::Low,
            ScapSeverity::Info => Severity::Low, // Map Info to Low (no Info variant exists)
            ScapSeverity::Unknown => Severity::Low,
        }
    }

    /// Convert Severity to string for database storage
    fn severity_to_string(severity: &Severity) -> &'static str {
        match severity {
            Severity::Critical => "Critical",
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Low",
        }
    }

    /// Store findings in database
    pub async fn store_findings(&self, findings: &[ComplianceFinding]) -> Result<()> {
        for finding in findings {
            sqlx::query(
                r#"
                INSERT INTO compliance_findings
                (id, scan_id, control_id, framework, status, severity, evidence,
                 affected_hosts, remediation, notes, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(&finding.id)
            .bind(&finding.scan_id)
            .bind(&finding.control_id)
            .bind(finding.framework.to_string())
            .bind(finding.status.to_string())
            .bind(Self::severity_to_string(&finding.severity))
            .bind(serde_json::to_string(&finding.evidence)?)
            .bind(serde_json::to_string(&finding.affected_hosts)?)
            .bind(&finding.remediation)
            .bind(&finding.notes)
            .bind(finding.created_at.to_rfc3339())
            .bind(finding.updated_at.to_rfc3339())
            .execute(&self.pool)
            .await?;
        }

        Ok(())
    }
}
