//! eMASS POA&M (Plan of Action & Milestones) Operations
//!
//! POA&M lifecycle management for tracking and remediating findings.

use anyhow::Result;
use chrono::{NaiveDate, Utc};
use std::collections::HashMap;

use super::client::EmassClient;
use super::types::*;

/// Get all POA&Ms for a system
pub async fn list_poams(client: &EmassClient, system_id: i64) -> Result<Vec<EmassPoam>> {
    client.get_poams(system_id).await
}

/// Get POA&Ms filtered by status
pub async fn get_poams_by_status(
    client: &EmassClient,
    system_id: i64,
    status: PoamStatus,
) -> Result<Vec<EmassPoam>> {
    let poams = client.get_poams(system_id).await?;
    Ok(poams
        .into_iter()
        .filter(|p| p.status == status)
        .collect())
}

/// Get overdue POA&Ms
pub async fn get_overdue_poams(client: &EmassClient, system_id: i64) -> Result<Vec<EmassPoam>> {
    let poams = client.get_poams(system_id).await?;
    let today = Utc::now().date_naive();

    Ok(poams
        .into_iter()
        .filter(|p| {
            p.status == PoamStatus::Ongoing && p.scheduled_completion_date < today
        })
        .collect())
}

/// Get POA&Ms by severity
pub async fn get_poams_by_severity(
    client: &EmassClient,
    system_id: i64,
    severity: PoamSeverity,
) -> Result<Vec<EmassPoam>> {
    let poams = client.get_poams(system_id).await?;
    Ok(poams
        .into_iter()
        .filter(|p| p.severity == severity)
        .collect())
}

/// Create a new POA&M
pub async fn create_poam(
    client: &EmassClient,
    system_id: i64,
    poam: &EmassPoam,
) -> Result<EmassPoam> {
    client.create_poam(system_id, poam).await
}

/// Update an existing POA&M
pub async fn update_poam(
    client: &EmassClient,
    system_id: i64,
    poam: &EmassPoam,
) -> Result<EmassPoam> {
    client.update_poam(system_id, poam).await
}

/// Create POA&Ms from HeroForge compliance findings
pub async fn create_poams_for_findings(
    client: &EmassClient,
    system_id: i64,
    findings: &[crate::compliance::types::ComplianceFinding],
) -> Result<Vec<EmassPoam>> {
    use crate::compliance::types::ControlStatus;

    let mut created_poams = Vec::new();

    for finding in findings {
        // Only create POA&Ms for non-compliant findings
        if finding.status == ControlStatus::Compliant ||
           finding.status == ControlStatus::NotApplicable {
            continue;
        }

        let poam = EmassPoam {
            poam_id: None,
            system_id,
            control_acronym: finding.control_id.clone(),
            cci: None, // CCI is derived from control mapping, not stored in finding
            status: PoamStatus::Ongoing,
            weakness_description: format!(
                "Control {} non-compliance detected for framework {:?}",
                finding.control_id, finding.framework
            ),
            source_identified: "HeroForge Automated Scan".to_string(),
            severity: map_severity_to_poam(&finding.severity),
            scheduled_completion_date: calculate_completion_date(&finding.severity),
            milestone_changes: create_default_milestones(&finding.severity),
            resources_required: Some("Security team remediation effort".to_string()),
            comments: Some(format!(
                "Auto-generated from HeroForge scan. Framework: {:?}. Recommendation: {}",
                finding.framework,
                if finding.remediation.is_empty() { "See control guidance" } else { &finding.remediation }
            )),
            created_date: None,
            modified_date: None,
        };

        let created = client.create_poam(system_id, &poam).await?;
        created_poams.push(created);
    }

    Ok(created_poams)
}

/// Map HeroForge severity to POA&M severity
fn map_severity_to_poam(severity: &crate::types::Severity) -> PoamSeverity {
    match severity {
        crate::types::Severity::Critical => PoamSeverity::VeryHigh,
        crate::types::Severity::High => PoamSeverity::High,
        crate::types::Severity::Medium => PoamSeverity::Moderate,
        crate::types::Severity::Low => PoamSeverity::Low,
    }
}

/// Calculate scheduled completion date based on severity
fn calculate_completion_date(severity: &crate::types::Severity) -> NaiveDate {
    let today = Utc::now().date_naive();
    let days = match severity {
        crate::types::Severity::Critical => 15,   // 15 days for critical
        crate::types::Severity::High => 30,       // 30 days for high
        crate::types::Severity::Medium => 90,     // 90 days for medium
        crate::types::Severity::Low => 180,       // 180 days for low
    };
    today + chrono::Duration::days(days)
}

/// Create default milestones for a POA&M
fn create_default_milestones(severity: &crate::types::Severity) -> Vec<PoamMilestone> {
    let today = Utc::now().date_naive();

    match severity {
        crate::types::Severity::Critical | crate::types::Severity::High => {
            vec![
                PoamMilestone {
                    milestone_id: None,
                    description: "Initial assessment and remediation planning".to_string(),
                    scheduled_completion_date: today + chrono::Duration::days(7),
                    status: MilestoneStatus::Pending,
                },
                PoamMilestone {
                    milestone_id: None,
                    description: "Implement remediation measures".to_string(),
                    scheduled_completion_date: today + chrono::Duration::days(14),
                    status: MilestoneStatus::Pending,
                },
                PoamMilestone {
                    milestone_id: None,
                    description: "Verification testing and documentation".to_string(),
                    scheduled_completion_date: today + chrono::Duration::days(21),
                    status: MilestoneStatus::Pending,
                },
            ]
        }
        crate::types::Severity::Medium => {
            vec![
                PoamMilestone {
                    milestone_id: None,
                    description: "Assessment and planning phase".to_string(),
                    scheduled_completion_date: today + chrono::Duration::days(30),
                    status: MilestoneStatus::Pending,
                },
                PoamMilestone {
                    milestone_id: None,
                    description: "Implementation phase".to_string(),
                    scheduled_completion_date: today + chrono::Duration::days(60),
                    status: MilestoneStatus::Pending,
                },
                PoamMilestone {
                    milestone_id: None,
                    description: "Testing and closure".to_string(),
                    scheduled_completion_date: today + chrono::Duration::days(90),
                    status: MilestoneStatus::Pending,
                },
            ]
        }
        crate::types::Severity::Low => {
            vec![
                PoamMilestone {
                    milestone_id: None,
                    description: "Planning and implementation".to_string(),
                    scheduled_completion_date: today + chrono::Duration::days(90),
                    status: MilestoneStatus::Pending,
                },
                PoamMilestone {
                    milestone_id: None,
                    description: "Closure and verification".to_string(),
                    scheduled_completion_date: today + chrono::Duration::days(180),
                    status: MilestoneStatus::Pending,
                },
            ]
        }
    }
}

/// POA&M summary statistics
#[derive(Debug, Clone, Default)]
pub struct PoamSummary {
    pub total_poams: usize,
    pub ongoing: usize,
    pub delayed: usize,
    pub completed: usize,
    pub cancelled: usize,
    pub risk_accepted: usize,
    pub overdue: usize,
    pub due_within_30_days: usize,
    pub very_high_severity: usize,
    pub high_severity: usize,
    pub moderate_severity: usize,
    pub low_severity: usize,
    pub very_low_severity: usize,
    pub by_control_family: HashMap<String, usize>,
}

/// Get POA&M summary for a system
pub async fn get_poam_summary(client: &EmassClient, system_id: i64) -> Result<PoamSummary> {
    let poams = client.get_poams(system_id).await?;
    let today = Utc::now().date_naive();
    let threshold_30 = today + chrono::Duration::days(30);

    let mut summary = PoamSummary {
        total_poams: poams.len(),
        ..Default::default()
    };

    for poam in &poams {
        // Count by status
        match poam.status {
            PoamStatus::Ongoing => {
                summary.ongoing += 1;
                if poam.scheduled_completion_date < today {
                    summary.overdue += 1;
                } else if poam.scheduled_completion_date <= threshold_30 {
                    summary.due_within_30_days += 1;
                }
            }
            PoamStatus::Delayed => summary.delayed += 1,
            PoamStatus::Completed => summary.completed += 1,
            PoamStatus::Cancelled => summary.cancelled += 1,
            PoamStatus::RiskAccepted => summary.risk_accepted += 1,
        }

        // Count by severity
        match poam.severity {
            PoamSeverity::VeryHigh => summary.very_high_severity += 1,
            PoamSeverity::High => summary.high_severity += 1,
            PoamSeverity::Moderate => summary.moderate_severity += 1,
            PoamSeverity::Low => summary.low_severity += 1,
            PoamSeverity::VeryLow => summary.very_low_severity += 1,
        }

        // Count by control family
        let family = poam.control_acronym
            .split('-')
            .next()
            .unwrap_or(&poam.control_acronym)
            .to_string();
        *summary.by_control_family.entry(family).or_default() += 1;
    }

    Ok(summary)
}

/// Close a POA&M with evidence
pub async fn close_poam_with_evidence(
    client: &EmassClient,
    system_id: i64,
    poam_id: i64,
    evidence_file: &str,
    closure_comments: &str,
) -> Result<EmassPoam> {
    // First, upload the evidence artifact
    let _artifact = client.upload_artifact(
        system_id,
        evidence_file,
        ArtifactType::Evidence,
    ).await?;

    // Get the current POA&M
    let poams = client.get_poams(system_id).await?;
    let mut poam = poams
        .into_iter()
        .find(|p| p.poam_id == Some(poam_id))
        .ok_or_else(|| anyhow::anyhow!("POA&M not found: {}", poam_id))?;

    // Update status and comments
    poam.status = PoamStatus::Completed;
    poam.comments = Some(format!(
        "{}\n\nClosure: {}",
        poam.comments.as_deref().unwrap_or(""),
        closure_comments
    ));

    // Mark all milestones as completed
    for milestone in &mut poam.milestone_changes {
        milestone.status = MilestoneStatus::Completed;
    }

    // Update the POA&M
    client.update_poam(system_id, &poam).await
}
