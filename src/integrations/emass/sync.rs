//! eMASS Bidirectional Sync
//!
//! Synchronization logic between HeroForge and eMASS.

use anyhow::Result;
use chrono::Utc;
use std::collections::HashMap;

use super::client::EmassClient;
use super::types::*;
use super::controls::{map_finding_to_control_status, map_finding_to_implementation_status};
use crate::compliance::types::ComplianceFinding;

/// Sync result containing changes made
#[derive(Debug, Clone, Default)]
pub struct SyncResult {
    pub controls_updated: usize,
    pub controls_unchanged: usize,
    pub controls_failed: usize,
    pub poams_created: usize,
    pub poams_updated: usize,
    pub poams_closed: usize,
    pub artifacts_uploaded: usize,
    pub errors: Vec<String>,
    pub timestamp: chrono::DateTime<Utc>,
}

/// Sync controls from HeroForge findings to eMASS
pub async fn sync_controls_from_findings(
    client: &EmassClient,
    system_id: i64,
    findings: &[ComplianceFinding],
) -> Result<SyncResult> {
    use crate::compliance::types::ControlStatus;

    let mut result = SyncResult {
        timestamp: Utc::now(),
        ..Default::default()
    };

    // Get current controls from eMASS
    let current_controls = client.get_controls(system_id).await?;
    let control_map: HashMap<String, EmassControl> = current_controls
        .into_iter()
        .map(|c| (c.control_acronym.clone(), c))
        .collect();

    // Group findings by control
    let mut findings_by_control: HashMap<String, Vec<&ComplianceFinding>> = HashMap::new();
    for finding in findings {
        findings_by_control
            .entry(finding.control_id.clone())
            .or_default()
            .push(finding);
    }

    // Update each control based on findings
    for (control_id, control_findings) in findings_by_control {
        if let Some(mut control) = control_map.get(&control_id).cloned() {
            // Determine overall status from all findings for this control
            let all_compliant = control_findings.iter().all(|f| f.status == ControlStatus::Compliant);
            let any_compliant = control_findings.iter().any(|f| f.status == ControlStatus::Compliant);
            let is_applicable = control_findings.iter().all(|f| f.status != ControlStatus::NotApplicable);

            let new_compliance_status = map_finding_to_control_status(all_compliant, is_applicable);
            let new_implementation_status = map_finding_to_implementation_status(
                all_compliant,
                any_compliant && !all_compliant,
                is_applicable,
            );

            // Check if update is needed
            if control.compliance_status != new_compliance_status ||
               control.implementation_status != new_implementation_status
            {
                control.compliance_status = new_compliance_status;
                control.implementation_status = new_implementation_status;

                // Build implementation narrative from findings
                let narrative = control_findings
                    .iter()
                    .map(|f| {
                        let status_str = match f.status {
                            ControlStatus::Compliant => "PASS",
                            ControlStatus::NonCompliant => "FAIL",
                            ControlStatus::PartiallyCompliant => "PARTIAL",
                            ControlStatus::NotApplicable => "N/A",
                            ControlStatus::NotAssessed => "NOT ASSESSED",
                            ControlStatus::ManualOverride => "OVERRIDE",
                        };
                        format!(
                            "- {}: {} ({})",
                            f.id,
                            status_str,
                            f.notes.as_deref().unwrap_or(&f.control_id)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n");

                control.implementation_narrative = Some(format!(
                    "Last scanned: {}\n\n{}",
                    Utc::now().format("%Y-%m-%d %H:%M UTC"),
                    narrative
                ));

                match client.update_control(system_id, &control).await {
                    Ok(_) => result.controls_updated += 1,
                    Err(e) => {
                        result.controls_failed += 1;
                        result.errors.push(format!("Failed to update {}: {}", control_id, e));
                    }
                }
            } else {
                result.controls_unchanged += 1;
            }
        }
    }

    Ok(result)
}

/// Sync POA&Ms based on failed findings
pub async fn sync_poams_from_findings(
    client: &EmassClient,
    system_id: i64,
    findings: &[ComplianceFinding],
) -> Result<SyncResult> {
    use crate::compliance::types::ControlStatus;

    let mut result = SyncResult {
        timestamp: Utc::now(),
        ..Default::default()
    };

    // Get current POA&Ms
    let current_poams = client.get_poams(system_id).await?;
    let poam_map: HashMap<String, &EmassPoam> = current_poams
        .iter()
        .filter(|p| p.status == PoamStatus::Ongoing || p.status == PoamStatus::Delayed)
        .map(|p| (format!("{}:{}", p.control_acronym, p.weakness_description.chars().take(50).collect::<String>()), p))
        .collect();

    // Process non-compliant findings (excluding N/A)
    let failed_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.status != ControlStatus::Compliant && f.status != ControlStatus::NotApplicable)
        .collect();

    for finding in failed_findings {
        let key = format!("{}:{}", finding.control_id, finding.notes.as_deref().unwrap_or(&finding.id).chars().take(50).collect::<String>());

        if poam_map.contains_key(&key) {
            // POA&M already exists - could update if needed
            result.poams_updated += 1;
        } else {
            // Create new POA&M
            let poam = create_poam_from_finding(system_id, finding);
            match client.create_poam(system_id, &poam).await {
                Ok(_) => result.poams_created += 1,
                Err(e) => {
                    result.errors.push(format!(
                        "Failed to create POA&M for {}: {}",
                        finding.control_id, e
                    ));
                }
            }
        }
    }

    // Check for POA&Ms that can be closed (finding now passes)
    let passed_controls: std::collections::HashSet<_> = findings
        .iter()
        .filter(|f| f.status == ControlStatus::Compliant)
        .map(|f| &f.control_id)
        .collect();

    for poam in &current_poams {
        if poam.status == PoamStatus::Ongoing && passed_controls.contains(&poam.control_acronym) {
            // Finding now passes, close the POA&M
            let mut updated_poam = poam.clone();
            updated_poam.status = PoamStatus::Completed;
            updated_poam.comments = Some(format!(
                "{}\n\nAuto-closed: Control now passes automated scan ({})",
                updated_poam.comments.as_deref().unwrap_or(""),
                Utc::now().format("%Y-%m-%d")
            ));

            match client.update_poam(system_id, &updated_poam).await {
                Ok(_) => result.poams_closed += 1,
                Err(e) => {
                    result.errors.push(format!(
                        "Failed to close POA&M {}: {}",
                        poam.poam_id.unwrap_or(0), e
                    ));
                }
            }
        }
    }

    Ok(result)
}

/// Create a POA&M from a compliance finding
fn create_poam_from_finding(system_id: i64, finding: &ComplianceFinding) -> EmassPoam {
    let severity = match &finding.severity {
        crate::types::Severity::Critical => PoamSeverity::VeryHigh,
        crate::types::Severity::High => PoamSeverity::High,
        crate::types::Severity::Medium => PoamSeverity::Moderate,
        crate::types::Severity::Low => PoamSeverity::Low,
    };

    let days_to_complete = match severity {
        PoamSeverity::VeryHigh => 15,
        PoamSeverity::High => 30,
        PoamSeverity::Moderate => 90,
        PoamSeverity::Low | PoamSeverity::VeryLow => 180,
    };

    let today = Utc::now().date_naive();

    EmassPoam {
        poam_id: None,
        system_id,
        control_acronym: finding.control_id.clone(),
        cci: None, // CCI is derived from control mapping, not stored in finding
        status: PoamStatus::Ongoing,
        weakness_description: format!(
            "Control {} non-compliance detected for framework {:?}",
            finding.control_id, finding.framework
        ),
        source_identified: format!("HeroForge Scan - {:?}", finding.framework),
        severity,
        scheduled_completion_date: today + chrono::Duration::days(days_to_complete),
        milestone_changes: vec![
            PoamMilestone {
                milestone_id: None,
                description: "Review finding and develop remediation plan".to_string(),
                scheduled_completion_date: today + chrono::Duration::days(days_to_complete / 4),
                status: MilestoneStatus::Pending,
            },
            PoamMilestone {
                milestone_id: None,
                description: "Implement remediation".to_string(),
                scheduled_completion_date: today + chrono::Duration::days(days_to_complete * 3 / 4),
                status: MilestoneStatus::Pending,
            },
            PoamMilestone {
                milestone_id: None,
                description: "Verify remediation and close".to_string(),
                scheduled_completion_date: today + chrono::Duration::days(days_to_complete),
                status: MilestoneStatus::Pending,
            },
        ],
        resources_required: Some("Security team resources for remediation".to_string()),
        comments: Some(format!(
            "Auto-generated by HeroForge\nFinding ID: {}\nRecommendation: {}",
            finding.id,
            if finding.remediation.is_empty() { "See control guidance" } else { &finding.remediation }
        )),
        created_date: None,
        modified_date: None,
    }
}

/// Full bidirectional sync
pub async fn full_sync(
    client: &EmassClient,
    system_id: i64,
    findings: &[ComplianceFinding],
    upload_report: Option<&str>,
) -> Result<SyncResult> {
    let mut result = SyncResult {
        timestamp: Utc::now(),
        ..Default::default()
    };

    // Sync controls
    let control_result = sync_controls_from_findings(client, system_id, findings).await?;
    result.controls_updated = control_result.controls_updated;
    result.controls_unchanged = control_result.controls_unchanged;
    result.controls_failed = control_result.controls_failed;
    result.errors.extend(control_result.errors);

    // Sync POA&Ms
    let poam_result = sync_poams_from_findings(client, system_id, findings).await?;
    result.poams_created = poam_result.poams_created;
    result.poams_updated = poam_result.poams_updated;
    result.poams_closed = poam_result.poams_closed;
    result.errors.extend(poam_result.errors);

    // Upload report as artifact if provided
    if let Some(report_path) = upload_report {
        match client.upload_artifact(system_id, report_path, ArtifactType::ScanResult).await {
            Ok(_) => result.artifacts_uploaded += 1,
            Err(e) => {
                result.errors.push(format!("Failed to upload report artifact: {}", e));
            }
        }
    }

    Ok(result)
}

/// Poll for POA&M updates from eMASS
pub async fn poll_poam_updates(
    client: &EmassClient,
    system_id: i64,
    since: chrono::DateTime<Utc>,
) -> Result<Vec<EmassPoam>> {
    let poams = client.get_poams(system_id).await?;

    Ok(poams
        .into_iter()
        .filter(|p| {
            p.modified_date
                .map(|d| d > since)
                .unwrap_or(false)
        })
        .collect())
}

/// Get sync status for a system
#[derive(Debug, Clone)]
pub struct SyncStatus {
    pub system_id: i64,
    pub last_sync: Option<chrono::DateTime<Utc>>,
    pub total_controls: usize,
    pub synced_controls: usize,
    pub open_poams: usize,
    pub overdue_poams: usize,
    pub needs_attention: bool,
}

/// Check sync status for a system
pub async fn check_sync_status(
    client: &EmassClient,
    system_id: i64,
) -> Result<SyncStatus> {
    let controls = client.get_controls(system_id).await?;
    let poams = client.get_poams(system_id).await?;
    let today = Utc::now().date_naive();

    let open_poams = poams
        .iter()
        .filter(|p| p.status == PoamStatus::Ongoing || p.status == PoamStatus::Delayed)
        .count();

    let overdue_poams = poams
        .iter()
        .filter(|p| {
            (p.status == PoamStatus::Ongoing || p.status == PoamStatus::Delayed) &&
            p.scheduled_completion_date < today
        })
        .count();

    let synced_controls = controls
        .iter()
        .filter(|c| c.implementation_narrative.is_some())
        .count();

    Ok(SyncStatus {
        system_id,
        last_sync: None, // Would be tracked in local database
        total_controls: controls.len(),
        synced_controls,
        open_poams,
        overdue_poams,
        needs_attention: overdue_poams > 0,
    })
}
