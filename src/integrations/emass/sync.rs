//! eMASS Bidirectional Sync
//!
//! Synchronization logic between HeroForge and eMASS.
//!
//! This module provides:
//! - Push sync: Push HeroForge findings to eMASS controls and POA&Ms
//! - Pull sync: Pull controls and POA&Ms from eMASS to local cache
//! - Bidirectional sync: Full sync in both directions
//! - Sync status tracking with database persistence

use anyhow::Result;
use chrono::Utc;
use sqlx::SqlitePool;
use std::collections::HashMap;

use super::client::EmassClient;
use super::types::*;
use super::controls::{map_finding_to_control_status, map_finding_to_implementation_status};
use crate::compliance::types::ComplianceFinding;
use crate::db::emass::{
    self, EmassControlCache, EmassPoamCache, EmassSyncHistory,
};

/// Sync result containing changes made
#[derive(Debug, Clone, Default)]
pub struct SyncResult {
    /// Controls pushed/updated to eMASS
    pub controls_updated: usize,
    /// Controls unchanged (no update needed)
    pub controls_unchanged: usize,
    /// Controls that failed to update
    pub controls_failed: usize,
    /// POA&Ms created in eMASS
    pub poams_created: usize,
    /// POA&Ms updated in eMASS
    pub poams_updated: usize,
    /// POA&Ms closed in eMASS
    pub poams_closed: usize,
    /// Artifacts uploaded to eMASS
    pub artifacts_uploaded: usize,
    /// Controls pulled from eMASS to local cache
    pub controls_pulled: usize,
    /// POA&Ms pulled from eMASS to local cache
    pub poams_pulled: usize,
    /// List of error messages
    pub errors: Vec<String>,
    /// Timestamp of sync operation
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

/// Pull controls and POA&Ms from eMASS to local cache
///
/// This function fetches the current state from eMASS and stores it in the local
/// database cache tables (`emass_control_cache` and `emass_poam_cache`).
pub async fn pull_from_emass(
    pool: &SqlitePool,
    client: &EmassClient,
    mapping_id: &str,
    system_id: i64,
    executed_by: &str,
) -> Result<SyncResult> {
    let mut result = SyncResult {
        timestamp: Utc::now(),
        ..Default::default()
    };

    let now = Utc::now().to_rfc3339();

    // Create sync history record
    let sync_history = EmassSyncHistory {
        id: String::new(),
        mapping_id: mapping_id.to_string(),
        sync_type: "full".to_string(),
        direction: "pull".to_string(),
        status: "started".to_string(),
        started_at: now.clone(),
        completed_at: None,
        controls_synced: 0,
        poams_created: 0,
        poams_updated: 0,
        artifacts_uploaded: 0,
        errors: 0,
        error_message: None,
        sync_details: None,
        executed_by: executed_by.to_string(),
    };
    let history_id = emass::create_sync_history(pool, &sync_history).await?;

    // Pull controls from eMASS
    match client.get_controls(system_id).await {
        Ok(controls) => {
            for control in &controls {
                let cache_entry = EmassControlCache {
                    id: String::new(),
                    mapping_id: mapping_id.to_string(),
                    control_acronym: control.control_acronym.clone(),
                    cci: Some(control.cci.clone()),
                    compliance_status: format!("{:?}", control.compliance_status),
                    implementation_status: format!("{:?}", control.implementation_status),
                    responsible_entities: if control.responsible_entities.is_empty() {
                        None
                    } else {
                        Some(control.responsible_entities.join(", "))
                    },
                    implementation_narrative: control.implementation_narrative.clone(),
                    last_emass_update: now.clone(),
                    last_sync_at: now.clone(),
                };

                if let Err(e) = emass::upsert_control_cache(pool, &cache_entry).await {
                    result.errors.push(format!(
                        "Failed to cache control {}: {}",
                        control.control_acronym, e
                    ));
                } else {
                    result.controls_pulled += 1;
                }
            }
            log::info!("Pulled {} controls from eMASS system {}", controls.len(), system_id);
        }
        Err(e) => {
            let msg = format!("Failed to fetch controls from eMASS: {}", e);
            result.errors.push(msg.clone());
            log::error!("{}", msg);
        }
    }

    // Pull POA&Ms from eMASS
    match client.get_poams(system_id).await {
        Ok(poams) => {
            for poam in &poams {
                let milestones_json = serde_json::to_string(&poam.milestone_changes).ok();

                let cache_entry = EmassPoamCache {
                    id: String::new(),
                    mapping_id: mapping_id.to_string(),
                    emass_poam_id: poam.poam_id.unwrap_or(0),
                    control_acronym: poam.control_acronym.clone(),
                    cci: poam.cci.clone(),
                    weakness_description: poam.weakness_description.clone(),
                    status: format!("{:?}", poam.status),
                    scheduled_completion_date: Some(poam.scheduled_completion_date.to_string()),
                    actual_completion_date: None, // Not directly available in API response
                    milestones: milestones_json,
                    resources: poam.resources_required.clone(),
                    heroforge_finding_id: None,
                    last_emass_update: poam.modified_date
                        .map(|d| d.to_rfc3339())
                        .unwrap_or_else(|| now.clone()),
                    last_sync_at: now.clone(),
                    needs_sync: false,
                    local_changes: None,
                };

                if let Err(e) = emass::upsert_poam_cache(pool, &cache_entry).await {
                    result.errors.push(format!(
                        "Failed to cache POA&M {}: {}",
                        poam.poam_id.unwrap_or(0), e
                    ));
                } else {
                    result.poams_pulled += 1;
                }
            }
            log::info!("Pulled {} POA&Ms from eMASS system {}", poams.len(), system_id);
        }
        Err(e) => {
            let msg = format!("Failed to fetch POA&Ms from eMASS: {}", e);
            result.errors.push(msg.clone());
            log::error!("{}", msg);
        }
    }

    // Update sync history
    let status = if result.errors.is_empty() { "completed" } else { "completed_with_errors" };
    let error_msg = if result.errors.is_empty() {
        None
    } else {
        Some(result.errors.join("; "))
    };

    emass::complete_sync_history(
        pool,
        &history_id,
        status,
        result.controls_pulled as i32,
        0, // poams_created (not applicable for pull)
        result.poams_pulled as i32, // using poams_updated for pulled count
        0, // artifacts_uploaded
        result.errors.len() as i32,
        error_msg.as_deref(),
        None,
    ).await?;

    // Update mapping sync status
    let mapping_status = if result.errors.is_empty() { "success" } else { "failed" };
    emass::update_mapping_sync_status(
        pool,
        mapping_id,
        mapping_status,
        error_msg.as_deref(),
    ).await?;

    Ok(result)
}

/// Full bidirectional sync with database persistence
///
/// This function performs both push and pull sync operations and tracks the
/// sync status in the database.
pub async fn full_bidirectional_sync(
    pool: &SqlitePool,
    client: &EmassClient,
    mapping_id: &str,
    system_id: i64,
    findings: &[ComplianceFinding],
    upload_report: Option<&str>,
    executed_by: &str,
) -> Result<SyncResult> {
    let mut result = SyncResult {
        timestamp: Utc::now(),
        ..Default::default()
    };

    let now = Utc::now().to_rfc3339();

    // Create sync history record
    let sync_history = EmassSyncHistory {
        id: String::new(),
        mapping_id: mapping_id.to_string(),
        sync_type: "full".to_string(),
        direction: "bidirectional".to_string(),
        status: "started".to_string(),
        started_at: now.clone(),
        completed_at: None,
        controls_synced: 0,
        poams_created: 0,
        poams_updated: 0,
        artifacts_uploaded: 0,
        errors: 0,
        error_message: None,
        sync_details: None,
        executed_by: executed_by.to_string(),
    };
    let history_id = emass::create_sync_history(pool, &sync_history).await?;

    // Step 1: Pull current state from eMASS
    log::info!("Starting bidirectional sync - Phase 1: Pull from eMASS");
    let pull_result = pull_from_emass(pool, client, mapping_id, system_id, executed_by).await?;
    result.controls_pulled = pull_result.controls_pulled;
    result.poams_pulled = pull_result.poams_pulled;
    result.errors.extend(pull_result.errors);

    // Step 2: Push updates to eMASS
    log::info!("Starting bidirectional sync - Phase 2: Push to eMASS");
    let push_result = full_sync(client, system_id, findings, upload_report).await?;
    result.controls_updated = push_result.controls_updated;
    result.controls_unchanged = push_result.controls_unchanged;
    result.controls_failed = push_result.controls_failed;
    result.poams_created = push_result.poams_created;
    result.poams_updated = push_result.poams_updated;
    result.poams_closed = push_result.poams_closed;
    result.artifacts_uploaded = push_result.artifacts_uploaded;
    result.errors.extend(push_result.errors);

    // Update sync history
    let status = if result.errors.is_empty() { "completed" } else { "completed_with_errors" };
    let error_msg = if result.errors.is_empty() {
        None
    } else {
        Some(result.errors.join("; "))
    };

    let sync_details = serde_json::json!({
        "controls_pulled": result.controls_pulled,
        "poams_pulled": result.poams_pulled,
        "controls_updated": result.controls_updated,
        "controls_unchanged": result.controls_unchanged,
        "poams_created": result.poams_created,
        "poams_updated": result.poams_updated,
        "poams_closed": result.poams_closed,
    });

    emass::complete_sync_history(
        pool,
        &history_id,
        status,
        (result.controls_pulled + result.controls_updated) as i32,
        result.poams_created as i32,
        (result.poams_pulled + result.poams_updated) as i32,
        result.artifacts_uploaded as i32,
        result.errors.len() as i32,
        error_msg.as_deref(),
        Some(&sync_details.to_string()),
    ).await?;

    // Update mapping sync status
    let mapping_status = if result.errors.is_empty() { "success" } else { "failed" };
    emass::update_mapping_sync_status(
        pool,
        mapping_id,
        mapping_status,
        error_msg.as_deref(),
    ).await?;

    log::info!(
        "Bidirectional sync complete: pulled {}/{} controls/POA&Ms, pushed {}/{} controls/POA&Ms",
        result.controls_pulled, result.poams_pulled,
        result.controls_updated, result.poams_created + result.poams_updated
    );

    Ok(result)
}

/// Get sync status for a system
#[derive(Debug, Clone)]
pub struct SyncStatus {
    pub system_id: i64,
    pub mapping_id: Option<String>,
    pub last_sync: Option<chrono::DateTime<Utc>>,
    pub sync_status: String,
    pub total_controls: usize,
    pub synced_controls: usize,
    pub cached_controls: usize,
    pub open_poams: usize,
    pub overdue_poams: usize,
    pub cached_poams: usize,
    pub needs_attention: bool,
}

/// Check sync status for a system with database tracking
///
/// This function queries both eMASS and the local database to provide
/// a comprehensive sync status including last sync time from the database.
pub async fn check_sync_status(
    pool: &SqlitePool,
    client: &EmassClient,
    mapping_id: &str,
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

    // Query mapping for last_sync_at from database
    let mapping = emass::get_mapping(pool, mapping_id).await?;
    let (last_sync, sync_status) = match &mapping {
        Some(m) => {
            let last_sync = m.last_sync_at
                .as_ref()
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc));
            (last_sync, m.sync_status.clone())
        }
        None => (None, "never".to_string()),
    };

    // Get cached counts from local database
    let cached_controls = emass::get_controls_for_mapping(pool, mapping_id)
        .await
        .map(|c| c.len())
        .unwrap_or(0);

    let cached_poams = emass::get_poams_for_mapping(pool, mapping_id, None)
        .await
        .map(|p| p.len())
        .unwrap_or(0);

    Ok(SyncStatus {
        system_id,
        mapping_id: Some(mapping_id.to_string()),
        last_sync,
        sync_status,
        total_controls: controls.len(),
        synced_controls,
        cached_controls,
        open_poams,
        overdue_poams,
        cached_poams,
        needs_attention: overdue_poams > 0,
    })
}

/// Check sync status without database (legacy function for backward compatibility)
pub async fn check_sync_status_simple(
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
        mapping_id: None,
        last_sync: None,
        sync_status: "unknown".to_string(),
        total_controls: controls.len(),
        synced_controls,
        cached_controls: 0,
        open_poams,
        overdue_poams,
        cached_poams: 0,
        needs_attention: overdue_poams > 0,
    })
}
