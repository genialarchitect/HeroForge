//! eMASS Control Operations
//!
//! Control status management and compliance tracking.

use anyhow::Result;
use std::collections::HashMap;

use super::client::EmassClient;
use super::types::*;

/// Get all controls for a system
pub async fn list_controls(client: &EmassClient, system_id: i64) -> Result<Vec<EmassControl>> {
    client.get_controls(system_id).await
}

/// Get controls filtered by compliance status
pub async fn get_controls_by_status(
    client: &EmassClient,
    system_id: i64,
    status: ControlComplianceStatus,
) -> Result<Vec<EmassControl>> {
    let controls = client.get_controls(system_id).await?;
    Ok(controls
        .into_iter()
        .filter(|c| c.compliance_status == status)
        .collect())
}

/// Get controls filtered by implementation status
pub async fn get_controls_by_implementation(
    client: &EmassClient,
    system_id: i64,
    status: ImplementationStatus,
) -> Result<Vec<EmassControl>> {
    let controls = client.get_controls(system_id).await?;
    Ok(controls
        .into_iter()
        .filter(|c| c.implementation_status == status)
        .collect())
}

/// Get controls by control family (e.g., "AC", "AU", "SI")
pub async fn get_controls_by_family(
    client: &EmassClient,
    system_id: i64,
    family: &str,
) -> Result<Vec<EmassControl>> {
    let controls = client.get_controls(system_id).await?;
    Ok(controls
        .into_iter()
        .filter(|c| c.control_acronym.starts_with(family))
        .collect())
}

/// Update control compliance status
pub async fn update_control_status(
    client: &EmassClient,
    system_id: i64,
    control: &EmassControl,
) -> Result<EmassControl> {
    client.update_control(system_id, control).await
}

/// Batch update multiple controls
pub async fn update_controls_batch(
    client: &EmassClient,
    system_id: i64,
    controls: &[EmassControl],
) -> Result<Vec<EmassControl>> {
    let mut results = Vec::with_capacity(controls.len());

    for control in controls {
        let updated = client.update_control(system_id, control).await?;
        results.push(updated);
    }

    Ok(results)
}

/// Control compliance summary
#[derive(Debug, Clone, Default)]
pub struct ControlSummary {
    pub total_controls: usize,
    pub compliant: usize,
    pub non_compliant: usize,
    pub not_applicable: usize,
    pub other: usize,
    pub implemented: usize,
    pub partially_implemented: usize,
    pub planned_not_implemented: usize,
    pub not_provided: usize,
    pub compliance_percentage: f64,
    pub by_family: HashMap<String, FamilySummary>,
}

/// Control family summary
#[derive(Debug, Clone, Default)]
pub struct FamilySummary {
    pub total: usize,
    pub compliant: usize,
    pub non_compliant: usize,
}

/// Get control compliance summary for a system
pub async fn get_control_summary(
    client: &EmassClient,
    system_id: i64,
) -> Result<ControlSummary> {
    let controls = client.get_controls(system_id).await?;

    let mut summary = ControlSummary {
        total_controls: controls.len(),
        ..Default::default()
    };

    for control in &controls {
        // Count by compliance status
        match control.compliance_status {
            ControlComplianceStatus::Compliant => summary.compliant += 1,
            ControlComplianceStatus::NonCompliant => summary.non_compliant += 1,
            ControlComplianceStatus::NotApplicable => summary.not_applicable += 1,
            ControlComplianceStatus::Other => summary.other += 1,
        }

        // Count by implementation status
        match control.implementation_status {
            ImplementationStatus::Implemented => summary.implemented += 1,
            ImplementationStatus::PartiallyImplemented => summary.partially_implemented += 1,
            ImplementationStatus::PlannedNotImplemented => summary.planned_not_implemented += 1,
            ImplementationStatus::NotApplicable => {} // Already counted above
            ImplementationStatus::NotProvided => summary.not_provided += 1,
        }

        // Group by family
        let family = extract_family(&control.control_acronym);
        let family_summary = summary.by_family.entry(family).or_default();
        family_summary.total += 1;
        match control.compliance_status {
            ControlComplianceStatus::Compliant => family_summary.compliant += 1,
            ControlComplianceStatus::NonCompliant => family_summary.non_compliant += 1,
            _ => {}
        }
    }

    // Calculate compliance percentage (excluding N/A)
    let applicable = summary.compliant + summary.non_compliant + summary.other;
    if applicable > 0 {
        summary.compliance_percentage = (summary.compliant as f64 / applicable as f64) * 100.0;
    }

    Ok(summary)
}

/// Extract control family from control acronym (e.g., "AC-1" -> "AC")
fn extract_family(control_acronym: &str) -> String {
    control_acronym
        .split('-')
        .next()
        .unwrap_or(control_acronym)
        .to_string()
}

/// NIST 800-53 control families
pub const CONTROL_FAMILIES: &[(&str, &str)] = &[
    ("AC", "Access Control"),
    ("AT", "Awareness and Training"),
    ("AU", "Audit and Accountability"),
    ("CA", "Assessment, Authorization, and Monitoring"),
    ("CM", "Configuration Management"),
    ("CP", "Contingency Planning"),
    ("IA", "Identification and Authentication"),
    ("IR", "Incident Response"),
    ("MA", "Maintenance"),
    ("MP", "Media Protection"),
    ("PE", "Physical and Environmental Protection"),
    ("PL", "Planning"),
    ("PM", "Program Management"),
    ("PS", "Personnel Security"),
    ("PT", "PII Processing and Transparency"),
    ("RA", "Risk Assessment"),
    ("SA", "System and Services Acquisition"),
    ("SC", "System and Communications Protection"),
    ("SI", "System and Information Integrity"),
    ("SR", "Supply Chain Risk Management"),
];

/// Get control family name
pub fn get_family_name(family_code: &str) -> Option<&'static str> {
    CONTROL_FAMILIES
        .iter()
        .find(|(code, _)| *code == family_code)
        .map(|(_, name)| *name)
}

/// Map HeroForge compliance finding to eMASS control status
pub fn map_finding_to_control_status(
    finding_passed: bool,
    is_applicable: bool,
) -> ControlComplianceStatus {
    if !is_applicable {
        ControlComplianceStatus::NotApplicable
    } else if finding_passed {
        ControlComplianceStatus::Compliant
    } else {
        ControlComplianceStatus::NonCompliant
    }
}

/// Map HeroForge finding to eMASS implementation status
pub fn map_finding_to_implementation_status(
    finding_passed: bool,
    has_partial_implementation: bool,
    is_applicable: bool,
) -> ImplementationStatus {
    if !is_applicable {
        ImplementationStatus::NotApplicable
    } else if finding_passed {
        ImplementationStatus::Implemented
    } else if has_partial_implementation {
        ImplementationStatus::PartiallyImplemented
    } else {
        ImplementationStatus::PlannedNotImplemented
    }
}
