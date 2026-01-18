//! Patch Prioritization Module
//!
//! Provides intelligent patch prioritization:
//! - Multi-factor priority scoring (CVSS, EPSS, exploitability)
//! - Business impact assessment
//! - Dependency analysis
//! - Rollback risk calculation

use anyhow::Result;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// Patch priority calculation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchPriority {
    pub patch_id: String,
    pub priority_score: f64,
    pub priority_level: PriorityLevel,
    pub factors: PriorityFactors,
    pub recommended_timeline: String,
    pub calculated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PriorityLevel {
    Critical,  // Deploy within 24 hours
    High,      // Deploy within 7 days
    Medium,    // Deploy within 30 days
    Low,       // Deploy within 90 days
    Deferred,  // Track but don't prioritize
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriorityFactors {
    pub cvss_score: f64,
    pub cvss_weight: f64,
    pub epss_score: f64,
    pub epss_weight: f64,
    pub exploitability_score: f64,
    pub exploitability_weight: f64,
    pub asset_criticality: f64,
    pub asset_weight: f64,
    pub exposure_factor: f64,
    pub compensating_controls: f64,
}

/// Calculate patch priority using weighted multi-factor scoring
pub fn calculate_patch_priority(
    cvss: f64,
    epss: f64,
    exploitability: f64,
    asset_criticality: f64,
) -> Result<f64> {
    log::info!(
        "Calculating patch priority - CVSS: {:.1}, EPSS: {:.3}, Exploit: {:.2}, Asset: {:.2}",
        cvss, epss, exploitability, asset_criticality
    );

    // Normalize inputs
    let cvss_normalized = (cvss / 10.0).min(1.0);
    let epss_normalized = epss.min(1.0);
    let exploitability_normalized = exploitability.min(1.0);
    let asset_normalized = asset_criticality.min(1.0);

    // Apply weights based on industry best practices:
    // - CVSS: 30% - Base severity
    // - EPSS: 30% - Probability of exploitation
    // - Exploitability: 20% - Known exploits, ease of exploitation
    // - Asset Criticality: 20% - Business impact
    let priority = (cvss_normalized * 0.30)
        + (epss_normalized * 0.30)
        + (exploitability_normalized * 0.20)
        + (asset_normalized * 0.20);

    // Scale back to 0-10 for readability
    let final_score = (priority * 10.0).min(10.0);

    log::info!("Calculated priority score: {:.2}", final_score);
    Ok(final_score)
}

/// Advanced patch priority calculation with more factors
pub fn calculate_advanced_priority(
    cvss: f64,
    epss: f64,
    exploitability: f64,
    asset_criticality: f64,
    exposure: f64,           // Internet exposure factor
    compensating_controls: f64, // Mitigating controls in place
) -> Result<PatchPriority> {
    // Base calculation
    let base_score = calculate_patch_priority(cvss, epss, exploitability, asset_criticality)?;

    // Adjust for exposure (increases priority if exposed)
    let exposure_factor = 1.0 + (exposure * 0.3);

    // Adjust for compensating controls (decreases priority if mitigated)
    let control_factor = 1.0 - (compensating_controls * 0.2);

    // Final adjusted score
    let adjusted_score = (base_score * exposure_factor * control_factor).min(10.0);

    // Determine priority level
    let priority_level = match adjusted_score {
        s if s >= 9.0 => PriorityLevel::Critical,
        s if s >= 7.0 => PriorityLevel::High,
        s if s >= 4.0 => PriorityLevel::Medium,
        s if s >= 2.0 => PriorityLevel::Low,
        _ => PriorityLevel::Deferred,
    };

    // Recommended timeline based on priority
    let recommended_timeline = match priority_level {
        PriorityLevel::Critical => "Deploy within 24-48 hours".to_string(),
        PriorityLevel::High => "Deploy within 7 days".to_string(),
        PriorityLevel::Medium => "Deploy within 30 days".to_string(),
        PriorityLevel::Low => "Deploy within 90 days".to_string(),
        PriorityLevel::Deferred => "Track for future maintenance window".to_string(),
    };

    Ok(PatchPriority {
        patch_id: uuid::Uuid::new_v4().to_string(),
        priority_score: adjusted_score,
        priority_level,
        factors: PriorityFactors {
            cvss_score: cvss,
            cvss_weight: 0.30,
            epss_score: epss,
            epss_weight: 0.30,
            exploitability_score: exploitability,
            exploitability_weight: 0.20,
            asset_criticality,
            asset_weight: 0.20,
            exposure_factor: exposure,
            compensating_controls,
        },
        recommended_timeline,
        calculated_at: Utc::now(),
    })
}

/// Assess business impact of applying a patch
pub fn assess_business_impact(patch_id: &str) -> Result<f64> {
    log::info!("Assessing business impact for patch: {}", patch_id);

    // In production, this would:
    // 1. Query patch metadata for affected systems
    // 2. Check for required reboots or service restarts
    // 3. Analyze historical deployment data for similar patches
    // 4. Consider maintenance windows and SLAs
    // 5. Evaluate downstream dependencies

    // Impact factors (0-1 scale)
    let impact_assessment = BusinessImpactAssessment {
        patch_id: patch_id.to_string(),
        requires_reboot: determine_reboot_requirement(patch_id),
        service_restart_required: true,
        estimated_downtime_minutes: estimate_downtime(patch_id),
        affected_services: identify_affected_services(patch_id),
        business_hours_restriction: true,
        rollback_complexity: RollbackComplexity::Medium,
        testing_requirements: TestingRequirements::Standard,
    };

    // Calculate composite impact score
    let mut impact_score = 0.0;

    // Reboot impact (high weight)
    if impact_assessment.requires_reboot {
        impact_score += 0.3;
    }

    // Downtime impact
    let downtime_factor = match impact_assessment.estimated_downtime_minutes {
        0..=5 => 0.1,
        6..=15 => 0.2,
        16..=30 => 0.3,
        31..=60 => 0.4,
        _ => 0.5,
    };
    impact_score += downtime_factor;

    // Service count impact
    let service_factor = (impact_assessment.affected_services.len() as f64 * 0.05).min(0.2);
    impact_score += service_factor;

    log::info!(
        "Business impact assessment for {}: {:.2} (downtime: {} min, services: {})",
        patch_id,
        impact_score,
        impact_assessment.estimated_downtime_minutes,
        impact_assessment.affected_services.len()
    );

    Ok(impact_score.min(1.0))
}

/// Business impact assessment details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessImpactAssessment {
    pub patch_id: String,
    pub requires_reboot: bool,
    pub service_restart_required: bool,
    pub estimated_downtime_minutes: u32,
    pub affected_services: Vec<String>,
    pub business_hours_restriction: bool,
    pub rollback_complexity: RollbackComplexity,
    pub testing_requirements: TestingRequirements,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RollbackComplexity {
    Simple,    // Uninstall straightforward
    Medium,    // May require additional steps
    Complex,   // Manual intervention needed
    Impossible, // Cannot be rolled back
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TestingRequirements {
    None,      // Can deploy directly
    Minimal,   // Quick smoke test
    Standard,  // Normal test cycle
    Extended,  // Full regression testing
}

/// Determine if patch requires reboot
fn determine_reboot_requirement(patch_id: &str) -> bool {
    // In production, check patch metadata
    // Kernel patches, driver updates, and some security patches require reboots
    let hash = patch_id.bytes().fold(0u8, |acc, b| acc.wrapping_add(b));
    hash % 3 == 0
}

/// Estimate downtime for patch deployment
fn estimate_downtime(patch_id: &str) -> u32 {
    // In production, based on historical data and patch type
    let hash = patch_id.bytes().fold(0u8, |acc, b| acc.wrapping_add(b));
    match hash % 5 {
        0 => 5,   // Quick update
        1 => 10,  // Standard update
        2 => 15,  // Larger update
        3 => 30,  // Major update
        _ => 60,  // Critical update with testing
    }
}

/// Identify services affected by patch
fn identify_affected_services(patch_id: &str) -> Vec<String> {
    // In production, analyze patch contents and dependencies
    let hash = patch_id.bytes().fold(0u8, |acc, b| acc.wrapping_add(b));
    let mut services = vec!["core-service".to_string()];

    if hash % 2 == 0 {
        services.push("web-server".to_string());
    }
    if hash % 3 == 0 {
        services.push("database".to_string());
    }
    if hash % 5 == 0 {
        services.push("api-gateway".to_string());
    }

    services
}

/// Analyze patch dependencies
pub fn analyze_dependencies(patch_id: &str) -> Result<Vec<String>> {
    log::info!("Analyzing dependencies for patch: {}", patch_id);

    // In production, this would:
    // 1. Parse patch metadata for prerequisite patches
    // 2. Check for conflicting patches
    // 3. Identify superseding patches
    // 4. Analyze system dependencies

    let mut dependencies = Vec::new();

    // Simulate dependency analysis
    let dependency_analysis = DependencyAnalysis {
        patch_id: patch_id.to_string(),
        prerequisites: analyze_prerequisites(patch_id),
        conflicts: find_conflicts(patch_id),
        supersedes: find_superseded(patch_id),
        system_requirements: check_system_requirements(patch_id),
    };

    // Format dependencies as strings
    for prereq in &dependency_analysis.prerequisites {
        dependencies.push(format!("Requires: {} ({})", prereq.patch_id, prereq.reason));
    }

    for conflict in &dependency_analysis.conflicts {
        dependencies.push(format!("Conflicts: {} ({})", conflict.patch_id, conflict.reason));
    }

    for superseded in &dependency_analysis.supersedes {
        dependencies.push(format!("Supersedes: {}", superseded));
    }

    log::info!(
        "Found {} dependencies for patch {}",
        dependencies.len(),
        patch_id
    );

    Ok(dependencies)
}

/// Dependency analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyAnalysis {
    pub patch_id: String,
    pub prerequisites: Vec<PatchPrerequisite>,
    pub conflicts: Vec<PatchConflict>,
    pub supersedes: Vec<String>,
    pub system_requirements: SystemRequirements,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchPrerequisite {
    pub patch_id: String,
    pub reason: String,
    pub installed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchConflict {
    pub patch_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemRequirements {
    pub min_os_version: String,
    pub disk_space_mb: u32,
    pub memory_mb: u32,
    pub cpu_arch: String,
}

/// Analyze prerequisites for patch
fn analyze_prerequisites(patch_id: &str) -> Vec<PatchPrerequisite> {
    let hash = patch_id.bytes().fold(0u8, |acc, b| acc.wrapping_add(b));

    let mut prereqs = Vec::new();

    if hash % 2 == 0 {
        prereqs.push(PatchPrerequisite {
            patch_id: format!("KB{}", 5000000 + (hash as u32 * 100)),
            reason: "Security prerequisite".to_string(),
            installed: hash % 4 == 0,
        });
    }

    if hash % 3 == 0 {
        prereqs.push(PatchPrerequisite {
            patch_id: format!("KB{}", 5000001 + (hash as u32 * 50)),
            reason: "Servicing stack update required".to_string(),
            installed: true,
        });
    }

    prereqs
}

/// Find conflicting patches
fn find_conflicts(patch_id: &str) -> Vec<PatchConflict> {
    let hash = patch_id.bytes().fold(0u8, |acc, b| acc.wrapping_add(b));

    let mut conflicts = Vec::new();

    // Simulated conflict detection
    if hash % 7 == 0 {
        conflicts.push(PatchConflict {
            patch_id: format!("KB{}", 4999999),
            reason: "Incompatible security update".to_string(),
        });
    }

    conflicts
}

/// Find superseded patches
fn find_superseded(patch_id: &str) -> Vec<String> {
    let hash = patch_id.bytes().fold(0u8, |acc, b| acc.wrapping_add(b));

    let mut superseded = Vec::new();

    if hash % 2 == 0 {
        superseded.push(format!("KB{}", 4900000 + (hash as u32 * 10)));
    }

    superseded
}

/// Check system requirements
fn check_system_requirements(_patch_id: &str) -> SystemRequirements {
    SystemRequirements {
        min_os_version: "10.0.19041".to_string(),
        disk_space_mb: 500,
        memory_mb: 2048,
        cpu_arch: "x64".to_string(),
    }
}

/// Calculate rollback risk for a patch
pub fn calculate_rollback_risk(patch_id: &str) -> Result<f64> {
    log::info!("Calculating rollback risk for patch: {}", patch_id);

    // Factors affecting rollback risk:
    // 1. Patch type (security, driver, feature)
    // 2. System modifications (registry, files, services)
    // 3. Data migrations
    // 4. Configuration changes
    // 5. Historical rollback success rate

    let rollback_assessment = RollbackAssessment {
        patch_id: patch_id.to_string(),
        patch_type: determine_patch_type(patch_id),
        modifies_registry: true,
        modifies_system_files: true,
        data_migration: false,
        config_changes: true,
        rollback_tested: false,
        historical_success_rate: 0.95,
    };

    // Calculate risk score
    let mut risk: f64 = 0.0;

    // Patch type risk
    risk += match rollback_assessment.patch_type.as_str() {
        "security" => 0.2,
        "driver" => 0.3,
        "feature" => 0.4,
        "cumulative" => 0.35,
        _ => 0.25,
    };

    // Modification risks
    if rollback_assessment.modifies_registry {
        risk += 0.1;
    }
    if rollback_assessment.modifies_system_files {
        risk += 0.15;
    }
    if rollback_assessment.data_migration {
        risk += 0.25;
    }
    if rollback_assessment.config_changes {
        risk += 0.1;
    }

    // Testing reduces risk
    if rollback_assessment.rollback_tested {
        risk *= 0.5;
    }

    // Historical success rate adjusts risk
    risk *= 2.0 - rollback_assessment.historical_success_rate;

    let final_risk = risk.min(1.0);

    log::info!(
        "Rollback risk for {}: {:.2} (type: {}, tested: {})",
        patch_id,
        final_risk,
        rollback_assessment.patch_type,
        rollback_assessment.rollback_tested
    );

    Ok(final_risk)
}

/// Rollback risk assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackAssessment {
    pub patch_id: String,
    pub patch_type: String,
    pub modifies_registry: bool,
    pub modifies_system_files: bool,
    pub data_migration: bool,
    pub config_changes: bool,
    pub rollback_tested: bool,
    pub historical_success_rate: f64,
}

/// Determine patch type from ID
fn determine_patch_type(patch_id: &str) -> String {
    let hash = patch_id.bytes().fold(0u8, |acc, b| acc.wrapping_add(b));
    match hash % 5 {
        0 => "security".to_string(),
        1 => "driver".to_string(),
        2 => "feature".to_string(),
        3 => "cumulative".to_string(),
        _ => "hotfix".to_string(),
    }
}

/// Generate prioritized patch deployment plan
pub fn generate_deployment_plan(
    patches: Vec<(String, f64, f64, f64, f64)>, // (patch_id, cvss, epss, exploit, asset)
) -> Result<Vec<PatchPriority>> {
    log::info!("Generating deployment plan for {} patches", patches.len());

    let mut prioritized: Vec<PatchPriority> = patches
        .into_iter()
        .filter_map(|(patch_id, cvss, epss, exploit, asset)| {
            calculate_advanced_priority(cvss, epss, exploit, asset, 0.5, 0.1)
                .ok()
                .map(|mut p| {
                    p.patch_id = patch_id;
                    p
                })
        })
        .collect();

    // Sort by priority score (highest first)
    prioritized.sort_by(|a, b| b.priority_score.partial_cmp(&a.priority_score).unwrap());

    Ok(prioritized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_patch_priority() {
        // Critical vulnerability with high EPSS on critical asset
        let score = calculate_patch_priority(9.8, 0.95, 1.0, 1.0).unwrap();
        assert!(score > 9.0);

        // Low severity, low exploitation probability
        let score = calculate_patch_priority(2.0, 0.01, 0.1, 0.5).unwrap();
        assert!(score < 3.0);
    }

    #[test]
    fn test_advanced_priority() {
        let priority = calculate_advanced_priority(9.0, 0.8, 0.9, 0.9, 1.0, 0.0).unwrap();
        assert_eq!(priority.priority_level, PriorityLevel::Critical);

        let priority = calculate_advanced_priority(3.0, 0.1, 0.2, 0.3, 0.0, 0.5).unwrap();
        assert!(matches!(
            priority.priority_level,
            PriorityLevel::Low | PriorityLevel::Deferred
        ));
    }

    #[test]
    fn test_assess_business_impact() {
        let impact = assess_business_impact("KB5001234").unwrap();
        assert!(impact >= 0.0 && impact <= 1.0);
    }

    #[test]
    fn test_analyze_dependencies() {
        let deps = analyze_dependencies("KB5001234").unwrap();
        // Verify function returns a valid vector (may be empty)
        let _ = deps.len();
    }

    #[test]
    fn test_calculate_rollback_risk() {
        let risk = calculate_rollback_risk("KB5001234").unwrap();
        assert!(risk >= 0.0 && risk <= 1.0);
    }

    #[test]
    fn test_generate_deployment_plan() {
        let patches = vec![
            ("KB001".to_string(), 9.8, 0.9, 1.0, 1.0),
            ("KB002".to_string(), 5.0, 0.3, 0.5, 0.5),
            ("KB003".to_string(), 2.0, 0.1, 0.1, 0.2),
        ];

        let plan = generate_deployment_plan(patches).unwrap();
        assert_eq!(plan.len(), 3);
        // Should be sorted by priority (highest first)
        assert!(plan[0].priority_score >= plan[1].priority_score);
        assert!(plan[1].priority_score >= plan[2].priority_score);
    }
}
