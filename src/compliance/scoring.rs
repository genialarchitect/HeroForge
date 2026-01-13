//! Compliance Scoring Module
//!
//! Calculates compliance scores based on control status and severity weights.

use crate::compliance::types::{
    ComplianceFinding, ComplianceFramework, ComplianceSummary, ControlStatus,
    ControlPriority, FrameworkSummary,
};
use crate::compliance::frameworks;
use crate::types::Severity;

/// Weight factors for control priorities
const PRIORITY_WEIGHT_CRITICAL: f32 = 2.0;
const PRIORITY_WEIGHT_HIGH: f32 = 1.5;
const PRIORITY_WEIGHT_MEDIUM: f32 = 1.0;
const PRIORITY_WEIGHT_LOW: f32 = 0.5;

/// Penalty factors for non-compliance severity
const SEVERITY_PENALTY_CRITICAL: f32 = 1.0;
const SEVERITY_PENALTY_HIGH: f32 = 0.8;
const SEVERITY_PENALTY_MEDIUM: f32 = 0.5;
const SEVERITY_PENALTY_LOW: f32 = 0.25;

/// Calculate the overall compliance score for a scan
pub fn calculate_compliance_score(summary: &ComplianceSummary) -> f32 {
    if summary.frameworks.is_empty() {
        return 100.0;
    }

    let mut total_weighted_score = 0.0;
    let mut total_weight = 0.0;

    for framework in &summary.frameworks {
        let weight = framework.total_controls as f32;
        total_weighted_score += framework.compliance_score * weight;
        total_weight += weight;
    }

    if total_weight > 0.0 {
        total_weighted_score / total_weight
    } else {
        100.0
    }
}

/// Calculate framework-specific compliance score with severity weighting
pub fn calculate_weighted_framework_score(
    framework: ComplianceFramework,
    findings: &[ComplianceFinding],
) -> f32 {
    let controls = frameworks::get_controls(framework);
    if controls.is_empty() {
        return 100.0;
    }

    let framework_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.framework == framework)
        .collect();

    let mut total_weight = 0.0;
    let mut achieved_score = 0.0;

    for control in &controls {
        let priority_weight = match control.priority {
            ControlPriority::Critical => PRIORITY_WEIGHT_CRITICAL,
            ControlPriority::High => PRIORITY_WEIGHT_HIGH,
            ControlPriority::Medium => PRIORITY_WEIGHT_MEDIUM,
            ControlPriority::Low => PRIORITY_WEIGHT_LOW,
        };

        total_weight += priority_weight;

        // Find finding for this control
        let finding = framework_findings
            .iter()
            .find(|f| f.control_id == control.control_id);

        match finding {
            Some(f) => {
                let status_score = match f.status {
                    ControlStatus::Compliant => 1.0,
                    ControlStatus::PartiallyCompliant => 0.5,
                    ControlStatus::ManualOverride => 1.0, // Treat as compliant if manually overridden
                    ControlStatus::NotApplicable => {
                        // Don't count N/A controls
                        total_weight -= priority_weight;
                        continue;
                    }
                    ControlStatus::NotAssessed => {
                        if !control.automated_check {
                            // Don't penalize manual controls
                            total_weight -= priority_weight;
                            continue;
                        }
                        0.0
                    }
                    ControlStatus::NonCompliant => {
                        // Apply severity penalty
                        let penalty = match f.severity {
                            Severity::Critical => SEVERITY_PENALTY_CRITICAL,
                            Severity::High => SEVERITY_PENALTY_HIGH,
                            Severity::Medium => SEVERITY_PENALTY_MEDIUM,
                            Severity::Low => SEVERITY_PENALTY_LOW,
                        };
                        -penalty // Negative score for non-compliance
                    }
                };
                achieved_score += priority_weight * status_score.max(0.0);
            }
            None => {
                // No finding = assume compliant for automated checks
                if control.automated_check {
                    achieved_score += priority_weight;
                } else {
                    // Manual control not assessed
                    total_weight -= priority_weight;
                }
            }
        }
    }

    if total_weight > 0.0 {
        (achieved_score / total_weight * 100.0).clamp(0.0, 100.0)
    } else {
        100.0
    }
}

/// Calculate risk-adjusted compliance score
/// Higher risk findings have more impact on the score
pub fn calculate_risk_adjusted_score(summary: &ComplianceSummary) -> f32 {
    let base_score = calculate_compliance_score(summary);

    // Apply penalties for critical/high findings
    let critical_penalty = summary.critical_findings as f32 * 5.0;
    let high_penalty = summary.high_findings as f32 * 2.0;
    let medium_penalty = summary.medium_findings as f32 * 0.5;

    let total_penalty = critical_penalty + high_penalty + medium_penalty;

    (base_score - total_penalty).clamp(0.0, 100.0)
}

/// Get compliance grade based on score
pub fn get_compliance_grade(score: f32) -> ComplianceGrade {
    match score as u32 {
        90..=100 => ComplianceGrade::A,
        80..=89 => ComplianceGrade::B,
        70..=79 => ComplianceGrade::C,
        60..=69 => ComplianceGrade::D,
        _ => ComplianceGrade::F,
    }
}

/// Compliance grade
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComplianceGrade {
    A,
    B,
    C,
    D,
    F,
}

impl ComplianceGrade {
    /// Get grade label
    pub fn label(&self) -> &'static str {
        match self {
            ComplianceGrade::A => "Excellent",
            ComplianceGrade::B => "Good",
            ComplianceGrade::C => "Fair",
            ComplianceGrade::D => "Poor",
            ComplianceGrade::F => "Critical",
        }
    }

    /// Get grade color (for UI)
    pub fn color(&self) -> &'static str {
        match self {
            ComplianceGrade::A => "green",
            ComplianceGrade::B => "lime",
            ComplianceGrade::C => "yellow",
            ComplianceGrade::D => "orange",
            ComplianceGrade::F => "red",
        }
    }
}

impl std::fmt::Display for ComplianceGrade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let grade = match self {
            ComplianceGrade::A => "A",
            ComplianceGrade::B => "B",
            ComplianceGrade::C => "C",
            ComplianceGrade::D => "D",
            ComplianceGrade::F => "F",
        };
        write!(f, "{}", grade)
    }
}

/// Calculate maturity score based on control coverage
pub fn calculate_maturity_score(framework_summary: &FrameworkSummary) -> MaturityLevel {
    let total = framework_summary.total_controls;
    if total == 0 {
        return MaturityLevel::Initial;
    }

    let assessed = total - framework_summary.not_assessed;
    let coverage = assessed as f32 / total as f32 * 100.0;
    let compliance = framework_summary.compliance_score;

    match (coverage as u32, compliance as u32) {
        (90..=100, 90..=100) => MaturityLevel::Optimizing,
        (80..=100, 70..=100) => MaturityLevel::Managed,
        (60..=100, 50..=100) => MaturityLevel::Defined,
        (40..=100, 30..=100) => MaturityLevel::Developing,
        _ => MaturityLevel::Initial,
    }
}

/// Security maturity level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaturityLevel {
    /// Level 1: Ad-hoc security practices
    Initial,
    /// Level 2: Basic security awareness
    Developing,
    /// Level 3: Documented processes
    Defined,
    /// Level 4: Measured and controlled
    Managed,
    /// Level 5: Continuous improvement
    Optimizing,
}

impl MaturityLevel {
    /// Get numeric level (1-5)
    pub fn level(&self) -> u8 {
        match self {
            MaturityLevel::Initial => 1,
            MaturityLevel::Developing => 2,
            MaturityLevel::Defined => 3,
            MaturityLevel::Managed => 4,
            MaturityLevel::Optimizing => 5,
        }
    }

    /// Get level description
    pub fn description(&self) -> &'static str {
        match self {
            MaturityLevel::Initial => "Ad-hoc security practices, reactive approach",
            MaturityLevel::Developing => "Basic security awareness, some documented processes",
            MaturityLevel::Defined => "Standardized processes, proactive security measures",
            MaturityLevel::Managed => "Measured controls, quantitative management",
            MaturityLevel::Optimizing => "Continuous improvement, adaptive security",
        }
    }
}

impl std::fmt::Display for MaturityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            MaturityLevel::Initial => "Initial",
            MaturityLevel::Developing => "Developing",
            MaturityLevel::Defined => "Defined",
            MaturityLevel::Managed => "Managed",
            MaturityLevel::Optimizing => "Optimizing",
        };
        write!(f, "{}", name)
    }
}

/// Summary of compliance metrics for reporting
#[derive(Debug, Clone)]
pub struct ComplianceMetrics {
    /// Overall compliance score (0-100)
    pub overall_score: f32,
    /// Risk-adjusted score (0-100)
    pub risk_adjusted_score: f32,
    /// Letter grade
    pub grade: ComplianceGrade,
    /// Number of frameworks assessed
    pub frameworks_assessed: usize,
    /// Total controls assessed
    pub total_controls: usize,
    /// Controls compliant
    pub compliant_controls: usize,
    /// Controls non-compliant
    pub non_compliant_controls: usize,
    /// High priority issues
    pub high_priority_issues: usize,
}

impl ComplianceMetrics {
    /// Calculate metrics from summary
    pub fn from_summary(summary: &ComplianceSummary) -> Self {
        let overall_score = calculate_compliance_score(summary);
        let risk_adjusted_score = calculate_risk_adjusted_score(summary);
        let grade = get_compliance_grade(overall_score);

        let total_controls: usize = summary
            .frameworks
            .iter()
            .map(|f| f.total_controls)
            .sum();
        let compliant_controls: usize = summary
            .frameworks
            .iter()
            .map(|f| f.compliant)
            .sum();
        let non_compliant_controls: usize = summary
            .frameworks
            .iter()
            .map(|f| f.non_compliant)
            .sum();

        ComplianceMetrics {
            overall_score,
            risk_adjusted_score,
            grade,
            frameworks_assessed: summary.frameworks.len(),
            total_controls,
            compliant_controls,
            non_compliant_controls,
            high_priority_issues: summary.critical_findings + summary.high_findings,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compliance_grade() {
        assert_eq!(get_compliance_grade(95.0), ComplianceGrade::A);
        assert_eq!(get_compliance_grade(85.0), ComplianceGrade::B);
        assert_eq!(get_compliance_grade(75.0), ComplianceGrade::C);
        assert_eq!(get_compliance_grade(65.0), ComplianceGrade::D);
        assert_eq!(get_compliance_grade(45.0), ComplianceGrade::F);
    }

    #[test]
    fn test_maturity_level() {
        assert_eq!(MaturityLevel::Initial.level(), 1);
        assert_eq!(MaturityLevel::Optimizing.level(), 5);
    }

    #[test]
    fn test_grade_display() {
        assert_eq!(format!("{}", ComplianceGrade::A), "A");
        assert_eq!(ComplianceGrade::A.label(), "Excellent");
    }
}
