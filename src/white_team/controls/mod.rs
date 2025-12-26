// Control Framework Module
//
// Provides comprehensive security control management:
// - Control library management
// - Framework mapping (NIST, CIS, ISO, PCI, etc.)
// - Control testing and effectiveness tracking
// - Framework crosswalk

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::types::{
    AutomationStatus, ComplianceFramework, Control, ControlCategory, ControlTest, ControlType,
    Effectiveness, FrameworkMapping, ImplementationStatus, TestResult, TestType,
};

/// Control framework management engine
pub struct ControlManager {
    controls: HashMap<String, Control>,
    tests: HashMap<String, Vec<ControlTest>>,
    control_counter: u32,
}

impl ControlManager {
    pub fn new() -> Self {
        Self {
            controls: HashMap::new(),
            tests: HashMap::new(),
            control_counter: 0,
        }
    }

    /// Create a new control
    pub fn create_control(
        &mut self,
        title: String,
        description: String,
        category: ControlCategory,
        control_type: ControlType,
        domain: String,
        owner_id: Option<String>,
    ) -> Control {
        self.control_counter += 1;
        let id = uuid::Uuid::new_v4().to_string();
        let control_id = format!("CTRL-{}-{:03}", domain.to_uppercase().chars().take(3).collect::<String>(), self.control_counter);
        let now = Utc::now();

        let control = Control {
            id: id.clone(),
            control_id,
            title,
            description,
            category,
            control_type,
            domain,
            owner_id,
            implementation_status: ImplementationStatus::NotImplemented,
            effectiveness: None,
            testing_frequency: None,
            last_tested_at: None,
            next_test_date: None,
            evidence_requirements: Vec::new(),
            automation_status: AutomationStatus::Manual,
            framework_mappings: Vec::new(),
            created_at: now,
            updated_at: now,
        };

        self.controls.insert(id, control.clone());
        control
    }

    /// Update control implementation status
    pub fn update_implementation_status(
        &mut self,
        control_id: &str,
        status: ImplementationStatus,
    ) -> Result<(), ControlError> {
        let control = self.controls.get_mut(control_id).ok_or(ControlError::NotFound)?;
        control.implementation_status = status;
        control.updated_at = Utc::now();
        Ok(())
    }

    /// Add framework mapping to a control
    pub fn add_framework_mapping(
        &mut self,
        control_id: &str,
        framework: ComplianceFramework,
        framework_control_id: String,
        framework_control_name: Option<String>,
        mapping_notes: Option<String>,
    ) -> Result<FrameworkMapping, ControlError> {
        let control = self.controls.get_mut(control_id).ok_or(ControlError::NotFound)?;

        let mapping = FrameworkMapping {
            framework,
            control_id: framework_control_id,
            control_name: framework_control_name,
            mapping_notes,
        };

        // Check for duplicate mapping
        if control.framework_mappings.iter().any(|m|
            m.framework == mapping.framework && m.control_id == mapping.control_id
        ) {
            return Err(ControlError::DuplicateMapping);
        }

        control.framework_mappings.push(mapping.clone());
        control.updated_at = Utc::now();

        Ok(mapping)
    }

    /// Remove framework mapping
    pub fn remove_framework_mapping(
        &mut self,
        control_id: &str,
        framework: &ComplianceFramework,
        framework_control_id: &str,
    ) -> Result<(), ControlError> {
        let control = self.controls.get_mut(control_id).ok_or(ControlError::NotFound)?;

        control.framework_mappings.retain(|m|
            !(&m.framework == framework && m.control_id == framework_control_id)
        );
        control.updated_at = Utc::now();

        Ok(())
    }

    /// Record a control test
    pub fn record_test(
        &mut self,
        control_id: &str,
        tester_id: String,
        test_type: TestType,
        test_procedure: String,
        result: TestResult,
        findings: Option<String>,
        sample_size: Option<u32>,
        evidence_refs: Vec<String>,
    ) -> Result<ControlTest, ControlError> {
        let control = self.controls.get_mut(control_id).ok_or(ControlError::NotFound)?;

        let now = Utc::now();
        let test = ControlTest {
            id: uuid::Uuid::new_v4().to_string(),
            control_id: control_id.to_string(),
            test_date: now.date_naive(),
            tester_id,
            test_type,
            test_procedure,
            sample_size,
            result: result.clone(),
            findings: findings.clone(),
            evidence_refs,
            remediation_required: result == TestResult::Fail || result == TestResult::Partial,
            created_at: now,
        };

        // Update control effectiveness based on test result
        control.effectiveness = Some(match result {
            TestResult::Pass => Effectiveness::Effective,
            TestResult::Partial => Effectiveness::PartiallyEffective,
            TestResult::Fail => Effectiveness::Ineffective,
            TestResult::NotApplicable => Effectiveness::NotTested,
        });
        control.last_tested_at = Some(now);
        control.updated_at = now;

        // Calculate next test date based on frequency
        if let Some(frequency) = &control.testing_frequency {
            let months = match frequency.as_str() {
                "monthly" => 1,
                "quarterly" => 3,
                "semi-annual" => 6,
                "annual" | "annually" => 12,
                _ => 12, // Default to annual
            };
            control.next_test_date = Some(
                now.date_naive() + chrono::Duration::days(months * 30)
            );
        }

        self.tests
            .entry(control_id.to_string())
            .or_default()
            .push(test.clone());

        Ok(test)
    }

    /// Set testing frequency
    pub fn set_testing_frequency(
        &mut self,
        control_id: &str,
        frequency: String,
    ) -> Result<(), ControlError> {
        let control = self.controls.get_mut(control_id).ok_or(ControlError::NotFound)?;
        control.testing_frequency = Some(frequency);
        control.updated_at = Utc::now();
        Ok(())
    }

    /// Set evidence requirements
    pub fn set_evidence_requirements(
        &mut self,
        control_id: &str,
        requirements: Vec<String>,
    ) -> Result<(), ControlError> {
        let control = self.controls.get_mut(control_id).ok_or(ControlError::NotFound)?;
        control.evidence_requirements = requirements;
        control.updated_at = Utc::now();
        Ok(())
    }

    /// Update automation status
    pub fn update_automation_status(
        &mut self,
        control_id: &str,
        status: AutomationStatus,
    ) -> Result<(), ControlError> {
        let control = self.controls.get_mut(control_id).ok_or(ControlError::NotFound)?;
        control.automation_status = status;
        control.updated_at = Utc::now();
        Ok(())
    }

    /// Get control by ID
    pub fn get_control(&self, control_id: &str) -> Option<&Control> {
        self.controls.get(control_id)
    }

    /// List all controls
    pub fn list_controls(
        &self,
        domain: Option<&str>,
        category: Option<ControlCategory>,
        implementation_status: Option<ImplementationStatus>,
    ) -> Vec<&Control> {
        self.controls
            .values()
            .filter(|c| {
                domain.map_or(true, |d| c.domain == d)
                    && category.as_ref().map_or(true, |cat| &c.category == cat)
                    && implementation_status.as_ref().map_or(true, |s| &c.implementation_status == s)
            })
            .collect()
    }

    /// Get controls by framework
    pub fn get_controls_by_framework(&self, framework: &ComplianceFramework) -> Vec<&Control> {
        self.controls
            .values()
            .filter(|c| c.framework_mappings.iter().any(|m| &m.framework == framework))
            .collect()
    }

    /// Get test history for a control
    pub fn get_test_history(&self, control_id: &str) -> Vec<&ControlTest> {
        self.tests
            .get(control_id)
            .map(|t| t.iter().collect())
            .unwrap_or_default()
    }

    /// Get controls due for testing
    pub fn get_controls_due_testing(&self) -> Vec<&Control> {
        let today = Utc::now().date_naive();
        self.controls
            .values()
            .filter(|c| c.next_test_date.map_or(false, |d| d <= today))
            .collect()
    }

    /// Generate framework crosswalk
    pub fn generate_crosswalk(
        &self,
        source_framework: &ComplianceFramework,
        target_framework: &ComplianceFramework,
    ) -> FrameworkCrosswalk {
        let mut mappings: Vec<CrosswalkMapping> = Vec::new();

        for control in self.controls.values() {
            let source_mappings: Vec<_> = control.framework_mappings
                .iter()
                .filter(|m| &m.framework == source_framework)
                .collect();

            let target_mappings: Vec<_> = control.framework_mappings
                .iter()
                .filter(|m| &m.framework == target_framework)
                .collect();

            for source in &source_mappings {
                for target in &target_mappings {
                    mappings.push(CrosswalkMapping {
                        source_control_id: source.control_id.clone(),
                        source_control_name: source.control_name.clone(),
                        target_control_id: target.control_id.clone(),
                        target_control_name: target.control_name.clone(),
                        internal_control_id: control.control_id.clone(),
                    });
                }
            }
        }

        FrameworkCrosswalk {
            source_framework: source_framework.clone(),
            target_framework: target_framework.clone(),
            mappings,
        }
    }

    /// Get gap analysis for a framework
    pub fn gap_analysis(&self, framework: &ComplianceFramework) -> GapAnalysis {
        let controls = self.get_controls_by_framework(framework);

        let total = controls.len() as u32;
        let mut implemented = 0;
        let mut partially_implemented = 0;
        let mut not_implemented = 0;
        let mut not_applicable = 0;
        let mut gaps: Vec<ControlGap> = Vec::new();

        for control in controls {
            match control.implementation_status {
                ImplementationStatus::Implemented => implemented += 1,
                ImplementationStatus::PartiallyImplemented => {
                    partially_implemented += 1;
                    gaps.push(ControlGap {
                        control_id: control.control_id.clone(),
                        control_title: control.title.clone(),
                        status: control.implementation_status.clone(),
                        effectiveness: control.effectiveness.clone(),
                    });
                }
                ImplementationStatus::NotImplemented => {
                    not_implemented += 1;
                    gaps.push(ControlGap {
                        control_id: control.control_id.clone(),
                        control_title: control.title.clone(),
                        status: control.implementation_status.clone(),
                        effectiveness: control.effectiveness.clone(),
                    });
                }
                ImplementationStatus::NotApplicable => not_applicable += 1,
            }
        }

        let applicable = total - not_applicable;
        let coverage = if applicable > 0 {
            (implemented as f64 + partially_implemented as f64 * 0.5) / applicable as f64 * 100.0
        } else {
            0.0
        };

        GapAnalysis {
            framework: framework.clone(),
            total_controls: total,
            implemented,
            partially_implemented,
            not_implemented,
            not_applicable,
            coverage_percentage: coverage,
            gaps,
        }
    }

    /// Get control statistics
    pub fn get_statistics(&self) -> ControlStatistics {
        let total = self.controls.len() as u32;
        let mut implemented = 0;
        let mut partially_implemented = 0;
        let mut not_implemented = 0;
        let mut effective = 0;
        let mut due_testing = 0;

        let today = Utc::now().date_naive();

        for control in self.controls.values() {
            match control.implementation_status {
                ImplementationStatus::Implemented => implemented += 1,
                ImplementationStatus::PartiallyImplemented => partially_implemented += 1,
                ImplementationStatus::NotImplemented => not_implemented += 1,
                ImplementationStatus::NotApplicable => {}
            }

            if control.effectiveness == Some(Effectiveness::Effective) {
                effective += 1;
            }

            if control.next_test_date.map_or(false, |d| d <= today) {
                due_testing += 1;
            }
        }

        // Calculate framework coverage
        let mut framework_coverage: HashMap<String, f64> = HashMap::new();
        for framework in [
            ComplianceFramework::Nist80053,
            ComplianceFramework::NistCsf,
            ComplianceFramework::Cis,
            ComplianceFramework::Iso27001,
            ComplianceFramework::PciDss,
            ComplianceFramework::Soc2,
            ComplianceFramework::Hipaa,
        ] {
            let analysis = self.gap_analysis(&framework);
            if analysis.total_controls > 0 {
                framework_coverage.insert(framework.to_string(), analysis.coverage_percentage);
            }
        }

        ControlStatistics {
            total_controls: total,
            implemented_controls: implemented,
            partially_implemented,
            not_implemented,
            effective_controls: effective,
            controls_due_testing: due_testing,
            framework_coverage,
        }
    }
}

impl Default for ControlManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkCrosswalk {
    pub source_framework: ComplianceFramework,
    pub target_framework: ComplianceFramework,
    pub mappings: Vec<CrosswalkMapping>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrosswalkMapping {
    pub source_control_id: String,
    pub source_control_name: Option<String>,
    pub target_control_id: String,
    pub target_control_name: Option<String>,
    pub internal_control_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GapAnalysis {
    pub framework: ComplianceFramework,
    pub total_controls: u32,
    pub implemented: u32,
    pub partially_implemented: u32,
    pub not_implemented: u32,
    pub not_applicable: u32,
    pub coverage_percentage: f64,
    pub gaps: Vec<ControlGap>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlGap {
    pub control_id: String,
    pub control_title: String,
    pub status: ImplementationStatus,
    pub effectiveness: Option<Effectiveness>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlStatistics {
    pub total_controls: u32,
    pub implemented_controls: u32,
    pub partially_implemented: u32,
    pub not_implemented: u32,
    pub effective_controls: u32,
    pub controls_due_testing: u32,
    pub framework_coverage: HashMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlError {
    NotFound,
    DuplicateMapping,
    ValidationError(String),
}

impl std::fmt::Display for ControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "Control not found"),
            Self::DuplicateMapping => write!(f, "Duplicate framework mapping"),
            Self::ValidationError(msg) => write!(f, "Validation error: {}", msg),
        }
    }
}

impl std::error::Error for ControlError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_creation_and_mapping() {
        let mut manager = ControlManager::new();

        // Create control
        let control = manager.create_control(
            "Access Control Policy".to_string(),
            "Establish access control policy".to_string(),
            ControlCategory::Preventive,
            ControlType::Administrative,
            "AC".to_string(),
            Some("user-1".to_string()),
        );

        assert!(control.control_id.starts_with("CTRL-AC-"));
        assert_eq!(control.implementation_status, ImplementationStatus::NotImplemented);

        // Add framework mappings
        manager.add_framework_mapping(
            &control.id,
            ComplianceFramework::Nist80053,
            "AC-1".to_string(),
            Some("Access Control Policy and Procedures".to_string()),
            None,
        ).unwrap();

        manager.add_framework_mapping(
            &control.id,
            ComplianceFramework::Cis,
            "6.1".to_string(),
            Some("Establish Access Control".to_string()),
            None,
        ).unwrap();

        let updated = manager.get_control(&control.id).unwrap();
        assert_eq!(updated.framework_mappings.len(), 2);
    }

    #[test]
    fn test_control_testing() {
        let mut manager = ControlManager::new();

        let control = manager.create_control(
            "Test Control".to_string(),
            "Description".to_string(),
            ControlCategory::Detective,
            ControlType::Technical,
            "DT".to_string(),
            None,
        );

        // Record a test
        let test = manager.record_test(
            &control.id,
            "tester-1".to_string(),
            TestType::OperatingEffectiveness,
            "Reviewed logs for 30 days".to_string(),
            TestResult::Pass,
            None,
            Some(30),
            vec!["evidence-1".to_string()],
        ).unwrap();

        assert_eq!(test.result, TestResult::Pass);
        assert!(!test.remediation_required);

        let updated = manager.get_control(&control.id).unwrap();
        assert_eq!(updated.effectiveness, Some(Effectiveness::Effective));
    }

    #[test]
    fn test_gap_analysis() {
        let mut manager = ControlManager::new();

        // Create controls with NIST mappings
        for i in 1..=5 {
            let control = manager.create_control(
                format!("Control {}", i),
                "Description".to_string(),
                ControlCategory::Preventive,
                ControlType::Technical,
                "TEST".to_string(),
                None,
            );

            manager.add_framework_mapping(
                &control.id,
                ComplianceFramework::Nist80053,
                format!("AC-{}", i),
                None,
                None,
            ).unwrap();

            // Set implementation status
            let status = match i {
                1 | 2 => ImplementationStatus::Implemented,
                3 => ImplementationStatus::PartiallyImplemented,
                _ => ImplementationStatus::NotImplemented,
            };
            manager.update_implementation_status(&control.id, status).unwrap();
        }

        let analysis = manager.gap_analysis(&ComplianceFramework::Nist80053);
        assert_eq!(analysis.total_controls, 5);
        assert_eq!(analysis.implemented, 2);
        assert_eq!(analysis.partially_implemented, 1);
        assert_eq!(analysis.not_implemented, 2);
        // Coverage: (2 + 0.5) / 5 * 100 = 50%
        assert!((analysis.coverage_percentage - 50.0).abs() < 0.01);
    }
}
