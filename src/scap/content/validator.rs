//! SCAP Content Validator
//!
//! Validates SCAP content against schema requirements for XCCDF 1.2 and OVAL 5.11.

use anyhow::Result;
use std::collections::HashSet;

use super::loader::ParsedScapContent;
use crate::scap::xccdf::{XccdfBenchmark, XccdfRule, XccdfProfile, CheckSystem};
use crate::scap::oval::types::{OvalDefinition, OvalTest, OvalObject, OvalState, Criteria, CriteriaNode};
use crate::scap::oval::OvalDefinitions;

/// Validation result with detailed messages
#[derive(Debug, Clone, Default)]
pub struct ValidationResult {
    /// Whether validation passed
    pub valid: bool,
    /// Validation errors (blocking issues)
    pub errors: Vec<ValidationError>,
    /// Validation warnings (non-blocking issues)
    pub warnings: Vec<ValidationWarning>,
    /// Validation info messages
    pub info: Vec<String>,
}

impl ValidationResult {
    pub fn new() -> Self {
        Self {
            valid: true,
            ..Default::default()
        }
    }

    pub fn add_error(&mut self, error: ValidationError) {
        self.valid = false;
        self.errors.push(error);
    }

    pub fn add_warning(&mut self, warning: ValidationWarning) {
        self.warnings.push(warning);
    }

    pub fn add_info(&mut self, info: String) {
        self.info.push(info);
    }

    pub fn is_valid(&self) -> bool {
        self.valid
    }

    pub fn merge(&mut self, other: ValidationResult) {
        if !other.valid {
            self.valid = false;
        }
        self.errors.extend(other.errors);
        self.warnings.extend(other.warnings);
        self.info.extend(other.info);
    }
}

/// Validation error
#[derive(Debug, Clone)]
pub struct ValidationError {
    pub code: String,
    pub message: String,
    pub location: Option<String>,
    pub severity: ErrorSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorSeverity {
    Critical,  // Prevents any use of the content
    Major,     // Prevents compliance use
    Minor,     // May cause issues with some evaluators
}

/// Validation warning
#[derive(Debug, Clone)]
pub struct ValidationWarning {
    pub code: String,
    pub message: String,
    pub location: Option<String>,
}

/// Validator for SCAP content
pub struct ContentValidator {
    /// Whether to validate referential integrity
    pub check_references: bool,
    /// Whether to validate ID formats
    pub check_id_format: bool,
    /// Whether to validate version requirements
    pub check_versions: bool,
    /// Minimum XCCDF version required
    pub min_xccdf_version: String,
    /// Minimum OVAL version required
    pub min_oval_version: String,
}

impl ContentValidator {
    pub fn new() -> Self {
        Self {
            check_references: true,
            check_id_format: true,
            check_versions: true,
            min_xccdf_version: "1.2".to_string(),
            min_oval_version: "5.11".to_string(),
        }
    }

    /// Validate parsed SCAP content
    pub fn validate(&self, content: &ParsedScapContent) -> Result<ValidationResult> {
        let mut result = ValidationResult::new();

        result.add_info(format!("Validating SCAP content (type: {})", content.content_type));
        result.add_info(format!("Found {} benchmarks, {} OVAL definitions",
            content.benchmarks.len(),
            content.oval_definitions.definitions.len()));

        // Validate XCCDF content
        if !content.benchmarks.is_empty() {
            self.validate_xccdf_content(&content.benchmarks, &mut result);
        }

        // Validate OVAL content
        if !content.oval_definitions.definitions.is_empty() {
            self.validate_oval_content(&content.oval_definitions, &mut result);
        }

        // Validate cross-references between XCCDF and OVAL
        if !content.benchmarks.is_empty() && !content.oval_definitions.definitions.is_empty() {
            self.validate_xccdf_oval_references(&content.benchmarks, &content.oval_definitions, &mut result);
        }

        // DataStream validation
        if content.content_type == "datastream" {
            self.validate_datastream_content(&content.benchmarks, &content.oval_definitions, &mut result);
        }

        Ok(result)
    }

    /// Validate XCCDF 1.2 content
    fn validate_xccdf_content(&self, benchmarks: &[XccdfBenchmark], result: &mut ValidationResult) {
        result.add_info("Validating XCCDF content...".to_string());

        // Validate benchmarks
        for benchmark in benchmarks {
            self.validate_xccdf_benchmark(benchmark, result);

            // Validate profiles within benchmark
            for profile in &benchmark.profiles {
                self.validate_xccdf_profile(profile, &benchmark.rules, result);
            }

            // Validate rules within benchmark
            for rule in &benchmark.rules {
                self.validate_xccdf_rule(rule, result);
            }
        }

        // Check for required elements
        if benchmarks.is_empty() {
            result.add_error(ValidationError {
                code: "XCCDF-001".to_string(),
                message: "XCCDF content must contain at least one Benchmark element".to_string(),
                location: None,
                severity: ErrorSeverity::Critical,
            });
        }
    }

    /// Validate a single XCCDF benchmark
    fn validate_xccdf_benchmark(&self, benchmark: &XccdfBenchmark, result: &mut ValidationResult) {
        // Check required attributes
        if benchmark.id.is_empty() {
            result.add_error(ValidationError {
                code: "XCCDF-002".to_string(),
                message: "Benchmark must have an id attribute".to_string(),
                location: Some("Benchmark".to_string()),
                severity: ErrorSeverity::Critical,
            });
        }

        // Validate ID format (XCCDF 1.2 requires specific format)
        if self.check_id_format && !benchmark.id.starts_with("xccdf_") {
            result.add_warning(ValidationWarning {
                code: "XCCDF-003".to_string(),
                message: format!("Benchmark ID '{}' does not follow XCCDF 1.2 naming convention (should start with 'xccdf_')", benchmark.id),
                location: Some(format!("Benchmark[@id='{}']", benchmark.id)),
            });
        }

        // Check version
        if self.check_versions {
            // Version format validation
            if !benchmark.version.chars().any(|c| c.is_ascii_digit()) {
                result.add_warning(ValidationWarning {
                    code: "XCCDF-004".to_string(),
                    message: format!("Benchmark version '{}' does not appear to be a valid version number", benchmark.version),
                    location: Some(format!("Benchmark[@id='{}']", benchmark.id)),
                });
            }
        }

        // Check for title
        if benchmark.title.text.is_empty() {
            result.add_warning(ValidationWarning {
                code: "XCCDF-005".to_string(),
                message: "Benchmark should have a title element".to_string(),
                location: Some(format!("Benchmark[@id='{}']", benchmark.id)),
            });
        }

        // Check status
        if benchmark.status.is_empty() {
            result.add_warning(ValidationWarning {
                code: "XCCDF-006".to_string(),
                message: "Benchmark should have at least one status element".to_string(),
                location: Some(format!("Benchmark[@id='{}']", benchmark.id)),
            });
        }
    }

    /// Validate a single XCCDF profile
    fn validate_xccdf_profile(&self, profile: &XccdfProfile, rules: &[XccdfRule], result: &mut ValidationResult) {
        // Check required attributes
        if profile.id.is_empty() {
            result.add_error(ValidationError {
                code: "XCCDF-010".to_string(),
                message: "Profile must have an id attribute".to_string(),
                location: None,
                severity: ErrorSeverity::Critical,
            });
            return;
        }

        // Validate ID format
        if self.check_id_format && !profile.id.starts_with("xccdf_") {
            result.add_warning(ValidationWarning {
                code: "XCCDF-011".to_string(),
                message: format!("Profile ID '{}' does not follow XCCDF 1.2 naming convention", profile.id),
                location: Some(format!("Profile[@id='{}']", profile.id)),
            });
        }

        // Check for title
        if profile.title.text.is_empty() {
            result.add_warning(ValidationWarning {
                code: "XCCDF-012".to_string(),
                message: format!("Profile '{}' should have a title element", profile.id),
                location: Some(format!("Profile[@id='{}']", profile.id)),
            });
        }

        // Validate rule selections reference existing rules
        let rule_ids: HashSet<_> = rules.iter().map(|r| &r.id).collect();
        for selection in &profile.selects {
            if !rule_ids.contains(&selection.id_ref) {
                result.add_warning(ValidationWarning {
                    code: "XCCDF-013".to_string(),
                    message: format!("Profile '{}' selects non-existent rule '{}'", profile.id, selection.id_ref),
                    location: Some(format!("Profile[@id='{}']/select[@idref='{}']", profile.id, selection.id_ref)),
                });
            }
        }
    }

    /// Validate a single XCCDF rule
    fn validate_xccdf_rule(&self, rule: &XccdfRule, result: &mut ValidationResult) {
        // Check required attributes
        if rule.id.is_empty() {
            result.add_error(ValidationError {
                code: "XCCDF-020".to_string(),
                message: "Rule must have an id attribute".to_string(),
                location: None,
                severity: ErrorSeverity::Critical,
            });
            return;
        }

        // Validate ID format
        if self.check_id_format && !rule.id.starts_with("xccdf_") {
            result.add_warning(ValidationWarning {
                code: "XCCDF-021".to_string(),
                message: format!("Rule ID '{}' does not follow XCCDF 1.2 naming convention", rule.id),
                location: Some(format!("Rule[@id='{}']", rule.id)),
            });
        }

        // Check for title
        if rule.title.text.is_empty() {
            result.add_warning(ValidationWarning {
                code: "XCCDF-022".to_string(),
                message: format!("Rule '{}' should have a title element", rule.id),
                location: Some(format!("Rule[@id='{}']", rule.id)),
            });
        }

        // Check for check element (required for automated rules)
        if rule.checks.is_empty() {
            result.add_warning(ValidationWarning {
                code: "XCCDF-023".to_string(),
                message: format!("Rule '{}' has no check elements - cannot be automatically evaluated", rule.id),
                location: Some(format!("Rule[@id='{}']", rule.id)),
            });
        }
    }

    /// Validate OVAL 5.11 content
    fn validate_oval_content(&self, oval_defs: &OvalDefinitions, result: &mut ValidationResult) {
        result.add_info("Validating OVAL content...".to_string());

        // Collect IDs for reference checking
        let definition_ids: HashSet<_> = oval_defs.definitions.keys().collect();
        let test_ids: HashSet<_> = oval_defs.tests.keys().collect();
        let object_ids: HashSet<_> = oval_defs.objects.keys().collect();
        let state_ids: HashSet<_> = oval_defs.states.keys().collect();

        // Validate definitions
        for definition in oval_defs.definitions.values() {
            self.validate_oval_definition(definition, &test_ids, &definition_ids, result);
        }

        // Validate tests
        for test in oval_defs.tests.values() {
            self.validate_oval_test(test, &object_ids, &state_ids, result);
        }

        // Validate objects
        for object in oval_defs.objects.values() {
            self.validate_oval_object(object, result);
        }

        // Validate states
        for state in oval_defs.states.values() {
            self.validate_oval_state(state, result);
        }

        // Check for orphaned elements
        let referenced_tests = self.collect_test_references(&oval_defs.definitions.values().cloned().collect::<Vec<_>>());
        for test in oval_defs.tests.values() {
            if !referenced_tests.contains(&test.id) {
                result.add_warning(ValidationWarning {
                    code: "OVAL-050".to_string(),
                    message: format!("Test '{}' is not referenced by any definition", test.id),
                    location: Some(format!("test[@id='{}']", test.id)),
                });
            }
        }
    }

    /// Validate a single OVAL definition
    fn validate_oval_definition(&self, definition: &OvalDefinition, test_ids: &HashSet<&String>, definition_ids: &HashSet<&String>, result: &mut ValidationResult) {
        // Check required attributes
        if definition.id.is_empty() {
            result.add_error(ValidationError {
                code: "OVAL-001".to_string(),
                message: "Definition must have an id attribute".to_string(),
                location: None,
                severity: ErrorSeverity::Critical,
            });
            return;
        }

        // Validate ID format (OVAL 5.11: oval:namespace:def:id)
        if self.check_id_format && !definition.id.starts_with("oval:") {
            result.add_warning(ValidationWarning {
                code: "OVAL-002".to_string(),
                message: format!("Definition ID '{}' does not follow OVAL naming convention (should start with 'oval:')", definition.id),
                location: Some(format!("definition[@id='{}']", definition.id)),
            });
        }

        // Check version is present
        if definition.version == 0 {
            result.add_warning(ValidationWarning {
                code: "OVAL-003".to_string(),
                message: format!("Definition '{}' has version 0 - should be at least 1", definition.id),
                location: Some(format!("definition[@id='{}']", definition.id)),
            });
        }

        // Check for criteria (required for evaluation)
        if definition.criteria.is_none() {
            result.add_warning(ValidationWarning {
                code: "OVAL-004".to_string(),
                message: format!("Definition '{}' has no criteria - cannot be evaluated", definition.id),
                location: Some(format!("definition[@id='{}']", definition.id)),
            });
        }

        // Validate criteria references
        if let Some(ref criteria) = definition.criteria {
            self.validate_criteria_references(criteria, test_ids, definition_ids, &definition.id, result);
        }

        // Check for metadata
        if definition.metadata.title.is_none() {
            result.add_warning(ValidationWarning {
                code: "OVAL-005".to_string(),
                message: format!("Definition '{}' should have a title in metadata", definition.id),
                location: Some(format!("definition[@id='{}']", definition.id)),
            });
        }
    }

    /// Validate criteria references
    fn validate_criteria_references(&self, criteria: &Criteria, test_ids: &HashSet<&String>, definition_ids: &HashSet<&String>, parent_id: &str, result: &mut ValidationResult) {
        for node in &criteria.children {
            match node {
                CriteriaNode::Criterion(crit) => {
                    if !test_ids.contains(&crit.test_ref) {
                        result.add_error(ValidationError {
                            code: "OVAL-010".to_string(),
                            message: format!("Definition '{}' references non-existent test '{}'", parent_id, crit.test_ref),
                            location: Some(format!("definition[@id='{}']/criteria", parent_id)),
                            severity: ErrorSeverity::Major,
                        });
                    }
                }
                CriteriaNode::ExtendDefinition(def_ref) => {
                    if !definition_ids.contains(def_ref) {
                        result.add_error(ValidationError {
                            code: "OVAL-011".to_string(),
                            message: format!("Definition '{}' extends non-existent definition '{}'", parent_id, def_ref),
                            location: Some(format!("definition[@id='{}']/criteria", parent_id)),
                            severity: ErrorSeverity::Major,
                        });
                    }
                }
                CriteriaNode::Criteria(nested) => {
                    self.validate_criteria_references(nested, test_ids, definition_ids, parent_id, result);
                }
            }
        }
    }

    /// Validate a single OVAL test
    fn validate_oval_test(&self, test: &OvalTest, object_ids: &HashSet<&String>, state_ids: &HashSet<&String>, result: &mut ValidationResult) {
        // Check required attributes
        if test.id.is_empty() {
            result.add_error(ValidationError {
                code: "OVAL-020".to_string(),
                message: "Test must have an id attribute".to_string(),
                location: None,
                severity: ErrorSeverity::Critical,
            });
            return;
        }

        // Validate ID format
        if self.check_id_format && !test.id.starts_with("oval:") {
            result.add_warning(ValidationWarning {
                code: "OVAL-021".to_string(),
                message: format!("Test ID '{}' does not follow OVAL naming convention", test.id),
                location: Some(format!("test[@id='{}']", test.id)),
            });
        }

        // Check object reference
        if !object_ids.contains(&test.object_ref) {
            result.add_error(ValidationError {
                code: "OVAL-022".to_string(),
                message: format!("Test '{}' references non-existent object '{}'", test.id, test.object_ref),
                location: Some(format!("test[@id='{}']", test.id)),
                severity: ErrorSeverity::Major,
            });
        }

        // Check state reference if present
        if let Some(ref state_ref) = test.state_ref {
            if !state_ids.contains(state_ref) {
                result.add_error(ValidationError {
                    code: "OVAL-023".to_string(),
                    message: format!("Test '{}' references non-existent state '{}'", test.id, state_ref),
                    location: Some(format!("test[@id='{}']", test.id)),
                    severity: ErrorSeverity::Major,
                });
            }
        }
    }

    /// Validate a single OVAL object
    fn validate_oval_object(&self, object: &OvalObject, result: &mut ValidationResult) {
        if object.id.is_empty() {
            result.add_error(ValidationError {
                code: "OVAL-030".to_string(),
                message: "Object must have an id attribute".to_string(),
                location: None,
                severity: ErrorSeverity::Critical,
            });
            return;
        }

        // Validate ID format
        if self.check_id_format && !object.id.starts_with("oval:") {
            result.add_warning(ValidationWarning {
                code: "OVAL-031".to_string(),
                message: format!("Object ID '{}' does not follow OVAL naming convention", object.id),
                location: Some(format!("object[@id='{}']", object.id)),
            });
        }
    }

    /// Validate a single OVAL state
    fn validate_oval_state(&self, state: &OvalState, result: &mut ValidationResult) {
        if state.id.is_empty() {
            result.add_error(ValidationError {
                code: "OVAL-040".to_string(),
                message: "State must have an id attribute".to_string(),
                location: None,
                severity: ErrorSeverity::Critical,
            });
            return;
        }

        // Validate ID format
        if self.check_id_format && !state.id.starts_with("oval:") {
            result.add_warning(ValidationWarning {
                code: "OVAL-041".to_string(),
                message: format!("State ID '{}' does not follow OVAL naming convention", state.id),
                location: Some(format!("state[@id='{}']", state.id)),
            });
        }
    }

    /// Validate DataStream content
    fn validate_datastream_content(&self, benchmarks: &[XccdfBenchmark], oval_defs: &OvalDefinitions, result: &mut ValidationResult) {
        result.add_info("Validating SCAP DataStream content...".to_string());

        // DataStream should contain both XCCDF and OVAL
        let has_xccdf = !benchmarks.is_empty();
        let has_oval = !oval_defs.definitions.is_empty();

        if !has_xccdf && !has_oval {
            result.add_error(ValidationError {
                code: "DS-001".to_string(),
                message: "DataStream must contain at least XCCDF or OVAL content".to_string(),
                location: None,
                severity: ErrorSeverity::Critical,
            });
        }
    }

    /// Validate XCCDF-OVAL cross-references
    fn validate_xccdf_oval_references(&self, benchmarks: &[XccdfBenchmark], oval_defs: &OvalDefinitions, result: &mut ValidationResult) {
        let definition_ids: HashSet<_> = oval_defs.definitions.keys().collect();

        for benchmark in benchmarks {
            for rule in &benchmark.rules {
                for check in &rule.checks {
                    // Only validate OVAL checks
                    if !matches!(check.system, CheckSystem::Oval) {
                        continue;
                    }

                    // Check content_ref or check_content_ref for OVAL definition ID
                    let check_ref = check.check_content_ref.as_ref()
                        .or(check.content_ref.as_ref());

                    if let Some(href) = check_ref {
                        // Extract the definition ID (may have # prefix)
                        let def_id = href.trim_start_matches('#');
                        if !def_id.is_empty() && !definition_ids.contains(&def_id.to_string()) {
                            result.add_warning(ValidationWarning {
                                code: "DS-010".to_string(),
                                message: format!("Rule '{}' references OVAL definition '{}' which is not present in the content", rule.id, def_id),
                                location: Some(format!("Rule[@id='{}']/check", rule.id)),
                            });
                        }
                    }
                }
            }
        }
    }

    /// Collect all test IDs referenced in definitions
    fn collect_test_references(&self, definitions: &[OvalDefinition]) -> HashSet<String> {
        let mut test_refs = HashSet::new();

        for definition in definitions {
            if let Some(ref criteria) = definition.criteria {
                self.collect_criteria_test_refs(criteria, &mut test_refs);
            }
        }

        test_refs
    }

    fn collect_criteria_test_refs(&self, criteria: &Criteria, test_refs: &mut HashSet<String>) {
        for node in &criteria.children {
            match node {
                CriteriaNode::Criterion(crit) => {
                    test_refs.insert(crit.test_ref.clone());
                }
                CriteriaNode::Criteria(nested) => {
                    self.collect_criteria_test_refs(nested, test_refs);
                }
                _ => {}
            }
        }
    }
}

impl Default for ContentValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_result() {
        let mut result = ValidationResult::new();
        assert!(result.is_valid());

        result.add_warning(ValidationWarning {
            code: "TEST-001".to_string(),
            message: "Test warning".to_string(),
            location: None,
        });
        assert!(result.is_valid()); // Warnings don't invalidate

        result.add_error(ValidationError {
            code: "TEST-002".to_string(),
            message: "Test error".to_string(),
            location: None,
            severity: ErrorSeverity::Major,
        });
        assert!(!result.is_valid()); // Errors invalidate
    }

    #[test]
    fn test_validator_creation() {
        let validator = ContentValidator::new();
        assert!(validator.check_references);
        assert!(validator.check_id_format);
        assert!(validator.check_versions);
    }

    #[test]
    fn test_validate_empty_content() {
        use crate::scap::oval::OvalDefinitions;

        let validator = ContentValidator::new();
        let content = ParsedScapContent {
            benchmarks: Vec::new(),
            oval_definitions: OvalDefinitions::new(),
            content_type: "xccdf".to_string(),
        };

        let result = validator.validate(&content).unwrap();
        // Empty content is valid (no errors) - validator only finds issues in existing content
        assert!(result.is_valid());
        // But it should have info about empty content
        assert!(result.info.iter().any(|i| i.contains("0 benchmarks")));
    }
}
