#![allow(dead_code)]
//! Safety Controller and Guardrails
//!
//! This module provides safety controls for BAS testing to ensure
//! simulations don't cause unintended harm to systems.

use super::techniques::TechniqueLibrary;
use super::types::{AttackTechnique, BasConfig, ExecutionMode, MitreTactic};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Safety violation detected during simulation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyViolation {
    /// Violation type
    pub violation_type: SafetyViolationType,
    /// Technique that caused the violation
    pub technique_id: Option<String>,
    /// Detailed message
    pub message: String,
    /// Severity (1-5)
    pub severity: u8,
    /// Recommended action
    pub recommendation: String,
}

/// Types of safety violations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyViolationType {
    /// Technique is marked as unsafe
    UnsafeTechnique,
    /// Execution mode not allowed
    DisallowedMode,
    /// Technique is blocklisted
    BlocklistedTechnique,
    /// Target not in allowed list
    DisallowedTarget,
    /// Elevation required but not approved
    ElevationRequired,
    /// Impact technique without explicit approval
    ImpactTechnique,
    /// Too many techniques in parallel
    TooManyParallel,
    /// Timeout exceeded
    TimeoutExceeded,
}

impl SafetyViolationType {
    pub fn as_str(&self) -> &'static str {
        match self {
            SafetyViolationType::UnsafeTechnique => "unsafe_technique",
            SafetyViolationType::DisallowedMode => "disallowed_mode",
            SafetyViolationType::BlocklistedTechnique => "blocklisted_technique",
            SafetyViolationType::DisallowedTarget => "disallowed_target",
            SafetyViolationType::ElevationRequired => "elevation_required",
            SafetyViolationType::ImpactTechnique => "impact_technique",
            SafetyViolationType::TooManyParallel => "too_many_parallel",
            SafetyViolationType::TimeoutExceeded => "timeout_exceeded",
        }
    }
}

/// Safety controller for BAS simulations
pub struct SafetyController {
    /// Configuration
    config: SafetyConfig,
    /// Technique library for validation
    library: TechniqueLibrary,
}

/// Safety configuration
#[derive(Debug, Clone)]
pub struct SafetyConfig {
    /// Allowed execution modes
    pub allowed_modes: HashSet<ExecutionMode>,
    /// Blocked technique IDs
    pub blocked_techniques: HashSet<String>,
    /// Allowed target patterns (CIDR, hostnames, etc.)
    pub allowed_targets: Vec<String>,
    /// Whether to allow unsafe techniques
    pub allow_unsafe: bool,
    /// Whether to allow impact techniques
    pub allow_impact: bool,
    /// Whether elevation is approved
    pub elevation_approved: bool,
    /// Maximum parallel executions
    pub max_parallel: usize,
    /// Maximum timeout in seconds
    pub max_timeout_secs: u64,
    /// Whether to require explicit approval for dangerous operations
    pub require_approval: bool,
}

impl Default for SafetyConfig {
    fn default() -> Self {
        let mut allowed_modes = HashSet::new();
        allowed_modes.insert(ExecutionMode::DryRun);
        allowed_modes.insert(ExecutionMode::Simulation);

        Self {
            allowed_modes,
            blocked_techniques: HashSet::new(),
            allowed_targets: vec![
                "127.0.0.1".to_string(),
                "localhost".to_string(),
                "*.local".to_string(),
            ],
            allow_unsafe: false,
            allow_impact: false,
            elevation_approved: false,
            max_parallel: 4,
            max_timeout_secs: 600,
            require_approval: true,
        }
    }
}

impl SafetyController {
    /// Create a new safety controller with default settings
    pub fn new() -> Self {
        Self {
            config: SafetyConfig::default(),
            library: TechniqueLibrary::new(),
        }
    }

    /// Create from BAS config
    pub fn from_config(config: &BasConfig) -> Self {
        let mut safety_config = SafetyConfig::default();
        safety_config.allowed_modes = config.allowed_modes.iter().cloned().collect();
        safety_config.blocked_techniques = config.blocked_techniques.iter().cloned().collect();
        safety_config.max_parallel = config.max_parallel;
        safety_config.max_timeout_secs = config.default_timeout_secs;

        Self {
            config: safety_config,
            library: TechniqueLibrary::new(),
        }
    }

    /// Create with custom safety config
    pub fn with_config(config: SafetyConfig) -> Self {
        Self {
            config,
            library: TechniqueLibrary::new(),
        }
    }

    /// Validate execution mode
    pub fn validate_mode(&self, mode: ExecutionMode) -> Result<(), SafetyViolation> {
        if !self.config.allowed_modes.contains(&mode) {
            return Err(SafetyViolation {
                violation_type: SafetyViolationType::DisallowedMode,
                technique_id: None,
                message: format!("Execution mode '{}' is not allowed", mode),
                severity: 4,
                recommendation: format!(
                    "Use one of the allowed modes: {:?}",
                    self.config.allowed_modes
                ),
            });
        }
        Ok(())
    }

    /// Validate a technique for execution
    pub fn validate_technique(
        &self,
        technique_id: &str,
        mode: ExecutionMode,
    ) -> Result<(), SafetyViolation> {
        // Check if technique is blocklisted
        if self.config.blocked_techniques.contains(technique_id) {
            return Err(SafetyViolation {
                violation_type: SafetyViolationType::BlocklistedTechnique,
                technique_id: Some(technique_id.to_string()),
                message: format!("Technique '{}' is blocklisted", technique_id),
                severity: 5,
                recommendation: "Remove technique from blocklist or select a different technique"
                    .to_string(),
            });
        }

        // Get technique from library
        if let Some(technique) = self.library.get(technique_id) {
            // Check if technique is safe
            if !technique.is_safe && !self.config.allow_unsafe {
                return Err(SafetyViolation {
                    violation_type: SafetyViolationType::UnsafeTechnique,
                    technique_id: Some(technique_id.to_string()),
                    message: format!(
                        "Technique '{}' is marked as unsafe and unsafe techniques are not allowed",
                        technique.name
                    ),
                    severity: 5,
                    recommendation: "Enable 'allow_unsafe' in configuration or select a safe technique".to_string(),
                });
            }

            // Check execution mode requirements
            if mode != ExecutionMode::DryRun && technique.min_execution_mode == ExecutionMode::DryRun {
                // This technique should only run in dry run mode
                return Err(SafetyViolation {
                    violation_type: SafetyViolationType::DisallowedMode,
                    technique_id: Some(technique_id.to_string()),
                    message: format!(
                        "Technique '{}' requires DryRun mode for safety",
                        technique.name
                    ),
                    severity: 4,
                    recommendation: "Use DryRun mode for this technique".to_string(),
                });
            }

            // Check for impact techniques
            if technique.tactics.contains(&MitreTactic::Impact) && !self.config.allow_impact {
                return Err(SafetyViolation {
                    violation_type: SafetyViolationType::ImpactTechnique,
                    technique_id: Some(technique_id.to_string()),
                    message: format!(
                        "Technique '{}' is an Impact technique and requires explicit approval",
                        technique.name
                    ),
                    severity: 5,
                    recommendation: "Enable 'allow_impact' in configuration after careful review"
                        .to_string(),
                });
            }
        }

        Ok(())
    }

    /// Validate a target
    pub fn validate_target(&self, target: &str) -> Result<(), SafetyViolation> {
        // Empty allowed targets means all targets are allowed
        if self.config.allowed_targets.is_empty() {
            return Ok(());
        }

        let target_lower = target.to_lowercase();

        for pattern in &self.config.allowed_targets {
            if pattern.starts_with('*') {
                // Wildcard pattern
                let suffix = &pattern[1..];
                if target_lower.ends_with(suffix) {
                    return Ok(());
                }
            } else if pattern.ends_with('*') {
                // Prefix pattern
                let prefix = &pattern[..pattern.len() - 1];
                if target_lower.starts_with(prefix) {
                    return Ok(());
                }
            } else if target_lower == pattern.to_lowercase() {
                return Ok(());
            }
        }

        Err(SafetyViolation {
            violation_type: SafetyViolationType::DisallowedTarget,
            technique_id: None,
            message: format!("Target '{}' is not in the allowed targets list", target),
            severity: 4,
            recommendation: format!(
                "Add target to allowed_targets or use one of: {:?}",
                self.config.allowed_targets
            ),
        })
    }

    /// Validate parallel execution count
    pub fn validate_parallel(&self, count: usize) -> Result<(), SafetyViolation> {
        if count > self.config.max_parallel {
            return Err(SafetyViolation {
                violation_type: SafetyViolationType::TooManyParallel,
                technique_id: None,
                message: format!(
                    "Requested {} parallel executions, maximum allowed is {}",
                    count, self.config.max_parallel
                ),
                severity: 3,
                recommendation: format!(
                    "Reduce parallel executions to {} or less",
                    self.config.max_parallel
                ),
            });
        }
        Ok(())
    }

    /// Validate timeout
    pub fn validate_timeout(&self, timeout_secs: u64) -> Result<(), SafetyViolation> {
        if timeout_secs > self.config.max_timeout_secs {
            return Err(SafetyViolation {
                violation_type: SafetyViolationType::TimeoutExceeded,
                technique_id: None,
                message: format!(
                    "Requested timeout {} seconds exceeds maximum of {} seconds",
                    timeout_secs, self.config.max_timeout_secs
                ),
                severity: 2,
                recommendation: format!(
                    "Reduce timeout to {} seconds or less",
                    self.config.max_timeout_secs
                ),
            });
        }
        Ok(())
    }

    /// Validate a complete scenario
    pub fn validate_scenario(
        &self,
        mode: ExecutionMode,
        technique_ids: &[String],
        targets: &[String],
        parallel: bool,
        timeout_secs: u64,
    ) -> Vec<SafetyViolation> {
        let mut violations = Vec::new();

        // Validate mode
        if let Err(v) = self.validate_mode(mode) {
            violations.push(v);
        }

        // Validate each technique
        for technique_id in technique_ids {
            if let Err(v) = self.validate_technique(technique_id, mode) {
                violations.push(v);
            }
        }

        // Validate each target
        for target in targets {
            if let Err(v) = self.validate_target(target) {
                violations.push(v);
            }
        }

        // Validate parallel count
        if parallel {
            if let Err(v) = self.validate_parallel(technique_ids.len()) {
                violations.push(v);
            }
        }

        // Validate timeout
        if let Err(v) = self.validate_timeout(timeout_secs) {
            violations.push(v);
        }

        violations
    }

    /// Check if a technique is allowed
    pub fn is_technique_allowed(&self, technique_id: &str, mode: ExecutionMode) -> bool {
        self.validate_technique(technique_id, mode).is_ok()
    }

    /// Get safe techniques for a given mode
    pub fn get_safe_techniques(&self, mode: ExecutionMode) -> Vec<&AttackTechnique> {
        self.library
            .all_techniques()
            .into_iter()
            .filter(|t| {
                self.validate_technique(&t.technique_id, mode).is_ok()
            })
            .collect()
    }

    /// Get unsafe technique IDs
    pub fn get_unsafe_techniques(&self) -> Vec<String> {
        self.library
            .all_techniques()
            .into_iter()
            .filter(|t| !t.is_safe)
            .map(|t| t.technique_id.clone())
            .collect()
    }

    /// Update allowed modes
    pub fn set_allowed_modes(&mut self, modes: Vec<ExecutionMode>) {
        self.config.allowed_modes = modes.into_iter().collect();
    }

    /// Add a blocked technique
    pub fn block_technique(&mut self, technique_id: &str) {
        self.config.blocked_techniques.insert(technique_id.to_string());
    }

    /// Remove a blocked technique
    pub fn unblock_technique(&mut self, technique_id: &str) {
        self.config.blocked_techniques.remove(technique_id);
    }

    /// Set allowed targets
    pub fn set_allowed_targets(&mut self, targets: Vec<String>) {
        self.config.allowed_targets = targets;
    }

    /// Enable unsafe techniques
    pub fn allow_unsafe(&mut self, allow: bool) {
        self.config.allow_unsafe = allow;
    }

    /// Enable impact techniques
    pub fn allow_impact(&mut self, allow: bool) {
        self.config.allow_impact = allow;
    }

    /// Get current configuration
    pub fn get_config(&self) -> &SafetyConfig {
        &self.config
    }
}

impl Default for SafetyController {
    fn default() -> Self {
        Self::new()
    }
}

/// Pre-execution safety check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyCheckResult {
    /// Whether the check passed
    pub passed: bool,
    /// List of violations found
    pub violations: Vec<SafetyViolation>,
    /// Warnings (non-blocking)
    pub warnings: Vec<String>,
    /// Approved techniques
    pub approved_techniques: Vec<String>,
    /// Denied techniques
    pub denied_techniques: Vec<String>,
}

impl SafetyCheckResult {
    pub fn pass() -> Self {
        Self {
            passed: true,
            violations: Vec::new(),
            warnings: Vec::new(),
            approved_techniques: Vec::new(),
            denied_techniques: Vec::new(),
        }
    }

    pub fn fail(violations: Vec<SafetyViolation>) -> Self {
        Self {
            passed: false,
            violations,
            warnings: Vec::new(),
            approved_techniques: Vec::new(),
            denied_techniques: Vec::new(),
        }
    }
}

/// Run a comprehensive safety check
pub fn run_safety_check(
    controller: &SafetyController,
    mode: ExecutionMode,
    technique_ids: &[String],
    targets: &[String],
    timeout_secs: u64,
) -> SafetyCheckResult {
    let violations = controller.validate_scenario(
        mode,
        technique_ids,
        targets,
        technique_ids.len() > 1,
        timeout_secs,
    );

    let mut result = if violations.is_empty() {
        SafetyCheckResult::pass()
    } else {
        SafetyCheckResult::fail(violations)
    };

    // Categorize techniques
    for technique_id in technique_ids {
        if controller.is_technique_allowed(technique_id, mode) {
            result.approved_techniques.push(technique_id.clone());
        } else {
            result.denied_techniques.push(technique_id.clone());
        }
    }

    // Add warnings
    if mode == ExecutionMode::ControlledExec {
        result.warnings.push("ControlledExec mode can modify system state".to_string());
    }

    if technique_ids.len() > 10 {
        result.warnings.push(format!(
            "Large number of techniques ({}) may take significant time",
            technique_ids.len()
        ));
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safety_controller_creation() {
        let controller = SafetyController::new();
        assert!(!controller.config.allow_unsafe);
        assert!(controller.config.allowed_modes.contains(&ExecutionMode::DryRun));
    }

    #[test]
    fn test_validate_mode() {
        let controller = SafetyController::new();
        assert!(controller.validate_mode(ExecutionMode::DryRun).is_ok());
        assert!(controller.validate_mode(ExecutionMode::Simulation).is_ok());
        assert!(controller.validate_mode(ExecutionMode::ControlledExec).is_err());
    }

    #[test]
    fn test_validate_target() {
        let controller = SafetyController::new();
        assert!(controller.validate_target("127.0.0.1").is_ok());
        assert!(controller.validate_target("localhost").is_ok());
        assert!(controller.validate_target("test.local").is_ok());
        assert!(controller.validate_target("example.com").is_err());
    }

    #[test]
    fn test_block_technique() {
        let mut controller = SafetyController::new();
        assert!(controller.is_technique_allowed("T1059.001", ExecutionMode::Simulation));

        controller.block_technique("T1059.001");
        assert!(!controller.is_technique_allowed("T1059.001", ExecutionMode::Simulation));

        controller.unblock_technique("T1059.001");
        assert!(controller.is_technique_allowed("T1059.001", ExecutionMode::Simulation));
    }

    #[test]
    fn test_unsafe_technique_validation() {
        let controller = SafetyController::new();

        // T1486 (Data Encrypted for Impact) is marked as unsafe
        let result = controller.validate_technique("T1486", ExecutionMode::Simulation);
        assert!(result.is_err());
    }

    #[test]
    fn test_safety_check() {
        let controller = SafetyController::new();
        let result = run_safety_check(
            &controller,
            ExecutionMode::Simulation,
            &["T1059.001".to_string(), "T1082".to_string()],
            &["localhost".to_string()],
            300,
        );

        assert!(result.passed);
        assert!(result.approved_techniques.contains(&"T1059.001".to_string()));
    }
}
