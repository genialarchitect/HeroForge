#![allow(dead_code)]
//! Breach & Attack Simulation (BAS) Module
//!
//! This module provides a safe breach and attack simulation framework for testing
//! security controls and identifying detection gaps. It simulates MITRE ATT&CK
//! techniques using safe payloads that don't cause actual harm.
//!
//! ## Features
//!
//! - **Safe Simulation**: Execute techniques using safe payloads (file markers, DNS beacons, etc.)
//! - **MITRE ATT&CK Mapping**: Full coverage of ATT&CK techniques with proper categorization
//! - **Detection Validation**: Verify if security controls detect simulated attacks
//! - **Detection Gap Analysis**: Identify techniques that evade current security controls
//! - **Safety Guardrails**: Multiple execution modes with strict safety controls
//!
//! ## Execution Modes
//!
//! - **DryRun**: Analyze only, no actual execution
//! - **Simulation**: Execute safe payloads only
//! - **ControlledExec**: Execute with safety guardrails (requires explicit approval)
//!
//! ## Example
//!
//! ```ignore
//! use heroforge::scanner::bas::{
//!     BasEngine, SimulationScenario, ExecutionMode,
//! };
//!
//! let engine = BasEngine::new(BasConfig::default());
//!
//! let scenario = SimulationScenario::new("test", "Test Scenario", "user_id")
//!     .with_techniques(vec!["T1059.001".to_string()])
//!     .with_mode(ExecutionMode::Simulation);
//!
//! let result = engine.run_simulation(scenario).await?;
//! println!("Detection rate: {:.1}%", result.summary.detection_rate * 100.0);
//! ```

pub mod automation;
pub mod detection;
pub mod engine;
pub mod payloads;
pub mod safety;
pub mod techniques;
pub mod types;

// Re-export main types
#[allow(unused_imports)]
pub use types::{
    AttackTechnique,
    BasConfig,
    DetectionGap,
    ExecutionMode,
    MitreTactic,
    PayloadType,
    SafePayload,
    ScenarioStatus,
    SimulationProgress,
    SimulationResult,
    SimulationScenario,
    SimulationStatus,
    SimulationSummary,
    TechniqueExecution,
    TechniqueExecutionStatus,
};

// Re-export engine
pub use engine::BasEngine;

// Re-export safety controller
#[allow(unused_imports)]
pub use safety::{SafetyController, SafetyViolation};

// Re-export technique library
pub use techniques::TechniqueLibrary;

// Re-export payloads
#[allow(unused_imports)]
pub use payloads::{PayloadExecutor, PayloadResult};

// Re-export detection
#[allow(unused_imports)]
pub use detection::{DetectionValidator, DetectionResult};

// Re-export automation
#[allow(unused_imports)]
pub use automation::{
    AttackSimulationAutomation, AttackChain, AttackChainStep, AttackChainResult,
    CampaignType, CampaignTemplate, ScheduledSimulation, ContinuousValidation,
    AutomationProgress, ChainExecutionStatus,
};

use anyhow::Result;

/// Run a quick BAS test with default techniques
pub async fn run_quick_test(
    config: BasConfig,
    targets: Vec<String>,
    user_id: &str,
) -> Result<SimulationResult> {
    let engine = BasEngine::new(config);

    // Create a scenario with common techniques
    let mut scenario = SimulationScenario::new(
        uuid::Uuid::new_v4().to_string(),
        "Quick Security Test",
        user_id,
    );
    scenario.targets = targets;
    scenario.execution_mode = ExecutionMode::Simulation;
    scenario.technique_ids = vec![
        "T1059.001".to_string(), // PowerShell
        "T1053.005".to_string(), // Scheduled Task
        "T1105".to_string(),     // Ingress Tool Transfer
        "T1071.001".to_string(), // Web Protocols
        "T1082".to_string(),     // System Information Discovery
    ];

    engine.run_simulation(scenario, None).await
}

/// Get coverage statistics for all techniques
pub fn get_technique_coverage() -> TechniqueCoverage {
    let library = TechniqueLibrary::new();
    let techniques = library.all_techniques();

    let mut coverage = TechniqueCoverage::default();
    coverage.total_techniques = techniques.len();

    for technique in &techniques {
        for tactic in &technique.tactics {
            *coverage.by_tactic.entry(*tactic).or_insert(0) += 1;
        }
        if technique.is_safe {
            coverage.safe_techniques += 1;
        }
    }

    coverage
}

/// Technique coverage statistics
#[derive(Debug, Clone, Default)]
pub struct TechniqueCoverage {
    pub total_techniques: usize,
    pub safe_techniques: usize,
    pub by_tactic: std::collections::HashMap<MitreTactic, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_technique_coverage() {
        let coverage = get_technique_coverage();
        assert!(coverage.total_techniques > 0);
        assert!(coverage.safe_techniques > 0);
        assert!(!coverage.by_tactic.is_empty());
    }

    #[test]
    fn test_bas_config_default() {
        let config = BasConfig::default();
        assert_eq!(config.default_mode, ExecutionMode::DryRun);
        assert!(config.enable_cleanup);
    }
}
