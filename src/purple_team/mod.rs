//! Purple Team - Combined Red/Blue Team Exercises
//!
//! This module provides a unified facade for purple team operations that
//! combine offensive and defensive security testing to validate detection
//! and response capabilities.
//!
//! ## Core Capabilities
//!
//! ### MITRE ATT&CK Integration
//! - Full ATT&CK framework mapping
//! - Technique and tactic coverage
//! - Sub-technique support
//! - Platform-specific filtering
//!
//! ### Attack Execution
//! - Atomic Red Team integration
//! - Built-in attack library
//! - Safe execution environment
//! - Parameterized attacks
//!
//! ### Detection Validation
//! - SIEM correlation checking
//! - Sigma rule generation
//! - Splunk/Elastic query generation
//! - Detection delay measurement
//!
//! ### Coverage Analysis
//! - Detection coverage mapping
//! - Gap identification
//! - Priority recommendations
//! - Trend tracking
//!
//! ### Live Exercises
//! - Coordinated red/blue exercises
//! - Real-time scoring
//! - Exercise playback and review
//! - Collaborative reporting
//!
//! ## Usage
//!
//! ```rust,ignore
//! use heroforge::purple_team;
//!
//! // Run a purple team exercise
//! let engine = purple_team::PurpleTeamEngine::new(pool);
//! let result = engine.run_exercise(exercise_config).await?;
//!
//! // Check detection coverage
//! let coverage = purple_team::CoverageCalculator::calculate(pool).await?;
//!
//! // Analyze gaps
//! let gaps = purple_team::GapAnalyzer::analyze(pool).await?;
//! ```

#![allow(unused_imports)]

// =============================================================================
// CORE PURPLE TEAM MODULES
// =============================================================================

pub mod types;
pub mod mitre_attack;
pub mod detection_check;
pub mod coverage;
pub mod gap_analysis;
pub mod engine;
pub mod live_exercises;
pub mod attack_library;
pub mod attack_execution;

pub use types::*;
pub use mitre_attack::MitreMapper;
pub use detection_check::{DetectionChecker, generate_sigma_rule, generate_splunk_query, generate_elastic_query};
pub use coverage::CoverageCalculator;
pub use gap_analysis::{GapAnalyzer, GapStatistics};
pub use engine::{PurpleTeamEngine, PurpleTeamProgress, ExercisePhase, ExerciseResult, AvailableAttack, AttackParameter, ParameterType};
pub use live_exercises::*;
pub use attack_library::*;
pub use attack_execution::{AtomicExecutor, AtomicTest, AtomicTestResult, AtomicExecutorConfig, BuiltInAtomics};

// =============================================================================
// INTEGRATION RE-EXPORTS
// =============================================================================

/// Red team capabilities for attack simulation
pub mod attack_simulation {
    //! Attack simulation tools for purple team exercises

    // BAS (Breach and Attack Simulation)
    pub use crate::scanner::bas::*;

    // Exploitation tools
    pub use crate::scanner::exploitation::*;
}

/// Blue team capabilities for detection validation
pub mod detection_validation {
    //! Detection and monitoring for purple team exercises

    // SIEM integration
    pub use crate::siem::{
        SiemAlert, SiemRule, CorrelationEngine, SigmaParser,
    };

    // Detection engineering
    pub use crate::detection_engineering::{
        Detection, DetectionTest, CoverageMapping, CoverageGap,
    };
}

/// Threat hunting for exercise follow-up
pub mod hunt_integration {
    //! Threat hunting integration

    pub use crate::threat_hunting::{
        ioc::*, mitre::*, playbooks::*,
    };
}

/// Reporting for exercises
pub mod exercise_reports {
    //! Exercise reporting and documentation

    pub use crate::reports::*;
}
