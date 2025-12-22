//! Purple Team Mode
//!
//! Execute attacks and correlate with SIEM to validate detection coverage
//! with MITRE ATT&CK mapping.

pub mod types;
pub mod mitre_attack;
pub mod detection_check;
pub mod coverage;
pub mod gap_analysis;
pub mod engine;

pub use types::*;
pub use mitre_attack::MitreMapper;
pub use detection_check::{DetectionChecker, generate_sigma_rule, generate_splunk_query, generate_elastic_query};
pub use coverage::CoverageCalculator;
pub use gap_analysis::{GapAnalyzer, GapStatistics};
pub use engine::{PurpleTeamEngine, PurpleTeamProgress, ExercisePhase, ExerciseResult, AvailableAttack, AttackParameter, ParameterType};
