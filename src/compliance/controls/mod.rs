//! Compliance Controls Module
//!
//! This module provides:
//! - Control trait definitions
//! - Vulnerability-to-control mapping engine
//! - Active compliance check implementations

#![allow(unused_imports)]

pub mod mapping;
pub mod checks;

pub use mapping::{VulnerabilityMapper, MappingResult};
pub use checks::{ComplianceCheck, CheckResult, run_compliance_checks, check_results_to_findings};
