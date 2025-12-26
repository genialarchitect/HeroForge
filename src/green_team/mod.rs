//! Green Team - Security Automation & Orchestration (SOAR)
//!
//! This module provides comprehensive SOAR capabilities including:
//! - Playbook management and execution
//! - Orchestration workflows
//! - Case management
//! - Threat intel automation
//! - Response metrics (MTTD, MTTR, SLA)

pub mod types;
pub mod playbooks;
pub mod orchestration;
pub mod case_management;
pub mod threat_intel_automation;
pub mod metrics;

pub use types::*;
pub use playbooks::*;
pub use case_management::*;
pub use threat_intel_automation::*;
pub use metrics::*;
