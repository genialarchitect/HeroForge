//! Attack Surface Management (ASM) module
//!
//! Provides continuous external monitoring with scheduled discovery,
//! change detection, and risk scoring capabilities.

pub mod types;
pub mod monitor;
pub mod baseline;
pub mod comparison;
pub mod risk_scoring;

pub use types::*;
pub use monitor::AsmMonitorEngine;
pub use baseline::BaselineManager;
pub use comparison::ChangeDetector;
pub use risk_scoring::RiskScorer;
