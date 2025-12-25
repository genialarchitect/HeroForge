//! Attack Surface Management (ASM) module
//!
//! Provides continuous external monitoring with scheduled discovery,
//! change detection, and risk scoring capabilities.

pub mod types;
pub mod monitor;
pub mod baseline;
pub mod comparison;
pub mod risk_scoring;

#[allow(unused_imports)]
pub use types::*;
#[allow(unused_imports)]
pub use monitor::AsmMonitorEngine;
#[allow(unused_imports)]
pub use baseline::BaselineManager;
#[allow(unused_imports)]
pub use comparison::ChangeDetector;
#[allow(unused_imports)]
pub use risk_scoring::RiskScorer;
