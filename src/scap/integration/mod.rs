//! SCAP Integration with HeroForge modules
//!
//! Bridges between SCAP engine and existing compliance/scanner modules.

mod compliance_bridge;
mod scanner_bridge;

pub use compliance_bridge::ScapComplianceBridge;
pub use scanner_bridge::ScannerBridge;
