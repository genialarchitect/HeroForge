//! Monitoring, Logging, and Continuous Attack Surface Surveillance
//!
//! This module provides:
//! - Logging infrastructure
//! - Metrics collection
//! - Alerting system
//! - Continuous monitoring engine for real-time attack surface visibility

pub mod logging;
pub mod metrics;
pub mod alerts;

// Continuous Monitoring Engine
pub mod engine;
pub mod change_detector;
pub mod types;

pub use engine::MonitoringEngine;
pub use change_detector::ChangeDetector;
pub use types::*;

/// Default lightweight scan interval in seconds
pub const DEFAULT_LIGHT_SCAN_INTERVAL: u64 = 5;

/// Default full scan interval in seconds (4 hours)
pub const DEFAULT_FULL_SCAN_INTERVAL: u64 = 4 * 60 * 60;

/// Default number of top ports for lightweight scans
pub const DEFAULT_LIGHT_SCAN_PORTS: usize = 100;

