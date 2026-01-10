//! IoT (Internet of Things) Security Module
//!
//! This module provides IoT device security assessment capabilities:
//! - Device discovery via mDNS, SSDP/UPnP, MQTT broker discovery
//! - Default credential checking
//! - Protocol scanning (MQTT, CoAP)
//! - Vulnerability assessment for common IoT devices

pub mod types;
pub mod discovery;
pub mod credentials;
pub mod protocols;
// Phase 4 Sprint 10: Enhanced IoT Security
pub mod profiling;
pub mod vulnerability;
pub mod threat_detection;
pub mod lifecycle;

