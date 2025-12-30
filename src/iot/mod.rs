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

pub use types::*;
pub use discovery::*;
pub use credentials::*;
