//! OT/ICS (Operational Technology / Industrial Control Systems) Security Module
//!
//! This module provides scanning and assessment capabilities for industrial control systems:
//! - OT asset discovery via protocol probes
//! - Industrial protocol scanning (Modbus, DNP3, OPC UA, BACnet, EtherNet/IP, S7)
//! - Device fingerprinting based on protocol responses
//! - Purdue Model classification for network segmentation analysis
//! - Security issue identification (no auth, cleartext, etc.)

pub mod types;
pub mod discovery;
pub mod protocols;
pub mod fingerprint;
pub mod purdue;

pub use types::*;
pub use discovery::*;
pub use fingerprint::*;
pub use purdue::*;
