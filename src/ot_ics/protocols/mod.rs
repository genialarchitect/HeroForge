//! OT/ICS Protocol Scanning Modules
//!
//! This module provides protocol-specific scanners for industrial control systems.
//! Each protocol module can detect the protocol, extract device information,
//! and identify security issues.

pub mod modbus;
pub mod dnp3;
pub mod opcua;
pub mod bacnet;
pub mod ethernetip;
pub mod s7;

use crate::ot_ics::types::{OtProtocolType, ProtocolDetails, SecurityIssue};
use anyhow::Result;
use std::net::SocketAddr;
use std::time::Duration;

/// Common protocol port mappings
pub fn get_default_port(protocol: &OtProtocolType) -> u16 {
    match protocol {
        OtProtocolType::Modbus => 502,
        OtProtocolType::Dnp3 => 20000,
        OtProtocolType::OpcUa => 4840,
        OtProtocolType::Bacnet => 47808,
        OtProtocolType::EthernetIp => 44818,
        OtProtocolType::S7 => 102,
        OtProtocolType::Iec61850 => 102,
        OtProtocolType::Profinet => 34964,
        OtProtocolType::Hart => 5094,
        OtProtocolType::Cip => 44818,
        OtProtocolType::Mqtt => 1883,
        OtProtocolType::Coap => 5683,
    }
}

/// Protocol scan result
#[derive(Debug, Clone)]
pub struct ProtocolScanResult {
    pub protocol: OtProtocolType,
    pub port: u16,
    pub detected: bool,
    pub details: ProtocolDetails,
    pub security_issues: Vec<SecurityIssue>,
    pub response_time_ms: u64,
}

/// Trait for protocol scanners
#[async_trait::async_trait]
pub trait ProtocolScanner: Send + Sync {
    /// Get the protocol type this scanner handles
    fn protocol_type(&self) -> OtProtocolType;

    /// Get the default port for this protocol
    fn default_port(&self) -> u16;

    /// Check if the protocol is present on the target
    async fn detect(&self, addr: SocketAddr, timeout: Duration) -> Result<bool>;

    /// Scan and extract protocol details
    async fn scan(&self, addr: SocketAddr, timeout: Duration) -> Result<ProtocolScanResult>;
}

/// Create all protocol scanners
pub fn create_scanners() -> Vec<Box<dyn ProtocolScanner>> {
    vec![
        Box::new(modbus::ModbusScanner::new()),
        Box::new(dnp3::Dnp3Scanner::new()),
        Box::new(opcua::OpcUaScanner::new()),
        Box::new(bacnet::BacnetScanner::new()),
        Box::new(ethernetip::EthernetIpScanner::new()),
        Box::new(s7::S7Scanner::new()),
    ]
}

/// Get a scanner for a specific protocol
pub fn get_scanner(protocol: &OtProtocolType) -> Option<Box<dyn ProtocolScanner>> {
    match protocol {
        OtProtocolType::Modbus => Some(Box::new(modbus::ModbusScanner::new())),
        OtProtocolType::Dnp3 => Some(Box::new(dnp3::Dnp3Scanner::new())),
        OtProtocolType::OpcUa => Some(Box::new(opcua::OpcUaScanner::new())),
        OtProtocolType::Bacnet => Some(Box::new(bacnet::BacnetScanner::new())),
        OtProtocolType::EthernetIp => Some(Box::new(ethernetip::EthernetIpScanner::new())),
        OtProtocolType::S7 => Some(Box::new(s7::S7Scanner::new())),
        _ => None, // Other protocols not yet implemented
    }
}
