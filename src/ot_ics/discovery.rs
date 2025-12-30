//! OT Asset Discovery
//!
//! Discovers OT/ICS assets on the network using protocol probes.

use crate::ot_ics::types::*;
use crate::ot_ics::protocols::{self, ProtocolScanner, ProtocolScanResult};
use anyhow::Result;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

/// OT Discovery Engine
pub struct OtDiscoveryEngine {
    /// Timeout for each probe
    timeout: Duration,
    /// Maximum concurrent connections
    max_concurrent: usize,
}

impl OtDiscoveryEngine {
    pub fn new(timeout: Duration, max_concurrent: usize) -> Self {
        Self {
            timeout,
            max_concurrent,
        }
    }

    /// Discover OT assets on the given IP addresses
    pub async fn discover(&self, targets: &[IpAddr], protocols_to_scan: &[OtProtocolType]) -> Result<Vec<DiscoveredAsset>> {
        let mut discovered = Vec::new();
        let semaphore = Arc::new(Semaphore::new(self.max_concurrent));

        // Create scanner instances for enabled protocols
        let scanners: Vec<Box<dyn ProtocolScanner>> = protocols_to_scan
            .iter()
            .filter_map(|p| protocols::get_scanner(p))
            .collect();

        // Scan each target
        let mut handles = Vec::new();

        for &ip in targets {
            for scanner in &scanners {
                let port = scanner.default_port();
                let addr = SocketAddr::new(ip, port);
                let timeout = self.timeout;
                let protocol = scanner.protocol_type();
                let permit = semaphore.clone().acquire_owned().await?;

                // Clone the scanner for the async task
                let scanner = protocols::get_scanner(&protocol).unwrap();

                let handle = tokio::spawn(async move {
                    let result = scanner.scan(addr, timeout).await;
                    drop(permit);
                    (ip, result)
                });
                handles.push(handle);
            }
        }

        // Collect results
        let mut asset_map: HashMap<IpAddr, DiscoveredAsset> = HashMap::new();

        for handle in handles {
            if let Ok((ip, Ok(result))) = handle.await {
                if result.detected {
                    let asset = asset_map.entry(ip).or_insert_with(|| DiscoveredAsset {
                        ip_address: ip.to_string(),
                        protocols: Vec::new(),
                        scan_results: Vec::new(),
                        suggested_type: None,
                        suggested_vendor: None,
                    });

                    asset.protocols.push(result.protocol.clone());
                    asset.scan_results.push(result.clone());

                    // Update suggested info based on scan results
                    if let Some(vendor) = &result.details.vendor_info {
                        asset.suggested_vendor = Some(vendor.clone());
                    }
                }
            }
        }

        // Infer asset types from discovered protocols
        for (_, asset) in asset_map.iter_mut() {
            asset.suggested_type = Some(infer_asset_type(&asset.protocols));
        }

        discovered.extend(asset_map.into_values());
        Ok(discovered)
    }

    /// Scan a specific IP and port for a protocol
    pub async fn probe_protocol(
        &self,
        ip: IpAddr,
        port: u16,
        protocol: &OtProtocolType,
    ) -> Result<Option<ProtocolScanResult>> {
        if let Some(scanner) = protocols::get_scanner(protocol) {
            let addr = SocketAddr::new(ip, port);
            let result = scanner.scan(addr, self.timeout).await?;
            if result.detected {
                return Ok(Some(result));
            }
        }
        Ok(None)
    }
}

impl Default for OtDiscoveryEngine {
    fn default() -> Self {
        Self::new(Duration::from_secs(5), 20)
    }
}

/// Discovered asset during scanning
#[derive(Debug, Clone)]
pub struct DiscoveredAsset {
    pub ip_address: String,
    pub protocols: Vec<OtProtocolType>,
    pub scan_results: Vec<ProtocolScanResult>,
    pub suggested_type: Option<OtAssetType>,
    pub suggested_vendor: Option<String>,
}

/// Infer asset type from detected protocols
fn infer_asset_type(protocols: &[OtProtocolType]) -> OtAssetType {
    // Priority-based type inference
    if protocols.contains(&OtProtocolType::S7) {
        return OtAssetType::Plc;
    }
    if protocols.contains(&OtProtocolType::Modbus) {
        // Modbus is common on PLCs, RTUs, and many devices
        return OtAssetType::Plc;
    }
    if protocols.contains(&OtProtocolType::Dnp3) {
        // DNP3 is typically SCADA/RTU
        return OtAssetType::Rtu;
    }
    if protocols.contains(&OtProtocolType::EthernetIp) {
        return OtAssetType::Plc;
    }
    if protocols.contains(&OtProtocolType::OpcUa) {
        // OPC UA could be many things, often HMI or SCADA
        return OtAssetType::Scada;
    }
    if protocols.contains(&OtProtocolType::Bacnet) {
        // BACnet is building automation
        return OtAssetType::FieldDevice;
    }
    if protocols.contains(&OtProtocolType::Iec61850) {
        // IEC 61850 is for IEDs in power systems
        return OtAssetType::Ied;
    }

    OtAssetType::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_infer_asset_type() {
        assert_eq!(infer_asset_type(&[OtProtocolType::S7]), OtAssetType::Plc);
        assert_eq!(infer_asset_type(&[OtProtocolType::Dnp3]), OtAssetType::Rtu);
        assert_eq!(infer_asset_type(&[OtProtocolType::Bacnet]), OtAssetType::FieldDevice);
        assert_eq!(infer_asset_type(&[]), OtAssetType::Unknown);
    }
}
