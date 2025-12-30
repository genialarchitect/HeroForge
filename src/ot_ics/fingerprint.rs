//! OT Device Fingerprinting
//!
//! Fingerprint OT/ICS devices based on protocol responses.

use crate::ot_ics::types::*;
use crate::ot_ics::protocols::ProtocolScanResult;
use std::collections::HashMap;

/// Device fingerprint database entry
#[derive(Debug, Clone)]
pub struct DeviceFingerprint {
    pub vendor: String,
    pub model: Option<String>,
    pub asset_type: OtAssetType,
    pub description: String,
}

/// OT Device Fingerprinter
pub struct OtFingerprinter {
    /// Known device fingerprints
    fingerprints: HashMap<String, DeviceFingerprint>,
}

impl OtFingerprinter {
    pub fn new() -> Self {
        let mut fingerprints = HashMap::new();

        // Siemens devices
        fingerprints.insert(
            "siemens:6ES7".to_string(),
            DeviceFingerprint {
                vendor: "Siemens".to_string(),
                model: Some("SIMATIC S7".to_string()),
                asset_type: OtAssetType::Plc,
                description: "Siemens SIMATIC S7 PLC".to_string(),
            },
        );
        fingerprints.insert(
            "siemens:6ES7214".to_string(),
            DeviceFingerprint {
                vendor: "Siemens".to_string(),
                model: Some("S7-1200".to_string()),
                asset_type: OtAssetType::Plc,
                description: "Siemens SIMATIC S7-1200 CPU".to_string(),
            },
        );
        fingerprints.insert(
            "siemens:6ES7315".to_string(),
            DeviceFingerprint {
                vendor: "Siemens".to_string(),
                model: Some("S7-300".to_string()),
                asset_type: OtAssetType::Plc,
                description: "Siemens SIMATIC S7-300 CPU".to_string(),
            },
        );
        fingerprints.insert(
            "siemens:6ES7416".to_string(),
            DeviceFingerprint {
                vendor: "Siemens".to_string(),
                model: Some("S7-400".to_string()),
                asset_type: OtAssetType::Plc,
                description: "Siemens SIMATIC S7-400 CPU".to_string(),
            },
        );
        fingerprints.insert(
            "siemens:6ES7512".to_string(),
            DeviceFingerprint {
                vendor: "Siemens".to_string(),
                model: Some("S7-1500".to_string()),
                asset_type: OtAssetType::Plc,
                description: "Siemens SIMATIC S7-1500 CPU".to_string(),
            },
        );

        // Rockwell/Allen-Bradley devices
        fingerprints.insert(
            "rockwell:1756".to_string(),
            DeviceFingerprint {
                vendor: "Rockwell Automation".to_string(),
                model: Some("ControlLogix".to_string()),
                asset_type: OtAssetType::Plc,
                description: "Allen-Bradley ControlLogix PLC".to_string(),
            },
        );
        fingerprints.insert(
            "rockwell:1769".to_string(),
            DeviceFingerprint {
                vendor: "Rockwell Automation".to_string(),
                model: Some("CompactLogix".to_string()),
                asset_type: OtAssetType::Plc,
                description: "Allen-Bradley CompactLogix PLC".to_string(),
            },
        );
        fingerprints.insert(
            "rockwell:2711".to_string(),
            DeviceFingerprint {
                vendor: "Rockwell Automation".to_string(),
                model: Some("PanelView".to_string()),
                asset_type: OtAssetType::Hmi,
                description: "Allen-Bradley PanelView HMI".to_string(),
            },
        );

        // Schneider Electric devices
        fingerprints.insert(
            "schneider:modicon".to_string(),
            DeviceFingerprint {
                vendor: "Schneider Electric".to_string(),
                model: Some("Modicon".to_string()),
                asset_type: OtAssetType::Plc,
                description: "Schneider Electric Modicon PLC".to_string(),
            },
        );
        fingerprints.insert(
            "schneider:m340".to_string(),
            DeviceFingerprint {
                vendor: "Schneider Electric".to_string(),
                model: Some("Modicon M340".to_string()),
                asset_type: OtAssetType::Plc,
                description: "Schneider Electric Modicon M340 PLC".to_string(),
            },
        );

        // ABB devices
        fingerprints.insert(
            "abb:ac500".to_string(),
            DeviceFingerprint {
                vendor: "ABB".to_string(),
                model: Some("AC500".to_string()),
                asset_type: OtAssetType::Plc,
                description: "ABB AC500 PLC".to_string(),
            },
        );

        // GE devices
        fingerprints.insert(
            "ge:pacsystems".to_string(),
            DeviceFingerprint {
                vendor: "GE".to_string(),
                model: Some("PACSystems".to_string()),
                asset_type: OtAssetType::Plc,
                description: "GE PACSystems PLC".to_string(),
            },
        );

        Self { fingerprints }
    }

    /// Fingerprint a device based on scan results
    pub fn fingerprint(&self, scan_results: &[ProtocolScanResult]) -> Option<DeviceFingerprint> {
        for result in scan_results {
            // Try to match based on vendor info
            if let Some(vendor_info) = &result.details.vendor_info {
                let vendor_lower = vendor_info.to_lowercase();

                // Siemens
                if vendor_lower.contains("siemens") {
                    // Try to get specific model from device ID
                    if let Some(device_id) = &result.details.device_id {
                        for (key, fp) in &self.fingerprints {
                            if key.starts_with("siemens:") && device_id.contains(&key[8..]) {
                                return Some(fp.clone());
                            }
                        }
                    }
                    // Generic Siemens
                    return self.fingerprints.get("siemens:6ES7").cloned();
                }

                // Rockwell Automation
                if vendor_lower.contains("rockwell") || vendor_lower.contains("allen-bradley") {
                    if let Some(metadata) = result.details.metadata.as_object() {
                        if let Some(product_code) = metadata.get("product_code") {
                            let code = product_code.to_string();
                            if code.contains("1756") {
                                return self.fingerprints.get("rockwell:1756").cloned();
                            }
                            if code.contains("1769") {
                                return self.fingerprints.get("rockwell:1769").cloned();
                            }
                            if code.contains("2711") {
                                return self.fingerprints.get("rockwell:2711").cloned();
                            }
                        }
                    }
                }

                // Schneider Electric
                if vendor_lower.contains("schneider") || vendor_lower.contains("modicon") {
                    return self.fingerprints.get("schneider:modicon").cloned();
                }

                // ABB
                if vendor_lower.contains("abb") {
                    return self.fingerprints.get("abb:ac500").cloned();
                }

                // GE
                if vendor_lower.contains("ge") || vendor_lower.contains("general electric") {
                    return self.fingerprints.get("ge:pacsystems").cloned();
                }
            }
        }

        None
    }

    /// Get all known fingerprints for a vendor
    pub fn get_vendor_fingerprints(&self, vendor: &str) -> Vec<DeviceFingerprint> {
        let vendor_lower = vendor.to_lowercase();
        self.fingerprints
            .iter()
            .filter(|(k, _)| k.starts_with(&vendor_lower) || k.contains(&format!(":{}", vendor_lower)))
            .map(|(_, v)| v.clone())
            .collect()
    }

    /// Get supported vendors
    pub fn get_supported_vendors(&self) -> Vec<String> {
        let mut vendors: Vec<String> = self
            .fingerprints
            .values()
            .map(|fp| fp.vendor.clone())
            .collect();
        vendors.sort();
        vendors.dedup();
        vendors
    }
}

impl Default for OtFingerprinter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supported_vendors() {
        let fp = OtFingerprinter::new();
        let vendors = fp.get_supported_vendors();
        assert!(vendors.contains(&"Siemens".to_string()));
        assert!(vendors.contains(&"Rockwell Automation".to_string()));
    }
}
