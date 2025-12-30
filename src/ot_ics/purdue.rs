//! Purdue Model Classification
//!
//! The Purdue Enterprise Reference Architecture (PERA) model for ICS network segmentation.

use crate::ot_ics::types::*;
use serde::{Deserialize, Serialize};

/// Purdue Model Level
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct PurdueLevel {
    pub level: i32,
    pub name: String,
    pub description: String,
    pub typical_systems: Vec<String>,
}

impl PurdueLevel {
    pub fn all_levels() -> Vec<PurdueLevel> {
        vec![
            PurdueLevel {
                level: 0,
                name: "Process".to_string(),
                description: "Physical process and field devices (sensors, actuators, I/O)".to_string(),
                typical_systems: vec![
                    "Sensors".to_string(),
                    "Actuators".to_string(),
                    "Field I/O".to_string(),
                    "Smart field devices".to_string(),
                ],
            },
            PurdueLevel {
                level: 1,
                name: "Basic Control".to_string(),
                description: "Basic control systems (PLCs, RTUs, DCS controllers)".to_string(),
                typical_systems: vec![
                    "PLCs".to_string(),
                    "RTUs".to_string(),
                    "DCS controllers".to_string(),
                    "Safety systems".to_string(),
                ],
            },
            PurdueLevel {
                level: 2,
                name: "Area Supervisory Control".to_string(),
                description: "HMIs, engineering workstations, local SCADA".to_string(),
                typical_systems: vec![
                    "HMI panels".to_string(),
                    "Engineering workstations".to_string(),
                    "Local SCADA servers".to_string(),
                    "Historian (local)".to_string(),
                ],
            },
            PurdueLevel {
                level: 3,
                name: "Site Manufacturing Operations".to_string(),
                description: "Site-wide manufacturing operations and control".to_string(),
                typical_systems: vec![
                    "SCADA server".to_string(),
                    "Site historian".to_string(),
                    "Batch management".to_string(),
                    "MES".to_string(),
                ],
            },
            PurdueLevel {
                level: 4,
                name: "Site Business Planning".to_string(),
                description: "Business logistics and IT systems".to_string(),
                typical_systems: vec![
                    "ERP systems".to_string(),
                    "Email servers".to_string(),
                    "File servers".to_string(),
                    "Web servers".to_string(),
                ],
            },
            PurdueLevel {
                level: 5,
                name: "Enterprise Network".to_string(),
                description: "Enterprise network and external connections".to_string(),
                typical_systems: vec![
                    "Corporate network".to_string(),
                    "Internet gateway".to_string(),
                    "Cloud services".to_string(),
                    "Remote access".to_string(),
                ],
            },
        ]
    }

    pub fn get_level(level: i32) -> Option<PurdueLevel> {
        Self::all_levels().into_iter().find(|l| l.level == level)
    }

    pub fn get_dmz() -> PurdueLevel {
        PurdueLevel {
            level: 35, // Represents 3.5
            name: "Industrial DMZ".to_string(),
            description: "DMZ between IT and OT networks".to_string(),
            typical_systems: vec![
                "Historian mirror".to_string(),
                "Patch server".to_string(),
                "Jump host".to_string(),
                "Data diode".to_string(),
            ],
        }
    }
}

/// Classify an OT asset into a Purdue level
pub fn classify_asset(asset_type: &OtAssetType, protocols: &[OtProtocolType]) -> i32 {
    match asset_type {
        // Level 0: Field devices
        OtAssetType::FieldDevice => 0,

        // Level 1: Basic control
        OtAssetType::Plc => 1,
        OtAssetType::Rtu => 1,
        OtAssetType::Ied => 1,
        OtAssetType::Sis => 1,
        OtAssetType::Dcs => 1,

        // Level 2: Area control
        OtAssetType::Hmi => 2,
        OtAssetType::EngineeringWorkstation => 2,

        // Level 3: Site operations
        OtAssetType::Scada => {
            // SCADA with historian functions might be higher
            if protocols.contains(&OtProtocolType::OpcUa) {
                3
            } else {
                2
            }
        }
        OtAssetType::Historian => 3,

        // Unknown defaults to Level 1 (conservative)
        OtAssetType::Unknown => 1,
    }
}

/// Purdue Model visualization data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurdueModelView {
    pub levels: Vec<PurdueLevelView>,
    pub dmz: PurdueLevelView,
    pub connections: Vec<PurdueConnection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurdueLevelView {
    pub level: i32,
    pub name: String,
    pub description: String,
    pub asset_count: i32,
    pub assets: Vec<PurdueAssetSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurdueAssetSummary {
    pub id: String,
    pub name: String,
    pub asset_type: String,
    pub ip_address: Option<String>,
    pub criticality: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurdueConnection {
    pub source_level: i32,
    pub target_level: i32,
    pub connection_type: String, // "allowed", "restricted", "blocked"
    pub protocols: Vec<String>,
}

/// Build Purdue Model view from assets
pub fn build_purdue_view(assets: &[OtAsset]) -> PurdueModelView {
    let mut levels: Vec<PurdueLevelView> = PurdueLevel::all_levels()
        .into_iter()
        .map(|l| PurdueLevelView {
            level: l.level,
            name: l.name,
            description: l.description,
            asset_count: 0,
            assets: Vec::new(),
        })
        .collect();

    let dmz = PurdueLevel::get_dmz();
    let mut dmz_view = PurdueLevelView {
        level: dmz.level,
        name: dmz.name,
        description: dmz.description,
        asset_count: 0,
        assets: Vec::new(),
    };

    // Classify assets into levels
    for asset in assets {
        let level = asset.purdue_level.unwrap_or_else(|| {
            classify_asset(&asset.asset_type, &asset.protocols)
        });

        let summary = PurdueAssetSummary {
            id: asset.id.clone(),
            name: asset.name.clone(),
            asset_type: asset.asset_type.to_string(),
            ip_address: asset.ip_address.clone(),
            criticality: asset.criticality.to_string(),
        };

        if level == 35 {
            // DMZ
            dmz_view.asset_count += 1;
            dmz_view.assets.push(summary);
        } else if let Some(level_view) = levels.iter_mut().find(|l| l.level == level) {
            level_view.asset_count += 1;
            level_view.assets.push(summary);
        }
    }

    // Define standard connections between levels
    let connections = vec![
        PurdueConnection {
            source_level: 0,
            target_level: 1,
            connection_type: "allowed".to_string(),
            protocols: vec!["Modbus RTU".to_string(), "HART".to_string(), "Fieldbus".to_string()],
        },
        PurdueConnection {
            source_level: 1,
            target_level: 2,
            connection_type: "allowed".to_string(),
            protocols: vec!["Modbus TCP".to_string(), "EtherNet/IP".to_string(), "OPC".to_string()],
        },
        PurdueConnection {
            source_level: 2,
            target_level: 3,
            connection_type: "allowed".to_string(),
            protocols: vec!["OPC UA".to_string(), "SQL".to_string()],
        },
        PurdueConnection {
            source_level: 3,
            target_level: 35, // DMZ
            connection_type: "restricted".to_string(),
            protocols: vec!["Historian replication".to_string()],
        },
        PurdueConnection {
            source_level: 35, // DMZ
            target_level: 4,
            connection_type: "restricted".to_string(),
            protocols: vec!["HTTPS".to_string(), "Database".to_string()],
        },
        PurdueConnection {
            source_level: 4,
            target_level: 5,
            connection_type: "allowed".to_string(),
            protocols: vec!["HTTPS".to_string(), "VPN".to_string()],
        },
        // Blocked connections (direct IT/OT)
        PurdueConnection {
            source_level: 5,
            target_level: 3,
            connection_type: "blocked".to_string(),
            protocols: Vec::new(),
        },
        PurdueConnection {
            source_level: 4,
            target_level: 2,
            connection_type: "blocked".to_string(),
            protocols: Vec::new(),
        },
    ];

    PurdueModelView {
        levels,
        dmz: dmz_view,
        connections,
    }
}

/// Security recommendations based on Purdue model analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurdueSecurityRecommendation {
    pub severity: String,
    pub title: String,
    pub description: String,
    pub affected_assets: Vec<String>,
    pub remediation: String,
}

/// Analyze Purdue model compliance and generate recommendations
pub fn analyze_purdue_compliance(assets: &[OtAsset]) -> Vec<PurdueSecurityRecommendation> {
    let mut recommendations = Vec::new();

    // Check for assets without Purdue classification
    let unclassified: Vec<String> = assets
        .iter()
        .filter(|a| a.purdue_level.is_none())
        .map(|a| a.name.clone())
        .collect();

    if !unclassified.is_empty() {
        recommendations.push(PurdueSecurityRecommendation {
            severity: "medium".to_string(),
            title: "Unclassified OT Assets".to_string(),
            description: "Some OT assets have not been classified into Purdue model levels.".to_string(),
            affected_assets: unclassified,
            remediation: "Assign Purdue model levels to all OT assets based on their function and network position.".to_string(),
        });
    }

    // Check for Level 0/1 assets with IT protocols
    let level_01_it: Vec<String> = assets
        .iter()
        .filter(|a| {
            let level = a.purdue_level.unwrap_or_else(|| classify_asset(&a.asset_type, &a.protocols));
            level <= 1 && (a.protocols.contains(&OtProtocolType::Mqtt) || a.protocols.contains(&OtProtocolType::Coap))
        })
        .map(|a| a.name.clone())
        .collect();

    if !level_01_it.is_empty() {
        recommendations.push(PurdueSecurityRecommendation {
            severity: "high".to_string(),
            title: "IT Protocols on Level 0/1 Devices".to_string(),
            description: "Low-level OT devices are using IT-oriented protocols (MQTT/CoAP) which may bridge to higher network levels.".to_string(),
            affected_assets: level_01_it,
            remediation: "Ensure proper network segmentation and consider using industrial protocol gateways.".to_string(),
        });
    }

    // Check for critical assets without proper zone assignment
    let critical_no_zone: Vec<String> = assets
        .iter()
        .filter(|a| a.criticality == Criticality::Critical && a.zone.is_none())
        .map(|a| a.name.clone())
        .collect();

    if !critical_no_zone.is_empty() {
        recommendations.push(PurdueSecurityRecommendation {
            severity: "high".to_string(),
            title: "Critical Assets Without Zone Assignment".to_string(),
            description: "Critical OT assets have not been assigned to security zones.".to_string(),
            affected_assets: critical_no_zone,
            remediation: "Assign all critical assets to appropriate security zones with defined conduits.".to_string(),
        });
    }

    recommendations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_asset() {
        assert_eq!(classify_asset(&OtAssetType::Plc, &[]), 1);
        assert_eq!(classify_asset(&OtAssetType::Hmi, &[]), 2);
        assert_eq!(classify_asset(&OtAssetType::FieldDevice, &[]), 0);
    }

    #[test]
    fn test_purdue_levels() {
        let levels = PurdueLevel::all_levels();
        assert_eq!(levels.len(), 6);
        assert_eq!(levels[0].level, 0);
        assert_eq!(levels[5].level, 5);
    }
}
