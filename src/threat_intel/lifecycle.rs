//! Threat Intelligence Lifecycle Management
//!
//! Manages the full lifecycle of threat intelligence:
//! - Priority Intelligence Requirements (PIRs)
//! - Diamond Model mapping
//! - Cyber Kill Chain mapping
//! - Intelligence dissemination

use anyhow::Result;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// Priority Intelligence Requirement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriorityIntelRequirement {
    pub id: String,
    pub title: String,
    pub description: String,
    pub priority: PirPriority,
    pub status: PirStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub due_date: Option<DateTime<Utc>>,
    pub requester: String,
    pub assigned_to: Option<String>,
    pub tags: Vec<String>,
    pub related_iocs: Vec<String>,
    pub collection_sources: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PirPriority {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PirStatus {
    Open,
    InProgress,
    AwaitingReview,
    Completed,
    Cancelled,
}

/// Diamond Model representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiamondModel {
    pub adversary: AdversaryVertex,
    pub capability: CapabilityVertex,
    pub infrastructure: InfrastructureVertex,
    pub victim: VictimVertex,
    pub meta_features: MetaFeatures,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdversaryVertex {
    pub id: Option<String>,
    pub name: Option<String>,
    pub aliases: Vec<String>,
    pub motivation: Option<String>,
    pub sophistication: Option<String>,
    pub country: Option<String>,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityVertex {
    pub malware_families: Vec<String>,
    pub tools: Vec<String>,
    pub techniques: Vec<String>,
    pub exploits: Vec<String>,
    pub ttps: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfrastructureVertex {
    pub domains: Vec<String>,
    pub ip_addresses: Vec<String>,
    pub urls: Vec<String>,
    pub email_addresses: Vec<String>,
    pub certificates: Vec<String>,
    pub hosting_providers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VictimVertex {
    pub sectors: Vec<String>,
    pub countries: Vec<String>,
    pub organizations: Vec<String>,
    pub assets_targeted: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaFeatures {
    pub timestamp: Option<DateTime<Utc>>,
    pub phase: Option<String>,
    pub result: Option<String>,
    pub direction: Option<String>,
    pub methodology: Option<String>,
    pub resources: Option<String>,
}

/// Cyber Kill Chain phase
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum KillChainPhase {
    Reconnaissance,
    Weaponization,
    Delivery,
    Exploitation,
    Installation,
    CommandAndControl,
    ActionsOnObjectives,
}

impl std::fmt::Display for KillChainPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Reconnaissance => write!(f, "Reconnaissance"),
            Self::Weaponization => write!(f, "Weaponization"),
            Self::Delivery => write!(f, "Delivery"),
            Self::Exploitation => write!(f, "Exploitation"),
            Self::Installation => write!(f, "Installation"),
            Self::CommandAndControl => write!(f, "Command & Control"),
            Self::ActionsOnObjectives => write!(f, "Actions on Objectives"),
        }
    }
}

/// Kill Chain mapping result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillChainMapping {
    pub phase: KillChainPhase,
    pub indicators: Vec<String>,
    pub techniques: Vec<String>,
    pub confidence: f32,
    pub description: String,
}

/// Manage Priority Intelligence Requirements
pub async fn manage_pir(pir: PriorityIntelRequirement) -> Result<PriorityIntelRequirement> {
    log::info!("Managing PIR: {} ({})", pir.title, pir.id);

    // Validate PIR fields
    if pir.title.is_empty() {
        anyhow::bail!("PIR title cannot be empty");
    }

    // In production, this would persist to database
    // For now, return the PIR with updated timestamp
    let mut updated_pir = pir;
    updated_pir.updated_at = Utc::now();

    Ok(updated_pir)
}

/// Create a new PIR
pub fn create_pir(
    title: &str,
    description: &str,
    priority: PirPriority,
    requester: &str,
) -> PriorityIntelRequirement {
    let now = Utc::now();
    PriorityIntelRequirement {
        id: uuid::Uuid::new_v4().to_string(),
        title: title.to_string(),
        description: description.to_string(),
        priority,
        status: PirStatus::Open,
        created_at: now,
        updated_at: now,
        due_date: None,
        requester: requester.to_string(),
        assigned_to: None,
        tags: Vec::new(),
        related_iocs: Vec::new(),
        collection_sources: Vec::new(),
    }
}

/// Map IOCs to the Diamond Model
pub fn map_to_diamond_model(iocs: &[String]) -> Result<serde_json::Value> {
    log::info!("Mapping {} IOCs to Diamond Model", iocs.len());

    let mut adversary = AdversaryVertex {
        id: None,
        name: None,
        aliases: Vec::new(),
        motivation: None,
        sophistication: None,
        country: None,
        confidence: 0.0,
    };

    let mut capability = CapabilityVertex {
        malware_families: Vec::new(),
        tools: Vec::new(),
        techniques: Vec::new(),
        exploits: Vec::new(),
        ttps: Vec::new(),
    };

    let mut infrastructure = InfrastructureVertex {
        domains: Vec::new(),
        ip_addresses: Vec::new(),
        urls: Vec::new(),
        email_addresses: Vec::new(),
        certificates: Vec::new(),
        hosting_providers: Vec::new(),
    };

    let victim = VictimVertex {
        sectors: Vec::new(),
        countries: Vec::new(),
        organizations: Vec::new(),
        assets_targeted: Vec::new(),
    };

    // Classify IOCs into Diamond Model vertices
    for ioc in iocs {
        let ioc_lower = ioc.to_lowercase();

        // Classify by IOC type pattern
        if is_ip_address(ioc) {
            infrastructure.ip_addresses.push(ioc.clone());
        } else if is_domain(ioc) {
            infrastructure.domains.push(ioc.clone());
        } else if is_url(ioc) {
            infrastructure.urls.push(ioc.clone());
        } else if is_email(ioc) {
            infrastructure.email_addresses.push(ioc.clone());
        } else if is_file_hash(ioc) {
            capability.malware_families.push(ioc.clone());
        } else if ioc_lower.starts_with("cve-") {
            capability.exploits.push(ioc.clone());
        } else if ioc_lower.starts_with("t") && ioc_lower.contains(".") {
            // MITRE ATT&CK technique pattern (e.g., T1059.001)
            capability.techniques.push(ioc.clone());
        } else if ioc_lower.contains("apt") || ioc_lower.contains("group") {
            adversary.aliases.push(ioc.clone());
        }
    }

    // Set confidence based on data completeness
    let mut confidence_score = 0.0;
    if !infrastructure.ip_addresses.is_empty() || !infrastructure.domains.is_empty() {
        confidence_score += 0.25;
    }
    if !capability.malware_families.is_empty() || !capability.techniques.is_empty() {
        confidence_score += 0.25;
    }
    if !adversary.aliases.is_empty() {
        confidence_score += 0.25;
    }
    adversary.confidence = confidence_score;

    let diamond = DiamondModel {
        adversary,
        capability,
        infrastructure,
        victim,
        meta_features: MetaFeatures {
            timestamp: Some(Utc::now()),
            phase: None,
            result: None,
            direction: None,
            methodology: None,
            resources: None,
        },
    };

    Ok(serde_json::to_value(diamond)?)
}

/// Map IOCs to Cyber Kill Chain phases
pub fn map_to_kill_chain(iocs: &[String]) -> Result<Vec<KillChainMapping>> {
    log::info!("Mapping {} IOCs to Cyber Kill Chain", iocs.len());

    let mut mappings: HashMap<KillChainPhase, KillChainMapping> = HashMap::new();

    // Initialize all phases
    for phase in [
        KillChainPhase::Reconnaissance,
        KillChainPhase::Weaponization,
        KillChainPhase::Delivery,
        KillChainPhase::Exploitation,
        KillChainPhase::Installation,
        KillChainPhase::CommandAndControl,
        KillChainPhase::ActionsOnObjectives,
    ] {
        mappings.insert(phase.clone(), KillChainMapping {
            phase: phase.clone(),
            indicators: Vec::new(),
            techniques: Vec::new(),
            confidence: 0.0,
            description: get_phase_description(&phase),
        });
    }

    // Classify IOCs into kill chain phases
    for ioc in iocs {
        let ioc_lower = ioc.to_lowercase();

        // Map based on IOC patterns and context
        if is_domain(ioc) || is_ip_address(ioc) {
            // Domains/IPs can be C2 or recon
            if ioc_lower.contains("scan") || ioc_lower.contains("recon") {
                if let Some(m) = mappings.get_mut(&KillChainPhase::Reconnaissance) {
                    m.indicators.push(ioc.clone());
                }
            } else {
                if let Some(m) = mappings.get_mut(&KillChainPhase::CommandAndControl) {
                    m.indicators.push(ioc.clone());
                }
            }
        } else if is_url(ioc) {
            // URLs typically indicate delivery or C2
            if ioc_lower.contains("download") || ioc_lower.contains("payload") {
                if let Some(m) = mappings.get_mut(&KillChainPhase::Delivery) {
                    m.indicators.push(ioc.clone());
                }
            } else {
                if let Some(m) = mappings.get_mut(&KillChainPhase::CommandAndControl) {
                    m.indicators.push(ioc.clone());
                }
            }
        } else if is_file_hash(ioc) {
            // File hashes are typically malware (weaponization or installation)
            if let Some(m) = mappings.get_mut(&KillChainPhase::Weaponization) {
                m.indicators.push(ioc.clone());
            }
            if let Some(m) = mappings.get_mut(&KillChainPhase::Installation) {
                m.indicators.push(ioc.clone());
            }
        } else if ioc_lower.starts_with("cve-") {
            // CVEs indicate exploitation
            if let Some(m) = mappings.get_mut(&KillChainPhase::Exploitation) {
                m.indicators.push(ioc.clone());
            }
        } else if ioc_lower.starts_with("t1") {
            // MITRE ATT&CK techniques - map based on technique category
            let phase = map_mitre_to_killchain(&ioc_lower);
            if let Some(m) = mappings.get_mut(&phase) {
                m.techniques.push(ioc.clone());
            }
        }
    }

    // Calculate confidence for each phase
    for mapping in mappings.values_mut() {
        let indicator_count = mapping.indicators.len() + mapping.techniques.len();
        mapping.confidence = match indicator_count {
            0 => 0.0,
            1..=2 => 0.3,
            3..=5 => 0.6,
            _ => 0.9,
        };
    }

    // Return only phases with indicators
    Ok(mappings
        .into_values()
        .filter(|m| !m.indicators.is_empty() || !m.techniques.is_empty())
        .collect())
}

/// Map MITRE ATT&CK technique to kill chain phase
fn map_mitre_to_killchain(technique: &str) -> KillChainPhase {
    // Based on technique ID prefix
    if technique.starts_with("t1595") || technique.starts_with("t1592") ||
       technique.starts_with("t1589") || technique.starts_with("t1590") {
        KillChainPhase::Reconnaissance
    } else if technique.starts_with("t1587") || technique.starts_with("t1588") ||
              technique.starts_with("t1583") || technique.starts_with("t1584") {
        KillChainPhase::Weaponization
    } else if technique.starts_with("t1566") || technique.starts_with("t1091") ||
              technique.starts_with("t1195") {
        KillChainPhase::Delivery
    } else if technique.starts_with("t1190") || technique.starts_with("t1203") ||
              technique.starts_with("t1211") || technique.starts_with("t1212") {
        KillChainPhase::Exploitation
    } else if technique.starts_with("t1547") || technique.starts_with("t1543") ||
              technique.starts_with("t1053") || technique.starts_with("t1136") {
        KillChainPhase::Installation
    } else if technique.starts_with("t1071") || technique.starts_with("t1102") ||
              technique.starts_with("t1105") || technique.starts_with("t1573") {
        KillChainPhase::CommandAndControl
    } else {
        KillChainPhase::ActionsOnObjectives
    }
}

/// Get description for kill chain phase
fn get_phase_description(phase: &KillChainPhase) -> String {
    match phase {
        KillChainPhase::Reconnaissance =>
            "Adversary gathering information about the target".to_string(),
        KillChainPhase::Weaponization =>
            "Adversary creating malicious payload or tool".to_string(),
        KillChainPhase::Delivery =>
            "Adversary transmitting payload to target environment".to_string(),
        KillChainPhase::Exploitation =>
            "Adversary exploiting vulnerability to gain access".to_string(),
        KillChainPhase::Installation =>
            "Adversary installing persistence mechanisms".to_string(),
        KillChainPhase::CommandAndControl =>
            "Adversary establishing C2 channel for remote access".to_string(),
        KillChainPhase::ActionsOnObjectives =>
            "Adversary achieving their goals (data theft, destruction, etc.)".to_string(),
    }
}

/// Check if string is an IP address
fn is_ip_address(s: &str) -> bool {
    // IPv4 pattern
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() == 4 {
        return parts.iter().all(|p| p.parse::<u8>().is_ok());
    }
    // IPv6 pattern (simplified check)
    s.contains(':') && s.chars().all(|c| c.is_ascii_hexdigit() || c == ':')
}

/// Check if string is a domain
fn is_domain(s: &str) -> bool {
    !s.contains('/') &&
    !s.contains('@') &&
    s.contains('.') &&
    !is_ip_address(s) &&
    !is_file_hash(s)
}

/// Check if string is a URL
fn is_url(s: &str) -> bool {
    s.starts_with("http://") || s.starts_with("https://") || s.starts_with("ftp://")
}

/// Check if string is an email
fn is_email(s: &str) -> bool {
    s.contains('@') && s.contains('.')
}

/// Check if string is a file hash
fn is_file_hash(s: &str) -> bool {
    let len = s.len();
    // MD5 (32), SHA1 (40), SHA256 (64), SHA512 (128)
    (len == 32 || len == 40 || len == 64 || len == 128) &&
    s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Intelligence dissemination tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisseminationRecord {
    pub id: String,
    pub intel_id: String,
    pub recipient: String,
    pub channel: DisseminationChannel,
    pub timestamp: DateTime<Utc>,
    pub acknowledged: bool,
    pub feedback: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DisseminationChannel {
    Email,
    ThreatFeed,
    SiemAlert,
    Api,
    Manual,
}

/// Track intelligence dissemination
pub async fn track_dissemination(
    intel_id: &str,
    recipient: &str,
    channel: DisseminationChannel,
) -> Result<DisseminationRecord> {
    let record = DisseminationRecord {
        id: uuid::Uuid::new_v4().to_string(),
        intel_id: intel_id.to_string(),
        recipient: recipient.to_string(),
        channel,
        timestamp: Utc::now(),
        acknowledged: false,
        feedback: None,
    };

    log::info!(
        "Intelligence {} disseminated to {} via {:?}",
        intel_id,
        recipient,
        record.channel
    );

    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_ip_address() {
        assert!(is_ip_address("192.168.1.1"));
        assert!(is_ip_address("8.8.8.8"));
        assert!(!is_ip_address("example.com"));
        assert!(!is_ip_address("not-an-ip"));
    }

    #[test]
    fn test_is_domain() {
        assert!(is_domain("example.com"));
        assert!(is_domain("sub.example.com"));
        assert!(!is_domain("192.168.1.1"));
        assert!(!is_domain("http://example.com"));
    }

    #[test]
    fn test_is_file_hash() {
        assert!(is_file_hash("d41d8cd98f00b204e9800998ecf8427e")); // MD5
        assert!(is_file_hash("da39a3ee5e6b4b0d3255bfef95601890afd80709")); // SHA1
        assert!(!is_file_hash("not-a-hash"));
    }

    #[test]
    fn test_map_to_diamond_model() {
        let iocs = vec![
            "192.168.1.1".to_string(),
            "evil.com".to_string(),
            "d41d8cd98f00b204e9800998ecf8427e".to_string(),
            "CVE-2021-44228".to_string(),
            "T1059.001".to_string(),
        ];

        let result = map_to_diamond_model(&iocs).unwrap();
        let diamond: DiamondModel = serde_json::from_value(result).unwrap();

        assert!(!diamond.infrastructure.ip_addresses.is_empty());
        assert!(!diamond.infrastructure.domains.is_empty());
        assert!(!diamond.capability.exploits.is_empty());
    }

    #[test]
    fn test_map_to_kill_chain() {
        let iocs = vec![
            "192.168.1.1".to_string(),
            "CVE-2021-44228".to_string(),
            "T1566.001".to_string(), // Phishing - Delivery
        ];

        let mappings = map_to_kill_chain(&iocs).unwrap();
        assert!(!mappings.is_empty());

        // Should have exploitation phase for CVE
        let has_exploitation = mappings.iter().any(|m| m.phase == KillChainPhase::Exploitation);
        assert!(has_exploitation);
    }

    #[test]
    fn test_create_pir() {
        let pir = create_pir(
            "Track APT29 Activity",
            "Monitor for APT29 indicators in our environment",
            PirPriority::High,
            "analyst@company.com",
        );

        assert!(!pir.id.is_empty());
        assert_eq!(pir.priority, PirPriority::High);
        assert_eq!(pir.status, PirStatus::Open);
    }
}
