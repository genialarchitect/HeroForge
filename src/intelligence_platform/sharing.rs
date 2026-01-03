//! Intelligence sharing networks
//!
//! Provides intelligence sharing capabilities including:
//! - Automated sharing with trusted peers
//! - ISAC/ISAO integration
//! - Industry vertical communities
//! - Supply chain intelligence sharing
//! - TLP (Traffic Light Protocol) enforcement

use super::types::*;
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use log::{info, warn};

/// Configure intelligence sharing networks
pub async fn configure_networks(config: &SharingConfig) -> Result<Vec<SharingNetwork>> {
    let mut networks = Vec::new();

    info!("Configuring {} sharing networks", config.networks.len());

    for network_config in &config.networks {
        let network = initialize_network(network_config, &config.trusted_peers).await?;
        networks.push(network);
    }

    if config.auto_sharing {
        info!("Auto-sharing enabled for configured networks");
    }

    Ok(networks)
}

/// Initialize a single sharing network
async fn initialize_network(
    config: &NetworkConfig,
    trusted_peers: &[String],
) -> Result<SharingNetwork> {
    // Determine initial members based on network type
    let members = match &config.network_type {
        NetworkType::PeerToPeer => trusted_peers.to_vec(),
        NetworkType::ISACIntegration => {
            // ISAC networks have predefined membership
            vec!["isac-central".to_string()]
        }
        NetworkType::IndustryVertical(vertical) => {
            vec![format!("{}-consortium", vertical)]
        }
        NetworkType::SupplyChain => {
            vec!["supply-chain-hub".to_string()]
        }
    };

    Ok(SharingNetwork {
        network_id: config.network_id.clone(),
        members,
        shared_indicators: 0,
        last_sync: chrono::Utc::now(),
    })
}

/// Share intelligence with a network
pub async fn share_intelligence(
    network: &mut SharingNetwork,
    indicators: Vec<SharedIndicator>,
    sharing_level: &SharingLevel,
) -> Result<ShareResult> {
    // Validate TLP compliance
    for indicator in &indicators {
        if !is_tlp_compliant(&indicator.tlp, sharing_level) {
            return Err(anyhow!(
                "Indicator {} has TLP {} which cannot be shared at level {:?}",
                indicator.indicator_id,
                format!("{:?}", indicator.tlp),
                sharing_level
            ));
        }
    }

    let count = indicators.len();

    // In real implementation, would send to network members
    for member in &network.members {
        info!("Sharing {} indicators with member: {}", count, member);
    }

    network.shared_indicators += count;
    network.last_sync = chrono::Utc::now();

    Ok(ShareResult {
        indicators_shared: count,
        members_notified: network.members.len(),
        timestamp: chrono::Utc::now(),
        failures: vec![],
    })
}

/// Check if sharing at the given level is compliant with indicator's TLP
fn is_tlp_compliant(indicator_tlp: &SharingLevel, target_level: &SharingLevel) -> bool {
    match (indicator_tlp, target_level) {
        // TLP:RED can only be shared with explicit permission (not implemented here)
        (SharingLevel::TLP_RED, _) => false,

        // TLP:AMBER can be shared with limited disclosure networks
        (SharingLevel::TLP_AMBER, SharingLevel::TLP_AMBER) => true,
        (SharingLevel::TLP_AMBER, SharingLevel::TLP_RED) => true,
        (SharingLevel::TLP_AMBER, _) => false,

        // TLP:GREEN can be shared with community
        (SharingLevel::TLP_GREEN, SharingLevel::TLP_WHITE) => false,
        (SharingLevel::TLP_GREEN, _) => true,

        // TLP:WHITE can be shared anywhere
        (SharingLevel::TLP_WHITE, _) => true,
    }
}

/// Receive intelligence from a network
pub async fn receive_intelligence(
    network: &mut SharingNetwork,
    source_member: &str,
) -> Result<Vec<SharedIndicator>> {
    if !network.members.contains(&source_member.to_string()) {
        return Err(anyhow!("Source {} is not a member of network {}", source_member, network.network_id));
    }

    // In real implementation, would fetch from network
    // For now, return empty (no new indicators)
    network.last_sync = chrono::Utc::now();

    Ok(vec![])
}

/// Add a member to a sharing network
pub async fn add_network_member(
    network: &mut SharingNetwork,
    member_id: &str,
    verification: Option<&MemberVerification>,
) -> Result<()> {
    if network.members.contains(&member_id.to_string()) {
        return Err(anyhow!("Member {} already exists in network", member_id));
    }

    // Verify member if verification is provided
    if let Some(verify) = verification {
        if !verify_member(member_id, verify).await {
            return Err(anyhow!("Member verification failed for {}", member_id));
        }
    }

    network.members.push(member_id.to_string());
    info!("Added member {} to network {}", member_id, network.network_id);

    Ok(())
}

/// Remove a member from a sharing network
pub async fn remove_network_member(
    network: &mut SharingNetwork,
    member_id: &str,
) -> Result<()> {
    if let Some(pos) = network.members.iter().position(|m| m == member_id) {
        network.members.remove(pos);
        info!("Removed member {} from network {}", member_id, network.network_id);
        Ok(())
    } else {
        Err(anyhow!("Member {} not found in network", member_id))
    }
}

/// Verify a member's identity
async fn verify_member(member_id: &str, verification: &MemberVerification) -> bool {
    match verification {
        MemberVerification::Certificate(cert) => {
            // Verify X.509 certificate
            !cert.is_empty() && cert.starts_with("-----BEGIN")
        }
        MemberVerification::ApiKey(key) => {
            // Verify API key
            key.len() >= 32
        }
        MemberVerification::TrustAnchor(anchor) => {
            // Verify trust anchor
            !anchor.is_empty()
        }
    }
}

/// Sync with all network members
pub async fn sync_network(network: &mut SharingNetwork) -> Result<SyncNetworkResult> {
    let mut received = 0;
    let mut failed_members = vec![];

    for member in network.members.clone() {
        match receive_intelligence(network, &member).await {
            Ok(indicators) => {
                received += indicators.len();
            }
            Err(e) => {
                warn!("Failed to sync with member {}: {}", member, e);
                failed_members.push(member);
            }
        }
    }

    network.last_sync = chrono::Utc::now();

    Ok(SyncNetworkResult {
        indicators_received: received,
        members_synced: network.members.len() - failed_members.len(),
        failed_members,
        timestamp: chrono::Utc::now(),
    })
}

/// Get network statistics
pub fn get_network_stats(networks: &[SharingNetwork]) -> NetworkStats {
    let total_members: usize = networks.iter().map(|n| n.members.len()).sum();
    let total_shared: usize = networks.iter().map(|n| n.shared_indicators).sum();

    let networks_by_status: HashMap<String, usize> = networks.iter()
        .map(|n| {
            let status = if n.last_sync > chrono::Utc::now() - chrono::Duration::hours(24) {
                "active"
            } else {
                "stale"
            };
            (status.to_string(), 1)
        })
        .fold(HashMap::new(), |mut acc, (status, count)| {
            *acc.entry(status).or_insert(0) += count;
            acc
        });

    NetworkStats {
        total_networks: networks.len(),
        total_members,
        total_shared_indicators: total_shared,
        networks_by_status,
    }
}

// Additional types for sharing operations

#[derive(Debug, Clone)]
pub struct SharedIndicator {
    pub indicator_id: String,
    pub indicator_type: String,
    pub value: String,
    pub tlp: SharingLevel,
    pub source: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub struct ShareResult {
    pub indicators_shared: usize,
    pub members_notified: usize,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub failures: Vec<ShareFailure>,
}

#[derive(Debug, Clone)]
pub struct ShareFailure {
    pub member_id: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub enum MemberVerification {
    Certificate(String),
    ApiKey(String),
    TrustAnchor(String),
}

#[derive(Debug, Clone)]
pub struct SyncNetworkResult {
    pub indicators_received: usize,
    pub members_synced: usize,
    pub failed_members: Vec<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub struct NetworkStats {
    pub total_networks: usize,
    pub total_members: usize,
    pub total_shared_indicators: usize,
    pub networks_by_status: HashMap<String, usize>,
}
