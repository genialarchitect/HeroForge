//! Honeypot system for deception technology (Sprint 7)
//!
//! Provides honeypot capabilities for threat detection including:
//! - Multiple honeypot types (SSH, HTTP, FTP, Database, Email)
//! - Interaction logging and analysis
//! - Attacker fingerprinting
//! - Alert generation

use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use log::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Honeypot {
    pub id: String,
    pub name: String,
    pub honeypot_type: HoneypotType,
    pub ip_address: String,
    pub port: u16,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HoneypotType {
    SSH,
    HTTP,
    FTP,
    Database,
    Email,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneypotInteraction {
    pub id: String,
    pub honeypot_id: String,
    pub source_ip: String,
    pub timestamp: DateTime<Utc>,
    pub interaction_type: String,
    pub details: String,
}

/// Global honeypot state
static HONEYPOT_STATE: once_cell::sync::Lazy<Arc<RwLock<HoneypotState>>> =
    once_cell::sync::Lazy::new(|| Arc::new(RwLock::new(HoneypotState::default())));

#[derive(Debug, Default)]
struct HoneypotState {
    honeypots: HashMap<String, Honeypot>,
    interactions: HashMap<String, Vec<HoneypotInteraction>>,
    attacker_profiles: HashMap<String, AttackerProfile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackerProfile {
    pub ip_address: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub interaction_count: usize,
    pub targeted_honeypots: Vec<String>,
    pub threat_level: ThreatLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ThreatLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Create a new honeypot
pub async fn create_honeypot(name: &str, honeypot_type: HoneypotType, ip: &str, port: u16) -> Result<Honeypot> {
    let honeypot = Honeypot {
        id: uuid::Uuid::new_v4().to_string(),
        name: name.to_string(),
        honeypot_type,
        ip_address: ip.to_string(),
        port,
        is_active: true,
        created_at: Utc::now(),
    };

    let mut state = HONEYPOT_STATE.write().await;
    state.honeypots.insert(honeypot.id.clone(), honeypot.clone());
    state.interactions.insert(honeypot.id.clone(), Vec::new());

    info!("Created honeypot: {} ({}:{})", name, ip, port);
    Ok(honeypot)
}

/// Log an interaction with a honeypot
pub async fn log_interaction(honeypot_id: &str, source_ip: &str, details: &str) -> Result<HoneypotInteraction> {
    let interaction = HoneypotInteraction {
        id: uuid::Uuid::new_v4().to_string(),
        honeypot_id: honeypot_id.to_string(),
        source_ip: source_ip.to_string(),
        timestamp: Utc::now(),
        interaction_type: "connection_attempt".to_string(),
        details: details.to_string(),
    };

    let mut state = HONEYPOT_STATE.write().await;

    // Add to interactions list
    if let Some(interactions) = state.interactions.get_mut(honeypot_id) {
        interactions.push(interaction.clone());
    } else {
        state.interactions.insert(honeypot_id.to_string(), vec![interaction.clone()]);
    }

    // Update attacker profile
    update_attacker_profile(&mut state, source_ip, honeypot_id);

    info!("Logged honeypot interaction from {} on honeypot {}", source_ip, honeypot_id);
    Ok(interaction)
}

/// Update attacker profile based on interaction
fn update_attacker_profile(state: &mut HoneypotState, ip: &str, honeypot_id: &str) {
    let now = Utc::now();

    if let Some(profile) = state.attacker_profiles.get_mut(ip) {
        profile.last_seen = now;
        profile.interaction_count += 1;
        if !profile.targeted_honeypots.contains(&honeypot_id.to_string()) {
            profile.targeted_honeypots.push(honeypot_id.to_string());
        }
        // Escalate threat level based on activity
        if profile.interaction_count > 50 || profile.targeted_honeypots.len() > 3 {
            profile.threat_level = ThreatLevel::Critical;
        } else if profile.interaction_count > 20 || profile.targeted_honeypots.len() > 2 {
            profile.threat_level = ThreatLevel::High;
        } else if profile.interaction_count > 5 {
            profile.threat_level = ThreatLevel::Medium;
        }
    } else {
        state.attacker_profiles.insert(ip.to_string(), AttackerProfile {
            ip_address: ip.to_string(),
            first_seen: now,
            last_seen: now,
            interaction_count: 1,
            targeted_honeypots: vec![honeypot_id.to_string()],
            threat_level: ThreatLevel::Low,
        });
    }
}

/// Get all interactions for a honeypot
pub async fn get_interactions(honeypot_id: &str) -> Result<Vec<HoneypotInteraction>> {
    let state = HONEYPOT_STATE.read().await;
    Ok(state.interactions.get(honeypot_id).cloned().unwrap_or_default())
}

/// Get a honeypot by ID
pub async fn get_honeypot(honeypot_id: &str) -> Result<Honeypot> {
    let state = HONEYPOT_STATE.read().await;
    state.honeypots.get(honeypot_id)
        .cloned()
        .ok_or_else(|| anyhow!("Honeypot not found: {}", honeypot_id))
}

/// List all honeypots
pub async fn list_honeypots() -> Vec<Honeypot> {
    let state = HONEYPOT_STATE.read().await;
    state.honeypots.values().cloned().collect()
}

/// Deactivate a honeypot
pub async fn deactivate_honeypot(honeypot_id: &str) -> Result<()> {
    let mut state = HONEYPOT_STATE.write().await;
    if let Some(honeypot) = state.honeypots.get_mut(honeypot_id) {
        honeypot.is_active = false;
        info!("Deactivated honeypot: {}", honeypot_id);
        Ok(())
    } else {
        Err(anyhow!("Honeypot not found: {}", honeypot_id))
    }
}

/// Get attacker profile
pub async fn get_attacker_profile(ip: &str) -> Option<AttackerProfile> {
    let state = HONEYPOT_STATE.read().await;
    state.attacker_profiles.get(ip).cloned()
}

/// List all attacker profiles
pub async fn list_attacker_profiles() -> Vec<AttackerProfile> {
    let state = HONEYPOT_STATE.read().await;
    state.attacker_profiles.values().cloned().collect()
}

/// Get high-threat attackers
pub async fn get_high_threat_attackers() -> Vec<AttackerProfile> {
    let state = HONEYPOT_STATE.read().await;
    state.attacker_profiles.values()
        .filter(|p| p.threat_level == ThreatLevel::High || p.threat_level == ThreatLevel::Critical)
        .cloned()
        .collect()
}

/// Get honeypot statistics
pub async fn get_honeypot_stats() -> HoneypotStats {
    let state = HONEYPOT_STATE.read().await;

    let total_interactions: usize = state.interactions.values().map(|i| i.len()).sum();
    let active_honeypots = state.honeypots.values().filter(|h| h.is_active).count();
    let unique_attackers = state.attacker_profiles.len();
    let high_threat_count = state.attacker_profiles.values()
        .filter(|p| p.threat_level == ThreatLevel::High || p.threat_level == ThreatLevel::Critical)
        .count();

    let interactions_by_type: HashMap<String, usize> = state.honeypots.values()
        .map(|h| {
            let type_str = format!("{:?}", h.honeypot_type);
            let count = state.interactions.get(&h.id).map(|i| i.len()).unwrap_or(0);
            (type_str, count)
        })
        .fold(HashMap::new(), |mut acc, (t, c)| {
            *acc.entry(t).or_insert(0) += c;
            acc
        });

    HoneypotStats {
        total_honeypots: state.honeypots.len(),
        active_honeypots,
        total_interactions,
        unique_attackers,
        high_threat_attackers: high_threat_count,
        interactions_by_type,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneypotStats {
    pub total_honeypots: usize,
    pub active_honeypots: usize,
    pub total_interactions: usize,
    pub unique_attackers: usize,
    pub high_threat_attackers: usize,
    pub interactions_by_type: HashMap<String, usize>,
}
