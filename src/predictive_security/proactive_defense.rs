use super::types::*;
use anyhow::Result;
use chrono::Utc;
use uuid::Uuid;
use std::collections::HashMap;
use once_cell::sync::Lazy;
use std::sync::{Arc, RwLock};
use log::{info, warn};

/// Active proactive actions tracking
static ACTIVE_ACTIONS: Lazy<Arc<RwLock<HashMap<String, ProactiveAction>>>> = Lazy::new(|| {
    Arc::new(RwLock::new(HashMap::new()))
});

/// Threat landscape monitoring state
static THREAT_LANDSCAPE: Lazy<Arc<RwLock<ThreatLandscape>>> = Lazy::new(|| {
    Arc::new(RwLock::new(ThreatLandscape::default()))
});

#[derive(Debug, Clone)]
struct ThreatLandscape {
    active_campaigns: Vec<ActiveCampaign>,
    emerging_threats: Vec<EmergingThreat>,
    blocked_iocs: Vec<BlockedIoc>,
    last_updated: chrono::DateTime<Utc>,
}

impl Default for ThreatLandscape {
    fn default() -> Self {
        Self {
            active_campaigns: Vec::new(),
            emerging_threats: Vec::new(),
            blocked_iocs: Vec::new(),
            last_updated: Utc::now(),
        }
    }
}

#[derive(Debug, Clone)]
struct ActiveCampaign {
    name: String,
    threat_actor: Option<String>,
    target_sectors: Vec<String>,
    techniques: Vec<String>,
    severity: f64,
    first_seen: chrono::DateTime<Utc>,
}

#[derive(Debug, Clone)]
struct EmergingThreat {
    name: String,
    category: String,
    risk_level: f64,
    description: String,
    mitigations: Vec<String>,
}

#[derive(Debug, Clone)]
struct BlockedIoc {
    value: String,
    ioc_type: String,
    blocked_at: chrono::DateTime<Utc>,
    reason: String,
    expires_at: Option<chrono::DateTime<Utc>>,
}

/// Proactively apply patch for vulnerability before exploitation
pub async fn proactive_patch(vulnerability_id: &str, prediction: &AttackPrediction) -> Result<ProactiveAction> {
    let action_id = Uuid::new_v4().to_string();

    // Analyze vulnerability criticality
    let vuln_lower = vulnerability_id.to_lowercase();
    let is_critical = vuln_lower.contains("cve-2024")
        || vuln_lower.contains("cve-2025")
        || vuln_lower.contains("cve-2026")
        || prediction.likelihood > 0.7;

    let urgency = if is_critical { "Critical" } else { "High" };

    // Build comprehensive rationale
    let mut rationale_parts = vec![
        format!("Predicted attack: {} ({:.0}% likelihood)", prediction.attack_type, prediction.likelihood * 100.0),
    ];

    if let Some(ref target) = prediction.predicted_target {
        rationale_parts.push(format!("Target: {}", target));
    }

    rationale_parts.push(format!("Confidence: {:.0}%", prediction.confidence * 100.0));
    rationale_parts.push(format!("Urgency: {}", urgency));

    let rationale = rationale_parts.join("; ");

    // Simulate patching process
    let patch_steps = vec![
        format!("Analyzing vulnerability {}", vulnerability_id),
        "Checking patch availability".to_string(),
        "Validating patch compatibility".to_string(),
        "Creating rollback checkpoint".to_string(),
        "Applying patch to affected systems".to_string(),
        "Verifying patch installation".to_string(),
        "Running post-patch validation".to_string(),
    ];

    for step in &patch_steps {
        info!("Proactive patch step: {}", step);
    }

    let action = ProactiveAction {
        id: action_id.clone(),
        action_type: "ProactivePatch".to_string(),
        target: vulnerability_id.to_string(),
        rationale,
        status: "Completed".to_string(),
        executed_at: Some(Utc::now()),
        created_at: Utc::now(),
    };

    // Track the action
    {
        let mut actions = ACTIVE_ACTIONS.write().unwrap();
        actions.insert(action_id, action.clone());

        // Cleanup old actions (keep last 1000)
        if actions.len() > 1000 {
            let oldest_keys: Vec<String> = actions.keys().take(100).cloned().collect();
            for key in oldest_keys {
                actions.remove(&key);
            }
        }
    }

    Ok(action)
}

/// Preemptively block an IOC before it's used in an attack
pub async fn preemptive_block(ioc: &str, prediction_confidence: f64) -> Result<ProactiveAction> {
    let action_id = Uuid::new_v4().to_string();

    // Determine IOC type and appropriate blocking method
    let (ioc_type, block_method) = classify_ioc(ioc);

    // Calculate block duration based on confidence
    let block_duration_hours = if prediction_confidence > 0.9 {
        168 // 1 week for high confidence
    } else if prediction_confidence > 0.7 {
        72  // 3 days for medium-high
    } else {
        24  // 1 day for lower confidence
    };

    // Build rationale with risk assessment
    let risk_level = if prediction_confidence > 0.8 {
        "High"
    } else if prediction_confidence > 0.5 {
        "Medium"
    } else {
        "Low"
    };

    let rationale = format!(
        "Predicted attack with {:.0}% confidence. Risk: {}. IOC type: {}. Block method: {}. Duration: {} hours",
        prediction_confidence * 100.0,
        risk_level,
        ioc_type,
        block_method,
        block_duration_hours
    );

    // Execute block based on IOC type
    let block_result = match ioc_type.as_str() {
        "ip_address" => block_ip_address(ioc, block_duration_hours).await,
        "domain" => block_domain(ioc, block_duration_hours).await,
        "url" => block_url(ioc, block_duration_hours).await,
        "hash" => block_file_hash(ioc, block_duration_hours).await,
        "email" => block_email_sender(ioc, block_duration_hours).await,
        _ => Ok(()),
    };

    let status = if block_result.is_ok() {
        "Completed"
    } else {
        warn!("Failed to block IOC {}: {:?}", ioc, block_result);
        "Failed"
    };

    // Record blocked IOC
    {
        let mut landscape = THREAT_LANDSCAPE.write().unwrap();
        landscape.blocked_iocs.push(BlockedIoc {
            value: ioc.to_string(),
            ioc_type: ioc_type.clone(),
            blocked_at: Utc::now(),
            reason: format!("Preemptive block - {:.0}% confidence", prediction_confidence * 100.0),
            expires_at: Some(Utc::now() + chrono::Duration::hours(block_duration_hours as i64)),
        });

        // Keep only last 10000 blocked IOCs
        if landscape.blocked_iocs.len() > 10000 {
            landscape.blocked_iocs.drain(0..1000);
        }
    }

    let action = ProactiveAction {
        id: action_id.clone(),
        action_type: "PreemptiveBlock".to_string(),
        target: ioc.to_string(),
        rationale,
        status: status.to_string(),
        executed_at: Some(Utc::now()),
        created_at: Utc::now(),
    };

    // Track the action
    {
        let mut actions = ACTIVE_ACTIONS.write().unwrap();
        actions.insert(action_id, action.clone());
    }

    Ok(action)
}

fn classify_ioc(ioc: &str) -> (String, String) {
    // IPv4 pattern
    if ioc.chars().filter(|c| *c == '.').count() == 3
        && ioc.split('.').all(|part| part.parse::<u8>().is_ok()) {
        return ("ip_address".to_string(), "firewall_rule".to_string());
    }

    // IPv6 pattern
    if ioc.contains(':') && !ioc.contains("://") {
        return ("ip_address".to_string(), "firewall_rule".to_string());
    }

    // URL pattern
    if ioc.starts_with("http://") || ioc.starts_with("https://") {
        return ("url".to_string(), "proxy_block".to_string());
    }

    // Email pattern
    if ioc.contains('@') && ioc.contains('.') {
        return ("email".to_string(), "email_filter".to_string());
    }

    // Hash patterns (MD5, SHA1, SHA256)
    let len = ioc.len();
    if (len == 32 || len == 40 || len == 64) && ioc.chars().all(|c| c.is_ascii_hexdigit()) {
        return ("hash".to_string(), "endpoint_protection".to_string());
    }

    // Domain pattern (default)
    if ioc.contains('.') && !ioc.contains(' ') {
        return ("domain".to_string(), "dns_sinkhole".to_string());
    }

    ("unknown".to_string(), "manual_review".to_string())
}

async fn block_ip_address(ip: &str, _duration_hours: i32) -> Result<()> {
    info!("Blocking IP address: {} via firewall rule", ip);
    // In production: Add firewall rule via API
    Ok(())
}

async fn block_domain(domain: &str, _duration_hours: i32) -> Result<()> {
    info!("Blocking domain: {} via DNS sinkhole", domain);
    // In production: Add to DNS blocklist
    Ok(())
}

async fn block_url(url: &str, _duration_hours: i32) -> Result<()> {
    info!("Blocking URL: {} via proxy", url);
    // In production: Add to proxy blocklist
    Ok(())
}

async fn block_file_hash(hash: &str, _duration_hours: i32) -> Result<()> {
    info!("Blocking file hash: {} via endpoint protection", hash);
    // In production: Add to EDR blocklist
    Ok(())
}

async fn block_email_sender(email: &str, _duration_hours: i32) -> Result<()> {
    info!("Blocking email sender: {} via email gateway", email);
    // In production: Add to email blocklist
    Ok(())
}

/// Proactively segment network around high-risk asset
pub async fn proactive_segmentation(asset_id: &str) -> Result<ProactiveAction> {
    let action_id = Uuid::new_v4().to_string();

    // Analyze asset to determine segmentation strategy
    let asset_lower = asset_id.to_lowercase();

    let (segment_type, rationale) = determine_segmentation_strategy(&asset_lower);

    // Build segmentation rules
    let segmentation_rules = generate_segmentation_rules(asset_id, &segment_type);

    info!("Applying {} segmentation for asset: {}", segment_type, asset_id);
    for rule in &segmentation_rules {
        info!("  Segmentation rule: {}", rule);
    }

    let full_rationale = format!(
        "{}. Applied {} segmentation with {} rules.",
        rationale,
        segment_type,
        segmentation_rules.len()
    );

    let action = ProactiveAction {
        id: action_id.clone(),
        action_type: "ProactiveSegmentation".to_string(),
        target: asset_id.to_string(),
        rationale: full_rationale,
        status: "Completed".to_string(),
        executed_at: Some(Utc::now()),
        created_at: Utc::now(),
    };

    // Track the action
    {
        let mut actions = ACTIVE_ACTIONS.write().unwrap();
        actions.insert(action_id, action.clone());
    }

    Ok(action)
}

fn determine_segmentation_strategy(asset_lower: &str) -> (String, String) {
    if asset_lower.contains("db") || asset_lower.contains("database") {
        return (
            "data_tier".to_string(),
            "High-value data asset isolated in secure data tier".to_string()
        );
    }

    if asset_lower.contains("web") || asset_lower.contains("www") || asset_lower.contains("dmz") {
        return (
            "dmz".to_string(),
            "Web-facing asset requires DMZ isolation".to_string()
        );
    }

    if asset_lower.contains("admin") || asset_lower.contains("mgmt") || asset_lower.contains("jump") {
        return (
            "management".to_string(),
            "Administrative asset requires management network isolation".to_string()
        );
    }

    if asset_lower.contains("dev") || asset_lower.contains("test") || asset_lower.contains("staging") {
        return (
            "non_production".to_string(),
            "Non-production asset segmented from production".to_string()
        );
    }

    if asset_lower.contains("iot") || asset_lower.contains("sensor") || asset_lower.contains("camera") {
        return (
            "iot".to_string(),
            "IoT device requires dedicated IoT network segment".to_string()
        );
    }

    if asset_lower.contains("legacy") || asset_lower.contains("old") {
        return (
            "legacy".to_string(),
            "Legacy system isolated due to elevated risk".to_string()
        );
    }

    (
        "standard".to_string(),
        "High-value asset with elevated risk profile".to_string()
    )
}

fn generate_segmentation_rules(asset_id: &str, segment_type: &str) -> Vec<String> {
    let mut rules = Vec::new();

    match segment_type {
        "data_tier" => {
            rules.push(format!("DENY all inbound to {} except from app_tier", asset_id));
            rules.push(format!("ALLOW app_tier:3306,5432,1433 to {}", asset_id));
            rules.push(format!("DENY {} outbound to internet", asset_id));
            rules.push(format!("ALLOW {} to backup_network", asset_id));
        }
        "dmz" => {
            rules.push(format!("ALLOW internet:80,443 to {}", asset_id));
            rules.push(format!("DENY {} to internal_network except via proxy", asset_id));
            rules.push(format!("DENY {} to database_tier", asset_id));
            rules.push(format!("LOG all traffic to/from {}", asset_id));
        }
        "management" => {
            rules.push(format!("DENY all to {} except from jump_hosts", asset_id));
            rules.push(format!("ALLOW jump_hosts:22,3389 to {}", asset_id));
            rules.push(format!("REQUIRE MFA for {} access", asset_id));
            rules.push(format!("LOG all access to {}", asset_id));
        }
        "non_production" => {
            rules.push(format!("DENY {} to production_network", asset_id));
            rules.push(format!("ALLOW {} to dev_network", asset_id));
            rules.push(format!("RATE_LIMIT {} internet_access", asset_id));
        }
        "iot" => {
            rules.push(format!("DENY {} to corporate_network", asset_id));
            rules.push(format!("ALLOW {} to iot_gateway only", asset_id));
            rules.push(format!("DENY {} outbound internet", asset_id));
            rules.push(format!("INSPECT all {} traffic", asset_id));
        }
        "legacy" => {
            rules.push(format!("QUARANTINE {} with minimal access", asset_id));
            rules.push(format!("ALLOW specific_apps to {}", asset_id));
            rules.push(format!("DENY {} lateral movement", asset_id));
            rules.push(format!("ENHANCED_MONITORING {}", asset_id));
        }
        _ => {
            rules.push(format!("RESTRICT {} to standard segment", asset_id));
            rules.push(format!("APPLY baseline ACLs to {}", asset_id));
        }
    }

    rules
}

/// Monitor threat landscape in real-time
pub async fn monitor_threat_landscape() -> Result<Vec<String>> {
    let mut alerts = Vec::new();

    // Simulate threat intelligence feed processing
    let current_threats = gather_threat_intelligence().await?;

    // Update landscape state
    {
        let mut landscape = THREAT_LANDSCAPE.write().unwrap();

        // Process new campaigns
        for campaign in &current_threats.campaigns {
            if campaign.severity > 0.7 {
                alerts.push(format!(
                    "ALERT: High-severity campaign '{}' detected targeting {}",
                    campaign.name,
                    campaign.target_sectors.join(", ")
                ));
            }

            // Check if campaign is new
            let is_new = !landscape.active_campaigns
                .iter()
                .any(|c| c.name == campaign.name);

            if is_new {
                alerts.push(format!("NEW: Campaign '{}' added to monitoring", campaign.name));
                landscape.active_campaigns.push(campaign.clone());
            }
        }

        // Process emerging threats
        for threat in &current_threats.emerging {
            if threat.risk_level > 0.6 {
                alerts.push(format!(
                    "EMERGING: {} threat '{}' - Risk: {:.0}%",
                    threat.category,
                    threat.name,
                    threat.risk_level * 100.0
                ));
            }

            let is_new = !landscape.emerging_threats
                .iter()
                .any(|t| t.name == threat.name);

            if is_new {
                landscape.emerging_threats.push(threat.clone());
            }
        }

        // Cleanup expired blocked IOCs
        let now = Utc::now();
        landscape.blocked_iocs.retain(|ioc| {
            ioc.expires_at.map(|exp| exp > now).unwrap_or(true)
        });

        // Keep only recent campaigns (last 30 days)
        let cutoff = now - chrono::Duration::days(30);
        landscape.active_campaigns.retain(|c| c.first_seen > cutoff);

        landscape.last_updated = now;
    }

    // Add summary alert
    let landscape = THREAT_LANDSCAPE.read().unwrap();
    alerts.push(format!(
        "SUMMARY: {} active campaigns, {} emerging threats, {} blocked IOCs",
        landscape.active_campaigns.len(),
        landscape.emerging_threats.len(),
        landscape.blocked_iocs.len()
    ));

    Ok(alerts)
}

struct ThreatIntelligence {
    campaigns: Vec<ActiveCampaign>,
    emerging: Vec<EmergingThreat>,
}

async fn gather_threat_intelligence() -> Result<ThreatIntelligence> {
    // Simulate gathering from multiple threat intel sources
    let campaigns = vec![
        ActiveCampaign {
            name: "Operation BlackShadow".to_string(),
            threat_actor: Some("APT-X".to_string()),
            target_sectors: vec!["Finance".to_string(), "Healthcare".to_string()],
            techniques: vec!["T1566.001".to_string(), "T1059.001".to_string()],
            severity: 0.85,
            first_seen: Utc::now() - chrono::Duration::days(5),
        },
        ActiveCampaign {
            name: "RansomBot Wave".to_string(),
            threat_actor: Some("Wizard Spider".to_string()),
            target_sectors: vec!["Manufacturing".to_string(), "Retail".to_string()],
            techniques: vec!["T1486".to_string(), "T1021.002".to_string()],
            severity: 0.92,
            first_seen: Utc::now() - chrono::Duration::days(2),
        },
    ];

    let emerging = vec![
        EmergingThreat {
            name: "AI-Powered Phishing".to_string(),
            category: "Social Engineering".to_string(),
            risk_level: 0.78,
            description: "Phishing campaigns using AI-generated content".to_string(),
            mitigations: vec![
                "Enhanced email filtering".to_string(),
                "User awareness training".to_string(),
            ],
        },
        EmergingThreat {
            name: "Supply Chain Malware".to_string(),
            category: "Supply Chain".to_string(),
            risk_level: 0.85,
            description: "Malware distributed through compromised software updates".to_string(),
            mitigations: vec![
                "Software integrity verification".to_string(),
                "Vendor security assessment".to_string(),
            ],
        },
    ];

    Ok(ThreatIntelligence { campaigns, emerging })
}

/// Get active proactive actions
pub async fn get_active_actions() -> Result<Vec<ProactiveAction>> {
    let actions = ACTIVE_ACTIONS.read().unwrap();
    Ok(actions.values().cloned().collect())
}

/// Get action by ID
pub async fn get_action(action_id: &str) -> Result<Option<ProactiveAction>> {
    let actions = ACTIVE_ACTIONS.read().unwrap();
    Ok(actions.get(action_id).cloned())
}

/// Cancel a proactive action
pub async fn cancel_action(action_id: &str) -> Result<bool> {
    let mut actions = ACTIVE_ACTIONS.write().unwrap();
    if let Some(mut action) = actions.get(action_id).cloned() {
        action.status = "Cancelled".to_string();
        actions.insert(action_id.to_string(), action);
        info!("Cancelled proactive action: {}", action_id);
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Automated threat response based on predictions
pub async fn automated_response(prediction: &AttackPrediction) -> Result<Vec<ProactiveAction>> {
    let mut actions = Vec::new();

    // Only respond automatically to high-confidence predictions
    if prediction.confidence < 0.6 {
        return Ok(actions);
    }

    info!("Initiating automated response for predicted {} attack", prediction.attack_type);

    // Block known indicators
    if let Some(ref indicators_json) = prediction.indicators {
        if let Ok(indicators) = serde_json::from_str::<Vec<String>>(indicators_json) {
            for ioc in indicators.iter().take(10) { // Limit to first 10
                let action = preemptive_block(ioc, prediction.confidence).await?;
                actions.push(action);
            }
        }
    }

    // Segment predicted target
    if let Some(ref target) = prediction.predicted_target {
        if prediction.likelihood > 0.7 {
            let action = proactive_segmentation(target).await?;
            actions.push(action);
        }
    }

    // Type-specific responses
    match prediction.attack_type.as_str() {
        "Ransomware" => {
            actions.push(create_response_action(
                "RansomwarePrevention",
                "backup_systems",
                "Verify backup integrity and create emergency restore point",
            ));
            actions.push(create_response_action(
                "RansomwarePrevention",
                "endpoint_protection",
                "Enable enhanced ransomware protection on endpoints",
            ));
        }
        "DDoS" => {
            actions.push(create_response_action(
                "DDoSMitigation",
                "traffic_management",
                "Enable DDoS mitigation and rate limiting",
            ));
            actions.push(create_response_action(
                "DDoSMitigation",
                "cdn_configuration",
                "Activate CDN absorption capacity",
            ));
        }
        "Phishing" => {
            actions.push(create_response_action(
                "PhishingPrevention",
                "email_gateway",
                "Enhanced email scanning and quarantine rules",
            ));
            actions.push(create_response_action(
                "PhishingPrevention",
                "user_notification",
                "Send targeted security awareness notification",
            ));
        }
        "DataExfiltration" => {
            actions.push(create_response_action(
                "DLPEnforcement",
                "network_monitoring",
                "Enable enhanced DLP monitoring and alerting",
            ));
            actions.push(create_response_action(
                "DLPEnforcement",
                "egress_control",
                "Restrict egress points and enable deep inspection",
            ));
        }
        _ => {}
    }

    Ok(actions)
}

fn create_response_action(action_type: &str, target: &str, rationale: &str) -> ProactiveAction {
    let action_id = Uuid::new_v4().to_string();

    let action = ProactiveAction {
        id: action_id.clone(),
        action_type: action_type.to_string(),
        target: target.to_string(),
        rationale: rationale.to_string(),
        status: "Completed".to_string(),
        executed_at: Some(Utc::now()),
        created_at: Utc::now(),
    };

    // Track the action
    {
        let mut actions = ACTIVE_ACTIONS.write().unwrap();
        actions.insert(action_id, action.clone());
    }

    action
}
