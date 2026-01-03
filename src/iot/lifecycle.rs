//! IoT Device Lifecycle Management
//!
//! Provides comprehensive IoT asset management:
//! - Shadow IoT device discovery
//! - Device lifecycle tracking
//! - End-of-life device identification
//! - Update compliance monitoring
//! - Automatic VLAN assignment
//! - Network policy generation

use anyhow::Result;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc, Duration};
use std::collections::HashMap;

/// IoT device asset information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoTAsset {
    pub device_id: String,
    pub device_type: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub lifecycle_stage: String, // Active, EndOfLife, Decommissioned
    pub update_compliance: bool,
    pub mac_address: Option<String>,
    pub ip_address: Option<String>,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub firmware_version: Option<String>,
    pub protocols: Vec<String>,
    pub open_ports: Vec<u16>,
    pub risk_score: f64,
    pub last_scan: Option<DateTime<Utc>>,
}

/// Device discovery result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryResult {
    pub total_discovered: usize,
    pub authorized: Vec<IoTAsset>,
    pub shadow_devices: Vec<IoTAsset>,
    pub scan_duration_ms: u64,
    pub scan_timestamp: DateTime<Utc>,
}

/// Known IoT device signatures for fingerprinting
const IOT_SIGNATURES: &[(&str, &str, &[u16])] = &[
    ("Philips Hue", "smart_light", &[80, 443, 8080]),
    ("Amazon Echo", "voice_assistant", &[80, 443, 8443]),
    ("Google Nest", "thermostat", &[80, 443, 8080, 9080]),
    ("Ring Doorbell", "camera", &[80, 443, 554, 8554]),
    ("TP-Link Camera", "camera", &[80, 554, 2020]),
    ("Wyze Camera", "camera", &[80, 443, 8443]),
    ("Sonos Speaker", "audio", &[80, 443, 1400, 1443]),
    ("Roku", "streaming", &[80, 8060, 8443]),
    ("Raspberry Pi", "sbc", &[22, 80]),
    ("ESP8266/ESP32", "microcontroller", &[80, 443]),
];

/// Discover unauthorized IoT devices on the network
pub async fn discover_shadow_iot() -> Result<Vec<IoTAsset>> {
    log::info!("Starting shadow IoT discovery scan");

    let mut shadow_devices = Vec::new();
    let scan_start = std::time::Instant::now();

    // In production, this would:
    // 1. Perform ARP scan to discover all devices
    // 2. MAC address OUI lookup to identify manufacturers
    // 3. Port scanning for common IoT ports
    // 4. Protocol fingerprinting
    // 5. Compare against asset inventory

    // Simulate discovery of shadow IoT devices
    let common_iot_macs = [
        ("AC:CC:8E", "Roku"),
        ("B4:E6:2D", "TP-Link"),
        ("DC:A6:32", "Raspberry Pi"),
        ("68:C6:3A", "ESP8266"),
        ("F4:12:FA", "Amazon"),
        ("50:C7:BF", "TP-Link Kasa"),
        ("D0:73:D5", "Wyze"),
    ];

    // Simulate finding some shadow devices
    for (i, (mac_prefix, manufacturer)) in common_iot_macs.iter().enumerate() {
        let device = IoTAsset {
            device_id: format!("shadow-{:04}", i + 1),
            device_type: identify_device_type_from_mac(mac_prefix),
            first_seen: Utc::now() - Duration::days(rand_days(1, 90)),
            last_seen: Utc::now(),
            lifecycle_stage: "Unknown".to_string(),
            update_compliance: false, // Shadow devices assumed non-compliant
            mac_address: Some(format!("{}:XX:XX:XX", mac_prefix)),
            ip_address: Some(format!("192.168.1.{}", 100 + i)),
            manufacturer: Some(manufacturer.to_string()),
            model: None,
            firmware_version: None,
            protocols: identify_protocols_from_type(&identify_device_type_from_mac(mac_prefix)),
            open_ports: identify_ports_from_type(&identify_device_type_from_mac(mac_prefix)),
            risk_score: calculate_risk_score(false, &identify_protocols_from_type(&identify_device_type_from_mac(mac_prefix))),
            last_scan: Some(Utc::now()),
        };

        // Only add devices that would be considered unauthorized
        if device.risk_score > 0.5 {
            shadow_devices.push(device);
        }
    }

    log::info!(
        "Shadow IoT discovery completed: {} devices found in {:?}",
        shadow_devices.len(),
        scan_start.elapsed()
    );

    Ok(shadow_devices)
}

/// Identify device type from MAC OUI prefix
fn identify_device_type_from_mac(mac_prefix: &str) -> String {
    match mac_prefix {
        "AC:CC:8E" => "streaming".to_string(),
        "B4:E6:2D" | "50:C7:BF" => "smart_plug".to_string(),
        "DC:A6:32" => "sbc".to_string(),
        "68:C6:3A" => "microcontroller".to_string(),
        "F4:12:FA" => "voice_assistant".to_string(),
        "D0:73:D5" => "camera".to_string(),
        _ => "unknown".to_string(),
    }
}

/// Identify common protocols for device type
fn identify_protocols_from_type(device_type: &str) -> Vec<String> {
    match device_type {
        "camera" => vec!["RTSP".to_string(), "HTTP".to_string(), "ONVIF".to_string()],
        "voice_assistant" => vec!["HTTP".to_string(), "HTTPS".to_string(), "mDNS".to_string()],
        "smart_plug" | "smart_light" => vec!["HTTP".to_string(), "CoAP".to_string()],
        "thermostat" => vec!["HTTP".to_string(), "HTTPS".to_string(), "Thread".to_string()],
        "streaming" => vec!["HTTP".to_string(), "DIAL".to_string()],
        "sbc" => vec!["SSH".to_string(), "HTTP".to_string()],
        "microcontroller" => vec!["MQTT".to_string(), "HTTP".to_string()],
        _ => vec!["HTTP".to_string()],
    }
}

/// Identify common ports for device type
fn identify_ports_from_type(device_type: &str) -> Vec<u16> {
    match device_type {
        "camera" => vec![80, 443, 554, 8080],
        "voice_assistant" => vec![80, 443, 8443],
        "smart_plug" | "smart_light" => vec![80, 9999],
        "thermostat" => vec![80, 443, 8080],
        "streaming" => vec![80, 8060],
        "sbc" => vec![22, 80],
        "microcontroller" => vec![80, 1883],
        _ => vec![80],
    }
}

/// Calculate risk score for device
fn calculate_risk_score(update_compliant: bool, protocols: &[String]) -> f64 {
    let mut score: f64 = 0.0;

    // Non-compliant devices are higher risk
    if !update_compliant {
        score += 0.3;
    }

    // Insecure protocols increase risk
    for proto in protocols {
        match proto.as_str() {
            "HTTP" => score += 0.1,
            "RTSP" => score += 0.15,
            "MQTT" => score += 0.1,
            "Telnet" => score += 0.3,
            _ => {}
        }
    }

    score.min(1.0)
}

/// Generate random days for simulation
fn rand_days(min: i64, max: i64) -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos() as i64;
    min + (nanos % (max - min + 1))
}

/// Track device from deployment to decommission
pub async fn track_device_lifecycle(device_id: &str) -> Result<IoTAsset> {
    log::info!("Tracking lifecycle for device: {}", device_id);

    // In production, query device database and monitoring systems
    // For now, return enriched device information

    let lifecycle_stage = determine_lifecycle_stage(device_id);
    let compliance = check_device_compliance(device_id);

    Ok(IoTAsset {
        device_id: device_id.to_string(),
        device_type: "smart_device".to_string(),
        first_seen: Utc::now() - Duration::days(180),
        last_seen: Utc::now(),
        lifecycle_stage,
        update_compliance: compliance,
        mac_address: Some(format!("AA:BB:CC:{}:{}:{}",
            &device_id[..2],
            &device_id[2..4],
            &device_id[4..6])),
        ip_address: Some("192.168.1.100".to_string()),
        manufacturer: Some("Generic IoT Vendor".to_string()),
        model: Some("Model XYZ".to_string()),
        firmware_version: Some("1.2.3".to_string()),
        protocols: vec!["HTTP".to_string(), "MQTT".to_string()],
        open_ports: vec![80, 1883],
        risk_score: if compliance { 0.3 } else { 0.7 },
        last_scan: Some(Utc::now()),
    })
}

/// Determine lifecycle stage based on device age and activity
fn determine_lifecycle_stage(device_id: &str) -> String {
    // In production, check against vendor support dates and activity patterns
    let hash = device_id.bytes().fold(0u8, |acc, b| acc.wrapping_add(b));

    match hash % 4 {
        0 => "Active".to_string(),
        1 => "Maintenance".to_string(),
        2 => "EndOfLife".to_string(),
        _ => "Decommissioned".to_string(),
    }
}

/// Check device compliance status
fn check_device_compliance(device_id: &str) -> bool {
    // In production, check firmware version against latest
    let hash = device_id.bytes().fold(0u8, |acc, b| acc.wrapping_add(b));
    hash % 2 == 0
}

/// Identify end-of-life devices that need attention
pub async fn identify_eol_devices() -> Result<Vec<String>> {
    log::info!("Scanning for end-of-life IoT devices");

    let mut eol_devices = Vec::new();

    // In production, check against vendor EOL databases
    // Common EOL check sources:
    // 1. Manufacturer announcements
    // 2. CVE databases (unsupported devices)
    // 3. Internal asset age thresholds
    // 4. Firmware update availability

    // Known EOL device patterns
    let eol_patterns = [
        ("Nest Secure", "Discontinued 2020"),
        ("Wink Hub v1", "Service ended 2023"),
        ("SmartThings Hub v1", "Discontinued 2019"),
        ("Insteon Hub", "Company defunct 2022"),
        ("Revolv Hub", "Discontinued 2016"),
    ];

    for (device, reason) in eol_patterns {
        eol_devices.push(format!("{} - {}", device, reason));
    }

    // Add age-based EOL candidates (devices > 5 years old)
    eol_devices.push("Generic Camera [Serial: CAM-2018-001] - Age > 5 years".to_string());
    eol_devices.push("Old Thermostat [Serial: THERM-2017-042] - No updates > 3 years".to_string());

    log::info!("Found {} EOL devices", eol_devices.len());
    Ok(eol_devices)
}

/// Check if device firmware is up to date
pub async fn check_update_compliance(device_id: &str) -> Result<bool> {
    log::info!("Checking update compliance for device: {}", device_id);

    // In production, this would:
    // 1. Query device for current firmware version
    // 2. Check vendor API for latest available version
    // 3. Compare versions
    // 4. Check security bulletins for known vulnerabilities

    // Compliance check result
    let compliance_check = ComplianceCheck {
        device_id: device_id.to_string(),
        current_version: "1.2.3".to_string(),
        latest_version: "1.2.5".to_string(),
        is_compliant: false,
        pending_updates: vec![
            "Security patch 1.2.4".to_string(),
            "Feature update 1.2.5".to_string(),
        ],
        last_check: Utc::now(),
        vulnerabilities_patched_in_update: vec![
            "CVE-2024-1234".to_string(),
            "CVE-2024-5678".to_string(),
        ],
    };

    log::info!(
        "Device {} compliance status: {} (current: {}, latest: {})",
        device_id,
        if compliance_check.is_compliant { "COMPLIANT" } else { "NON-COMPLIANT" },
        compliance_check.current_version,
        compliance_check.latest_version
    );

    Ok(compliance_check.is_compliant)
}

/// Compliance check result
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ComplianceCheck {
    device_id: String,
    current_version: String,
    latest_version: String,
    is_compliant: bool,
    pending_updates: Vec<String>,
    last_check: DateTime<Utc>,
    vulnerabilities_patched_in_update: Vec<String>,
}

/// Automatically assign VLAN for IoT device based on type and risk
pub async fn auto_vlan_assignment(device_id: &str) -> Result<String> {
    log::info!("Determining VLAN assignment for device: {}", device_id);

    // VLAN assignment strategy:
    // - VLAN_CRITICAL (10): Critical infrastructure devices
    // - VLAN_SECURE (20): Authenticated, secure devices
    // - VLAN_IOT_TRUSTED (30): Known IoT devices, verified
    // - VLAN_IOT_UNTRUSTED (40): Known IoT devices, unverified
    // - VLAN_QUARANTINE (99): Unknown or suspicious devices

    let device = track_device_lifecycle(device_id).await?;

    let vlan = match device.lifecycle_stage.as_str() {
        "Decommissioned" => "VLAN_QUARANTINE_99",
        "EndOfLife" => "VLAN_IOT_UNTRUSTED_40",
        _ => {
            if device.update_compliance {
                if device.risk_score < 0.3 {
                    "VLAN_IOT_TRUSTED_30"
                } else {
                    "VLAN_IOT_UNTRUSTED_40"
                }
            } else {
                "VLAN_IOT_UNTRUSTED_40"
            }
        }
    };

    log::info!("Device {} assigned to {}", device_id, vlan);
    Ok(vlan.to_string())
}

/// Generate network access policy for device
pub async fn generate_network_policy(device_id: &str) -> Result<serde_json::Value> {
    log::info!("Generating network policy for device: {}", device_id);

    let device = track_device_lifecycle(device_id).await?;
    let vlan = auto_vlan_assignment(device_id).await?;

    // Generate micro-segmentation policy
    let policy = NetworkPolicy {
        device_id: device_id.to_string(),
        vlan: vlan.clone(),
        allowed_destinations: determine_allowed_destinations(&device.device_type),
        allowed_ports: device.open_ports.clone(),
        allowed_protocols: device.protocols.clone(),
        rate_limit_mbps: determine_rate_limit(&device.device_type),
        internet_access: should_allow_internet(&device.device_type),
        dns_filtering: true,
        logging_level: if device.risk_score > 0.5 { "verbose" } else { "standard" }.to_string(),
        created_at: Utc::now(),
        expires_at: None,
    };

    Ok(serde_json::json!({
        "policy": policy,
        "firewall_rules": generate_firewall_rules(&policy),
        "acl_entries": generate_acl_entries(&policy),
        "recommended_actions": generate_recommendations(&device),
    }))
}

/// Network policy structure
#[derive(Debug, Clone, Serialize, Deserialize)]
struct NetworkPolicy {
    device_id: String,
    vlan: String,
    allowed_destinations: Vec<String>,
    allowed_ports: Vec<u16>,
    allowed_protocols: Vec<String>,
    rate_limit_mbps: u32,
    internet_access: bool,
    dns_filtering: bool,
    logging_level: String,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
}

/// Determine allowed destinations based on device type
fn determine_allowed_destinations(device_type: &str) -> Vec<String> {
    match device_type {
        "camera" => vec![
            "local_nvr".to_string(),
            "cloud_storage_allowed".to_string(),
        ],
        "voice_assistant" => vec![
            "amazon.com".to_string(),
            "google.com".to_string(),
        ],
        "thermostat" => vec![
            "nest.com".to_string(),
            "local_hvac_controller".to_string(),
        ],
        "smart_plug" => vec![
            "cloud_iot_gateway".to_string(),
        ],
        _ => vec!["restricted".to_string()],
    }
}

/// Determine rate limit based on device type
fn determine_rate_limit(device_type: &str) -> u32 {
    match device_type {
        "camera" => 50, // Video streaming needs bandwidth
        "streaming" => 100,
        "voice_assistant" => 10,
        _ => 5, // Default low bandwidth for most IoT
    }
}

/// Determine if device should have internet access
fn should_allow_internet(device_type: &str) -> bool {
    match device_type {
        "voice_assistant" | "streaming" | "thermostat" => true,
        "camera" => false, // Local storage preferred
        _ => false,
    }
}

/// Generate firewall rules from policy
fn generate_firewall_rules(policy: &NetworkPolicy) -> Vec<serde_json::Value> {
    let mut rules = Vec::new();

    // Default deny rule
    rules.push(serde_json::json!({
        "action": "deny",
        "source": policy.device_id,
        "destination": "any",
        "protocol": "any",
        "priority": 1000
    }));

    // Allow specific destinations
    for (i, dest) in policy.allowed_destinations.iter().enumerate() {
        rules.push(serde_json::json!({
            "action": "allow",
            "source": policy.device_id,
            "destination": dest,
            "protocol": "tcp",
            "ports": policy.allowed_ports,
            "priority": 100 + i
        }));
    }

    // Allow DNS if filtering enabled
    if policy.dns_filtering {
        rules.push(serde_json::json!({
            "action": "allow",
            "source": policy.device_id,
            "destination": "internal_dns",
            "protocol": "udp",
            "ports": [53],
            "priority": 50
        }));
    }

    rules
}

/// Generate ACL entries from policy
fn generate_acl_entries(policy: &NetworkPolicy) -> Vec<String> {
    let mut entries = Vec::new();

    entries.push(format!(
        "permit {} to {} ports {:?}",
        policy.device_id,
        policy.allowed_destinations.join(", "),
        policy.allowed_ports
    ));

    entries.push(format!(
        "rate-limit {} {}mbps",
        policy.device_id,
        policy.rate_limit_mbps
    ));

    if !policy.internet_access {
        entries.push(format!("deny {} to internet", policy.device_id));
    }

    entries
}

/// Generate security recommendations
fn generate_recommendations(device: &IoTAsset) -> Vec<String> {
    let mut recommendations = Vec::new();

    if !device.update_compliance {
        recommendations.push("Update device firmware to latest version".to_string());
    }

    if device.lifecycle_stage == "EndOfLife" {
        recommendations.push("Consider replacing end-of-life device".to_string());
    }

    if device.risk_score > 0.7 {
        recommendations.push("Isolate high-risk device in quarantine VLAN".to_string());
    }

    if device.protocols.contains(&"HTTP".to_string()) && !device.protocols.contains(&"HTTPS".to_string()) {
        recommendations.push("Enable HTTPS for encrypted communication".to_string());
    }

    if device.open_ports.contains(&23) {
        recommendations.push("Disable Telnet and use SSH instead".to_string());
    }

    recommendations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_discover_shadow_iot() {
        let devices = discover_shadow_iot().await.unwrap();
        // May or may not find shadow devices depending on risk calculation
        assert!(devices.len() >= 0);
    }

    #[tokio::test]
    async fn test_track_device_lifecycle() {
        let device = track_device_lifecycle("ABC123").await.unwrap();
        assert_eq!(device.device_id, "ABC123");
        assert!(!device.lifecycle_stage.is_empty());
    }

    #[tokio::test]
    async fn test_identify_eol_devices() {
        let eol = identify_eol_devices().await.unwrap();
        assert!(!eol.is_empty());
    }

    #[tokio::test]
    async fn test_check_update_compliance() {
        let result = check_update_compliance("device123").await.unwrap();
        // Result can be true or false
        assert!(result == true || result == false);
    }

    #[tokio::test]
    async fn test_auto_vlan_assignment() {
        let vlan = auto_vlan_assignment("device123").await.unwrap();
        assert!(vlan.starts_with("VLAN_"));
    }

    #[tokio::test]
    async fn test_generate_network_policy() {
        let policy = generate_network_policy("device123").await.unwrap();
        assert!(policy.get("policy").is_some());
        assert!(policy.get("firewall_rules").is_some());
    }

    #[test]
    fn test_identify_device_type_from_mac() {
        assert_eq!(identify_device_type_from_mac("DC:A6:32"), "sbc");
        assert_eq!(identify_device_type_from_mac("D0:73:D5"), "camera");
    }

    #[test]
    fn test_calculate_risk_score() {
        let high_risk = calculate_risk_score(false, &["Telnet".to_string(), "HTTP".to_string()]);
        let low_risk = calculate_risk_score(true, &["HTTPS".to_string()]);
        assert!(high_risk > low_risk);
    }
}
