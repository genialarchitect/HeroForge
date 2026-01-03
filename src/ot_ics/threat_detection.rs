use anyhow::Result;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use log::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcsThreatDetection {
    pub id: String,
    pub threat_type: IcsThreatType,
    pub severity: ThreatSeverity,
    pub description: String,
    pub indicators: Vec<String>,
    pub timestamp: DateTime<Utc>,
    pub mitre_attack_ids: Vec<String>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IcsThreatType {
    Stuxnet,
    Triton,
    BlackEnergy,
    Industroyer,
    Havex,
    IronGate,
    CrashOverride,
    Pipedream,
    PlcMalware,
    CommandInjection,
    ProtocolManipulation,
    Reconnaissance,
    DoS,
    ManInTheMiddle,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ThreatSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Known ICS/OT attack patterns
struct AttackSignature {
    name: &'static str,
    threat_type: IcsThreatType,
    patterns: Vec<&'static [u8]>,
    mitre_ids: Vec<&'static str>,
}

/// Stuxnet-specific patterns
const STUXNET_PATTERNS: &[&[u8]] = &[
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",  // Null padding pattern
    // S7 protocol manipulation signatures
    b"\x32\x01\x00\x00",  // S7 header
    b"\x32\x03\x00\x00",  // S7 write request
];

/// TRITON/TRISIS patterns
const TRITON_PATTERNS: &[&[u8]] = &[
    // Triconex TSAA protocol patterns
    b"\x00\x00\x00\x00\x00\x00\x05",  // TSAA command
    b"\x00\x00\x00\x00\x00\x00\x06",  // TSAA response
];

/// BlackEnergy patterns
const BLACKENERGY_PATTERNS: &[&[u8]] = &[
    // Known BlackEnergy command patterns
    b"\x68\x65\x6c\x6c\x6f",  // C2 beacon
];

/// Detect Stuxnet-style attacks
pub async fn detect_stuxnet_patterns(traffic: &[u8]) -> Result<Option<IcsThreatDetection>> {
    info!("Scanning for Stuxnet-style attack patterns");

    if traffic.is_empty() {
        return Ok(None);
    }

    let mut indicators = Vec::new();

    // Check for S7comm protocol manipulation
    if traffic.len() >= 4 && traffic[0] == 0x32 {
        indicators.push("S7comm protocol detected".to_string());

        // Check for suspicious S7 function codes
        if traffic.len() >= 10 {
            let function_code = traffic[8];

            // PLC program download (function 0x1a)
            if function_code == 0x1a {
                indicators.push("PLC program download attempt detected".to_string());
            }

            // Block write (function 0x1b)
            if function_code == 0x1b {
                indicators.push("PLC block write operation detected".to_string());
            }

            // Stop PLC (function 0x29)
            if function_code == 0x29 {
                indicators.push("PLC stop command detected".to_string());
            }
        }
    }

    // Check for known Stuxnet byte patterns
    for pattern in STUXNET_PATTERNS {
        if contains_pattern(traffic, pattern) {
            indicators.push(format!("Stuxnet signature pattern matched: {:?}", &pattern[..4.min(pattern.len())]));
        }
    }

    // Check for centrifuge-specific targeting
    if traffic.len() > 100 {
        // Look for frequency converter parameters
        let traffic_str = String::from_utf8_lossy(traffic);
        if traffic_str.contains("frequency") && traffic_str.contains("1410") {
            indicators.push("Centrifuge frequency manipulation pattern detected".to_string());
        }
    }

    if !indicators.is_empty() {
        return Ok(Some(IcsThreatDetection {
            id: uuid::Uuid::new_v4().to_string(),
            threat_type: IcsThreatType::Stuxnet,
            severity: ThreatSeverity::Critical,
            description: "Stuxnet-style attack patterns detected - potential PLC manipulation".to_string(),
            indicators,
            timestamp: Utc::now(),
            mitre_attack_ids: vec![
                "T0831".to_string(), // Manipulation of Control
                "T0821".to_string(), // Modify Controller Tasking
                "T0839".to_string(), // Module Firmware
            ],
            recommendations: vec![
                "Immediately isolate affected PLC from network".to_string(),
                "Verify PLC program integrity".to_string(),
                "Check for unauthorized code modifications".to_string(),
                "Enable S7 protocol encryption if available".to_string(),
            ],
        }));
    }

    Ok(None)
}

/// Detect TRITON/TRISIS malware patterns
pub async fn detect_triton(traffic: &[u8]) -> Result<Option<IcsThreatDetection>> {
    info!("Scanning for TRITON/TRISIS attack patterns");

    if traffic.is_empty() {
        return Ok(None);
    }

    let mut indicators = Vec::new();

    // Check for Triconex protocol patterns
    if traffic.len() >= 8 {
        // TSAA (Triconex System Access Application) protocol
        // Look for memory write commands to safety system
        if traffic[0..4] == [0x00, 0x00, 0x00, 0x00] {
            // Check for module download attempt
            if traffic.len() >= 12 && traffic[6] == 0x05 {
                indicators.push("TSAA protocol module download command detected".to_string());
            }

            // Check for program modification
            if traffic.len() >= 12 && traffic[6] == 0x08 {
                indicators.push("TSAA protocol program modification command detected".to_string());
            }
        }
    }

    // Check for known TRITON byte patterns
    for pattern in TRITON_PATTERNS {
        if contains_pattern(traffic, pattern) {
            indicators.push(format!("TRITON signature pattern matched"));
        }
    }

    // Check for suspicious Python payload (TRITON uses Python)
    let traffic_str = String::from_utf8_lossy(traffic);
    if traffic_str.contains("import struct") || traffic_str.contains("TriStation") {
        indicators.push("TRITON-related code patterns detected".to_string());
    }

    // Check for SIS bypass attempts
    if traffic_str.contains("disable_safety") || traffic_str.contains("bypass_interlock") {
        indicators.push("Safety system bypass attempt detected".to_string());
    }

    if !indicators.is_empty() {
        return Ok(Some(IcsThreatDetection {
            id: uuid::Uuid::new_v4().to_string(),
            threat_type: IcsThreatType::Triton,
            severity: ThreatSeverity::Critical,
            description: "TRITON/TRISIS malware patterns detected - safety system compromise attempt".to_string(),
            indicators,
            timestamp: Utc::now(),
            mitre_attack_ids: vec![
                "T0880".to_string(), // Loss of Safety
                "T0879".to_string(), // Damage to Property
                "T0836".to_string(), // Modify Parameter
            ],
            recommendations: vec![
                "IMMEDIATELY isolate safety controllers from network".to_string(),
                "Do NOT attempt to restart safety system without verification".to_string(),
                "Contact safety system vendor emergency support".to_string(),
                "Preserve all forensic evidence".to_string(),
                "Consider controlled shutdown of protected process".to_string(),
            ],
        }));
    }

    Ok(None)
}

/// Detect BlackEnergy/Industroyer attacks
pub async fn detect_blackenergy(traffic: &[u8]) -> Result<Option<IcsThreatDetection>> {
    info!("Scanning for BlackEnergy/Industroyer attack patterns");

    if traffic.is_empty() {
        return Ok(None);
    }

    let mut indicators = Vec::new();

    // Check for IEC 61850 protocol manipulation
    if traffic.len() >= 4 {
        // MMS (Manufacturing Message Specification) header
        if traffic[0] == 0x03 && traffic[1] == 0x00 {
            indicators.push("IEC 61850 MMS protocol detected".to_string());

            // Check for control operations
            if traffic.len() >= 20 {
                let traffic_str = String::from_utf8_lossy(traffic);
                if traffic_str.contains("Operate") || traffic_str.contains("SBOw") {
                    indicators.push("IEC 61850 GOOSE control operation detected".to_string());
                }
            }
        }
    }

    // Check for IEC 104 protocol manipulation
    if traffic.len() >= 6 && traffic[0] == 0x68 {
        indicators.push("IEC 60870-5-104 protocol detected".to_string());

        // Check for control commands (Type ID 45-51)
        if traffic.len() >= 12 {
            let type_id = traffic[6];
            if type_id >= 45 && type_id <= 51 {
                indicators.push(format!("IEC 104 control command detected: Type ID {}", type_id));
            }
        }
    }

    // Check for OPC UA manipulation
    let traffic_str = String::from_utf8_lossy(traffic);
    if traffic_str.contains("opc.tcp://") || traffic_str.contains("OpcUa") {
        indicators.push("OPC UA protocol detected".to_string());
    }

    // Check for known BlackEnergy patterns
    for pattern in BLACKENERGY_PATTERNS {
        if contains_pattern(traffic, pattern) {
            indicators.push("BlackEnergy signature pattern matched".to_string());
        }
    }

    // Check for wiper component indicators
    if traffic_str.contains("KillDisk") || traffic_str.contains("0x00" .repeat(1024).as_str()) {
        indicators.push("Disk wiper component indicators detected".to_string());
    }

    if !indicators.is_empty() {
        return Ok(Some(IcsThreatDetection {
            id: uuid::Uuid::new_v4().to_string(),
            threat_type: IcsThreatType::BlackEnergy,
            severity: ThreatSeverity::Critical,
            description: "BlackEnergy/Industroyer attack patterns detected - grid infrastructure targeted".to_string(),
            indicators,
            timestamp: Utc::now(),
            mitre_attack_ids: vec![
                "T0855".to_string(), // Unauthorized Command Message
                "T0816".to_string(), // Device Restart/Shutdown
                "T0826".to_string(), // Loss of Availability
            ],
            recommendations: vec![
                "Isolate affected substations/RTUs".to_string(),
                "Switch to manual control mode".to_string(),
                "Notify grid operator and CERT".to_string(),
                "Preserve network captures for forensics".to_string(),
            ],
        }));
    }

    Ok(None)
}

/// Detect PLC malware
pub async fn detect_plc_malware(plc_data: &serde_json::Value) -> Result<Vec<IcsThreatDetection>> {
    info!("Scanning for PLC malware indicators");

    let mut detections = Vec::new();

    // Extract PLC state information
    let program_hash = plc_data.get("program_hash")
        .and_then(|h| h.as_str())
        .unwrap_or("");

    let firmware_version = plc_data.get("firmware_version")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let running_blocks = plc_data.get("running_blocks")
        .and_then(|b| b.as_array())
        .map(|arr| arr.len())
        .unwrap_or(0);

    let mut indicators = Vec::new();

    // Check for unexpected program modifications
    if let Some(expected_hash) = plc_data.get("expected_program_hash").and_then(|h| h.as_str()) {
        if !program_hash.is_empty() && program_hash != expected_hash {
            indicators.push(format!(
                "PLC program hash mismatch: expected {}, found {}",
                &expected_hash[..8.min(expected_hash.len())],
                &program_hash[..8.min(program_hash.len())]
            ));
        }
    }

    // Check for suspicious function blocks
    if let Some(blocks) = plc_data.get("running_blocks").and_then(|b| b.as_array()) {
        for block in blocks {
            if let Some(block_name) = block.get("name").and_then(|n| n.as_str()) {
                // Check for suspicious block names
                if block_name.starts_with("OB") && block_name.contains("999") {
                    indicators.push(format!("Suspicious OB block detected: {}", block_name));
                }

                // Check for hidden blocks
                if block_name.starts_with("_") || block_name.starts_with(".") {
                    indicators.push(format!("Hidden function block detected: {}", block_name));
                }
            }

            // Check for unusually large blocks
            if let Some(size) = block.get("size").and_then(|s| s.as_u64()) {
                if size > 64000 { // Unusual size for typical PLC logic
                    indicators.push(format!("Unusually large code block: {} bytes", size));
                }
            }
        }
    }

    // Check for firmware manipulation
    if let Some(expected_firmware) = plc_data.get("expected_firmware").and_then(|f| f.as_str()) {
        if !firmware_version.is_empty() && firmware_version != expected_firmware {
            indicators.push(format!(
                "Firmware version mismatch: expected {}, found {}",
                expected_firmware, firmware_version
            ));
        }
    }

    // Check for suspicious I/O patterns
    if let Some(io_status) = plc_data.get("io_status").and_then(|i| i.as_object()) {
        let forced_count = io_status.iter()
            .filter(|(_, v)| v.get("forced").and_then(|f| f.as_bool()).unwrap_or(false))
            .count();

        if forced_count > 5 {
            indicators.push(format!("{} I/O points are forced - potential manipulation", forced_count));
        }
    }

    // Check for timing anomalies
    if let Some(cycle_time) = plc_data.get("scan_cycle_ms").and_then(|c| c.as_f64()) {
        if let Some(expected_cycle) = plc_data.get("expected_cycle_ms").and_then(|c| c.as_f64()) {
            if (cycle_time - expected_cycle).abs() > expected_cycle * 0.5 {
                indicators.push(format!(
                    "Scan cycle anomaly: expected {:.1}ms, actual {:.1}ms",
                    expected_cycle, cycle_time
                ));
            }
        }
    }

    if !indicators.is_empty() {
        detections.push(IcsThreatDetection {
            id: uuid::Uuid::new_v4().to_string(),
            threat_type: IcsThreatType::PlcMalware,
            severity: ThreatSeverity::High,
            description: "PLC malware indicators detected - possible ladder logic manipulation".to_string(),
            indicators,
            timestamp: Utc::now(),
            mitre_attack_ids: vec![
                "T0821".to_string(), // Modify Controller Tasking
                "T0839".to_string(), // Module Firmware
                "T0836".to_string(), // Modify Parameter
            ],
            recommendations: vec![
                "Verify PLC program against known-good backup".to_string(),
                "Check PLC event logs for unauthorized access".to_string(),
                "Consider restoring PLC from verified backup".to_string(),
                "Enable password protection on PLC if not already".to_string(),
            ],
        });
    }

    Ok(detections)
}

/// Detect command injection attacks
pub async fn detect_command_injection(protocol: &str, command: &str) -> Result<Option<IcsThreatDetection>> {
    info!("Scanning for command injection in {} protocol", protocol);

    let mut indicators = Vec::new();
    let command_lower = command.to_lowercase();

    // Check for shell command injection
    let shell_patterns = [";", "&&", "||", "|", "`", "$(", ">/", "<"];
    for pattern in shell_patterns {
        if command.contains(pattern) {
            indicators.push(format!("Shell metacharacter detected: {}", pattern));
        }
    }

    // Check for SQL injection in SCADA historian queries
    let sql_patterns = ["'--", "'; --", "' OR ", "UNION SELECT", "DROP TABLE"];
    for pattern in sql_patterns {
        if command_lower.contains(&pattern.to_lowercase()) {
            indicators.push(format!("SQL injection pattern detected: {}", pattern));
        }
    }

    // Protocol-specific checks
    match protocol.to_uppercase().as_str() {
        "MODBUS" => {
            // Check for dangerous Modbus function codes
            if command_lower.contains("write_coil") || command_lower.contains("write_register") {
                if command.contains("broadcast") || command.contains("0x00") {
                    indicators.push("Modbus broadcast write command detected".to_string());
                }
            }
        }
        "DNP3" => {
            // Check for DNP3 control commands
            if command_lower.contains("cold_restart") || command_lower.contains("warm_restart") {
                indicators.push("DNP3 device restart command detected".to_string());
            }
            if command_lower.contains("disable_unsolicited") {
                indicators.push("DNP3 unsolicited response disable command".to_string());
            }
        }
        "OPC" | "OPCUA" => {
            // Check for OPC security bypass
            if command_lower.contains("anonymous") || command_lower.contains("bypass") {
                indicators.push("OPC security bypass attempt detected".to_string());
            }
        }
        _ => {}
    }

    // Check for path traversal
    if command.contains("../") || command.contains("..\\") {
        indicators.push("Path traversal attempt detected".to_string());
    }

    // Check for system command execution
    let system_commands = ["cmd.exe", "/bin/sh", "powershell", "wget", "curl", "nc "];
    for cmd in system_commands {
        if command_lower.contains(cmd) {
            indicators.push(format!("System command execution attempt: {}", cmd));
        }
    }

    if !indicators.is_empty() {
        return Ok(Some(IcsThreatDetection {
            id: uuid::Uuid::new_v4().to_string(),
            threat_type: IcsThreatType::CommandInjection,
            severity: ThreatSeverity::High,
            description: format!("Command injection attack detected in {} protocol", protocol),
            indicators,
            timestamp: Utc::now(),
            mitre_attack_ids: vec![
                "T0855".to_string(), // Unauthorized Command Message
                "T0843".to_string(), // Program Upload
            ],
            recommendations: vec![
                "Block suspicious traffic immediately".to_string(),
                "Review firewall rules for ICS protocols".to_string(),
                "Enable command validation on HMI/SCADA".to_string(),
                "Audit recent command history".to_string(),
            ],
        }));
    }

    Ok(None)
}

/// Detect reconnaissance activity
pub async fn detect_reconnaissance(traffic: &[u8]) -> Result<Option<IcsThreatDetection>> {
    info!("Scanning for reconnaissance activity");

    if traffic.is_empty() {
        return Ok(None);
    }

    let mut indicators = Vec::new();
    let traffic_str = String::from_utf8_lossy(traffic);

    // Check for Modbus device enumeration
    if traffic.len() >= 8 {
        // Modbus TCP header
        if traffic[2] == 0x00 && traffic[3] == 0x00 {
            // Function code 43 (Read Device Identification)
            if traffic.len() >= 12 && traffic[7] == 0x2B {
                indicators.push("Modbus device identification request detected".to_string());
            }
        }
    }

    // Check for S7 enumeration
    if traffic_str.contains("S7") && (traffic_str.contains("SZL") || traffic_str.contains("read_szl")) {
        indicators.push("S7 system state list enumeration detected".to_string());
    }

    // Check for SNMP enumeration
    if traffic_str.contains("public") || traffic_str.contains("private") {
        if traffic_str.contains("sysDescr") || traffic_str.contains("1.3.6.1") {
            indicators.push("SNMP enumeration with default community string".to_string());
        }
    }

    // Check for port scanning patterns
    // Rapid sequential connection attempts to ICS ports
    let ics_ports = [102, 502, 20000, 44818, 47808, 1911, 2222, 2404, 4000];
    for port in ics_ports {
        if traffic_str.contains(&format!(":{}", port)) {
            indicators.push(format!("Connection to ICS port {} detected", port));
        }
    }

    if !indicators.is_empty() {
        return Ok(Some(IcsThreatDetection {
            id: uuid::Uuid::new_v4().to_string(),
            threat_type: IcsThreatType::Reconnaissance,
            severity: ThreatSeverity::Medium,
            description: "ICS reconnaissance activity detected - potential attack preparation".to_string(),
            indicators,
            timestamp: Utc::now(),
            mitre_attack_ids: vec![
                "T0840".to_string(), // Network Service Scanning
                "T0842".to_string(), // Network Sniffing
                "T0846".to_string(), // Remote System Discovery
            ],
            recommendations: vec![
                "Monitor source IP for further suspicious activity".to_string(),
                "Review access control lists".to_string(),
                "Enable IDS signatures for ICS protocols".to_string(),
            ],
        }));
    }

    Ok(None)
}

/// Helper function to check if traffic contains a byte pattern
fn contains_pattern(traffic: &[u8], pattern: &[u8]) -> bool {
    if pattern.len() > traffic.len() {
        return false;
    }

    for i in 0..=(traffic.len() - pattern.len()) {
        if &traffic[i..i + pattern.len()] == pattern {
            return true;
        }
    }

    false
}

/// Run all threat detection checks
pub async fn run_full_detection(traffic: &[u8], plc_data: Option<&serde_json::Value>) -> Result<Vec<IcsThreatDetection>> {
    info!("Running full ICS threat detection scan");

    let mut all_detections = Vec::new();

    // Run all detection functions
    if let Some(detection) = detect_stuxnet_patterns(traffic).await? {
        all_detections.push(detection);
    }

    if let Some(detection) = detect_triton(traffic).await? {
        all_detections.push(detection);
    }

    if let Some(detection) = detect_blackenergy(traffic).await? {
        all_detections.push(detection);
    }

    if let Some(plc) = plc_data {
        all_detections.extend(detect_plc_malware(plc).await?);
    }

    if let Some(detection) = detect_reconnaissance(traffic).await? {
        all_detections.push(detection);
    }

    info!("Full detection complete: {} threats found", all_detections.len());
    Ok(all_detections)
}
