//! OT/ICS Compliance Checking
//!
//! Provides compliance assessment for industrial control systems against:
//! - IEC 62443 (Industrial Automation and Control Systems Security)
//! - NERC CIP (Critical Infrastructure Protection for power utilities)
//! - API 1164 (Pipeline SCADA Security)
//! - NIST SP 800-82 (Guide to ICS Security)

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use log::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcsComplianceResult {
    pub framework: String,
    pub compliant: bool,
    pub findings: Vec<ComplianceFinding>,
    pub score: f64,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceFinding {
    pub control_id: String,
    pub control_name: String,
    pub severity: FindingSeverity,
    pub status: ComplianceStatus,
    pub description: String,
    pub evidence: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FindingSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ComplianceStatus {
    Pass,
    Fail,
    NotApplicable,
    Manual,
}

/// IEC 62443 Security Levels
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Iec62443SecurityLevel {
    SL0, // No specific requirements
    SL1, // Protection against casual or coincidental violation
    SL2, // Protection against intentional violation using simple means
    SL3, // Protection against sophisticated attacks
    SL4, // Protection against state-sponsored attacks
}

/// Check IEC 62443 compliance for industrial assets
pub async fn check_iec_62443_compliance(assets: &[serde_json::Value]) -> Result<IcsComplianceResult> {
    info!("Checking IEC 62443 compliance for {} assets", assets.len());

    let mut findings = Vec::new();
    let mut total_points = 0.0;
    let mut max_points = 0.0;

    // FR 1: Identification and Authentication Control (IAC)
    let (fr1_finding, fr1_score) = check_iec_62443_fr1(assets);
    findings.push(fr1_finding);
    total_points += fr1_score;
    max_points += 100.0;

    // FR 2: Use Control (UC)
    let (fr2_finding, fr2_score) = check_iec_62443_fr2(assets);
    findings.push(fr2_finding);
    total_points += fr2_score;
    max_points += 100.0;

    // FR 3: System Integrity (SI)
    let (fr3_finding, fr3_score) = check_iec_62443_fr3(assets);
    findings.push(fr3_finding);
    total_points += fr3_score;
    max_points += 100.0;

    // FR 4: Data Confidentiality (DC)
    let (fr4_finding, fr4_score) = check_iec_62443_fr4(assets);
    findings.push(fr4_finding);
    total_points += fr4_score;
    max_points += 100.0;

    // FR 5: Restricted Data Flow (RDF)
    let (fr5_finding, fr5_score) = check_iec_62443_fr5(assets);
    findings.push(fr5_finding);
    total_points += fr5_score;
    max_points += 100.0;

    // FR 6: Timely Response to Events (TRE)
    let (fr6_finding, fr6_score) = check_iec_62443_fr6(assets);
    findings.push(fr6_finding);
    total_points += fr6_score;
    max_points += 100.0;

    // FR 7: Resource Availability (RA)
    let (fr7_finding, fr7_score) = check_iec_62443_fr7(assets);
    findings.push(fr7_finding);
    total_points += fr7_score;
    max_points += 100.0;

    let score = if max_points > 0.0 {
        (total_points / max_points) * 100.0
    } else {
        0.0
    };

    let compliant = score >= 70.0 && !findings.iter().any(|f| f.severity == FindingSeverity::Critical && f.status == ComplianceStatus::Fail);

    let mut recommendations = Vec::new();
    for finding in &findings {
        if finding.status == ComplianceStatus::Fail {
            recommendations.push(format!("{}: {}", finding.control_id, finding.description));
        }
    }

    info!("IEC 62443 compliance score: {:.1}%", score);

    Ok(IcsComplianceResult {
        framework: "IEC 62443".to_string(),
        compliant,
        findings,
        score,
        recommendations,
    })
}

/// FR 1: Identification and Authentication Control
fn check_iec_62443_fr1(assets: &[serde_json::Value]) -> (ComplianceFinding, f64) {
    let mut score: f64 = 100.0;
    let mut issues = Vec::new();

    for asset in assets {
        // Check for authentication enabled
        let auth_enabled = asset.get("authentication_enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if !auth_enabled {
            score -= 20.0;
            issues.push("Authentication not enabled on device");
        }

        // Check for default credentials
        let has_default_creds = asset.get("has_default_credentials")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if has_default_creds {
            score -= 30.0;
            issues.push("Default credentials detected");
        }

        // Check for unique identifiers
        let has_unique_id = asset.get("device_id")
            .and_then(|v| v.as_str())
            .map(|s| !s.is_empty())
            .unwrap_or(false);

        if !has_unique_id {
            score -= 10.0;
            issues.push("Missing unique device identifier");
        }
    }

    score = score.max(0.0);
    let status = if score >= 70.0 { ComplianceStatus::Pass } else { ComplianceStatus::Fail };
    let severity = if score < 50.0 { FindingSeverity::Critical } else if score < 70.0 { FindingSeverity::High } else { FindingSeverity::Low };

    (ComplianceFinding {
        control_id: "IEC 62443-3-3 FR1".to_string(),
        control_name: "Identification and Authentication Control".to_string(),
        severity,
        status,
        description: if issues.is_empty() {
            "All IAC requirements met".to_string()
        } else {
            format!("Issues: {}", issues.join("; "))
        },
        evidence: Some(format!("{} assets analyzed", assets.len())),
    }, score)
}

/// FR 2: Use Control
fn check_iec_62443_fr2(assets: &[serde_json::Value]) -> (ComplianceFinding, f64) {
    let mut score: f64 = 100.0;
    let mut issues = Vec::new();

    for asset in assets {
        // Check for role-based access control
        let has_rbac = asset.get("role_based_access")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if !has_rbac {
            score -= 15.0;
            issues.push("RBAC not implemented");
        }

        // Check for session management
        let has_session_mgmt = asset.get("session_timeout_enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if !has_session_mgmt {
            score -= 10.0;
            issues.push("Session timeout not configured");
        }
    }

    score = score.max(0.0);
    let status = if score >= 70.0 { ComplianceStatus::Pass } else { ComplianceStatus::Fail };
    let severity = if score < 50.0 { FindingSeverity::High } else { FindingSeverity::Medium };

    (ComplianceFinding {
        control_id: "IEC 62443-3-3 FR2".to_string(),
        control_name: "Use Control".to_string(),
        severity,
        status,
        description: if issues.is_empty() {
            "Use control requirements met".to_string()
        } else {
            format!("Issues: {}", issues.join("; "))
        },
        evidence: None,
    }, score)
}

/// FR 3: System Integrity
fn check_iec_62443_fr3(assets: &[serde_json::Value]) -> (ComplianceFinding, f64) {
    let mut score: f64 = 100.0;
    let mut issues = Vec::new();

    for asset in assets {
        // Check firmware integrity validation
        let firmware_validated = asset.get("firmware_integrity_validated")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if !firmware_validated {
            score -= 20.0;
            issues.push("Firmware integrity not validated");
        }

        // Check for secure boot
        let secure_boot = asset.get("secure_boot_enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if !secure_boot {
            score -= 15.0;
            issues.push("Secure boot not enabled");
        }
    }

    score = score.max(0.0);
    let status = if score >= 70.0 { ComplianceStatus::Pass } else { ComplianceStatus::Fail };
    let severity = if score < 50.0 { FindingSeverity::High } else { FindingSeverity::Medium };

    (ComplianceFinding {
        control_id: "IEC 62443-3-3 FR3".to_string(),
        control_name: "System Integrity".to_string(),
        severity,
        status,
        description: if issues.is_empty() {
            "System integrity requirements met".to_string()
        } else {
            format!("Issues: {}", issues.join("; "))
        },
        evidence: None,
    }, score)
}

/// FR 4: Data Confidentiality
fn check_iec_62443_fr4(assets: &[serde_json::Value]) -> (ComplianceFinding, f64) {
    let mut score: f64 = 100.0;
    let mut issues: Vec<String> = Vec::new();

    for asset in assets {
        // Check for encrypted communications
        let encrypted = asset.get("encryption_enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if !encrypted {
            score -= 25.0;
            issues.push("Communications not encrypted".to_string());
        }

        // Check protocols for encryption support
        if let Some(protocols) = asset.get("protocols").and_then(|p| p.as_array()) {
            for protocol in protocols {
                let proto_str = protocol.as_str().unwrap_or("");
                // Cleartext protocols are a risk
                if ["modbus", "dnp3", "bacnet"].contains(&proto_str.to_lowercase().as_str()) {
                    if !encrypted {
                        score -= 10.0;
                        issues.push(format!("Cleartext protocol {} without encryption wrapper", proto_str));
                    }
                }
            }
        }
    }

    score = score.max(0.0);
    let status = if score >= 70.0 { ComplianceStatus::Pass } else { ComplianceStatus::Fail };
    let severity = if score < 50.0 { FindingSeverity::High } else { FindingSeverity::Medium };

    (ComplianceFinding {
        control_id: "IEC 62443-3-3 FR4".to_string(),
        control_name: "Data Confidentiality".to_string(),
        severity,
        status,
        description: if issues.is_empty() {
            "Data confidentiality requirements met".to_string()
        } else {
            "Encryption gaps detected - sensitive data may be exposed".to_string()
        },
        evidence: None,
    }, score)
}

/// FR 5: Restricted Data Flow
fn check_iec_62443_fr5(assets: &[serde_json::Value]) -> (ComplianceFinding, f64) {
    let mut score: f64 = 100.0;
    let mut issues = Vec::new();

    // Check for network segmentation
    let mut zones_found: HashMap<String, i32> = HashMap::new();
    for asset in assets {
        if let Some(zone) = asset.get("network_zone").and_then(|z| z.as_str()) {
            *zones_found.entry(zone.to_string()).or_insert(0) += 1;
        } else {
            score -= 10.0;
            issues.push("Asset without defined network zone");
        }
    }

    // Check for zone separation
    if zones_found.len() < 2 && assets.len() > 5 {
        score -= 30.0;
        issues.push("Insufficient network segmentation");
    }

    // Check for firewall presence
    let has_firewall = assets.iter().any(|a| {
        a.get("firewall_protected").and_then(|v| v.as_bool()).unwrap_or(false)
    });

    if !has_firewall && !assets.is_empty() {
        score -= 20.0;
        issues.push("No firewall protection detected");
    }

    score = score.max(0.0);
    let status = if score >= 70.0 { ComplianceStatus::Pass } else { ComplianceStatus::Fail };
    let severity = if score < 50.0 { FindingSeverity::Critical } else { FindingSeverity::High };

    (ComplianceFinding {
        control_id: "IEC 62443-3-3 FR5".to_string(),
        control_name: "Restricted Data Flow".to_string(),
        severity,
        status,
        description: if issues.is_empty() {
            "Data flow restrictions properly implemented".to_string()
        } else {
            format!("Network segmentation issues: {}", issues.join("; "))
        },
        evidence: Some(format!("{} zones identified", zones_found.len())),
    }, score)
}

/// FR 6: Timely Response to Events
fn check_iec_62443_fr6(assets: &[serde_json::Value]) -> (ComplianceFinding, f64) {
    let mut score: f64 = 100.0;
    let mut issues = Vec::new();

    for asset in assets {
        // Check for logging enabled
        let logging_enabled = asset.get("logging_enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if !logging_enabled {
            score -= 15.0;
            issues.push("Security logging not enabled");
        }

        // Check for monitoring
        let monitored = asset.get("monitored")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if !monitored {
            score -= 10.0;
            issues.push("Asset not being monitored");
        }
    }

    score = score.max(0.0);
    let status = if score >= 70.0 { ComplianceStatus::Pass } else { ComplianceStatus::Fail };
    let severity = if score < 50.0 { FindingSeverity::High } else { FindingSeverity::Medium };

    (ComplianceFinding {
        control_id: "IEC 62443-3-3 FR6".to_string(),
        control_name: "Timely Response to Events".to_string(),
        severity,
        status,
        description: if issues.is_empty() {
            "Event monitoring and response capabilities in place".to_string()
        } else {
            format!("Monitoring gaps: {}", issues.join("; "))
        },
        evidence: None,
    }, score)
}

/// FR 7: Resource Availability
fn check_iec_62443_fr7(assets: &[serde_json::Value]) -> (ComplianceFinding, f64) {
    let mut score: f64 = 100.0;
    let mut issues = Vec::new();

    for asset in assets {
        // Check for redundancy
        let has_redundancy = asset.get("redundancy_configured")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let criticality = asset.get("criticality")
            .and_then(|c| c.as_str())
            .unwrap_or("low");

        if criticality == "critical" && !has_redundancy {
            score -= 25.0;
            issues.push("Critical asset without redundancy");
        }

        // Check for backup
        let has_backup = asset.get("backup_configured")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if !has_backup {
            score -= 10.0;
            issues.push("Configuration backup not available");
        }
    }

    score = score.max(0.0);
    let status = if score >= 70.0 { ComplianceStatus::Pass } else { ComplianceStatus::Fail };
    let severity = if score < 50.0 { FindingSeverity::High } else { FindingSeverity::Medium };

    (ComplianceFinding {
        control_id: "IEC 62443-3-3 FR7".to_string(),
        control_name: "Resource Availability".to_string(),
        severity,
        status,
        description: if issues.is_empty() {
            "Resource availability requirements met".to_string()
        } else {
            format!("Availability concerns: {}", issues.join("; "))
        },
        evidence: None,
    }, score)
}

/// Check NERC CIP compliance for power utility assets
pub async fn check_nerc_cip_compliance(assets: &[serde_json::Value]) -> Result<IcsComplianceResult> {
    info!("Checking NERC CIP compliance for {} assets", assets.len());

    let mut findings = Vec::new();
    let mut total_points = 0.0;
    let mut max_points = 0.0;

    // CIP-002: BES Cyber System Categorization
    let (cip002_finding, cip002_score) = check_nerc_cip_002(assets);
    findings.push(cip002_finding);
    total_points += cip002_score;
    max_points += 100.0;

    // CIP-003: Security Management Controls
    let (cip003_finding, cip003_score) = check_nerc_cip_003(assets);
    findings.push(cip003_finding);
    total_points += cip003_score;
    max_points += 100.0;

    // CIP-005: Electronic Security Perimeter
    let (cip005_finding, cip005_score) = check_nerc_cip_005(assets);
    findings.push(cip005_finding);
    total_points += cip005_score;
    max_points += 100.0;

    // CIP-007: Systems Security Management
    let (cip007_finding, cip007_score) = check_nerc_cip_007(assets);
    findings.push(cip007_finding);
    total_points += cip007_score;
    max_points += 100.0;

    // CIP-010: Configuration Change Management
    let (cip010_finding, cip010_score) = check_nerc_cip_010(assets);
    findings.push(cip010_finding);
    total_points += cip010_score;
    max_points += 100.0;

    let score = if max_points > 0.0 {
        (total_points / max_points) * 100.0
    } else {
        0.0
    };

    let compliant = score >= 80.0 && !findings.iter().any(|f| f.severity == FindingSeverity::Critical && f.status == ComplianceStatus::Fail);

    let mut recommendations = Vec::new();
    for finding in &findings {
        if finding.status == ComplianceStatus::Fail {
            recommendations.push(format!("{}: {}", finding.control_id, finding.description));
        }
    }

    info!("NERC CIP compliance score: {:.1}%", score);

    Ok(IcsComplianceResult {
        framework: "NERC CIP".to_string(),
        compliant,
        findings,
        score,
        recommendations,
    })
}

fn check_nerc_cip_002(assets: &[serde_json::Value]) -> (ComplianceFinding, f64) {
    let mut score = 100.0;

    // Check that all assets have impact ratings
    let categorized_count = assets.iter().filter(|a| {
        a.get("impact_rating").and_then(|i| i.as_str()).is_some()
    }).count();

    let categorization_rate = if !assets.is_empty() {
        (categorized_count as f64 / assets.len() as f64) * 100.0
    } else {
        100.0
    };

    if categorization_rate < 100.0 {
        score = categorization_rate;
    }

    let status = if score >= 100.0 { ComplianceStatus::Pass } else { ComplianceStatus::Fail };
    let severity = if score < 50.0 { FindingSeverity::Critical } else { FindingSeverity::High };

    (ComplianceFinding {
        control_id: "CIP-002-5.1a".to_string(),
        control_name: "BES Cyber System Categorization".to_string(),
        severity,
        status,
        description: format!("{:.0}% of assets have impact categorization", categorization_rate),
        evidence: Some(format!("{}/{} assets categorized", categorized_count, assets.len())),
    }, score)
}

fn check_nerc_cip_003(assets: &[serde_json::Value]) -> (ComplianceFinding, f64) {
    // Security management controls - check for policy indicators
    let has_security_policies = assets.iter().any(|a| {
        a.get("security_policy_applied").and_then(|v| v.as_bool()).unwrap_or(false)
    });

    let score = if has_security_policies || assets.is_empty() { 100.0 } else { 50.0 };
    let status = if score >= 80.0 { ComplianceStatus::Pass } else { ComplianceStatus::Fail };

    (ComplianceFinding {
        control_id: "CIP-003-8".to_string(),
        control_name: "Security Management Controls".to_string(),
        severity: FindingSeverity::Medium,
        status,
        description: if has_security_policies {
            "Security policies documented and applied".to_string()
        } else {
            "Security policy application not verified".to_string()
        },
        evidence: None,
    }, score)
}

fn check_nerc_cip_005(assets: &[serde_json::Value]) -> (ComplianceFinding, f64) {
    let mut score = 100.0;

    // Check for Electronic Security Perimeter (ESP) controls
    let esp_protected = assets.iter().filter(|a| {
        a.get("esp_protected").and_then(|v| v.as_bool()).unwrap_or(false) ||
        a.get("firewall_protected").and_then(|v| v.as_bool()).unwrap_or(false)
    }).count();

    let protection_rate = if !assets.is_empty() {
        (esp_protected as f64 / assets.len() as f64) * 100.0
    } else {
        100.0
    };

    if protection_rate < 100.0 {
        score = protection_rate;
    }

    let status = if score >= 90.0 { ComplianceStatus::Pass } else { ComplianceStatus::Fail };
    let severity = if score < 50.0 { FindingSeverity::Critical } else { FindingSeverity::High };

    (ComplianceFinding {
        control_id: "CIP-005-6".to_string(),
        control_name: "Electronic Security Perimeter".to_string(),
        severity,
        status,
        description: format!("{:.0}% of high/medium impact assets within ESP", protection_rate),
        evidence: Some(format!("{}/{} assets protected", esp_protected, assets.len())),
    }, score)
}

fn check_nerc_cip_007(assets: &[serde_json::Value]) -> (ComplianceFinding, f64) {
    let mut score: f64 = 100.0;
    let mut issues: Vec<String> = Vec::new();

    // Check for ports/services management
    let ports_managed = assets.iter().filter(|a| {
        a.get("ports_documented").and_then(|v| v.as_bool()).unwrap_or(false)
    }).count();

    if ports_managed < assets.len() {
        score -= 20.0;
        issues.push("Ports/services not fully documented".to_string());
    }

    // Check for patch management
    let patch_current = assets.iter().filter(|a| {
        a.get("patches_current").and_then(|v| v.as_bool()).unwrap_or(false)
    }).count();

    let patch_rate = if !assets.is_empty() {
        (patch_current as f64 / assets.len() as f64) * 100.0
    } else {
        100.0
    };

    if patch_rate < 90.0 {
        score -= (90.0 - patch_rate) * 0.5;
        issues.push(format!("{:.0}% patch compliance", patch_rate));
    }

    score = score.max(0.0);
    let status = if score >= 80.0 { ComplianceStatus::Pass } else { ComplianceStatus::Fail };
    let severity = if score < 50.0 { FindingSeverity::High } else { FindingSeverity::Medium };

    (ComplianceFinding {
        control_id: "CIP-007-6".to_string(),
        control_name: "Systems Security Management".to_string(),
        severity,
        status,
        description: if issues.is_empty() {
            "Systems security management controls in place".to_string()
        } else {
            format!("Gaps: {}", issues.join("; "))
        },
        evidence: None,
    }, score)
}

fn check_nerc_cip_010(assets: &[serde_json::Value]) -> (ComplianceFinding, f64) {
    let mut score = 100.0;

    // Check for configuration baseline
    let baseline_count = assets.iter().filter(|a| {
        a.get("configuration_baselined").and_then(|v| v.as_bool()).unwrap_or(false)
    }).count();

    let baseline_rate = if !assets.is_empty() {
        (baseline_count as f64 / assets.len() as f64) * 100.0
    } else {
        100.0
    };

    if baseline_rate < 100.0 {
        score = baseline_rate;
    }

    let status = if score >= 90.0 { ComplianceStatus::Pass } else { ComplianceStatus::Fail };
    let severity = if score < 50.0 { FindingSeverity::High } else { FindingSeverity::Medium };

    (ComplianceFinding {
        control_id: "CIP-010-3".to_string(),
        control_name: "Configuration Change Management".to_string(),
        severity,
        status,
        description: format!("{:.0}% of assets have configuration baselines", baseline_rate),
        evidence: Some(format!("{}/{} assets baselined", baseline_count, assets.len())),
    }, score)
}

/// Check API 1164 compliance for pipeline SCADA systems
pub async fn check_api_1164_compliance(assets: &[serde_json::Value]) -> Result<IcsComplianceResult> {
    info!("Checking API 1164 compliance for {} assets", assets.len());

    let mut findings = Vec::new();
    let mut total_points = 0.0;
    let mut max_points = 0.0;

    // Check network security controls
    let (network_finding, network_score) = check_api_1164_network_security(assets);
    findings.push(network_finding);
    total_points += network_score;
    max_points += 100.0;

    // Check access control
    let (access_finding, access_score) = check_api_1164_access_control(assets);
    findings.push(access_finding);
    total_points += access_score;
    max_points += 100.0;

    // Check remote access security
    let (remote_finding, remote_score) = check_api_1164_remote_access(assets);
    findings.push(remote_finding);
    total_points += remote_score;
    max_points += 100.0;

    // Check monitoring
    let (monitoring_finding, monitoring_score) = check_api_1164_monitoring(assets);
    findings.push(monitoring_finding);
    total_points += monitoring_score;
    max_points += 100.0;

    let score = if max_points > 0.0 {
        (total_points / max_points) * 100.0
    } else {
        0.0
    };

    let compliant = score >= 75.0;

    let mut recommendations = Vec::new();
    for finding in &findings {
        if finding.status == ComplianceStatus::Fail {
            recommendations.push(format!("{}: {}", finding.control_id, finding.description));
        }
    }

    info!("API 1164 compliance score: {:.1}%", score);

    Ok(IcsComplianceResult {
        framework: "API 1164".to_string(),
        compliant,
        findings,
        score,
        recommendations,
    })
}

fn check_api_1164_network_security(assets: &[serde_json::Value]) -> (ComplianceFinding, f64) {
    let mut score = 100.0;

    let segmented = assets.iter().filter(|a| {
        a.get("network_segmented").and_then(|v| v.as_bool()).unwrap_or(false)
    }).count();

    if segmented < assets.len() && !assets.is_empty() {
        let rate = segmented as f64 / assets.len() as f64;
        score = rate * 100.0;
    }

    let status = if score >= 80.0 { ComplianceStatus::Pass } else { ComplianceStatus::Fail };

    (ComplianceFinding {
        control_id: "API 1164 Sec 4".to_string(),
        control_name: "Network Security".to_string(),
        severity: FindingSeverity::High,
        status,
        description: format!("{:.0}% network segmentation compliance", score),
        evidence: None,
    }, score)
}

fn check_api_1164_access_control(assets: &[serde_json::Value]) -> (ComplianceFinding, f64) {
    let mut score = 100.0;

    let access_controlled = assets.iter().filter(|a| {
        a.get("authentication_enabled").and_then(|v| v.as_bool()).unwrap_or(false)
    }).count();

    if access_controlled < assets.len() && !assets.is_empty() {
        let rate = access_controlled as f64 / assets.len() as f64;
        score = rate * 100.0;
    }

    let status = if score >= 90.0 { ComplianceStatus::Pass } else { ComplianceStatus::Fail };

    (ComplianceFinding {
        control_id: "API 1164 Sec 5".to_string(),
        control_name: "Access Control".to_string(),
        severity: FindingSeverity::High,
        status,
        description: format!("{:.0}% of assets have access controls", score),
        evidence: None,
    }, score)
}

fn check_api_1164_remote_access(assets: &[serde_json::Value]) -> (ComplianceFinding, f64) {
    let mut score = 100.0;

    let remote_assets = assets.iter().filter(|a| {
        a.get("remote_access_enabled").and_then(|v| v.as_bool()).unwrap_or(false)
    });

    let secure_remote = remote_assets.clone().filter(|a| {
        a.get("remote_access_secured").and_then(|v| v.as_bool()).unwrap_or(false)
    }).count();

    let remote_count = remote_assets.count();

    if remote_count > 0 {
        score = (secure_remote as f64 / remote_count as f64) * 100.0;
    }

    let status = if score >= 100.0 { ComplianceStatus::Pass } else { ComplianceStatus::Fail };

    (ComplianceFinding {
        control_id: "API 1164 Sec 6".to_string(),
        control_name: "Remote Access Security".to_string(),
        severity: FindingSeverity::Critical,
        status,
        description: if remote_count > 0 {
            format!("{:.0}% of remote access points secured", score)
        } else {
            "No remote access points detected".to_string()
        },
        evidence: None,
    }, score)
}

fn check_api_1164_monitoring(assets: &[serde_json::Value]) -> (ComplianceFinding, f64) {
    let mut score = 100.0;

    let monitored = assets.iter().filter(|a| {
        a.get("monitored").and_then(|v| v.as_bool()).unwrap_or(false)
    }).count();

    if monitored < assets.len() && !assets.is_empty() {
        let rate = monitored as f64 / assets.len() as f64;
        score = rate * 100.0;
    }

    let status = if score >= 80.0 { ComplianceStatus::Pass } else { ComplianceStatus::Fail };

    (ComplianceFinding {
        control_id: "API 1164 Sec 7".to_string(),
        control_name: "Monitoring and Incident Response".to_string(),
        severity: FindingSeverity::Medium,
        status,
        description: format!("{:.0}% of assets under monitoring", score),
        evidence: None,
    }, score)
}

/// Validate IEC 62443 zone and conduit model
pub async fn validate_zone_conduit_model(network_topology: &serde_json::Value) -> Result<bool> {
    info!("Validating IEC 62443 zone and conduit model");

    // Extract zones from topology
    let zones = network_topology.get("zones")
        .and_then(|z| z.as_array());

    let conduits = network_topology.get("conduits")
        .and_then(|c| c.as_array());

    // Validation rules
    let mut valid = true;
    let mut issues = Vec::new();

    // Rule 1: All zones must have a security level
    if let Some(zones) = zones {
        for zone in zones {
            if zone.get("security_level").is_none() {
                issues.push(format!("Zone {} missing security level",
                    zone.get("name").and_then(|n| n.as_str()).unwrap_or("unknown")));
                valid = false;
            }
        }
    } else {
        issues.push("No zones defined".to_string());
        valid = false;
    }

    // Rule 2: All conduits must connect to defined zones
    if let Some(conduits) = conduits {
        let zone_names: Vec<&str> = zones
            .map(|z| z.iter().filter_map(|zone| zone.get("name").and_then(|n| n.as_str())).collect())
            .unwrap_or_default();

        for conduit in conduits {
            let source = conduit.get("source_zone").and_then(|s| s.as_str()).unwrap_or("");
            let dest = conduit.get("destination_zone").and_then(|d| d.as_str()).unwrap_or("");

            if !zone_names.contains(&source) {
                issues.push(format!("Conduit references unknown source zone: {}", source));
                valid = false;
            }
            if !zone_names.contains(&dest) {
                issues.push(format!("Conduit references unknown destination zone: {}", dest));
                valid = false;
            }
        }
    }

    // Rule 3: High security zones should not connect directly to low security zones
    if let (Some(zones), Some(conduits)) = (zones, conduits) {
        let zone_levels: HashMap<&str, i64> = zones.iter()
            .filter_map(|z| {
                let name = z.get("name").and_then(|n| n.as_str())?;
                let level = z.get("security_level").and_then(|l| l.as_i64()).unwrap_or(0);
                Some((name, level))
            })
            .collect();

        for conduit in conduits {
            let source = conduit.get("source_zone").and_then(|s| s.as_str()).unwrap_or("");
            let dest = conduit.get("destination_zone").and_then(|d| d.as_str()).unwrap_or("");

            let source_level = zone_levels.get(source).copied().unwrap_or(0);
            let dest_level = zone_levels.get(dest).copied().unwrap_or(0);

            // Security level difference should not exceed 2 without DMZ
            if (source_level - dest_level).abs() > 2 {
                let has_dmz = conduit.get("dmz_zone").is_some();
                if !has_dmz {
                    warn!("Conduit between {} (SL{}) and {} (SL{}) may need DMZ",
                        source, source_level, dest, dest_level);
                    issues.push(format!("Large security level gap without DMZ between {} and {}", source, dest));
                    // This is a warning, not necessarily invalid
                }
            }
        }
    }

    if !issues.is_empty() {
        info!("Zone/conduit validation issues: {:?}", issues);
    }

    Ok(valid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_iec_62443_compliance() {
        let assets = vec![
            json!({
                "device_id": "plc-001",
                "authentication_enabled": true,
                "encryption_enabled": true,
                "logging_enabled": true,
                "network_zone": "zone1",
                "firewall_protected": true
            }),
        ];

        let result = check_iec_62443_compliance(&assets).await.unwrap();
        assert_eq!(result.framework, "IEC 62443");
        assert!(result.score > 0.0);
    }

    #[tokio::test]
    async fn test_nerc_cip_compliance() {
        let assets = vec![
            json!({
                "device_id": "relay-001",
                "impact_rating": "high",
                "esp_protected": true,
                "patches_current": true,
                "configuration_baselined": true
            }),
        ];

        let result = check_nerc_cip_compliance(&assets).await.unwrap();
        assert_eq!(result.framework, "NERC CIP");
        assert!(result.score > 0.0);
    }

    #[tokio::test]
    async fn test_zone_conduit_validation() {
        let topology = json!({
            "zones": [
                {"name": "enterprise", "security_level": 2},
                {"name": "dmz", "security_level": 3},
                {"name": "control", "security_level": 4}
            ],
            "conduits": [
                {"source_zone": "enterprise", "destination_zone": "dmz"},
                {"source_zone": "dmz", "destination_zone": "control"}
            ]
        });

        let result = validate_zone_conduit_model(&topology).await.unwrap();
        assert!(result);
    }
}
