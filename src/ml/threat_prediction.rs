//! Threat prediction using ML

use anyhow::Result;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

use super::models::{predict, Prediction};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatPrediction {
    pub threat_level: f32,
    pub threat_category: String,
    pub attack_vector: String,
    pub confidence: f32,
    pub indicators: Vec<ThreatIndicator>,
    pub mitre_techniques: Vec<String>,
    pub recommended_actions: Vec<String>,
    pub time_to_exploit: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    pub indicator_type: String,
    pub value: String,
    pub severity: String,
    pub contribution: f32,
}

/// Scan result features for ML processing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanFeatures {
    pub open_ports: Vec<u16>,
    pub services: Vec<String>,
    pub os_info: Option<String>,
    pub vulnerabilities: Vec<VulnInfo>,
    pub host_ip: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnInfo {
    pub cve_id: Option<String>,
    pub severity: String,
    pub cvss_score: Option<f32>,
    pub exploitable: bool,
}

/// Extract numerical features from scan results for ML model
fn extract_features(scan_data: &ScanFeatures) -> Vec<f32> {
    // Feature vector:
    // [port_count, high_risk_port_count, service_diversity, vuln_count,
    //  critical_vuln_count, exploitable_count, avg_cvss, exposure_score]

    let port_count = scan_data.open_ports.len() as f32;

    // High-risk ports (common attack targets)
    let high_risk_ports = vec![21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017];
    let high_risk_count = scan_data
        .open_ports
        .iter()
        .filter(|p| high_risk_ports.contains(p))
        .count() as f32;

    let service_diversity = scan_data.services.iter().collect::<std::collections::HashSet<_>>().len() as f32;

    let vuln_count = scan_data.vulnerabilities.len() as f32;

    let critical_count = scan_data
        .vulnerabilities
        .iter()
        .filter(|v| v.severity.to_lowercase() == "critical" || v.severity.to_lowercase() == "high")
        .count() as f32;

    let exploitable_count = scan_data
        .vulnerabilities
        .iter()
        .filter(|v| v.exploitable)
        .count() as f32;

    let avg_cvss = if !scan_data.vulnerabilities.is_empty() {
        scan_data
            .vulnerabilities
            .iter()
            .filter_map(|v| v.cvss_score)
            .sum::<f32>()
            / scan_data.vulnerabilities.len() as f32
    } else {
        0.0
    };

    // Exposure score (0-100): combination of factors
    let exposure = ((port_count / 10.0) * 20.0 +
                    (high_risk_count / 5.0) * 30.0 +
                    (critical_count / 3.0) * 30.0 +
                    (exploitable_count / 2.0) * 20.0)
                    .min(100.0);

    vec![
        port_count,
        high_risk_count,
        service_diversity,
        vuln_count,
        critical_count,
        exploitable_count,
        avg_cvss,
        exposure,
    ]
}

/// Analyze attack vectors based on open ports and services
fn analyze_attack_vectors(scan_data: &ScanFeatures) -> Vec<(String, f32)> {
    let mut vectors: HashMap<String, f32> = HashMap::new();

    for port in &scan_data.open_ports {
        let (vector, weight) = match port {
            21 => ("FTP Brute Force / Anonymous Access", 0.7),
            22 => ("SSH Brute Force / Key Extraction", 0.8),
            23 => ("Telnet Credential Theft", 0.9),
            25 | 587 => ("SMTP Relay Abuse / Phishing", 0.6),
            53 => ("DNS Amplification / Zone Transfer", 0.7),
            80 | 8080 | 8000 => ("Web Application Attack", 0.85),
            110 | 143 | 993 | 995 => ("Email Credential Harvesting", 0.6),
            135 | 139 | 445 => ("SMB/RPC Exploitation", 0.9),
            443 | 8443 => ("HTTPS Interception / SSL Attacks", 0.7),
            1433 => ("MSSQL Injection / Brute Force", 0.85),
            1521 => ("Oracle Database Attack", 0.8),
            3306 => ("MySQL Injection / Brute Force", 0.85),
            3389 => ("RDP Brute Force / BlueKeep", 0.9),
            5432 => ("PostgreSQL Attack", 0.8),
            5900..=5999 => ("VNC Brute Force", 0.85),
            6379 => ("Redis Unauthorized Access", 0.9),
            27017 => ("MongoDB NoAuth Exploitation", 0.9),
            _ => continue,
        };

        let entry = vectors.entry(vector.to_string()).or_insert(0.0);
        *entry = (*entry + weight).min(1.0);
    }

    // Add vulnerability-based attack vectors
    for vuln in &scan_data.vulnerabilities {
        if vuln.exploitable {
            let vector = match vuln.severity.to_lowercase().as_str() {
                "critical" => "Remote Code Execution",
                "high" => "Privilege Escalation",
                _ => continue,
            };
            let entry = vectors.entry(vector.to_string()).or_insert(0.0);
            *entry = (*entry + 0.9).min(1.0);
        }
    }

    let mut result: Vec<_> = vectors.into_iter().collect();
    result.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    result
}

/// Generate MITRE ATT&CK technique mappings
fn map_to_mitre(attack_vectors: &[(String, f32)], scan_data: &ScanFeatures) -> Vec<String> {
    let mut techniques = Vec::new();

    for (vector, _) in attack_vectors {
        let mitre = match vector.as_str() {
            "SSH Brute Force / Key Extraction" => vec!["T1110 - Brute Force", "T1552 - Unsecured Credentials"],
            "FTP Brute Force / Anonymous Access" => vec!["T1110 - Brute Force", "T1078 - Valid Accounts"],
            "RDP Brute Force / BlueKeep" => vec!["T1110 - Brute Force", "T1210 - Exploitation of Remote Services"],
            "SMB/RPC Exploitation" => vec!["T1021.002 - SMB/Windows Admin Shares", "T1210 - Exploitation of Remote Services"],
            "Web Application Attack" => vec!["T1190 - Exploit Public-Facing Application"],
            "Remote Code Execution" => vec!["T1203 - Exploitation for Client Execution", "T1059 - Command and Scripting Interpreter"],
            "Privilege Escalation" => vec!["T1068 - Exploitation for Privilege Escalation"],
            "DNS Amplification / Zone Transfer" => vec!["T1498 - Network Denial of Service", "T1596 - Search Open Technical Databases"],
            "SMTP Relay Abuse / Phishing" => vec!["T1566 - Phishing"],
            _ => vec![],
        };
        techniques.extend(mitre.into_iter().map(String::from));
    }

    // Check for lateral movement indicators
    if scan_data.open_ports.contains(&445) || scan_data.open_ports.contains(&3389) {
        techniques.push("T1570 - Lateral Tool Transfer".to_string());
    }

    // Deduplicate
    techniques.sort();
    techniques.dedup();
    techniques
}

/// Generate recommended actions based on findings
fn generate_recommendations(
    threat_level: f32,
    attack_vectors: &[(String, f32)],
    scan_data: &ScanFeatures,
) -> Vec<String> {
    let mut actions = Vec::new();

    // Priority actions based on threat level
    if threat_level >= 0.8 {
        actions.push("IMMEDIATE: Isolate host from network pending investigation".to_string());
        actions.push("IMMEDIATE: Enable enhanced logging and monitoring".to_string());
    }

    // Specific recommendations based on attack vectors
    for (vector, score) in attack_vectors {
        if *score < 0.5 {
            continue;
        }

        let recommendation = match vector.as_str() {
            "SSH Brute Force / Key Extraction" => "Implement fail2ban, disable password auth, use key-based authentication",
            "RDP Brute Force / BlueKeep" => "Apply MS17-010 and CVE-2019-0708 patches, enable NLA, restrict RDP access",
            "SMB/RPC Exploitation" => "Apply all SMB patches, disable SMBv1, restrict to internal networks only",
            "Web Application Attack" => "Deploy WAF, perform security audit, update web frameworks",
            "Remote Code Execution" => "Apply vendor patches immediately, implement network segmentation",
            "Redis Unauthorized Access" => "Enable Redis authentication, bind to localhost, use firewall rules",
            "MongoDB NoAuth Exploitation" => "Enable MongoDB authentication, restrict network access",
            "FTP Brute Force / Anonymous Access" => "Disable anonymous FTP, use SFTP instead",
            "Telnet Credential Theft" => "Disable Telnet completely, migrate to SSH",
            _ => continue,
        };
        actions.push(format!("{}: {}", vector, recommendation));
    }

    // General recommendations
    if !scan_data.vulnerabilities.is_empty() {
        actions.push("Apply all pending security patches to vulnerable services".to_string());
    }

    if scan_data.open_ports.len() > 10 {
        actions.push("Review and minimize exposed services, implement principle of least privilege".to_string());
    }

    actions
}

/// Estimate time to potential exploit based on findings
fn estimate_time_to_exploit(threat_level: f32, scan_data: &ScanFeatures) -> Option<String> {
    let has_exploitable = scan_data.vulnerabilities.iter().any(|v| v.exploitable);
    let has_critical = scan_data.vulnerabilities.iter().any(|v|
        v.severity.to_lowercase() == "critical" && v.cvss_score.unwrap_or(0.0) >= 9.0
    );

    if has_critical && has_exploitable {
        Some("Minutes to hours - Active exploitation likely".to_string())
    } else if has_exploitable {
        Some("Hours to days - Targeted attacks possible".to_string())
    } else if threat_level >= 0.7 {
        Some("Days to weeks - Opportunistic attacks likely".to_string())
    } else if threat_level >= 0.4 {
        Some("Weeks to months - Low priority target".to_string())
    } else {
        None
    }
}

pub async fn predict_threat(scan_results: &str) -> Result<ThreatPrediction> {
    // Try to parse scan results as JSON
    let scan_data: ScanFeatures = serde_json::from_str(scan_results).unwrap_or_else(|_| {
        // If parsing fails, analyze the raw text for indicators
        parse_raw_scan_results(scan_results)
    });

    // Extract features for ML model
    let features = extract_features(&scan_data);

    // Use ML model for threat classification
    let ml_prediction = predict("threat-classifier-v1", features.clone()).await
        .unwrap_or_else(|_| Prediction {
            class: "suspicious".to_string(),
            confidence: 0.5,
            probabilities: vec![],
        });

    // Calculate threat level from model output and features
    let base_threat_level = match ml_prediction.class.as_str() {
        "malicious" => 0.85,
        "suspicious" => 0.55,
        "benign" => 0.15,
        _ => 0.5,
    };

    // Adjust based on specific findings
    let exposure_score = features.get(7).copied().unwrap_or(0.0);
    let threat_level = (base_threat_level + (exposure_score / 200.0)).min(1.0);

    // Analyze attack vectors
    let attack_vectors = analyze_attack_vectors(&scan_data);

    let primary_vector = attack_vectors
        .first()
        .map(|(v, _)| v.clone())
        .unwrap_or_else(|| "Unknown".to_string());

    // Map to MITRE ATT&CK
    let mitre_techniques = map_to_mitre(&attack_vectors, &scan_data);

    // Generate threat indicators
    let mut indicators = Vec::new();

    // Add port-based indicators
    for port in &scan_data.open_ports {
        let (severity, contribution) = match port {
            23 | 3389 | 445 => ("high", 0.8),
            21 | 22 | 80 | 443 | 3306 => ("medium", 0.5),
            _ => ("low", 0.2),
        };

        if contribution >= 0.5 {
            indicators.push(ThreatIndicator {
                indicator_type: "open_port".to_string(),
                value: port.to_string(),
                severity: severity.to_string(),
                contribution,
            });
        }
    }

    // Add vulnerability indicators
    for vuln in &scan_data.vulnerabilities {
        if vuln.cvss_score.unwrap_or(0.0) >= 7.0 {
            indicators.push(ThreatIndicator {
                indicator_type: "vulnerability".to_string(),
                value: vuln.cve_id.clone().unwrap_or_else(|| "Unknown CVE".to_string()),
                severity: vuln.severity.clone(),
                contribution: vuln.cvss_score.unwrap_or(7.0) / 10.0,
            });
        }
    }

    // Generate recommendations
    let recommended_actions = generate_recommendations(threat_level, &attack_vectors, &scan_data);

    // Estimate time to exploit
    let time_to_exploit = estimate_time_to_exploit(threat_level, &scan_data);

    // Determine threat category
    let threat_category = if threat_level >= 0.8 {
        "Critical - Immediate Action Required"
    } else if threat_level >= 0.6 {
        "High - Prompt Remediation Needed"
    } else if threat_level >= 0.4 {
        "Medium - Schedule Remediation"
    } else {
        "Low - Monitor and Review"
    };

    Ok(ThreatPrediction {
        threat_level,
        threat_category: threat_category.to_string(),
        attack_vector: primary_vector,
        confidence: ml_prediction.confidence,
        indicators,
        mitre_techniques,
        recommended_actions,
        time_to_exploit,
    })
}

/// Parse raw text scan results into structured format
fn parse_raw_scan_results(raw: &str) -> ScanFeatures {
    let mut open_ports = Vec::new();
    let mut services = Vec::new();
    let mut vulnerabilities = Vec::new();

    // Simple parsing for common scan output formats
    for line in raw.lines() {
        let line_lower = line.to_lowercase();

        // Extract port numbers
        if line_lower.contains("/tcp") || line_lower.contains("/udp") {
            if let Some(port_str) = line.split('/').next() {
                if let Ok(port) = port_str.trim().parse::<u16>() {
                    open_ports.push(port);
                }
            }
        }

        // Extract service names
        for service in ["ssh", "http", "https", "ftp", "smtp", "mysql", "postgresql", "mongodb", "redis", "rdp", "smb"] {
            if line_lower.contains(service) && !services.contains(&service.to_string()) {
                services.push(service.to_string());
            }
        }

        // Extract CVE references
        let cve_pattern = regex::Regex::new(r"CVE-\d{4}-\d+").ok();
        if let Some(re) = cve_pattern {
            for cap in re.find_iter(line) {
                vulnerabilities.push(VulnInfo {
                    cve_id: Some(cap.as_str().to_string()),
                    severity: "high".to_string(), // Default assumption for CVEs
                    cvss_score: Some(7.0),
                    exploitable: false,
                });
            }
        }

        // Check for critical/high severity indicators
        if line_lower.contains("critical") || line_lower.contains("vulnerability") {
            if vulnerabilities.is_empty() {
                vulnerabilities.push(VulnInfo {
                    cve_id: None,
                    severity: if line_lower.contains("critical") { "critical" } else { "high" }.to_string(),
                    cvss_score: Some(8.0),
                    exploitable: line_lower.contains("exploit"),
                });
            }
        }
    }

    ScanFeatures {
        open_ports,
        services,
        os_info: None,
        vulnerabilities,
        host_ip: "unknown".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_threat_prediction() {
        let scan_json = r#"{
            "open_ports": [22, 80, 443, 3306],
            "services": ["ssh", "http", "https", "mysql"],
            "os_info": "Linux",
            "vulnerabilities": [
                {"cve_id": "CVE-2021-44228", "severity": "critical", "cvss_score": 10.0, "exploitable": true}
            ],
            "host_ip": "192.168.1.100"
        }"#;

        let prediction = predict_threat(scan_json).await.unwrap();

        assert!(prediction.threat_level > 0.0);
        assert!(prediction.confidence > 0.0);
        assert!(!prediction.recommended_actions.is_empty());
    }

    #[tokio::test]
    async fn test_raw_scan_parsing() {
        let raw_output = "22/tcp open ssh
80/tcp open http
443/tcp open https
CVE-2021-44228 detected - Critical";

        let prediction = predict_threat(raw_output).await.unwrap();

        assert!(!prediction.attack_vector.is_empty());
    }
}
