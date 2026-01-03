//! Network Forensics Detection Module
//!
//! Detect C2 traffic, data exfiltration, lateral movement, and other suspicious network activity.

use crate::investigation::types::NetworkForensicsFinding;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Known C2 beacon characteristics
#[derive(Debug, Clone)]
pub struct C2Characteristics {
    /// Regular interval between connections (in seconds)
    pub beacon_interval: Option<u64>,
    /// Jitter percentage in beacon timing
    pub jitter_percent: Option<f64>,
    /// Common C2 ports
    pub suspicious_ports: HashSet<u16>,
    /// Known C2 user agents
    pub suspicious_user_agents: Vec<String>,
    /// Known C2 URI patterns
    pub suspicious_uri_patterns: Vec<String>,
}

impl Default for C2Characteristics {
    fn default() -> Self {
        let mut suspicious_ports = HashSet::new();
        suspicious_ports.insert(4444);  // Metasploit
        suspicious_ports.insert(8080);  // Common proxy/C2
        suspicious_ports.insert(8443);  // HTTPS alternate
        suspicious_ports.insert(1337);  // "Leet" port
        suspicious_ports.insert(31337); // Back Orifice
        suspicious_ports.insert(6666);  // IRC
        suspicious_ports.insert(6667);  // IRC
        suspicious_ports.insert(6668);  // IRC
        suspicious_ports.insert(5555);  // Common backdoor

        Self {
            beacon_interval: None,
            jitter_percent: None,
            suspicious_ports,
            suspicious_user_agents: vec![
                "Mozilla/4.0".to_string(),
                "Java/".to_string(),
                "MSIE 6.0".to_string(),
                "Wget".to_string(),
                "curl".to_string(),
            ],
            suspicious_uri_patterns: vec![
                "/beacon".to_string(),
                "/c2/".to_string(),
                "/stage".to_string(),
                "/shell".to_string(),
                "/cmd".to_string(),
                "/exec".to_string(),
                "/upload".to_string(),
                "/download".to_string(),
            ],
        }
    }
}

/// Session metadata for analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMetadata {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub start_time: i64,
    pub end_time: Option<i64>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub user_agent: Option<String>,
    pub uri: Option<String>,
    pub host: Option<String>,
}

/// Detect C2 (Command & Control) traffic patterns
pub fn detect_c2_traffic(sessions: &[serde_json::Value]) -> Result<Vec<NetworkForensicsFinding>> {
    let mut findings = Vec::new();
    let chars = C2Characteristics::default();

    // Parse sessions into structured metadata
    let parsed_sessions: Vec<SessionMetadata> = sessions.iter()
        .filter_map(|s| parse_session_metadata(s).ok())
        .collect();

    // Group sessions by destination
    let mut sessions_by_dst: HashMap<String, Vec<&SessionMetadata>> = HashMap::new();
    for session in &parsed_sessions {
        sessions_by_dst.entry(session.dst_ip.clone())
            .or_default()
            .push(session);
    }

    // Analyze each destination for C2 patterns
    for (dst_ip, dst_sessions) in &sessions_by_dst {
        let mut indicators = Vec::new();
        let mut evidence = Vec::new();
        let mut iocs = Vec::new();

        // Check for suspicious ports
        let suspicious_port_sessions: Vec<_> = dst_sessions.iter()
            .filter(|s| chars.suspicious_ports.contains(&s.dst_port))
            .collect();

        if !suspicious_port_sessions.is_empty() {
            indicators.push("Connection to known C2 port".to_string());
            for s in &suspicious_port_sessions {
                evidence.push(format!("{}:{} -> {}:{}", s.src_ip, s.src_port, s.dst_ip, s.dst_port));
            }
        }

        // Check for beacon pattern (regular intervals)
        if dst_sessions.len() >= 3 {
            let mut intervals: Vec<i64> = Vec::new();
            let mut sorted_sessions = dst_sessions.clone();
            sorted_sessions.sort_by_key(|s| s.start_time);

            for i in 1..sorted_sessions.len() {
                let interval = sorted_sessions[i].start_time - sorted_sessions[i - 1].start_time;
                intervals.push(interval);
            }

            if !intervals.is_empty() {
                let avg_interval: f64 = intervals.iter().sum::<i64>() as f64 / intervals.len() as f64;
                let variance: f64 = intervals.iter()
                    .map(|&i| (i as f64 - avg_interval).powi(2))
                    .sum::<f64>() / intervals.len() as f64;
                let std_dev = variance.sqrt();

                // Low variance relative to mean suggests beaconing
                let jitter = if avg_interval > 0.0 { std_dev / avg_interval } else { 1.0 };

                if jitter < 0.2 && avg_interval > 10.0 && avg_interval < 3600.0 {
                    indicators.push(format!(
                        "Beacon pattern detected: ~{:.0}s interval with {:.1}% jitter",
                        avg_interval, jitter * 100.0
                    ));
                    evidence.push(format!(
                        "{} connections at regular intervals over {} sessions",
                        dst_sessions.len(), sorted_sessions.len()
                    ));
                }
            }
        }

        // Check for suspicious user agents
        for session in dst_sessions {
            if let Some(ref ua) = session.user_agent {
                for suspicious_ua in &chars.suspicious_user_agents {
                    if ua.contains(suspicious_ua) {
                        indicators.push(format!("Suspicious user agent: {}", ua));
                        break;
                    }
                }
            }

            // Check for suspicious URIs
            if let Some(ref uri) = session.uri {
                for pattern in &chars.suspicious_uri_patterns {
                    if uri.to_lowercase().contains(&pattern.to_lowercase()) {
                        indicators.push(format!("Suspicious URI pattern: {}", uri));
                        break;
                    }
                }
            }
        }

        // Check for asymmetric traffic (command responses typically small, data exfil large)
        let total_sent: u64 = dst_sessions.iter().map(|s| s.bytes_sent).sum();
        let total_recv: u64 = dst_sessions.iter().map(|s| s.bytes_received).sum();

        if total_sent > 0 && total_recv > 0 {
            let ratio = total_recv as f64 / total_sent as f64;
            if ratio > 10.0 {
                indicators.push(format!(
                    "Highly asymmetric traffic: sent {} bytes, received {} bytes (ratio: {:.1}x)",
                    total_sent, total_recv, ratio
                ));
            }
        }

        // Generate finding if suspicious indicators found
        if !indicators.is_empty() {
            iocs.push(dst_ip.clone());

            let severity = if indicators.len() >= 3 {
                "High"
            } else if indicators.len() >= 2 {
                "Medium"
            } else {
                "Low"
            };

            findings.push(NetworkForensicsFinding {
                finding_type: "C2".to_string(),
                description: format!(
                    "Potential C2 traffic to {}: {}",
                    dst_ip,
                    indicators.join("; ")
                ),
                severity: severity.to_string(),
                sessions: dst_sessions.iter().map(|_| "session_id".to_string()).collect(),
                evidence,
                iocs,
            });
        }
    }

    Ok(findings)
}

/// Detect data exfiltration attempts
pub fn detect_data_exfiltration(sessions: &[serde_json::Value]) -> Result<Vec<NetworkForensicsFinding>> {
    let mut findings = Vec::new();

    // Parse sessions
    let parsed_sessions: Vec<SessionMetadata> = sessions.iter()
        .filter_map(|s| parse_session_metadata(s).ok())
        .collect();

    // Group by source IP to detect internal hosts exfiltrating data
    let mut sessions_by_src: HashMap<String, Vec<&SessionMetadata>> = HashMap::new();
    for session in &parsed_sessions {
        sessions_by_src.entry(session.src_ip.clone())
            .or_default()
            .push(session);
    }

    for (src_ip, src_sessions) in &sessions_by_src {
        let mut indicators = Vec::new();
        let mut evidence = Vec::new();
        let mut iocs = Vec::new();

        // Calculate total outbound data
        let total_bytes_out: u64 = src_sessions.iter().map(|s| s.bytes_sent).sum();

        // Large data transfers (> 100MB in analysis period)
        if total_bytes_out > 100_000_000 {
            indicators.push(format!(
                "Large outbound data volume: {} MB",
                total_bytes_out / 1_000_000
            ));
        }

        // Check for data transfer to suspicious destinations
        let external_destinations: HashSet<_> = src_sessions.iter()
            .filter(|s| !is_private_ip(&s.dst_ip))
            .map(|s| s.dst_ip.clone())
            .collect();

        if external_destinations.len() > 10 {
            indicators.push(format!(
                "Data sent to {} unique external destinations",
                external_destinations.len()
            ));
            for dst in &external_destinations {
                iocs.push(dst.clone());
            }
        }

        // Check for DNS tunneling (high volume DNS queries to single domain)
        let dns_sessions: Vec<_> = src_sessions.iter()
            .filter(|s| s.dst_port == 53)
            .collect();

        if !dns_sessions.is_empty() {
            let dns_bytes: u64 = dns_sessions.iter().map(|s| s.bytes_sent).sum();
            if dns_bytes > 1_000_000 {
                indicators.push(format!(
                    "Potential DNS tunneling: {} KB sent via DNS",
                    dns_bytes / 1000
                ));
            }
        }

        // Check for unusual protocols/ports for data transfer
        let unusual_ports: Vec<_> = src_sessions.iter()
            .filter(|s| {
                s.bytes_sent > 10_000_000 &&
                    !matches!(s.dst_port, 80 | 443 | 22 | 21 | 25 | 587)
            })
            .collect();

        if !unusual_ports.is_empty() {
            indicators.push("Large data transfer on non-standard port".to_string());
            for s in &unusual_ports {
                evidence.push(format!(
                    "{}:{} -> {}:{} ({} MB)",
                    s.src_ip, s.src_port, s.dst_ip, s.dst_port, s.bytes_sent / 1_000_000
                ));
            }
        }

        // Check for encrypted uploads (HTTPS POST with large body)
        let large_https: Vec<_> = src_sessions.iter()
            .filter(|s| s.dst_port == 443 && s.bytes_sent > 50_000_000)
            .collect();

        if !large_https.is_empty() {
            indicators.push(format!(
                "{} large encrypted uploads detected",
                large_https.len()
            ));
        }

        // Generate finding
        if !indicators.is_empty() {
            let severity = if total_bytes_out > 1_000_000_000 || indicators.len() >= 3 {
                "Critical"
            } else if total_bytes_out > 100_000_000 || indicators.len() >= 2 {
                "High"
            } else {
                "Medium"
            };

            findings.push(NetworkForensicsFinding {
                finding_type: "DataExfil".to_string(),
                description: format!(
                    "Potential data exfiltration from {}: {}",
                    src_ip,
                    indicators.join("; ")
                ),
                severity: severity.to_string(),
                sessions: src_sessions.iter().map(|_| "session_id".to_string()).collect(),
                evidence,
                iocs,
            });
        }
    }

    Ok(findings)
}

/// Detect lateral movement within the network
pub fn detect_lateral_movement(sessions: &[serde_json::Value]) -> Result<Vec<NetworkForensicsFinding>> {
    let mut findings = Vec::new();

    // Parse sessions
    let parsed_sessions: Vec<SessionMetadata> = sessions.iter()
        .filter_map(|s| parse_session_metadata(s).ok())
        .collect();

    // Track internal-to-internal connections
    let internal_sessions: Vec<_> = parsed_sessions.iter()
        .filter(|s| is_private_ip(&s.src_ip) && is_private_ip(&s.dst_ip))
        .collect();

    // Group by source to detect hosts scanning/pivoting
    let mut sessions_by_src: HashMap<String, Vec<&SessionMetadata>> = HashMap::new();
    for session in &internal_sessions {
        sessions_by_src.entry(session.src_ip.clone())
            .or_default()
            .push(session);
    }

    for (src_ip, src_sessions) in &sessions_by_src {
        let mut indicators = Vec::new();
        let mut evidence = Vec::new();
        let mut iocs = Vec::new();

        // Count unique internal destinations
        let unique_destinations: HashSet<_> = src_sessions.iter()
            .map(|s| s.dst_ip.clone())
            .collect();

        // Multiple internal destinations suggest scanning/lateral movement
        if unique_destinations.len() >= 5 {
            indicators.push(format!(
                "Connections to {} unique internal hosts",
                unique_destinations.len()
            ));
            for dst in &unique_destinations {
                iocs.push(dst.clone());
            }
        }

        // Check for SMB lateral movement (port 445, 139)
        let smb_sessions: Vec<_> = src_sessions.iter()
            .filter(|s| s.dst_port == 445 || s.dst_port == 139)
            .collect();

        if smb_sessions.len() >= 3 {
            let smb_destinations: HashSet<_> = smb_sessions.iter()
                .map(|s| s.dst_ip.clone())
                .collect();

            indicators.push(format!(
                "SMB connections to {} internal hosts",
                smb_destinations.len()
            ));

            for s in &smb_sessions {
                evidence.push(format!("SMB: {} -> {}:445", s.src_ip, s.dst_ip));
            }
        }

        // Check for WMI/WinRM lateral movement (port 5985, 5986, 135)
        let wmi_sessions: Vec<_> = src_sessions.iter()
            .filter(|s| matches!(s.dst_port, 5985 | 5986 | 135))
            .collect();

        if wmi_sessions.len() >= 2 {
            indicators.push(format!(
                "{} WMI/WinRM connections detected",
                wmi_sessions.len()
            ));
        }

        // Check for SSH lateral movement (port 22)
        let ssh_sessions: Vec<_> = src_sessions.iter()
            .filter(|s| s.dst_port == 22)
            .collect();

        if ssh_sessions.len() >= 3 {
            let ssh_destinations: HashSet<_> = ssh_sessions.iter()
                .map(|s| s.dst_ip.clone())
                .collect();

            indicators.push(format!(
                "SSH connections to {} internal hosts",
                ssh_destinations.len()
            ));
        }

        // Check for RDP lateral movement (port 3389)
        let rdp_sessions: Vec<_> = src_sessions.iter()
            .filter(|s| s.dst_port == 3389)
            .collect();

        if rdp_sessions.len() >= 2 {
            let rdp_destinations: HashSet<_> = rdp_sessions.iter()
                .map(|s| s.dst_ip.clone())
                .collect();

            indicators.push(format!(
                "RDP connections to {} internal hosts",
                rdp_destinations.len()
            ));

            for s in &rdp_sessions {
                evidence.push(format!("RDP: {} -> {}:3389", s.src_ip, s.dst_ip));
            }
        }

        // Check for PsExec-like behavior (SMB followed by service creation)
        let has_smb = !smb_sessions.is_empty();
        let has_service = src_sessions.iter().any(|s| s.dst_port == 445);

        if has_smb && has_service && unique_destinations.len() >= 2 {
            indicators.push("Pattern consistent with PsExec/remote execution".to_string());
        }

        // Generate finding
        if !indicators.is_empty() {
            let severity = if indicators.len() >= 3 || unique_destinations.len() >= 10 {
                "High"
            } else if indicators.len() >= 2 || unique_destinations.len() >= 5 {
                "Medium"
            } else {
                "Low"
            };

            iocs.insert(0, src_ip.clone());

            findings.push(NetworkForensicsFinding {
                finding_type: "LateralMovement".to_string(),
                description: format!(
                    "Potential lateral movement from {}: {}",
                    src_ip,
                    indicators.join("; ")
                ),
                severity: severity.to_string(),
                sessions: src_sessions.iter().map(|_| "session_id".to_string()).collect(),
                evidence,
                iocs,
            });
        }
    }

    Ok(findings)
}

/// Parse session metadata from JSON
fn parse_session_metadata(session: &serde_json::Value) -> Result<SessionMetadata> {
    Ok(SessionMetadata {
        src_ip: session.get("src_ip")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0.0")
            .to_string(),
        dst_ip: session.get("dst_ip")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0.0")
            .to_string(),
        src_port: session.get("src_port")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u16,
        dst_port: session.get("dst_port")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u16,
        protocol: session.get("protocol")
            .and_then(|v| v.as_str())
            .unwrap_or("tcp")
            .to_string(),
        start_time: session.get("start_time")
            .and_then(|v| v.as_i64())
            .unwrap_or(0),
        end_time: session.get("end_time")
            .and_then(|v| v.as_i64()),
        bytes_sent: session.get("bytes_sent")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        bytes_received: session.get("bytes_received")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        packets_sent: session.get("packets_sent")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        packets_received: session.get("packets_received")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        user_agent: session.get("user_agent")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        uri: session.get("uri")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        host: session.get("host")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
    })
}

/// Check if an IP is in private ranges
fn is_private_ip(ip: &str) -> bool {
    // Parse IPv4
    let parts: Vec<u8> = ip.split('.')
        .filter_map(|p| p.parse::<u8>().ok())
        .collect();

    if parts.len() != 4 {
        return false;
    }

    // 10.0.0.0/8
    if parts[0] == 10 {
        return true;
    }

    // 172.16.0.0/12
    if parts[0] == 172 && (16..=31).contains(&parts[1]) {
        return true;
    }

    // 192.168.0.0/16
    if parts[0] == 192 && parts[1] == 168 {
        return true;
    }

    // Localhost
    if parts[0] == 127 {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_private_ip() {
        assert!(is_private_ip("10.0.0.1"));
        assert!(is_private_ip("192.168.1.1"));
        assert!(is_private_ip("172.16.0.1"));
        assert!(!is_private_ip("8.8.8.8"));
        assert!(!is_private_ip("1.1.1.1"));
    }

    #[test]
    fn test_detect_c2_empty() {
        let sessions: Vec<serde_json::Value> = vec![];
        let findings = detect_c2_traffic(&sessions).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn test_detect_exfil_empty() {
        let sessions: Vec<serde_json::Value> = vec![];
        let findings = detect_data_exfiltration(&sessions).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn test_detect_lateral_empty() {
        let sessions: Vec<serde_json::Value> = vec![];
        let findings = detect_lateral_movement(&sessions).unwrap();
        assert!(findings.is_empty());
    }
}
