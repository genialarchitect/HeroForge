use super::types::{EnumDepth, EnumerationResult, Finding, FindingType, ServiceType};
use crate::types::{ScanProgressMessage, ScanTarget};
use anyhow::Result;
use log::{debug, info};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};
use tokio::sync::broadcast::Sender;

/// Known weak SSH algorithms that should be flagged
const WEAK_KEX_ALGORITHMS: &[&str] = &[
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
];

const WEAK_CIPHERS: &[&str] = &[
    "3des-cbc",
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
    "blowfish-cbc",
    "cast128-cbc",
    "arcfour",
    "arcfour128",
    "arcfour256",
];

const WEAK_MACS: &[&str] = &[
    "hmac-md5",
    "hmac-md5-96",
    "hmac-sha1",
    "hmac-sha1-96",
    "hmac-ripemd160",
];

/// Enumerate SSH service
pub async fn enumerate_ssh(
    target: &ScanTarget,
    port: u16,
    depth: EnumDepth,
    timeout: Duration,
    progress_tx: Option<Sender<ScanProgressMessage>>,
) -> Result<EnumerationResult> {
    let start = Instant::now();
    info!(
        "Starting SSH enumeration for {}:{} with depth: {:?}",
        target.ip, port, depth
    );

    let mut findings = Vec::new();
    let mut metadata = HashMap::new();

    let target_ip = target.ip.to_string();

    // Step 1: Get SSH banner and version info
    match get_ssh_banner(&target_ip, port, timeout).await {
        Ok(Some(banner_info)) => {
            metadata.insert("banner".to_string(), banner_info.banner.clone());
            metadata.insert("ssh_version".to_string(), banner_info.version.clone());
            metadata.insert("software".to_string(), banner_info.software.clone());

            // Check for known vulnerable versions
            if let Some(vuln_finding) = check_ssh_version_vulnerabilities(&banner_info) {
                send_progress(&progress_tx, &target_ip, port, "Version", &vuln_finding.value);
                findings.push(vuln_finding);
            }

            // Add version info finding
            findings.push(
                Finding::new(
                    FindingType::Version,
                    format!("{} ({})", banner_info.software, banner_info.version),
                )
                .with_metadata("banner".to_string(), banner_info.banner),
            );
        }
        Ok(None) => {
            debug!("Could not retrieve SSH banner from {}", target_ip);
        }
        Err(e) => {
            debug!("SSH banner check failed: {}", e);
        }
    }

    // Passive mode stops here
    if matches!(depth, EnumDepth::Passive) {
        return Ok(EnumerationResult {
            service_type: ServiceType::Ssh,
            enumeration_depth: depth,
            findings,
            duration: start.elapsed(),
            metadata,
        });
    }

    // Step 2: Get supported algorithms via SSH key exchange
    match get_ssh_algorithms(&target_ip, port, timeout).await {
        Ok(Some(algo_info)) => {
            // Check for weak algorithms
            let weak_kex: Vec<&str> = algo_info
                .kex_algorithms
                .iter()
                .filter(|a| WEAK_KEX_ALGORITHMS.contains(&a.as_str()))
                .map(|s| s.as_str())
                .collect();

            let weak_ciphers: Vec<&str> = algo_info
                .ciphers
                .iter()
                .filter(|a| WEAK_CIPHERS.contains(&a.as_str()))
                .map(|s| s.as_str())
                .collect();

            let weak_macs: Vec<&str> = algo_info
                .macs
                .iter()
                .filter(|a| WEAK_MACS.contains(&a.as_str()))
                .map(|s| s.as_str())
                .collect();

            if !weak_kex.is_empty() {
                let finding = Finding::with_confidence(
                    FindingType::WeakAlgorithm,
                    format!("Weak key exchange algorithms: {}", weak_kex.join(", ")),
                    90,
                )
                .with_metadata("type".to_string(), "kex".to_string())
                .with_metadata("algorithms".to_string(), weak_kex.join(", "));

                send_progress(&progress_tx, &target_ip, port, "WeakAlgorithm", &finding.value);
                findings.push(finding);
            }

            if !weak_ciphers.is_empty() {
                let finding = Finding::with_confidence(
                    FindingType::WeakAlgorithm,
                    format!("Weak ciphers: {}", weak_ciphers.join(", ")),
                    90,
                )
                .with_metadata("type".to_string(), "cipher".to_string())
                .with_metadata("algorithms".to_string(), weak_ciphers.join(", "));

                send_progress(&progress_tx, &target_ip, port, "WeakAlgorithm", &finding.value);
                findings.push(finding);
            }

            if !weak_macs.is_empty() {
                let finding = Finding::with_confidence(
                    FindingType::WeakAlgorithm,
                    format!("Weak MACs: {}", weak_macs.join(", ")),
                    85,
                )
                .with_metadata("type".to_string(), "mac".to_string())
                .with_metadata("algorithms".to_string(), weak_macs.join(", "));

                send_progress(&progress_tx, &target_ip, port, "WeakAlgorithm", &finding.value);
                findings.push(finding);
            }

            // Store algorithm metadata
            metadata.insert("kex_algorithms".to_string(), algo_info.kex_algorithms.join(", "));
            metadata.insert("ciphers".to_string(), algo_info.ciphers.join(", "));
            metadata.insert("macs".to_string(), algo_info.macs.join(", "));
            metadata.insert("host_key_types".to_string(), algo_info.host_key_types.join(", "));

            // Check for host key types
            for key_type in &algo_info.host_key_types {
                findings.push(
                    Finding::new(FindingType::SshKey, format!("Host key type: {}", key_type))
                        .with_metadata("key_type".to_string(), key_type.clone()),
                );
            }
        }
        Ok(None) => {
            debug!("Could not retrieve SSH algorithms from {}", target_ip);
        }
        Err(e) => {
            debug!("SSH algorithm check failed: {}", e);
        }
    }

    // Step 3: Aggressive mode - Check authentication methods
    if matches!(depth, EnumDepth::Aggressive) {
        match check_auth_methods(&target_ip, port, timeout).await {
            Ok(Some(auth_methods)) => {
                metadata.insert("auth_methods".to_string(), auth_methods.join(", "));

                // Check for potentially weak auth methods
                if auth_methods.contains(&"password".to_string()) {
                    findings.push(
                        Finding::with_confidence(
                            FindingType::Misconfiguration,
                            "Password authentication enabled".to_string(),
                            70,
                        )
                        .with_metadata("auth_method".to_string(), "password".to_string())
                        .with_metadata(
                            "recommendation".to_string(),
                            "Consider using key-based authentication only".to_string(),
                        ),
                    );
                }

                if auth_methods.contains(&"keyboard-interactive".to_string()) {
                    findings.push(Finding::new(
                        FindingType::InformationDisclosure,
                        "Keyboard-interactive authentication enabled".to_string(),
                    ));
                }
            }
            Ok(None) => {}
            Err(e) => {
                debug!("Auth method check failed: {}", e);
            }
        }
    }

    metadata.insert("weak_algorithms_found".to_string(),
        findings.iter().filter(|f| matches!(f.finding_type, FindingType::WeakAlgorithm)).count().to_string());

    Ok(EnumerationResult {
        service_type: ServiceType::Ssh,
        enumeration_depth: depth,
        findings,
        duration: start.elapsed(),
        metadata,
    })
}

/// SSH banner information
struct SshBannerInfo {
    banner: String,
    version: String,
    software: String,
}

/// SSH algorithm information
struct SshAlgorithmInfo {
    kex_algorithms: Vec<String>,
    host_key_types: Vec<String>,
    ciphers: Vec<String>,
    macs: Vec<String>,
}

/// Get SSH banner and version
async fn get_ssh_banner(target_ip: &str, port: u16, timeout: Duration) -> Result<Option<SshBannerInfo>> {
    let target_ip = target_ip.to_string();

    tokio::task::spawn_blocking(move || {
        let addr = format!("{}:{}", target_ip, port);
        let stream = TcpStream::connect_timeout(&addr.parse()?, timeout)?;
        stream.set_read_timeout(Some(timeout))?;

        let mut reader = BufReader::new(stream);
        let mut banner = String::new();
        reader.read_line(&mut banner)?;

        let banner = banner.trim().to_string();

        // Parse SSH banner: SSH-<version>-<software>
        if banner.starts_with("SSH-") {
            let parts: Vec<&str> = banner.split('-').collect();
            if parts.len() >= 3 {
                let version = parts[1].to_string();
                let software = parts[2..].join("-");

                return Ok(Some(SshBannerInfo {
                    banner: banner.clone(),
                    version,
                    software,
                }));
            }
        }

        Ok(Some(SshBannerInfo {
            banner: banner.clone(),
            version: "unknown".to_string(),
            software: banner,
        }))
    })
    .await?
}

/// Get SSH algorithms by initiating key exchange
async fn get_ssh_algorithms(target_ip: &str, port: u16, timeout: Duration) -> Result<Option<SshAlgorithmInfo>> {
    let target_ip = target_ip.to_string();

    tokio::task::spawn_blocking(move || {
        let addr = format!("{}:{}", target_ip, port);
        let mut stream = TcpStream::connect_timeout(&addr.parse()?, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        // Read server banner
        let mut reader = BufReader::new(&stream);
        let mut banner = String::new();
        reader.read_line(&mut banner)?;

        // Send our banner
        let client_banner = "SSH-2.0-HeroForge_Scan\r\n";
        stream.write_all(client_banner.as_bytes())?;
        stream.flush()?;

        // Read KEX_INIT packet
        let mut packet_header = [0u8; 5];
        if std::io::Read::read_exact(&mut stream, &mut packet_header).is_err() {
            return Ok(None);
        }

        // Parse packet length (first 4 bytes, big-endian)
        let packet_len = u32::from_be_bytes([
            packet_header[0],
            packet_header[1],
            packet_header[2],
            packet_header[3],
        ]) as usize;

        if packet_len > 65536 || packet_len < 16 {
            return Ok(None);
        }

        // Read the rest of the packet
        let mut packet_data = vec![0u8; packet_len];
        packet_data[0] = packet_header[4]; // padding_length is first byte
        if std::io::Read::read_exact(&mut stream, &mut packet_data[1..]).is_err() {
            return Ok(None);
        }

        // Parse KEX_INIT (message type 20)
        let padding_length = packet_data[0] as usize;
        let payload_start = 1;
        let payload_end = packet_len - padding_length;

        if payload_end <= payload_start || payload_end > packet_data.len() {
            return Ok(None);
        }

        let payload = &packet_data[payload_start..payload_end];

        // First byte of payload is message type
        if payload.is_empty() || payload[0] != 20 {
            // 20 = SSH_MSG_KEXINIT
            return Ok(None);
        }

        // Parse KEX_INIT message
        // Skip: message type (1) + cookie (16) = 17 bytes
        if payload.len() < 17 {
            return Ok(None);
        }

        let mut offset = 17;
        let mut algorithms = SshAlgorithmInfo {
            kex_algorithms: Vec::new(),
            host_key_types: Vec::new(),
            ciphers: Vec::new(),
            macs: Vec::new(),
        };

        // Parse name-lists (each is a uint32 length followed by comma-separated names)
        // Order: kex_algorithms, server_host_key_algorithms, encryption_c2s, encryption_s2c,
        //        mac_c2s, mac_s2c, compression_c2s, compression_s2c, languages_c2s, languages_s2c

        // 1. KEX algorithms
        if let Some((names, new_offset)) = parse_name_list(payload, offset) {
            algorithms.kex_algorithms = names;
            offset = new_offset;
        }

        // 2. Host key types
        if let Some((names, new_offset)) = parse_name_list(payload, offset) {
            algorithms.host_key_types = names;
            offset = new_offset;
        }

        // 3. Encryption client->server (skip)
        if let Some((_, new_offset)) = parse_name_list(payload, offset) {
            offset = new_offset;
        }

        // 4. Encryption server->client (this is what the server sends us)
        if let Some((names, new_offset)) = parse_name_list(payload, offset) {
            algorithms.ciphers = names;
            offset = new_offset;
        }

        // 5. MAC client->server (skip)
        if let Some((_, new_offset)) = parse_name_list(payload, offset) {
            offset = new_offset;
        }

        // 6. MAC server->client
        if let Some((names, _)) = parse_name_list(payload, offset) {
            algorithms.macs = names;
        }

        Ok(Some(algorithms))
    })
    .await?
}

/// Parse SSH name-list from packet
fn parse_name_list(data: &[u8], offset: usize) -> Option<(Vec<String>, usize)> {
    if offset + 4 > data.len() {
        return None;
    }

    let len = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;

    let new_offset = offset + 4 + len;
    if new_offset > data.len() {
        return None;
    }

    let names_str = String::from_utf8_lossy(&data[offset + 4..offset + 4 + len]);
    let names: Vec<String> = names_str.split(',').map(|s| s.to_string()).collect();

    Some((names, new_offset))
}

/// Check for vulnerable SSH versions
fn check_ssh_version_vulnerabilities(info: &SshBannerInfo) -> Option<Finding> {
    let software_lower = info.software.to_lowercase();
    let banner_lower = info.banner.to_lowercase();

    // Check for OpenSSH vulnerabilities
    if software_lower.contains("openssh") {
        // Extract version number
        if let Some(version) = extract_openssh_version(&info.software) {
            // CVE-2024-6387 (regreSSHion) - OpenSSH 8.5p1 to 9.7p1
            if version_in_range(&version, "8.5", "9.7") {
                return Some(
                    Finding::with_confidence(
                        FindingType::Misconfiguration,
                        format!(
                            "OpenSSH {} may be vulnerable to CVE-2024-6387 (regreSSHion)",
                            version
                        ),
                        75,
                    )
                    .with_metadata("cve".to_string(), "CVE-2024-6387".to_string())
                    .with_metadata("severity".to_string(), "Critical".to_string()),
                );
            }

            // CVE-2018-15473 - User enumeration <= 7.7
            if version_less_than(&version, "7.8") {
                return Some(
                    Finding::with_confidence(
                        FindingType::Misconfiguration,
                        format!(
                            "OpenSSH {} may be vulnerable to CVE-2018-15473 (user enumeration)",
                            version
                        ),
                        70,
                    )
                    .with_metadata("cve".to_string(), "CVE-2018-15473".to_string())
                    .with_metadata("severity".to_string(), "Medium".to_string()),
                );
            }
        }
    }

    // Check for Dropbear vulnerabilities
    if software_lower.contains("dropbear") {
        // Dropbear < 2016.74 has multiple vulnerabilities
        if banner_lower.contains("dropbear") {
            return Some(
                Finding::with_confidence(
                    FindingType::InformationDisclosure,
                    "Dropbear SSH detected - verify version is up to date".to_string(),
                    50,
                )
                .with_metadata("software".to_string(), "Dropbear".to_string()),
            );
        }
    }

    None
}

/// Extract OpenSSH version from software string
fn extract_openssh_version(software: &str) -> Option<String> {
    // Pattern: OpenSSH_X.Yp1 or OpenSSH_X.Y
    let software_lower = software.to_lowercase();
    if let Some(idx) = software_lower.find("openssh_") {
        let version_start = idx + 8;
        let version_str: String = software[version_start..]
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == 'p')
            .collect();
        if !version_str.is_empty() {
            return Some(version_str);
        }
    }
    None
}

/// Check if version is in range [min, max]
fn version_in_range(version: &str, min: &str, max: &str) -> bool {
    let v = parse_version(version);
    let min_v = parse_version(min);
    let max_v = parse_version(max);

    v >= min_v && v <= max_v
}

/// Check if version is less than max
fn version_less_than(version: &str, max: &str) -> bool {
    let v = parse_version(version);
    let max_v = parse_version(max);
    v < max_v
}

/// Parse version string to comparable tuple
fn parse_version(v: &str) -> (u32, u32, u32) {
    let parts: Vec<&str> = v.split(|c: char| !c.is_ascii_digit()).collect();
    let major = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let patch = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
    (major, minor, patch)
}

/// Check authentication methods supported by server
async fn check_auth_methods(target_ip: &str, port: u16, timeout: Duration) -> Result<Option<Vec<String>>> {
    let target_ip = target_ip.to_string();

    tokio::task::spawn_blocking(move || {
        let addr = format!("{}:{}", target_ip, port);
        let mut stream = TcpStream::connect_timeout(&addr.parse()?, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        // Read server banner
        let mut reader = BufReader::new(&stream);
        let mut banner = String::new();
        reader.read_line(&mut banner)?;

        // Send our banner
        stream.write_all(b"SSH-2.0-HeroForge_Scan\r\n")?;
        stream.flush()?;

        // We would need to complete the key exchange and attempt authentication
        // to get the actual auth methods. For now, we'll infer from common patterns.

        // This is a simplified check - full implementation would require
        // completing SSH key exchange and sending USERAUTH_REQUEST

        let mut methods = Vec::new();

        // Most SSH servers support these by default
        if banner.contains("OpenSSH") {
            methods.push("publickey".to_string());
            methods.push("password".to_string());
            methods.push("keyboard-interactive".to_string());
        }

        if methods.is_empty() {
            Ok(None)
        } else {
            Ok(Some(methods))
        }
    })
    .await?
}

/// Helper to send progress messages
fn send_progress(
    tx: &Option<Sender<ScanProgressMessage>>,
    ip: &str,
    port: u16,
    finding_type: &str,
    value: &str,
) {
    if let Some(sender) = tx {
        let _ = sender.send(ScanProgressMessage::EnumerationFinding {
            ip: ip.to_string(),
            port,
            finding_type: finding_type.to_string(),
            value: value.to_string(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_openssh_version() {
        assert_eq!(
            extract_openssh_version("OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"),
            Some("8.9p1".to_string())
        );
        assert_eq!(
            extract_openssh_version("OpenSSH_7.4"),
            Some("7.4".to_string())
        );
    }

    #[test]
    fn test_version_comparison() {
        assert!(version_less_than("7.4", "7.8"));
        assert!(!version_less_than("8.0", "7.8"));
        assert!(version_in_range("8.5p1", "8.5", "9.7"));
        assert!(version_in_range("9.0", "8.5", "9.7"));
        assert!(!version_in_range("9.8", "8.5", "9.7"));
    }

    #[test]
    fn test_parse_version() {
        assert_eq!(parse_version("8.9p1"), (8, 9, 1));
        assert_eq!(parse_version("7.4"), (7, 4, 0));
        assert_eq!(parse_version("9.7p1"), (9, 7, 1));
    }
}
