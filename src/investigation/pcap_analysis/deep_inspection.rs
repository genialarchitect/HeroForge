//! Deep Packet Inspection Module
//!
//! Analyze packets and payloads for malware, credentials, and C2 patterns.

use crate::investigation::types::{PacketInspectionResult, PayloadAnalysis, CredentialExtraction};
use anyhow::Result;
use chrono::{DateTime, Utc};
use std::path::Path;

/// C2 patterns to detect
const C2_PATTERNS: &[(&str, &str)] = &[
    ("Cobalt Strike", r"(?:\/\w{4})?\/submit\.php\?id="),
    ("Metasploit", r"(?:meterpreter|stage[0-9])"),
    ("Empire", r"\/admin\/get\.php|\/news\.php"),
    ("Covenant", r"\/en-us\/test\.html"),
    ("PoshC2", r"\/images\/[a-z]+\.png"),
    ("Sliver", r"beacon\.[a-z0-9]+\.(com|net|org)"),
];

/// Known malware signatures in payloads
const MALWARE_SIGNATURES: &[(&str, &[u8])] = &[
    ("MZ_HEADER", b"MZ"),
    ("PE_SIGNATURE", b"PE\x00\x00"),
    ("ELF_HEADER", b"\x7fELF"),
    ("SHELLCODE_NOP", b"\x90\x90\x90\x90"),
    ("POWERSHELL_ENCODED", b"-enc "),
    ("REVERSE_SHELL", b"/bin/sh -i"),
];

/// Credential patterns
const CREDENTIAL_PATTERNS: &[(&str, &str)] = &[
    ("HTTP_BASIC", r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)"),
    ("HTTP_DIGEST", r"Authorization:\s*Digest\s+"),
    ("FTP_USER", r"USER\s+(\S+)"),
    ("FTP_PASS", r"PASS\s+(\S+)"),
    ("SMTP_AUTH", r"AUTH\s+(?:LOGIN|PLAIN)\s+"),
    ("HTTP_COOKIE_SESSION", r"(?:session|token|auth)=([A-Za-z0-9+/=-]+)"),
    ("MYSQL_AUTH", r"\x00\x00\x00\x01\x85\xa6"),
    ("NTLM_CHALLENGE", r"NTLMSSP\x00\x02"),
];

/// Inspect PCAP file for deep packet analysis
pub async fn inspect_pcap(pcap_path: &str) -> Result<Vec<PacketInspectionResult>> {
    let mut results = Vec::new();

    // Verify file exists
    let path = Path::new(pcap_path);
    if !path.exists() {
        return Ok(results);
    }

    // Read PCAP file header
    let content = tokio::fs::read(pcap_path).await?;

    // Parse PCAP magic number
    if content.len() < 24 {
        return Ok(results);
    }

    let magic = u32::from_le_bytes([content[0], content[1], content[2], content[3]]);
    let is_pcap = magic == 0xa1b2c3d4 || magic == 0xd4c3b2a1;
    let is_pcapng = magic == 0x0a0d0d0a;

    if !is_pcap && !is_pcapng {
        return Ok(results);
    }

    // Parse packets based on format
    if is_pcap {
        results = parse_pcap_packets(&content)?;
    } else {
        results = parse_pcapng_packets(&content)?;
    }

    Ok(results)
}

/// Parse packets from standard PCAP format
fn parse_pcap_packets(content: &[u8]) -> Result<Vec<PacketInspectionResult>> {
    let mut results = Vec::new();
    let mut offset = 24; // Skip global header
    let mut packet_id: i64 = 0;

    while offset + 16 <= content.len() {
        // Parse packet header
        let ts_sec = u32::from_le_bytes([
            content[offset], content[offset + 1],
            content[offset + 2], content[offset + 3],
        ]);
        let ts_usec = u32::from_le_bytes([
            content[offset + 4], content[offset + 5],
            content[offset + 6], content[offset + 7],
        ]);
        let incl_len = u32::from_le_bytes([
            content[offset + 8], content[offset + 9],
            content[offset + 10], content[offset + 11],
        ]) as usize;

        offset += 16;

        if offset + incl_len > content.len() {
            break;
        }

        let packet_data = &content[offset..offset + incl_len];
        offset += incl_len;

        // Parse Ethernet frame
        if let Some(result) = parse_ethernet_frame(packet_data, packet_id, ts_sec, ts_usec) {
            results.push(result);
        }

        packet_id += 1;

        // Limit to first 10000 packets for performance
        if packet_id > 10000 {
            break;
        }
    }

    Ok(results)
}

/// Parse packets from PCAPNG format
fn parse_pcapng_packets(content: &[u8]) -> Result<Vec<PacketInspectionResult>> {
    let mut results = Vec::new();
    let mut offset = 0;
    let mut packet_id: i64 = 0;

    while offset + 8 <= content.len() {
        // Parse block type and length
        let block_type = u32::from_le_bytes([
            content[offset], content[offset + 1],
            content[offset + 2], content[offset + 3],
        ]);
        let block_len = u32::from_le_bytes([
            content[offset + 4], content[offset + 5],
            content[offset + 6], content[offset + 7],
        ]) as usize;

        if block_len < 12 || offset + block_len > content.len() {
            break;
        }

        // Enhanced Packet Block (0x06)
        if block_type == 0x00000006 && block_len > 28 {
            let ts_high = u32::from_le_bytes([
                content[offset + 12], content[offset + 13],
                content[offset + 14], content[offset + 15],
            ]);
            let captured_len = u32::from_le_bytes([
                content[offset + 20], content[offset + 21],
                content[offset + 22], content[offset + 23],
            ]) as usize;

            if offset + 28 + captured_len <= content.len() {
                let packet_data = &content[offset + 28..offset + 28 + captured_len];

                if let Some(result) = parse_ethernet_frame(packet_data, packet_id, ts_high, 0) {
                    results.push(result);
                }
                packet_id += 1;
            }
        }

        offset += block_len;

        // Limit packets
        if packet_id > 10000 {
            break;
        }
    }

    Ok(results)
}

/// Parse Ethernet frame and extract IP/TCP/UDP data
fn parse_ethernet_frame(data: &[u8], packet_id: i64, ts_sec: u32, ts_usec: u32) -> Option<PacketInspectionResult> {
    if data.len() < 14 {
        return None;
    }

    let ethertype = u16::from_be_bytes([data[12], data[13]]);

    // Only handle IPv4 (0x0800) for now
    if ethertype != 0x0800 {
        return None;
    }

    parse_ipv4_packet(&data[14..], packet_id, ts_sec, ts_usec)
}

/// Parse IPv4 packet
fn parse_ipv4_packet(data: &[u8], packet_id: i64, ts_sec: u32, ts_usec: u32) -> Option<PacketInspectionResult> {
    if data.len() < 20 {
        return None;
    }

    let version_ihl = data[0];
    let ihl = (version_ihl & 0x0F) as usize * 4;

    if ihl < 20 || data.len() < ihl {
        return None;
    }

    let protocol = data[9];
    let src_ip = format!("{}.{}.{}.{}", data[12], data[13], data[14], data[15]);
    let dst_ip = format!("{}.{}.{}.{}", data[16], data[17], data[18], data[19]);

    let transport_data = &data[ihl..];
    let (src_port, dst_port, payload) = match protocol {
        6 => parse_tcp_header(transport_data)?,  // TCP
        17 => parse_udp_header(transport_data)?, // UDP
        _ => return None,
    };

    let protocol_name = match protocol {
        6 => "TCP",
        17 => "UDP",
        _ => "Unknown",
    };

    // Analyze payload
    let payload_analysis = if !payload.is_empty() {
        Some(analyze_payload(payload))
    } else {
        None
    };

    // Detect anomalies
    let mut anomalies = Vec::new();

    if let Some(ref analysis) = payload_analysis {
        if analysis.malware_detected {
            anomalies.push("Malware signature detected".to_string());
        }
        if !analysis.c2_patterns.is_empty() {
            anomalies.push(format!("C2 pattern: {}", analysis.c2_patterns.join(", ")));
        }
        if !analysis.credentials.is_empty() {
            anomalies.push("Credentials in transit".to_string());
        }
    }

    // Check for suspicious ports
    if matches!(dst_port, 4444 | 5555 | 6666 | 1337 | 31337) {
        anomalies.push(format!("Suspicious destination port: {}", dst_port));
    }

    let timestamp = DateTime::from_timestamp(ts_sec as i64, ts_usec * 1000)
        .unwrap_or_else(Utc::now);

    Some(PacketInspectionResult {
        packet_id,
        timestamp,
        protocol: protocol_name.to_string(),
        src: format!("{}:{}", src_ip, src_port),
        dst: format!("{}:{}", dst_ip, dst_port),
        payload_analysis,
        anomalies,
    })
}

/// Parse TCP header and return (src_port, dst_port, payload)
fn parse_tcp_header(data: &[u8]) -> Option<(u16, u16, &[u8])> {
    if data.len() < 20 {
        return None;
    }

    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let data_offset = ((data[12] >> 4) as usize) * 4;

    if data_offset < 20 || data.len() < data_offset {
        return Some((src_port, dst_port, &[]));
    }

    Some((src_port, dst_port, &data[data_offset..]))
}

/// Parse UDP header and return (src_port, dst_port, payload)
fn parse_udp_header(data: &[u8]) -> Option<(u16, u16, &[u8])> {
    if data.len() < 8 {
        return None;
    }

    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);

    Some((src_port, dst_port, &data[8..]))
}

/// Analyze payload for malware, C2 patterns, and credentials
pub fn analyze_payload(payload: &[u8]) -> PayloadAnalysis {
    let mut extracted_files = Vec::new();
    let mut credentials = Vec::new();
    let mut malware_detected = false;
    let mut c2_patterns = Vec::new();

    // Detect content type
    let content_type = detect_content_type(payload);

    // Check for malware signatures
    for (name, signature) in MALWARE_SIGNATURES {
        if payload.windows(signature.len()).any(|w| w == *signature) {
            malware_detected = true;

            // If MZ header found, potential embedded executable
            if *name == "MZ_HEADER" {
                extracted_files.push("Embedded PE executable detected".to_string());
            }
        }
    }

    // Convert payload to string for pattern matching
    let payload_str = String::from_utf8_lossy(payload);

    // Check for C2 patterns
    for (name, pattern) in C2_PATTERNS {
        if let Ok(re) = regex::Regex::new(pattern) {
            if re.is_match(&payload_str) {
                c2_patterns.push(name.to_string());
            }
        }
    }

    // Check for credential patterns
    for (protocol, pattern) in CREDENTIAL_PATTERNS {
        if let Ok(re) = regex::Regex::new(pattern) {
            if let Some(captures) = re.captures(&payload_str) {
                let value = captures.get(1)
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();

                // Decode if Base64 (HTTP Basic)
                let decoded = if *protocol == "HTTP_BASIC" {
                    base64_decode(&value)
                } else {
                    value.clone()
                };

                // Extract username/password if possible
                let (username, password_hash) = if decoded.contains(':') {
                    let parts: Vec<&str> = decoded.splitn(2, ':').collect();
                    (parts[0].to_string(), Some(parts.get(1).unwrap_or(&"").to_string()))
                } else if *protocol == "FTP_USER" {
                    (value.clone(), None)
                } else {
                    (value, None)
                };

                credentials.push(CredentialExtraction {
                    protocol: protocol.to_string(),
                    username,
                    password_hash,
                    source: "packet_capture".to_string(),
                });
            }
        }
    }

    // Check for additional file types
    if payload.starts_with(b"GIF8") {
        extracted_files.push("GIF image".to_string());
    } else if payload.starts_with(b"\x89PNG") {
        extracted_files.push("PNG image".to_string());
    } else if payload.starts_with(b"\xFF\xD8\xFF") {
        extracted_files.push("JPEG image".to_string());
    } else if payload.starts_with(b"PK\x03\x04") {
        extracted_files.push("ZIP archive".to_string());
    } else if payload.starts_with(b"\x1f\x8b") {
        extracted_files.push("GZIP archive".to_string());
    } else if payload.starts_with(b"%PDF") {
        extracted_files.push("PDF document".to_string());
    }

    PayloadAnalysis {
        content_type,
        extracted_files,
        credentials,
        malware_detected,
        c2_patterns,
    }
}

/// Detect content type from payload magic bytes
fn detect_content_type(payload: &[u8]) -> Option<String> {
    if payload.is_empty() {
        return None;
    }

    // Check magic bytes
    if payload.starts_with(b"HTTP/") {
        return Some("HTTP Response".to_string());
    }
    if payload.starts_with(b"GET ") || payload.starts_with(b"POST ") ||
        payload.starts_with(b"PUT ") || payload.starts_with(b"DELETE ") {
        return Some("HTTP Request".to_string());
    }
    if payload.starts_with(b"MZ") {
        return Some("Windows Executable (PE)".to_string());
    }
    if payload.starts_with(b"\x7fELF") {
        return Some("Linux Executable (ELF)".to_string());
    }
    if payload.starts_with(b"PK\x03\x04") {
        return Some("ZIP Archive".to_string());
    }
    if payload.starts_with(b"%PDF") {
        return Some("PDF Document".to_string());
    }
    if payload.starts_with(b"\x89PNG") {
        return Some("PNG Image".to_string());
    }
    if payload.starts_with(b"\xFF\xD8\xFF") {
        return Some("JPEG Image".to_string());
    }
    if payload.starts_with(b"GIF8") {
        return Some("GIF Image".to_string());
    }
    if payload.starts_with(b"RIFF") {
        return Some("RIFF/AVI/WAV".to_string());
    }
    if payload.starts_with(b"OggS") {
        return Some("OGG Media".to_string());
    }
    if payload.starts_with(b"ftyp") || (payload.len() > 4 && &payload[4..8] == b"ftyp") {
        return Some("MP4/M4A Video".to_string());
    }

    // Check for text content
    let text_chars = payload.iter().take(100)
        .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        .count();
    let total = std::cmp::min(payload.len(), 100);

    if total > 0 && text_chars * 100 / total > 90 {
        // Detect specific text formats
        let text = String::from_utf8_lossy(&payload[..std::cmp::min(200, payload.len())]);
        if text.contains("<?xml") || text.contains("<html") {
            return Some("XML/HTML".to_string());
        }
        if text.starts_with('{') || text.starts_with('[') {
            return Some("JSON".to_string());
        }
        return Some("Text/Plain".to_string());
    }

    Some("Binary/Unknown".to_string())
}

/// Base64 decode helper
fn base64_decode(input: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(input)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .unwrap_or_else(|| input.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_content_type() {
        assert_eq!(detect_content_type(b"GET / HTTP/1.1"), Some("HTTP Request".to_string()));
        assert_eq!(detect_content_type(b"HTTP/1.1 200 OK"), Some("HTTP Response".to_string()));
        assert_eq!(detect_content_type(b"MZ\x90\x00"), Some("Windows Executable (PE)".to_string()));
        assert_eq!(detect_content_type(b"\x7fELF"), Some("Linux Executable (ELF)".to_string()));
    }

    #[test]
    fn test_analyze_payload() {
        let http_payload = b"GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let analysis = analyze_payload(http_payload);
        assert!(!analysis.malware_detected);
        assert!(analysis.c2_patterns.is_empty());
    }

    #[test]
    fn test_parse_tcp_header() {
        // Minimal TCP header
        let tcp_data = [
            0x00, 0x50, // src port 80
            0x1F, 0x90, // dst port 8080
            0x00, 0x00, 0x00, 0x00, // seq
            0x00, 0x00, 0x00, 0x00, // ack
            0x50, 0x00, // data offset (5 * 4 = 20) + flags
            0x00, 0x00, // window
            0x00, 0x00, // checksum
            0x00, 0x00, // urgent pointer
        ];
        let result = parse_tcp_header(&tcp_data);
        assert!(result.is_some());
        let (src, dst, _) = result.unwrap();
        assert_eq!(src, 80);
        assert_eq!(dst, 8080);
    }
}
