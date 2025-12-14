//! UDP service detection from response data
//!
//! This module parses UDP responses to extract service information
//! such as service name, version, and other details.

use crate::types::ServiceInfo;
use log::debug;

/// Detect service from UDP response data
pub fn detect_udp_service(port: u16, response: &[u8]) -> Option<ServiceInfo> {
    if response.is_empty() {
        return None;
    }

    match port {
        53 | 5353 => detect_dns_service(response),
        123 => detect_ntp_service(response),
        161 | 162 => detect_snmp_service(response),
        137 => detect_netbios_service(response),
        69 => detect_tftp_service(response),
        1900 => detect_ssdp_service(response),
        5060 => detect_sip_service(response),
        67 | 68 => detect_dhcp_service(response),
        _ => detect_generic_service(port, response),
    }
}

/// Detect DNS service from response
fn detect_dns_service(response: &[u8]) -> Option<ServiceInfo> {
    if response.len() < 12 {
        return None;
    }

    // Check if it's a valid DNS response (QR bit set in flags)
    // Flags are at bytes 2-3, QR is the high bit of byte 2
    if response[2] & 0x80 == 0 {
        return None;
    }

    let mut version = None;

    // Try to extract version from TXT response (version.bind)
    // This is a simplified parser - full DNS parsing would be more complex
    if let Some(txt) = extract_dns_txt_record(response) {
        version = Some(txt);
    }

    Some(ServiceInfo {
        name: "dns".to_string(),
        version,
        banner: Some(format!("DNS response ({} bytes)", response.len())),
        cpe: None,
        enumeration: None,
    })
}

/// Extract TXT record data from DNS response
fn extract_dns_txt_record(response: &[u8]) -> Option<String> {
    // Skip header (12 bytes) and find answer section
    if response.len() < 12 {
        return None;
    }

    // Get number of answers
    let answer_count = u16::from_be_bytes([response[6], response[7]]);
    if answer_count == 0 {
        return None;
    }

    // Skip question section - find the first null byte after header
    let mut pos = 12;
    while pos < response.len() && response[pos] != 0 {
        pos += 1;
    }
    pos += 5; // Skip null, QTYPE (2), QCLASS (2)

    if pos >= response.len() {
        return None;
    }

    // Now in answer section - skip name (might be pointer)
    if pos < response.len() && (response[pos] & 0xC0) == 0xC0 {
        pos += 2; // Pointer is 2 bytes
    } else {
        while pos < response.len() && response[pos] != 0 {
            pos += 1;
        }
        pos += 1;
    }

    // Skip TYPE (2), CLASS (2), TTL (4), RDLENGTH (2)
    pos += 10;

    if pos >= response.len() {
        return None;
    }

    // TXT record: first byte is length, followed by text
    let txt_len = response.get(pos).copied()? as usize;
    pos += 1;

    if pos + txt_len > response.len() {
        return None;
    }

    String::from_utf8(response[pos..pos + txt_len].to_vec()).ok()
}

/// Detect NTP service from response
fn detect_ntp_service(response: &[u8]) -> Option<ServiceInfo> {
    if response.len() < 48 {
        return None;
    }

    // Extract NTP version from LI_VN_MODE byte
    let li_vn_mode = response[0];
    let version = (li_vn_mode >> 3) & 0x07;
    let mode = li_vn_mode & 0x07;

    // Mode 4 = server response
    if mode != 4 && mode != 5 {
        debug!("Unexpected NTP mode: {}", mode);
    }

    // Extract stratum
    let stratum = response[1];
    let stratum_desc = match stratum {
        0 => "unspecified",
        1 => "primary (GPS/atomic clock)",
        2..=15 => "secondary",
        16 => "unsynchronized",
        _ => "reserved",
    };

    // Try to extract reference identifier for stratum 1
    let ref_id = if stratum == 1 && response.len() >= 16 {
        String::from_utf8(response[12..16].to_vec())
            .ok()
            .map(|s| s.trim_matches('\0').to_string())
    } else {
        None
    };

    let banner = if let Some(ref_id) = &ref_id {
        format!(
            "NTPv{} stratum {} ({}) ref={}",
            version, stratum, stratum_desc, ref_id
        )
    } else {
        format!("NTPv{} stratum {} ({})", version, stratum, stratum_desc)
    };

    Some(ServiceInfo {
        name: "ntp".to_string(),
        version: Some(format!("NTPv{}", version)),
        banner: Some(banner),
        cpe: None,
        enumeration: None,
    })
}

/// Detect SNMP service from response
fn detect_snmp_service(response: &[u8]) -> Option<ServiceInfo> {
    if response.len() < 10 {
        return None;
    }

    // Basic ASN.1 BER validation - should start with SEQUENCE
    if response[0] != 0x30 {
        return None;
    }

    // Try to extract SNMP version
    let version = extract_snmp_version(response);
    let version_str = match version {
        Some(0) => "SNMPv1",
        Some(1) => "SNMPv2c",
        Some(3) => "SNMPv3",
        _ => "SNMP",
    };

    // Try to extract sysDescr from response
    let sys_descr = extract_snmp_string(response);

    let banner = if let Some(ref desc) = sys_descr {
        format!("{}: {}", version_str, desc)
    } else {
        format!("{} response ({} bytes)", version_str, response.len())
    };

    Some(ServiceInfo {
        name: "snmp".to_string(),
        version: Some(version_str.to_string()),
        banner: Some(banner),
        cpe: None,
        enumeration: None,
    })
}

/// Extract SNMP version from response
fn extract_snmp_version(response: &[u8]) -> Option<u8> {
    // SNMP message format: SEQUENCE { version INTEGER, ... }
    // Skip SEQUENCE tag and length
    if response.len() < 5 {
        return None;
    }

    let mut pos = 2; // Skip SEQUENCE tag and length byte

    // Handle multi-byte length
    if response[1] & 0x80 != 0 {
        let len_bytes = (response[1] & 0x7F) as usize;
        pos += len_bytes;
    }

    if pos + 3 > response.len() {
        return None;
    }

    // Should be INTEGER tag for version
    if response[pos] != 0x02 {
        return None;
    }
    pos += 1;

    // Version length (should be 1)
    let len = response[pos] as usize;
    pos += 1;

    if pos + len > response.len() {
        return None;
    }

    Some(response[pos])
}

/// Extract string value from SNMP response (e.g., sysDescr)
fn extract_snmp_string(response: &[u8]) -> Option<String> {
    // Look for OCTET STRING tag (0x04) with reasonable length
    for i in 0..response.len().saturating_sub(10) {
        if response[i] == 0x04 {
            let len = response.get(i + 1).copied()? as usize;
            if len > 0 && len < 256 && i + 2 + len <= response.len() {
                if let Ok(s) = String::from_utf8(response[i + 2..i + 2 + len].to_vec()) {
                    // Check if it looks like a valid description
                    if s.chars().all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace()) {
                        return Some(s);
                    }
                }
            }
        }
    }
    None
}

/// Detect NetBIOS service from response
fn detect_netbios_service(response: &[u8]) -> Option<ServiceInfo> {
    if response.len() < 12 {
        return None;
    }

    // NBSTAT response should have answer count > 0
    let answer_count = u16::from_be_bytes([response[6], response[7]]);
    if answer_count == 0 {
        return None;
    }

    // Try to extract NetBIOS names
    let names = extract_netbios_names(response);
    let banner = if !names.is_empty() {
        format!("NetBIOS names: {}", names.join(", "))
    } else {
        format!("NetBIOS response ({} bytes)", response.len())
    };

    Some(ServiceInfo {
        name: "netbios-ns".to_string(),
        version: None,
        banner: Some(banner),
        cpe: None,
        enumeration: None,
    })
}

/// Extract NetBIOS names from NBSTAT response
fn extract_netbios_names(response: &[u8]) -> Vec<String> {
    let mut names = Vec::new();

    // Skip header and find the name table
    // This is a simplified parser
    if response.len() < 57 {
        return names;
    }

    // Find number of names (at offset after header + RR fields)
    // This is approximate - real parsing would track offsets
    for i in 50..response.len().saturating_sub(18) {
        // NetBIOS name is 15 chars + suffix byte + flags
        if response[i..].len() >= 18 {
            let name_bytes = &response[i..i + 15];
            if let Ok(name) = String::from_utf8(name_bytes.to_vec()) {
                let trimmed = name.trim();
                if !trimmed.is_empty()
                    && trimmed.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                {
                    if !names.contains(&trimmed.to_string()) {
                        names.push(trimmed.to_string());
                    }
                }
            }
        }
        if names.len() >= 5 {
            break; // Limit names
        }
    }

    names
}

/// Detect TFTP service from response
fn detect_tftp_service(response: &[u8]) -> Option<ServiceInfo> {
    if response.len() < 4 {
        return None;
    }

    let opcode = u16::from_be_bytes([response[0], response[1]]);

    let banner = match opcode {
        3 => "TFTP Data packet".to_string(),
        4 => "TFTP ACK".to_string(),
        5 => {
            // Error packet
            let error_code = u16::from_be_bytes([response[2], response[3]]);
            let error_msg = if response.len() > 4 {
                String::from_utf8_lossy(&response[4..])
                    .trim_matches('\0')
                    .to_string()
            } else {
                String::new()
            };
            format!("TFTP Error {}: {}", error_code, error_msg)
        }
        6 => "TFTP OACK".to_string(),
        _ => format!("TFTP response (opcode {})", opcode),
    };

    Some(ServiceInfo {
        name: "tftp".to_string(),
        version: None,
        banner: Some(banner),
        cpe: None,
        enumeration: None,
    })
}

/// Detect SSDP/UPnP service from response
fn detect_ssdp_service(response: &[u8]) -> Option<ServiceInfo> {
    let response_str = String::from_utf8_lossy(response);

    if !response_str.contains("HTTP/") {
        return None;
    }

    // Extract Server header
    let server = response_str
        .lines()
        .find(|line| line.to_lowercase().starts_with("server:"))
        .map(|line| line[7..].trim().to_string());

    // Extract ST (Search Target) or USN
    let st = response_str
        .lines()
        .find(|line| line.to_lowercase().starts_with("st:"))
        .map(|line| line[3..].trim().to_string());

    let banner = if let Some(ref srv) = server {
        format!("SSDP: {}", srv)
    } else if let Some(ref search_target) = st {
        format!("SSDP: {}", search_target)
    } else {
        "SSDP/UPnP response".to_string()
    };

    Some(ServiceInfo {
        name: "ssdp".to_string(),
        version: server,
        banner: Some(banner),
        cpe: None,
        enumeration: None,
    })
}

/// Detect SIP service from response
fn detect_sip_service(response: &[u8]) -> Option<ServiceInfo> {
    let response_str = String::from_utf8_lossy(response);

    if !response_str.contains("SIP/") {
        return None;
    }

    // Extract Server or User-Agent header
    let server = response_str
        .lines()
        .find(|line| {
            let lower = line.to_lowercase();
            lower.starts_with("server:") || lower.starts_with("user-agent:")
        })
        .and_then(|line| line.split_once(':'))
        .map(|(_, v)| v.trim().to_string());

    let banner = if let Some(ref srv) = server {
        format!("SIP: {}", srv)
    } else {
        "SIP response".to_string()
    };

    Some(ServiceInfo {
        name: "sip".to_string(),
        version: server,
        banner: Some(banner),
        cpe: None,
        enumeration: None,
    })
}

/// Detect DHCP service from response
fn detect_dhcp_service(response: &[u8]) -> Option<ServiceInfo> {
    if response.len() < 240 {
        return None;
    }

    // Check DHCP magic cookie at offset 236
    if response[236..240] != [0x63, 0x82, 0x53, 0x63] {
        return None;
    }

    // Message type is at byte 0
    let msg_type = match response[0] {
        1 => "BOOTREQUEST",
        2 => "BOOTREPLY",
        _ => "Unknown",
    };

    Some(ServiceInfo {
        name: "dhcp".to_string(),
        version: None,
        banner: Some(format!("DHCP {} response", msg_type)),
        cpe: None,
        enumeration: None,
    })
}

/// Generic service detection for unknown ports
fn detect_generic_service(port: u16, response: &[u8]) -> Option<ServiceInfo> {
    let banner = if response.iter().all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace()) {
        Some(
            String::from_utf8_lossy(response)
                .chars()
                .take(100)
                .collect::<String>(),
        )
    } else {
        Some(format!("Binary response ({} bytes)", response.len()))
    };

    Some(ServiceInfo {
        name: crate::scanner::udp_probes::get_udp_service_name(port).to_string(),
        version: None,
        banner,
        cpe: None,
        enumeration: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_ntp_service() {
        // Minimal NTP response: LI=0, VN=4, Mode=4, Stratum=2
        let mut response = vec![0u8; 48];
        response[0] = 0x24; // VN=4, Mode=4
        response[1] = 2; // Stratum 2

        let service = detect_ntp_service(&response).unwrap();
        assert_eq!(service.name, "ntp");
        assert!(service.version.unwrap().contains("NTPv4"));
    }

    #[test]
    fn test_detect_dns_response() {
        // Minimal DNS response with QR bit set
        let response = vec![
            0x00, 0x01, // Transaction ID
            0x80, 0x00, // Flags: QR=1 (response)
            0x00, 0x01, // Questions
            0x00, 0x00, // Answers
            0x00, 0x00, // Authority
            0x00, 0x00, // Additional
        ];

        let service = detect_dns_service(&response).unwrap();
        assert_eq!(service.name, "dns");
    }

    #[test]
    fn test_extract_snmp_version() {
        // SNMPv1 response start
        let response = vec![
            0x30, 0x20, // SEQUENCE
            0x02, 0x01, 0x00, // INTEGER: version 0 (SNMPv1)
        ];

        assert_eq!(extract_snmp_version(&response), Some(0));
    }
}
