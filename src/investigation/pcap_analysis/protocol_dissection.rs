//! Protocol Dissection Module
//!
//! Deep protocol analysis and parsing for HTTP, DNS, TLS, and other protocols.

use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// HTTP request/response dissection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpDissection {
    pub method: Option<String>,
    pub uri: Option<String>,
    pub version: String,
    pub status_code: Option<u16>,
    pub status_text: Option<String>,
    pub headers: HashMap<String, String>,
    pub host: Option<String>,
    pub content_type: Option<String>,
    pub content_length: Option<usize>,
    pub user_agent: Option<String>,
    pub cookies: Vec<String>,
    pub is_request: bool,
    pub body_preview: Option<String>,
    pub suspicious_indicators: Vec<String>,
}

/// DNS dissection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsDissection {
    pub transaction_id: u16,
    pub is_query: bool,
    pub is_response: bool,
    pub opcode: u8,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub response_code: u8,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additionals: Vec<DnsRecord>,
    pub suspicious_indicators: Vec<String>,
}

/// DNS question entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: String,
    pub qclass: String,
}

/// DNS resource record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: String,
    pub record_class: String,
    pub ttl: u32,
    pub data: String,
}

/// TLS dissection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsDissection {
    pub record_type: String,
    pub version: String,
    pub handshake_type: Option<String>,
    pub server_name: Option<String>,
    pub cipher_suites: Vec<String>,
    pub extensions: Vec<TlsExtension>,
    pub certificate_chain: Vec<CertificateInfo>,
    pub ja3_fingerprint: Option<String>,
    pub ja3s_fingerprint: Option<String>,
    pub suspicious_indicators: Vec<String>,
}

/// TLS extension
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsExtension {
    pub extension_type: u16,
    pub name: String,
    pub data: String,
}

/// Certificate information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    pub is_self_signed: bool,
}

/// Dissect HTTP traffic from payload
pub fn dissect_http(payload: &[u8]) -> Result<serde_json::Value> {
    let text = String::from_utf8_lossy(payload);
    let lines: Vec<&str> = text.lines().collect();

    if lines.is_empty() {
        return Ok(serde_json::json!({"error": "Empty payload"}));
    }

    let first_line = lines[0];
    let is_request = first_line.starts_with("GET ") ||
                     first_line.starts_with("POST ") ||
                     first_line.starts_with("PUT ") ||
                     first_line.starts_with("DELETE ") ||
                     first_line.starts_with("HEAD ") ||
                     first_line.starts_with("OPTIONS ") ||
                     first_line.starts_with("PATCH ") ||
                     first_line.starts_with("CONNECT ");

    let mut headers: HashMap<String, String> = HashMap::new();
    let mut suspicious_indicators = Vec::new();

    // Parse headers
    let mut body_start = 0;
    for (i, line) in lines.iter().enumerate().skip(1) {
        if line.is_empty() {
            body_start = i + 1;
            break;
        }
        if let Some(colon_pos) = line.find(':') {
            let key = line[..colon_pos].trim().to_lowercase();
            let value = line[colon_pos + 1..].trim().to_string();
            headers.insert(key, value);
        }
    }

    // Extract key fields
    let host = headers.get("host").cloned();
    let content_type = headers.get("content-type").cloned();
    let content_length = headers.get("content-length")
        .and_then(|v| v.parse().ok());
    let user_agent = headers.get("user-agent").cloned();

    // Extract cookies
    let cookies: Vec<String> = headers.get("cookie")
        .map(|c| c.split(';').map(|s| s.trim().to_string()).collect())
        .unwrap_or_default();

    // Check for suspicious indicators
    if let Some(ua) = &user_agent {
        let ua_lower = ua.to_lowercase();
        if ua_lower.contains("curl") || ua_lower.contains("wget") || ua_lower.contains("python") {
            suspicious_indicators.push("Scripted user agent detected".to_string());
        }
        if ua_lower.len() < 20 {
            suspicious_indicators.push("Short user agent (possible bot)".to_string());
        }
    }

    if let Some(h) = &host {
        // Check for IP-based hosts
        if h.chars().all(|c| c.is_numeric() || c == '.') {
            suspicious_indicators.push("IP address used as host".to_string());
        }
        // Check for suspicious TLDs
        if h.ends_with(".xyz") || h.ends_with(".top") || h.ends_with(".tk") {
            suspicious_indicators.push("Suspicious TLD detected".to_string());
        }
    }

    let dissection = if is_request {
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        let method = parts.get(0).map(|s| s.to_string());
        let uri = parts.get(1).map(|s| s.to_string());
        let version = parts.get(2).unwrap_or(&"HTTP/1.1").to_string();

        // Check URI for suspicious patterns
        if let Some(ref u) = uri {
            if u.contains("..") {
                suspicious_indicators.push("Path traversal attempt detected".to_string());
            }
            if u.contains("%00") || u.contains("\\x00") {
                suspicious_indicators.push("Null byte injection attempt".to_string());
            }
            if u.len() > 2000 {
                suspicious_indicators.push("Unusually long URI".to_string());
            }
        }

        HttpDissection {
            method,
            uri,
            version,
            status_code: None,
            status_text: None,
            headers,
            host,
            content_type,
            content_length,
            user_agent,
            cookies,
            is_request: true,
            body_preview: lines.get(body_start..).map(|l| l.join("\n").chars().take(500).collect()),
            suspicious_indicators,
        }
    } else if first_line.starts_with("HTTP/") {
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        let version = parts.get(0).unwrap_or(&"HTTP/1.1").to_string();
        let status_code = parts.get(1).and_then(|s| s.parse().ok());
        let status_text = parts.get(2..).map(|p| p.join(" "));

        HttpDissection {
            method: None,
            uri: None,
            version,
            status_code,
            status_text,
            headers,
            host,
            content_type,
            content_length,
            user_agent,
            cookies,
            is_request: false,
            body_preview: lines.get(body_start..).map(|l| l.join("\n").chars().take(500).collect()),
            suspicious_indicators,
        }
    } else {
        return Ok(serde_json::json!({"error": "Not a valid HTTP message"}));
    };

    serde_json::to_value(&dissection).context("Failed to serialize HTTP dissection")
}

/// Dissect DNS traffic from payload
pub fn dissect_dns(payload: &[u8]) -> Result<serde_json::Value> {
    if payload.len() < 12 {
        return Ok(serde_json::json!({"error": "Payload too short for DNS"}));
    }

    let transaction_id = u16::from_be_bytes([payload[0], payload[1]]);
    let flags = u16::from_be_bytes([payload[2], payload[3]]);

    let is_response = (flags >> 15) & 1 == 1;
    let opcode = ((flags >> 11) & 0xF) as u8;
    let authoritative = (flags >> 10) & 1 == 1;
    let truncated = (flags >> 9) & 1 == 1;
    let recursion_desired = (flags >> 8) & 1 == 1;
    let recursion_available = (flags >> 7) & 1 == 1;
    let response_code = (flags & 0xF) as u8;

    let qdcount = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    let ancount = u16::from_be_bytes([payload[6], payload[7]]) as usize;
    let nscount = u16::from_be_bytes([payload[8], payload[9]]) as usize;
    let arcount = u16::from_be_bytes([payload[10], payload[11]]) as usize;

    let mut offset = 12;
    let mut questions = Vec::new();
    let mut suspicious_indicators = Vec::new();

    // Parse questions
    for _ in 0..qdcount {
        if offset >= payload.len() {
            break;
        }
        let (name, new_offset) = parse_dns_name(payload, offset)?;
        offset = new_offset;

        if offset + 4 > payload.len() {
            break;
        }
        let qtype = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let qclass = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]);
        offset += 4;

        // Check for suspicious patterns
        if name.len() > 50 {
            suspicious_indicators.push(format!("Long domain name: {}", name));
        }
        if name.matches('.').count() > 5 {
            suspicious_indicators.push(format!("Many subdomains: {}", name));
        }
        // Check for potential DNS tunneling
        if name.chars().filter(|c| c.is_numeric()).count() > name.len() / 3 {
            suspicious_indicators.push("Possible DNS tunneling (high numeric ratio)".to_string());
        }

        questions.push(DnsQuestion {
            name,
            qtype: dns_type_to_string(qtype),
            qclass: dns_class_to_string(qclass),
        });
    }

    // Parse answers
    let answers = parse_dns_records(payload, &mut offset, ancount)?;
    let authorities = parse_dns_records(payload, &mut offset, nscount)?;
    let additionals = parse_dns_records(payload, &mut offset, arcount)?;

    // Check for NXDOMAIN responses (common in DGA)
    if is_response && response_code == 3 {
        suspicious_indicators.push("NXDOMAIN response (could indicate DGA)".to_string());
    }

    // Check for suspicious record types
    for answer in &answers {
        if answer.record_type == "TXT" && answer.data.len() > 100 {
            suspicious_indicators.push("Long TXT record (possible data exfiltration)".to_string());
        }
    }

    let dissection = DnsDissection {
        transaction_id,
        is_query: !is_response,
        is_response,
        opcode,
        authoritative,
        truncated,
        recursion_desired,
        recursion_available,
        response_code,
        questions,
        answers,
        authorities,
        additionals,
        suspicious_indicators,
    };

    serde_json::to_value(&dissection).context("Failed to serialize DNS dissection")
}

/// Parse DNS name from payload
fn parse_dns_name(payload: &[u8], start: usize) -> Result<(String, usize)> {
    let mut name_parts = Vec::new();
    let mut offset = start;
    let mut jumped = false;
    let mut final_offset = start;

    loop {
        if offset >= payload.len() {
            break;
        }
        let len = payload[offset] as usize;

        // Check for compression pointer
        if len & 0xC0 == 0xC0 {
            if offset + 1 >= payload.len() {
                break;
            }
            let pointer = ((len & 0x3F) << 8) | payload[offset + 1] as usize;
            if !jumped {
                final_offset = offset + 2;
            }
            jumped = true;
            offset = pointer;
            continue;
        }

        if len == 0 {
            if !jumped {
                final_offset = offset + 1;
            }
            break;
        }

        offset += 1;
        if offset + len > payload.len() {
            break;
        }

        let label = String::from_utf8_lossy(&payload[offset..offset + len]).to_string();
        name_parts.push(label);
        offset += len;
    }

    Ok((name_parts.join("."), final_offset))
}

/// Parse DNS resource records
fn parse_dns_records(payload: &[u8], offset: &mut usize, count: usize) -> Result<Vec<DnsRecord>> {
    let mut records = Vec::new();

    for _ in 0..count {
        if *offset >= payload.len() {
            break;
        }

        let (name, new_offset) = parse_dns_name(payload, *offset)?;
        *offset = new_offset;

        if *offset + 10 > payload.len() {
            break;
        }

        let rtype = u16::from_be_bytes([payload[*offset], payload[*offset + 1]]);
        let rclass = u16::from_be_bytes([payload[*offset + 2], payload[*offset + 3]]);
        let ttl = u32::from_be_bytes([
            payload[*offset + 4],
            payload[*offset + 5],
            payload[*offset + 6],
            payload[*offset + 7],
        ]);
        let rdlength = u16::from_be_bytes([payload[*offset + 8], payload[*offset + 9]]) as usize;
        *offset += 10;

        if *offset + rdlength > payload.len() {
            break;
        }

        let data = parse_dns_rdata(payload, *offset, rtype, rdlength)?;
        *offset += rdlength;

        records.push(DnsRecord {
            name,
            record_type: dns_type_to_string(rtype),
            record_class: dns_class_to_string(rclass),
            ttl,
            data,
        });
    }

    Ok(records)
}

/// Parse DNS record data based on type
fn parse_dns_rdata(payload: &[u8], offset: usize, rtype: u16, rdlength: usize) -> Result<String> {
    match rtype {
        1 => { // A record
            if rdlength == 4 {
                Ok(format!("{}.{}.{}.{}",
                    payload[offset], payload[offset + 1],
                    payload[offset + 2], payload[offset + 3]))
            } else {
                Ok("Invalid A record".to_string())
            }
        }
        28 => { // AAAA record
            if rdlength == 16 {
                let parts: Vec<String> = payload[offset..offset + 16]
                    .chunks(2)
                    .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
                    .collect();
                Ok(parts.join(":"))
            } else {
                Ok("Invalid AAAA record".to_string())
            }
        }
        5 | 2 | 12 => { // CNAME, NS, PTR
            let (name, _) = parse_dns_name(payload, offset)?;
            Ok(name)
        }
        15 => { // MX
            if rdlength >= 2 {
                let priority = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
                let (exchange, _) = parse_dns_name(payload, offset + 2)?;
                Ok(format!("{} {}", priority, exchange))
            } else {
                Ok("Invalid MX record".to_string())
            }
        }
        16 => { // TXT
            let txt = String::from_utf8_lossy(&payload[offset..offset + rdlength]).to_string();
            Ok(txt)
        }
        _ => {
            Ok(hex::encode(&payload[offset..offset + rdlength]))
        }
    }
}

/// Convert DNS type to string
fn dns_type_to_string(qtype: u16) -> String {
    match qtype {
        1 => "A".to_string(),
        2 => "NS".to_string(),
        5 => "CNAME".to_string(),
        6 => "SOA".to_string(),
        12 => "PTR".to_string(),
        15 => "MX".to_string(),
        16 => "TXT".to_string(),
        28 => "AAAA".to_string(),
        33 => "SRV".to_string(),
        255 => "ANY".to_string(),
        _ => format!("TYPE{}", qtype),
    }
}

/// Convert DNS class to string
fn dns_class_to_string(qclass: u16) -> String {
    match qclass {
        1 => "IN".to_string(),
        3 => "CH".to_string(),
        4 => "HS".to_string(),
        255 => "ANY".to_string(),
        _ => format!("CLASS{}", qclass),
    }
}

/// Dissect TLS traffic from payload
pub fn dissect_tls(payload: &[u8]) -> Result<serde_json::Value> {
    if payload.len() < 5 {
        return Ok(serde_json::json!({"error": "Payload too short for TLS"}));
    }

    let content_type = payload[0];
    let version_major = payload[1];
    let version_minor = payload[2];
    let length = u16::from_be_bytes([payload[3], payload[4]]) as usize;

    let record_type = match content_type {
        20 => "ChangeCipherSpec",
        21 => "Alert",
        22 => "Handshake",
        23 => "ApplicationData",
        _ => "Unknown",
    }.to_string();

    let version = format!("{}.{}", version_major, version_minor);
    let version_name = match (version_major, version_minor) {
        (3, 0) => "SSL 3.0",
        (3, 1) => "TLS 1.0",
        (3, 2) => "TLS 1.1",
        (3, 3) => "TLS 1.2",
        (3, 4) => "TLS 1.3",
        _ => "Unknown",
    };

    let mut suspicious_indicators = Vec::new();
    let mut handshake_type = None;
    let mut server_name = None;
    let mut cipher_suites = Vec::new();
    let mut extensions = Vec::new();

    // Check for suspicious TLS versions
    if version_major < 3 || (version_major == 3 && version_minor < 1) {
        suspicious_indicators.push("Outdated TLS/SSL version".to_string());
    }

    // Parse handshake message if applicable
    if content_type == 22 && payload.len() > 5 {
        let hs_type = payload[5];
        handshake_type = Some(match hs_type {
            0 => "HelloRequest",
            1 => "ClientHello",
            2 => "ServerHello",
            4 => "NewSessionTicket",
            11 => "Certificate",
            12 => "ServerKeyExchange",
            13 => "CertificateRequest",
            14 => "ServerHelloDone",
            15 => "CertificateVerify",
            16 => "ClientKeyExchange",
            20 => "Finished",
            _ => "Unknown",
        }.to_string());

        // Parse ClientHello
        if hs_type == 1 && payload.len() > 43 {
            let session_id_len = payload[43] as usize;
            let mut offset = 44 + session_id_len;

            if offset + 2 <= payload.len() {
                let cipher_len = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
                offset += 2;

                // Parse cipher suites
                let mut cs_offset = 0;
                while cs_offset + 2 <= cipher_len && offset + cs_offset + 2 <= payload.len() {
                    let cipher = u16::from_be_bytes([
                        payload[offset + cs_offset],
                        payload[offset + cs_offset + 1],
                    ]);
                    cipher_suites.push(format!("0x{:04X}", cipher));
                    cs_offset += 2;
                }
                offset += cipher_len;

                // Skip compression methods
                if offset < payload.len() {
                    let comp_len = payload[offset] as usize;
                    offset += 1 + comp_len;
                }

                // Parse extensions
                if offset + 2 <= payload.len() {
                    let ext_len = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
                    offset += 2;
                    let ext_end = offset + ext_len;

                    while offset + 4 <= ext_end && offset + 4 <= payload.len() {
                        let ext_type = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
                        let ext_data_len = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]) as usize;
                        offset += 4;

                        let ext_name = match ext_type {
                            0 => "server_name",
                            5 => "status_request",
                            10 => "supported_groups",
                            11 => "ec_point_formats",
                            13 => "signature_algorithms",
                            16 => "application_layer_protocol_negotiation",
                            23 => "extended_master_secret",
                            35 => "session_ticket",
                            43 => "supported_versions",
                            45 => "psk_key_exchange_modes",
                            51 => "key_share",
                            _ => "unknown",
                        };

                        // Extract server name if SNI extension
                        if ext_type == 0 && offset + ext_data_len <= payload.len() {
                            if ext_data_len > 5 {
                                let name_len = u16::from_be_bytes([
                                    payload[offset + 3],
                                    payload[offset + 4],
                                ]) as usize;
                                if name_len > 0 && offset + 5 + name_len <= payload.len() {
                                    server_name = Some(
                                        String::from_utf8_lossy(&payload[offset + 5..offset + 5 + name_len])
                                            .to_string()
                                    );
                                }
                            }
                        }

                        extensions.push(TlsExtension {
                            extension_type: ext_type,
                            name: ext_name.to_string(),
                            data: if offset + ext_data_len <= payload.len() {
                                hex::encode(&payload[offset..offset + ext_data_len])
                            } else {
                                String::new()
                            },
                        });

                        offset += ext_data_len;
                    }
                }
            }
        }
    }

    // Calculate JA3 fingerprint (simplified)
    let ja3_fingerprint = if !cipher_suites.is_empty() {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        let ja3_string = format!(
            "{},{},{},{},{}",
            format!("{}", (version_major as u16) << 8 | version_minor as u16),
            cipher_suites.join("-"),
            extensions.iter().map(|e| e.extension_type.to_string()).collect::<Vec<_>>().join("-"),
            "", // elliptic_curves placeholder
            "", // ec_point_formats placeholder
        );
        hasher.update(ja3_string.as_bytes());
        Some(format!("{:x}", hasher.finalize()))
    } else {
        None
    };

    let dissection = TlsDissection {
        record_type,
        version: format!("{} ({})", version_name, version),
        handshake_type,
        server_name,
        cipher_suites,
        extensions,
        certificate_chain: Vec::new(), // Would need full certificate parsing
        ja3_fingerprint,
        ja3s_fingerprint: None,
        suspicious_indicators,
    };

    serde_json::to_value(&dissection).context("Failed to serialize TLS dissection")
}

/// Dissect SMB traffic
pub fn dissect_smb(payload: &[u8]) -> Result<serde_json::Value> {
    if payload.len() < 4 {
        return Ok(serde_json::json!({"error": "Payload too short for SMB"}));
    }

    // Check for NetBIOS Session Service header
    let is_smb2 = payload.len() > 4 && &payload[4..8] == b"\xfeSMB";
    let is_smb1 = payload.len() > 4 && &payload[4..8] == b"\xffSMB";

    if is_smb2 {
        dissect_smb2(&payload[4..])
    } else if is_smb1 {
        dissect_smb1(&payload[4..])
    } else {
        Ok(serde_json::json!({"error": "Not a valid SMB message"}))
    }
}

fn dissect_smb1(payload: &[u8]) -> Result<serde_json::Value> {
    if payload.len() < 32 {
        return Ok(serde_json::json!({"error": "SMB1 header too short"}));
    }

    let command = payload[4];
    let command_name = match command {
        0x00 => "CreateDirectory",
        0x01 => "DeleteDirectory",
        0x02 => "Open",
        0x03 => "Create",
        0x04 => "Close",
        0x05 => "Flush",
        0x06 => "Delete",
        0x07 => "Rename",
        0x08 => "QueryInformation",
        0x25 => "Transaction",
        0x32 => "Transaction2",
        0x72 => "NegotiateProtocol",
        0x73 => "SessionSetup",
        0x75 => "TreeConnect",
        _ => "Unknown",
    };

    Ok(serde_json::json!({
        "version": "SMB1",
        "command": command_name,
        "command_code": format!("0x{:02X}", command),
        "flags": payload[13],
        "flags2": u16::from_le_bytes([payload[14], payload[15]]),
    }))
}

fn dissect_smb2(payload: &[u8]) -> Result<serde_json::Value> {
    if payload.len() < 64 {
        return Ok(serde_json::json!({"error": "SMB2 header too short"}));
    }

    let command = u16::from_le_bytes([payload[12], payload[13]]);
    let command_name = match command {
        0 => "Negotiate",
        1 => "SessionSetup",
        2 => "Logoff",
        3 => "TreeConnect",
        4 => "TreeDisconnect",
        5 => "Create",
        6 => "Close",
        7 => "Flush",
        8 => "Read",
        9 => "Write",
        10 => "Lock",
        11 => "Ioctl",
        12 => "Cancel",
        13 => "Echo",
        14 => "QueryDirectory",
        15 => "ChangeNotify",
        16 => "QueryInfo",
        17 => "SetInfo",
        18 => "OplockBreak",
        _ => "Unknown",
    };

    let flags = u32::from_le_bytes([payload[16], payload[17], payload[18], payload[19]]);
    let is_response = flags & 1 == 1;

    Ok(serde_json::json!({
        "version": "SMB2",
        "command": command_name,
        "command_code": command,
        "is_response": is_response,
        "flags": flags,
        "message_id": u64::from_le_bytes([
            payload[24], payload[25], payload[26], payload[27],
            payload[28], payload[29], payload[30], payload[31],
        ]),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dissect_http_request() {
        let payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n";
        let result = dissect_http(payload).unwrap();
        assert!(result.get("method").is_some());
        assert_eq!(result["method"], "GET");
    }

    #[test]
    fn test_dissect_http_response() {
        let payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>";
        let result = dissect_http(payload).unwrap();
        assert_eq!(result["status_code"], 200);
    }

    #[test]
    fn test_dns_type_to_string() {
        assert_eq!(dns_type_to_string(1), "A");
        assert_eq!(dns_type_to_string(28), "AAAA");
        assert_eq!(dns_type_to_string(999), "TYPE999");
    }
}
