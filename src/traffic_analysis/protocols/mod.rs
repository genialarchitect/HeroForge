//! Protocol Analysis Module
//!
//! Deep protocol dissection for:
//! - HTTP/HTTPS requests and responses
//! - DNS queries and responses
//! - TLS handshakes and certificates
//! - SMB/CIFS operations
//! - FTP commands and transfers

use crate::traffic_analysis::types::*;
use chrono::{DateTime, Utc};
use md5::{Md5, Digest as Md5Digest};
use std::collections::HashMap;
use std::net::IpAddr;

/// Protocol analyzer for deep packet inspection
pub struct ProtocolAnalyzer {
    /// HTTP transactions
    http_transactions: Vec<HttpTransaction>,
    /// DNS queries
    dns_queries: Vec<DnsQuery>,
    /// TLS connections
    tls_connections: Vec<TlsConnection>,
    /// Protocol anomalies
    anomalies: Vec<ProtocolAnomaly>,
}

impl ProtocolAnalyzer {
    /// Create a new protocol analyzer
    pub fn new() -> Self {
        Self {
            http_transactions: Vec::new(),
            dns_queries: Vec::new(),
            tls_connections: Vec::new(),
            anomalies: Vec::new(),
        }
    }

    /// Analyze a packet payload for protocol data
    pub fn analyze_packet(
        &mut self,
        pcap_id: &str,
        session_id: &str,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
        timestamp: DateTime<Utc>,
    ) {
        // Detect protocol and parse
        if dst_port == 80 || src_port == 80 || dst_port == 8080 || src_port == 8080 {
            self.parse_http(pcap_id, session_id, payload, timestamp);
        }

        if dst_port == 53 || src_port == 53 {
            self.parse_dns(pcap_id, session_id, payload, timestamp);
        }

        if dst_port == 443 || src_port == 443 {
            self.parse_tls(session_id, payload);
        }

        // Check for anomalies
        self.check_anomalies(pcap_id, session_id, src_ip, dst_ip, dst_port, payload, timestamp);
    }

    /// Parse HTTP request/response
    fn parse_http(&mut self, pcap_id: &str, session_id: &str, payload: &[u8], timestamp: DateTime<Utc>) {
        let text = String::from_utf8_lossy(payload);

        // Check for HTTP request
        if text.starts_with("GET ") || text.starts_with("POST ") ||
           text.starts_with("PUT ") || text.starts_with("DELETE ") ||
           text.starts_with("HEAD ") || text.starts_with("OPTIONS ") ||
           text.starts_with("PATCH ") {
            if let Some(transaction) = self.parse_http_request(pcap_id, session_id, &text, timestamp) {
                self.http_transactions.push(transaction);
            }
        }

        // Check for HTTP response
        if text.starts_with("HTTP/") {
            // Find the index of the transaction to update
            let idx = self.http_transactions.iter()
                .enumerate()
                .rev()
                .find(|(_, t)| t.session_id == session_id && t.response_code.is_none())
                .map(|(i, _)| i);

            // Update existing transaction with response in a separate scope
            if let Some(idx) = idx {
                Self::parse_http_response_static(&mut self.http_transactions[idx], &text, timestamp);
            }
        }
    }

    /// Parse HTTP request
    fn parse_http_request(&self, pcap_id: &str, session_id: &str, text: &str, timestamp: DateTime<Utc>) -> Option<HttpTransaction> {
        let lines: Vec<&str> = text.lines().collect();
        if lines.is_empty() {
            return None;
        }

        // Parse request line
        let parts: Vec<&str> = lines[0].split_whitespace().collect();
        if parts.len() < 2 {
            return None;
        }

        let method = parts[0].to_string();
        let uri = parts[1].to_string();

        // Parse headers
        let mut headers = HashMap::new();
        let mut host = String::new();
        let mut user_agent = None;
        let mut content_length = 0usize;

        for line in lines.iter().skip(1) {
            if line.is_empty() {
                break;
            }
            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim().to_string();
                let value = value.trim().to_string();

                match key.to_lowercase().as_str() {
                    "host" => host = value.clone(),
                    "user-agent" => user_agent = Some(value.clone()),
                    "content-length" => content_length = value.parse().unwrap_or(0),
                    _ => {}
                }

                headers.insert(key, value);
            }
        }

        let full_url = if host.is_empty() {
            uri.clone()
        } else if uri.starts_with('/') {
            format!("http://{}{}", host, uri)
        } else {
            uri.clone()
        };

        // Check for suspicious indicators
        let mut suspicion_reasons = Vec::new();
        let is_suspicious = self.check_http_suspicious(&uri, &headers, &mut suspicion_reasons);

        Some(HttpTransaction {
            id: uuid::Uuid::new_v4().to_string(),
            pcap_id: pcap_id.to_string(),
            session_id: session_id.to_string(),
            request_time: timestamp,
            method,
            host,
            uri,
            full_url,
            user_agent,
            request_headers: headers,
            request_body_size: content_length as u64,
            request_body_hash: None,
            response_time: None,
            response_code: None,
            response_headers: HashMap::new(),
            response_body_size: 0,
            response_body_hash: None,
            content_type: None,
            is_suspicious,
            suspicion_reasons,
        })
    }

    /// Parse HTTP response (static version to avoid borrow conflicts)
    fn parse_http_response_static(transaction: &mut HttpTransaction, text: &str, timestamp: DateTime<Utc>) {
        let lines: Vec<&str> = text.lines().collect();
        if lines.is_empty() {
            return;
        }

        // Parse status line
        let parts: Vec<&str> = lines[0].split_whitespace().collect();
        if parts.len() >= 2 {
            if let Ok(code) = parts[1].parse::<u16>() {
                transaction.response_code = Some(code);
            }
        }

        transaction.response_time = Some(timestamp);

        // Parse headers
        let mut content_length = 0u64;
        for line in lines.iter().skip(1) {
            if line.is_empty() {
                break;
            }
            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim().to_string();
                let value = value.trim().to_string();

                match key.to_lowercase().as_str() {
                    "content-type" => transaction.content_type = Some(value.clone()),
                    "content-length" => content_length = value.parse().unwrap_or(0),
                    _ => {}
                }

                transaction.response_headers.insert(key, value);
            }
        }

        transaction.response_body_size = content_length;
    }

    /// Check for suspicious HTTP indicators
    fn check_http_suspicious(&self, uri: &str, headers: &HashMap<String, String>, reasons: &mut Vec<String>) -> bool {
        let mut suspicious = false;
        let uri_lower = uri.to_lowercase();

        // Check for SQL injection patterns
        if uri_lower.contains("' or ") || uri_lower.contains("1=1") ||
           uri_lower.contains("union select") || uri_lower.contains("--") {
            reasons.push("Possible SQL injection attempt".to_string());
            suspicious = true;
        }

        // Check for XSS patterns
        if uri_lower.contains("<script") || uri_lower.contains("javascript:") ||
           uri_lower.contains("onerror=") || uri_lower.contains("onload=") {
            reasons.push("Possible XSS attempt".to_string());
            suspicious = true;
        }

        // Check for path traversal
        if uri.contains("../") || uri.contains("..\\") {
            reasons.push("Path traversal attempt".to_string());
            suspicious = true;
        }

        // Check for suspicious user agents
        if let Some(ua) = headers.get("User-Agent").or_else(|| headers.get("user-agent")) {
            let ua_lower = ua.to_lowercase();
            if ua_lower.contains("sqlmap") || ua_lower.contains("nikto") ||
               ua_lower.contains("nmap") || ua_lower.contains("masscan") ||
               ua_lower.contains("dirbuster") || ua_lower.contains("gobuster") {
                reasons.push(format!("Security tool user agent: {}", ua));
                suspicious = true;
            }
        }

        // Check for shell commands
        if uri_lower.contains("cmd.exe") || uri_lower.contains("/bin/bash") ||
           uri_lower.contains("powershell") || uri_lower.contains("wget") ||
           uri_lower.contains("curl") {
            reasons.push("Command execution attempt".to_string());
            suspicious = true;
        }

        suspicious
    }

    /// Parse DNS query/response
    fn parse_dns(&mut self, pcap_id: &str, session_id: &str, payload: &[u8], timestamp: DateTime<Utc>) {
        if payload.len() < 12 {
            return;
        }

        // DNS header
        let _id = u16::from_be_bytes([payload[0], payload[1]]);
        let flags = u16::from_be_bytes([payload[2], payload[3]]);
        let qr = (flags >> 15) & 1; // 0 = query, 1 = response
        let rcode = flags & 0x0f;

        let qdcount = u16::from_be_bytes([payload[4], payload[5]]) as usize;
        let ancount = u16::from_be_bytes([payload[6], payload[7]]) as usize;

        if qdcount == 0 {
            return;
        }

        // Parse question section
        let mut offset = 12;
        let query_name = self.parse_dns_name(payload, &mut offset);

        if offset + 4 > payload.len() {
            return;
        }

        let qtype = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        offset += 4; // qtype + qclass

        let query_type = match qtype {
            1 => DnsQueryType::A,
            28 => DnsQueryType::Aaaa,
            5 => DnsQueryType::Cname,
            15 => DnsQueryType::Mx,
            2 => DnsQueryType::Ns,
            12 => DnsQueryType::Ptr,
            6 => DnsQueryType::Soa,
            33 => DnsQueryType::Srv,
            16 => DnsQueryType::Txt,
            255 => DnsQueryType::Any,
            _ => DnsQueryType::Other,
        };

        let response_code = match rcode {
            0 => DnsResponseCode::NoError,
            1 => DnsResponseCode::FormErr,
            2 => DnsResponseCode::ServFail,
            3 => DnsResponseCode::NxDomain,
            4 => DnsResponseCode::NotImp,
            5 => DnsResponseCode::Refused,
            _ => DnsResponseCode::Other,
        };

        // Parse answers if response
        let mut answers = Vec::new();
        let mut ttl = None;

        if qr == 1 && ancount > 0 {
            for _ in 0..ancount {
                if offset >= payload.len() {
                    break;
                }

                // Skip name
                self.parse_dns_name(payload, &mut offset);

                if offset + 10 > payload.len() {
                    break;
                }

                let atype = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
                offset += 2;
                offset += 2; // class
                let answer_ttl = u32::from_be_bytes([
                    payload[offset], payload[offset + 1],
                    payload[offset + 2], payload[offset + 3]
                ]);
                offset += 4;
                let rdlength = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
                offset += 2;

                if ttl.is_none() {
                    ttl = Some(answer_ttl);
                }

                // Parse answer data
                let value = match atype {
                    1 if rdlength == 4 && offset + 4 <= payload.len() => {
                        format!("{}.{}.{}.{}",
                            payload[offset], payload[offset + 1],
                            payload[offset + 2], payload[offset + 3])
                    }
                    28 if rdlength == 16 && offset + 16 <= payload.len() => {
                        // IPv6
                        let mut parts = Vec::new();
                        for i in 0..8 {
                            let idx = offset + i * 2;
                            parts.push(format!("{:x}",
                                u16::from_be_bytes([payload[idx], payload[idx + 1]])));
                        }
                        parts.join(":")
                    }
                    5 | 2 | 12 => {
                        // CNAME, NS, PTR
                        let mut name_offset = offset;
                        self.parse_dns_name(payload, &mut name_offset)
                    }
                    _ => format!("(type {} rdlength {})", atype, rdlength),
                };

                let answer_type = match atype {
                    1 => DnsQueryType::A,
                    28 => DnsQueryType::Aaaa,
                    5 => DnsQueryType::Cname,
                    15 => DnsQueryType::Mx,
                    2 => DnsQueryType::Ns,
                    12 => DnsQueryType::Ptr,
                    6 => DnsQueryType::Soa,
                    33 => DnsQueryType::Srv,
                    16 => DnsQueryType::Txt,
                    _ => DnsQueryType::Other,
                };

                answers.push(DnsAnswer {
                    answer_type,
                    value,
                    ttl: answer_ttl,
                });

                offset += rdlength;
            }
        }

        // Check for suspicious DNS
        let (is_suspicious, dga_score, suspicion_reasons) = self.check_dns_suspicious(&query_name);

        self.dns_queries.push(DnsQuery {
            id: uuid::Uuid::new_v4().to_string(),
            pcap_id: pcap_id.to_string(),
            session_id: Some(session_id.to_string()),
            query_time: timestamp,
            query_type,
            query_name,
            response_code,
            answers,
            ttl,
            is_suspicious,
            dga_score,
            suspicion_reasons,
        });
    }

    /// Parse DNS name from payload
    fn parse_dns_name(&self, payload: &[u8], offset: &mut usize) -> String {
        let mut name_parts = Vec::new();
        let mut jumped = false;
        let original_offset = *offset;

        while *offset < payload.len() {
            let len = payload[*offset] as usize;

            if len == 0 {
                if !jumped {
                    *offset += 1;
                }
                break;
            }

            // Pointer (compression)
            if len & 0xc0 == 0xc0 {
                if *offset + 1 >= payload.len() {
                    break;
                }
                let ptr = ((len & 0x3f) << 8) | (payload[*offset + 1] as usize);
                if !jumped {
                    *offset += 2;
                }
                jumped = true;
                let mut ptr_offset = ptr;
                let part = self.parse_dns_name(payload, &mut ptr_offset);
                name_parts.push(part);
                break;
            }

            *offset += 1;
            if *offset + len > payload.len() {
                break;
            }

            if let Ok(part) = std::str::from_utf8(&payload[*offset..*offset + len]) {
                name_parts.push(part.to_string());
            }
            *offset += len;
        }

        if jumped {
            *offset = original_offset + 2;
        }

        name_parts.join(".")
    }

    /// Check for suspicious DNS indicators
    fn check_dns_suspicious(&self, name: &str) -> (bool, Option<f64>, Vec<String>) {
        let mut suspicious = false;
        let mut reasons = Vec::new();

        // Calculate DGA score based on entropy and patterns
        let dga_score = self.calculate_dga_score(name);

        if dga_score > 0.7 {
            suspicious = true;
            reasons.push(format!("High DGA score: {:.2}", dga_score));
        }

        // Check for suspicious TLDs
        let suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".top", ".xyz", ".work", ".click"];
        for tld in &suspicious_tlds {
            if name.ends_with(tld) {
                suspicious = true;
                reasons.push(format!("Suspicious TLD: {}", tld));
            }
        }

        // Check for long subdomain
        let parts: Vec<&str> = name.split('.').collect();
        if parts.len() > 5 {
            suspicious = true;
            reasons.push("Excessive subdomain depth".to_string());
        }

        // Check for numeric subdomains
        if parts.iter().any(|p| p.chars().all(|c| c.is_ascii_digit())) {
            suspicious = true;
            reasons.push("Numeric subdomain".to_string());
        }

        // Check for base64-like patterns
        if parts.iter().any(|p| p.len() > 20 && p.chars().all(|c| c.is_ascii_alphanumeric())) {
            suspicious = true;
            reasons.push("Possible encoded data in hostname".to_string());
        }

        (suspicious, Some(dga_score), reasons)
    }

    /// Calculate DGA (Domain Generation Algorithm) score
    fn calculate_dga_score(&self, name: &str) -> f64 {
        // Remove TLD
        let parts: Vec<&str> = name.split('.').collect();
        if parts.is_empty() {
            return 0.0;
        }

        let domain = parts[0];
        if domain.len() < 4 {
            return 0.0;
        }

        // Calculate entropy
        let mut char_counts = HashMap::new();
        for c in domain.chars() {
            *char_counts.entry(c).or_insert(0) += 1;
        }

        let len = domain.len() as f64;
        let mut entropy = 0.0;
        for count in char_counts.values() {
            let p = *count as f64 / len;
            entropy -= p * p.log2();
        }

        // Normalize entropy (max ~4.7 for random string)
        let normalized_entropy = (entropy / 4.7).min(1.0);

        // Check for consonant clusters
        let vowels = ['a', 'e', 'i', 'o', 'u'];
        let mut max_consonants = 0;
        let mut current_consonants = 0;

        for c in domain.chars() {
            if c.is_alphabetic() && !vowels.contains(&c.to_ascii_lowercase()) {
                current_consonants += 1;
                max_consonants = max_consonants.max(current_consonants);
            } else {
                current_consonants = 0;
            }
        }

        let consonant_score = (max_consonants as f64 / 5.0).min(1.0);

        // Digit ratio
        let digit_count = domain.chars().filter(|c| c.is_ascii_digit()).count();
        let digit_ratio = digit_count as f64 / len;

        // Combine scores
        (normalized_entropy * 0.5 + consonant_score * 0.3 + digit_ratio * 0.2).min(1.0)
    }

    /// Parse TLS handshake
    fn parse_tls(&mut self, session_id: &str, payload: &[u8]) {
        if payload.len() < 5 {
            return;
        }

        // TLS record header
        let content_type = payload[0];
        let _version = u16::from_be_bytes([payload[1], payload[2]]);
        let _length = u16::from_be_bytes([payload[3], payload[4]]);

        if content_type != 22 {
            // Not handshake
            return;
        }

        if payload.len() < 6 {
            return;
        }

        let handshake_type = payload[5];

        if handshake_type == 1 {
            // Client Hello
            if let Some(connection) = self.parse_client_hello(session_id, &payload[5..]) {
                self.tls_connections.push(connection);
            }
        } else if handshake_type == 2 {
            // Server Hello - update existing connection
            // Find the index first to avoid borrow conflict
            let idx = self.tls_connections.iter()
                .enumerate()
                .rev()
                .find(|(_, c)| c.session_id == session_id)
                .map(|(i, _)| i);

            if let Some(idx) = idx {
                let payload_slice = &payload[5..];
                self.parse_server_hello_by_index(idx, payload_slice);
            }
        }
    }

    /// Parse TLS Client Hello
    fn parse_client_hello(&self, session_id: &str, payload: &[u8]) -> Option<TlsConnection> {
        if payload.len() < 39 {
            return None;
        }

        // Skip handshake header (1 + 3 = 4 bytes)
        let mut offset = 4;

        // Version
        let version = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        offset += 2;

        let tls_version = match version {
            0x0300 => TlsVersion::Ssl30,
            0x0301 => TlsVersion::Tls10,
            0x0302 => TlsVersion::Tls11,
            0x0303 => TlsVersion::Tls12,
            0x0304 => TlsVersion::Tls13,
            _ => TlsVersion::Unknown,
        };

        // Skip random (32 bytes)
        offset += 32;

        // Session ID
        if offset >= payload.len() {
            return None;
        }
        let session_id_len = payload[offset] as usize;
        offset += 1 + session_id_len;

        // Cipher suites
        if offset + 2 > payload.len() {
            return None;
        }
        let cipher_suites_len = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
        offset += 2;

        let cipher_suites_data = if offset + cipher_suites_len <= payload.len() {
            &payload[offset..offset + cipher_suites_len]
        } else {
            return None;
        };
        offset += cipher_suites_len;

        // Compression methods
        if offset >= payload.len() {
            return None;
        }
        let comp_len = payload[offset] as usize;
        offset += 1 + comp_len;

        // Extensions
        let mut server_name = None;
        let mut extension_types = Vec::new();
        let mut elliptic_curves = Vec::new();
        let mut ec_point_formats = Vec::new();

        if offset + 2 <= payload.len() {
            let ext_len = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
            offset += 2;

            let ext_end = (offset + ext_len).min(payload.len());

            while offset + 4 <= ext_end {
                let ext_type = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
                let ext_data_len = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]) as usize;
                offset += 4;

                extension_types.push(ext_type);

                if ext_type == 0 && ext_data_len > 0 && offset + ext_data_len <= ext_end {
                    // Server Name Indication
                    let sni_data = &payload[offset..offset + ext_data_len];
                    if sni_data.len() > 5 {
                        let name_len = u16::from_be_bytes([sni_data[3], sni_data[4]]) as usize;
                        if 5 + name_len <= sni_data.len() {
                            server_name = String::from_utf8(sni_data[5..5 + name_len].to_vec()).ok();
                        }
                    }
                } else if ext_type == 10 && offset + ext_data_len <= ext_end {
                    // Supported groups (elliptic curves)
                    let curves_data = &payload[offset..offset + ext_data_len];
                    if curves_data.len() >= 2 {
                        let curves_len = u16::from_be_bytes([curves_data[0], curves_data[1]]) as usize;
                        for i in (2..2 + curves_len).step_by(2) {
                            if i + 1 < curves_data.len() {
                                let curve = u16::from_be_bytes([curves_data[i], curves_data[i + 1]]);
                                elliptic_curves.push(curve);
                            }
                        }
                    }
                } else if ext_type == 11 && offset + ext_data_len <= ext_end {
                    // EC point formats
                    let formats_data = &payload[offset..offset + ext_data_len];
                    if !formats_data.is_empty() {
                        let formats_len = formats_data[0] as usize;
                        for i in 1..=formats_len {
                            if i < formats_data.len() {
                                ec_point_formats.push(formats_data[i]);
                            }
                        }
                    }
                }

                offset += ext_data_len;
            }
        }

        // Calculate JA3
        let (ja3_hash, ja3_string) = self.calculate_ja3(
            version,
            cipher_suites_data,
            &extension_types,
            &elliptic_curves,
            &ec_point_formats,
        );

        Some(TlsConnection {
            id: uuid::Uuid::new_v4().to_string(),
            session_id: session_id.to_string(),
            version: tls_version,
            cipher_suite: String::new(), // Set in Server Hello
            server_name,
            certificate_chain: Vec::new(),
            ja3_hash,
            ja3_string,
            ja3s_hash: None,
            ja3s_string: None,
            is_self_signed: false,
            is_expired: false,
            is_suspicious: false,
        })
    }

    /// Parse TLS Server Hello
    fn parse_server_hello(&self, connection: &mut TlsConnection, payload: &[u8]) {
        if payload.len() < 39 {
            return;
        }

        // Skip handshake header
        let mut offset = 4;

        // Version
        let version = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        offset += 2;

        connection.version = match version {
            0x0300 => TlsVersion::Ssl30,
            0x0301 => TlsVersion::Tls10,
            0x0302 => TlsVersion::Tls11,
            0x0303 => TlsVersion::Tls12,
            0x0304 => TlsVersion::Tls13,
            _ => TlsVersion::Unknown,
        };

        // Skip random
        offset += 32;

        // Session ID
        if offset >= payload.len() {
            return;
        }
        let session_id_len = payload[offset] as usize;
        offset += 1 + session_id_len;

        // Cipher suite
        if offset + 2 > payload.len() {
            return;
        }
        let cipher = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        connection.cipher_suite = self.cipher_suite_name(cipher);
        offset += 2;

        // Compression method
        offset += 1;

        // Extensions for JA3S
        let mut extension_types = Vec::new();

        if offset + 2 <= payload.len() {
            let ext_len = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
            offset += 2;

            let ext_end = (offset + ext_len).min(payload.len());

            while offset + 4 <= ext_end {
                let ext_type = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
                let ext_data_len = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]) as usize;
                extension_types.push(ext_type);
                offset += 4 + ext_data_len;
            }
        }

        // Calculate JA3S
        let (ja3s_hash, ja3s_string) = self.calculate_ja3s(version, cipher, &extension_types);
        connection.ja3s_hash = Some(ja3s_hash);
        connection.ja3s_string = Some(ja3s_string);

        // Check for weak TLS
        if matches!(connection.version, TlsVersion::Ssl30 | TlsVersion::Tls10 | TlsVersion::Tls11) {
            connection.is_suspicious = true;
        }
    }

    /// Parse TLS Server Hello by index (to avoid borrow conflicts)
    fn parse_server_hello_by_index(&mut self, idx: usize, payload: &[u8]) {
        if payload.len() < 39 {
            return;
        }

        // Skip handshake header
        let mut offset = 4;

        // Version
        let version = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        offset += 2;

        let tls_version = match version {
            0x0300 => TlsVersion::Ssl30,
            0x0301 => TlsVersion::Tls10,
            0x0302 => TlsVersion::Tls11,
            0x0303 => TlsVersion::Tls12,
            0x0304 => TlsVersion::Tls13,
            _ => TlsVersion::Unknown,
        };

        // Skip random
        offset += 32;

        // Session ID
        if offset >= payload.len() {
            return;
        }
        let session_id_len = payload[offset] as usize;
        offset += 1 + session_id_len;

        // Cipher suite
        if offset + 2 > payload.len() {
            return;
        }
        let cipher = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let cipher_name = self.cipher_suite_name(cipher);
        offset += 2;

        // Compression method
        offset += 1;

        // Extensions for JA3S
        let mut extension_types = Vec::new();

        if offset + 2 <= payload.len() {
            let ext_len = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
            offset += 2;

            let ext_end = (offset + ext_len).min(payload.len());

            while offset + 4 <= ext_end {
                let ext_type = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
                let ext_data_len = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]) as usize;
                extension_types.push(ext_type);
                offset += 4 + ext_data_len;
            }
        }

        // Calculate JA3S
        let (ja3s_hash, ja3s_string) = self.calculate_ja3s(version, cipher, &extension_types);

        // Now update the connection
        let connection = &mut self.tls_connections[idx];
        connection.version = tls_version;
        connection.cipher_suite = cipher_name;
        connection.ja3s_hash = Some(ja3s_hash);
        connection.ja3s_string = Some(ja3s_string);

        // Check for weak TLS
        if matches!(connection.version, TlsVersion::Ssl30 | TlsVersion::Tls10 | TlsVersion::Tls11) {
            connection.is_suspicious = true;
        }
    }

    /// Calculate JA3 fingerprint
    fn calculate_ja3(
        &self,
        version: u16,
        cipher_suites: &[u8],
        extensions: &[u16],
        curves: &[u16],
        ec_formats: &[u8],
    ) -> (String, String) {
        // Extract cipher suite values
        let mut ciphers = Vec::new();
        for i in (0..cipher_suites.len()).step_by(2) {
            let cipher = u16::from_be_bytes([cipher_suites[i], cipher_suites[i + 1]]);
            // Skip GREASE values
            if !self.is_grease(cipher) {
                ciphers.push(cipher.to_string());
            }
        }

        // Filter extensions
        let ext_str: Vec<String> = extensions.iter()
            .filter(|e| !self.is_grease(**e))
            .map(|e| e.to_string())
            .collect();

        // Filter curves
        let curves_str: Vec<String> = curves.iter()
            .filter(|c| !self.is_grease(**c))
            .map(|c| c.to_string())
            .collect();

        // EC point formats
        let ec_str: Vec<String> = ec_formats.iter()
            .map(|f| f.to_string())
            .collect();

        let ja3_string = format!("{},{},{},{},{}",
            version,
            ciphers.join("-"),
            ext_str.join("-"),
            curves_str.join("-"),
            ec_str.join("-")
        );

        let mut hasher = Md5::new();
        Md5Digest::update(&mut hasher, ja3_string.as_bytes());
        let ja3_hash = format!("{:x}", hasher.finalize());

        (ja3_hash, ja3_string)
    }

    /// Calculate JA3S fingerprint
    fn calculate_ja3s(&self, version: u16, cipher: u16, extensions: &[u16]) -> (String, String) {
        let ext_str: Vec<String> = extensions.iter()
            .filter(|e| !self.is_grease(**e))
            .map(|e| e.to_string())
            .collect();

        let ja3s_string = format!("{},{},{}",
            version,
            cipher,
            ext_str.join("-")
        );

        let mut hasher = Md5::new();
        Md5Digest::update(&mut hasher, ja3s_string.as_bytes());
        let ja3s_hash = format!("{:x}", hasher.finalize());

        (ja3s_hash, ja3s_string)
    }

    /// Check if value is GREASE
    fn is_grease(&self, value: u16) -> bool {
        let grease_values = [
            0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
            0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
        ];
        grease_values.contains(&value)
    }

    /// Get cipher suite name
    fn cipher_suite_name(&self, cipher: u16) -> String {
        match cipher {
            0x1301 => "TLS_AES_128_GCM_SHA256".to_string(),
            0x1302 => "TLS_AES_256_GCM_SHA384".to_string(),
            0x1303 => "TLS_CHACHA20_POLY1305_SHA256".to_string(),
            0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".to_string(),
            0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".to_string(),
            0xc02b => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".to_string(),
            0xc02c => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384".to_string(),
            0xcca8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256".to_string(),
            0xcca9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256".to_string(),
            0x009c => "TLS_RSA_WITH_AES_128_GCM_SHA256".to_string(),
            0x009d => "TLS_RSA_WITH_AES_256_GCM_SHA384".to_string(),
            _ => format!("0x{:04x}", cipher),
        }
    }

    /// Check for protocol anomalies
    fn check_anomalies(
        &mut self,
        pcap_id: &str,
        session_id: &str,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        port: u16,
        payload: &[u8],
        timestamp: DateTime<Utc>,
    ) {
        // Check for data on unusual ports
        let common_ports = [
            20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 123, 143, 161, 162, 389, 443,
            445, 465, 587, 636, 993, 995, 1433, 1521, 3306, 3389, 5432, 5672, 6379,
            8080, 8443, 27017,
        ];

        if !common_ports.contains(&port) && payload.len() > 100 {
            // Check for HTTP on non-standard port
            let text = String::from_utf8_lossy(&payload[..payload.len().min(20)]);
            if text.starts_with("HTTP/") || text.starts_with("GET ") || text.starts_with("POST ") {
                self.anomalies.push(ProtocolAnomaly {
                    id: uuid::Uuid::new_v4().to_string(),
                    pcap_id: pcap_id.to_string(),
                    session_id: Some(session_id.to_string()),
                    timestamp,
                    anomaly_type: AnomalyType::UnusualPort,
                    protocol: "HTTP".to_string(),
                    description: format!("HTTP traffic on non-standard port {}", port),
                    severity: IdsSeverity::Low,
                    src_ip,
                    dst_ip,
                });
            }
        }

        // Check for potential tunneling
        if port == 53 && payload.len() > 200 {
            self.anomalies.push(ProtocolAnomaly {
                id: uuid::Uuid::new_v4().to_string(),
                pcap_id: pcap_id.to_string(),
                session_id: Some(session_id.to_string()),
                timestamp,
                anomaly_type: AnomalyType::TunnelingDetected,
                protocol: "DNS".to_string(),
                description: "Large DNS packet - possible DNS tunneling".to_string(),
                severity: IdsSeverity::Medium,
                src_ip,
                dst_ip,
            });
        }

        // Check for potential data exfiltration
        if payload.len() > 10000 {
            // Check entropy for encrypted data
            let entropy = self.calculate_entropy(payload);
            if entropy > 7.5 {
                self.anomalies.push(ProtocolAnomaly {
                    id: uuid::Uuid::new_v4().to_string(),
                    pcap_id: pcap_id.to_string(),
                    session_id: Some(session_id.to_string()),
                    timestamp,
                    anomaly_type: AnomalyType::DataExfiltration,
                    protocol: format!("Port {}", port),
                    description: format!("Large encrypted payload ({} bytes, entropy {:.2})", payload.len(), entropy),
                    severity: IdsSeverity::Medium,
                    src_ip,
                    dst_ip,
                });
            }
        }
    }

    /// Calculate Shannon entropy
    fn calculate_entropy(&self, data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut counts = [0u64; 256];
        for byte in data {
            counts[*byte as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for count in counts.iter() {
            if *count > 0 {
                let p = *count as f64 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// Get HTTP transactions
    pub fn get_http_transactions(&self) -> &[HttpTransaction] {
        &self.http_transactions
    }

    /// Get DNS queries
    pub fn get_dns_queries(&self) -> &[DnsQuery] {
        &self.dns_queries
    }

    /// Get TLS connections
    pub fn get_tls_connections(&self) -> &[TlsConnection] {
        &self.tls_connections
    }

    /// Get protocol anomalies
    pub fn get_anomalies(&self) -> &[ProtocolAnomaly] {
        &self.anomalies
    }
}

impl Default for ProtocolAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
