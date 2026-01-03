//! File Carving Module
//!
//! Extract files and credentials from network captures.

use anyhow::{Result, Context};
use std::path::Path;

/// File signature for carving
struct FileSignature {
    name: &'static str,
    extension: &'static str,
    header: &'static [u8],
    footer: Option<&'static [u8]>,
    max_size: usize,
}

/// Known file signatures
const FILE_SIGNATURES: &[FileSignature] = &[
    FileSignature {
        name: "JPEG",
        extension: "jpg",
        header: b"\xFF\xD8\xFF",
        footer: Some(b"\xFF\xD9"),
        max_size: 50_000_000,
    },
    FileSignature {
        name: "PNG",
        extension: "png",
        header: b"\x89PNG\r\n\x1a\n",
        footer: Some(b"\x49\x45\x4E\x44\xAE\x42\x60\x82"),
        max_size: 50_000_000,
    },
    FileSignature {
        name: "GIF",
        extension: "gif",
        header: b"GIF8",
        footer: Some(b"\x00\x3B"),
        max_size: 20_000_000,
    },
    FileSignature {
        name: "PDF",
        extension: "pdf",
        header: b"%PDF",
        footer: Some(b"%%EOF"),
        max_size: 100_000_000,
    },
    FileSignature {
        name: "ZIP",
        extension: "zip",
        header: b"PK\x03\x04",
        footer: None,
        max_size: 500_000_000,
    },
    FileSignature {
        name: "RAR",
        extension: "rar",
        header: b"Rar!\x1a\x07",
        footer: None,
        max_size: 500_000_000,
    },
    FileSignature {
        name: "7z",
        extension: "7z",
        header: b"7z\xBC\xAF\x27\x1C",
        footer: None,
        max_size: 500_000_000,
    },
    FileSignature {
        name: "GZIP",
        extension: "gz",
        header: b"\x1f\x8b\x08",
        footer: None,
        max_size: 100_000_000,
    },
    FileSignature {
        name: "PE_EXE",
        extension: "exe",
        header: b"MZ",
        footer: None,
        max_size: 100_000_000,
    },
    FileSignature {
        name: "ELF",
        extension: "elf",
        header: b"\x7fELF",
        footer: None,
        max_size: 100_000_000,
    },
    FileSignature {
        name: "DOC",
        extension: "doc",
        header: b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1",
        footer: None,
        max_size: 100_000_000,
    },
    FileSignature {
        name: "DOCX",
        extension: "docx",
        header: b"PK\x03\x04\x14\x00\x06\x00",
        footer: None,
        max_size: 100_000_000,
    },
];

/// Carved file information
#[derive(Debug, Clone)]
pub struct CarvedFile {
    pub file_type: String,
    pub extension: String,
    pub offset: usize,
    pub size: usize,
    pub output_path: String,
    pub sha256_hash: String,
}

/// Carve files from PCAP capture
pub async fn carve_files_from_pcap(pcap_path: &str, output_dir: &str) -> Result<Vec<String>> {
    let mut extracted = Vec::new();

    // Ensure output directory exists
    tokio::fs::create_dir_all(output_dir).await?;

    // Read PCAP file
    let path = Path::new(pcap_path);
    if !path.exists() {
        return Ok(extracted);
    }

    let content = tokio::fs::read(pcap_path).await
        .context("Failed to read PCAP file")?;

    // Skip PCAP header (24 bytes for standard PCAP)
    if content.len() < 24 {
        return Ok(extracted);
    }

    // Carve files from the raw content
    let carved = carve_files_from_bytes(&content[24..], output_dir).await?;
    extracted.extend(carved.iter().map(|c| c.output_path.clone()));

    Ok(extracted)
}

/// Carve files from raw bytes
async fn carve_files_from_bytes(data: &[u8], output_dir: &str) -> Result<Vec<CarvedFile>> {
    let mut carved_files = Vec::new();
    let mut file_counter = 0;

    for sig in FILE_SIGNATURES {
        let mut offset = 0;

        while offset < data.len() {
            // Find header
            if let Some(header_pos) = find_pattern(&data[offset..], sig.header) {
                let abs_pos = offset + header_pos;

                // Try to find footer or estimate size
                let (file_size, end_found) = if let Some(footer) = sig.footer {
                    if let Some(footer_pos) = find_pattern(&data[abs_pos..], footer) {
                        let size = footer_pos + footer.len();
                        if size <= sig.max_size {
                            (size, true)
                        } else {
                            (sig.max_size, false)
                        }
                    } else {
                        // No footer found, use max or remaining data
                        let remaining = data.len() - abs_pos;
                        (std::cmp::min(remaining, sig.max_size), false)
                    }
                } else {
                    // No footer defined, use heuristics
                    let remaining = data.len() - abs_pos;
                    (std::cmp::min(remaining, sig.max_size), false)
                };

                // Only extract if reasonable size
                if file_size >= 100 && abs_pos + file_size <= data.len() {
                    let file_data = &data[abs_pos..abs_pos + file_size];

                    // Calculate hash
                    use sha2::{Sha256, Digest};
                    let mut hasher = Sha256::new();
                    hasher.update(file_data);
                    let hash = format!("{:x}", hasher.finalize());

                    // Generate output filename
                    let output_filename = format!(
                        "carved_{:04}_{}.{}",
                        file_counter,
                        &hash[..8],
                        sig.extension
                    );
                    let output_path = format!("{}/{}", output_dir, output_filename);

                    // Write file
                    tokio::fs::write(&output_path, file_data).await?;

                    carved_files.push(CarvedFile {
                        file_type: sig.name.to_string(),
                        extension: sig.extension.to_string(),
                        offset: abs_pos,
                        size: file_size,
                        output_path,
                        sha256_hash: hash,
                    });

                    file_counter += 1;
                }

                // Move past this occurrence
                offset = abs_pos + std::cmp::max(1, file_size);
            } else {
                break; // No more occurrences of this signature
            }
        }
    }

    Ok(carved_files)
}

/// Find pattern in data
fn find_pattern(data: &[u8], pattern: &[u8]) -> Option<usize> {
    data.windows(pattern.len())
        .position(|window| window == pattern)
}

/// Extracted credential from network traffic
#[derive(Debug, Clone)]
pub struct ExtractedCredential {
    pub protocol: String,
    pub username: String,
    pub credential: String, // Could be password, hash, or token
    pub source_ip: Option<String>,
    pub dest_ip: Option<String>,
    pub timestamp: Option<i64>,
}

/// Extract credentials from PCAP
pub fn extract_credentials_from_pcap(pcap_path: &str) -> Result<Vec<(String, String, String)>> {
    let mut credentials = Vec::new();

    // Read file synchronously for this function
    let path = Path::new(pcap_path);
    if !path.exists() {
        return Ok(credentials);
    }

    let content = std::fs::read(pcap_path)
        .context("Failed to read PCAP file")?;

    // Skip PCAP header
    if content.len() < 24 {
        return Ok(credentials);
    }

    // Extract credentials from payload data
    let extracted = extract_credentials_from_bytes(&content[24..]);
    credentials.extend(extracted);

    Ok(credentials)
}

/// Extract credentials from raw bytes
fn extract_credentials_from_bytes(data: &[u8]) -> Vec<(String, String, String)> {
    let mut credentials = Vec::new();
    let text = String::from_utf8_lossy(data);

    // HTTP Basic Authentication
    let basic_auth_pattern = regex::Regex::new(r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)")
        .unwrap();
    for cap in basic_auth_pattern.captures_iter(&text) {
        if let Some(encoded) = cap.get(1) {
            if let Ok(decoded) = base64_decode(encoded.as_str()) {
                if let Some(pos) = decoded.find(':') {
                    let username = decoded[..pos].to_string();
                    let password = decoded[pos + 1..].to_string();
                    credentials.push(("HTTP Basic".to_string(), username, password));
                }
            }
        }
    }

    // FTP credentials
    let ftp_user_pattern = regex::Regex::new(r"USER\s+(\S+)\r?\n").unwrap();
    let ftp_pass_pattern = regex::Regex::new(r"PASS\s+(\S+)\r?\n").unwrap();

    let users: Vec<_> = ftp_user_pattern.captures_iter(&text)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
        .collect();
    let passes: Vec<_> = ftp_pass_pattern.captures_iter(&text)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
        .collect();

    for (i, user) in users.iter().enumerate() {
        let pass = passes.get(i).cloned().unwrap_or_default();
        credentials.push(("FTP".to_string(), user.clone(), pass));
    }

    // SMTP credentials (LOGIN mechanism)
    let smtp_login_pattern = regex::Regex::new(r"AUTH LOGIN\r?\n([A-Za-z0-9+/=]+)\r?\n([A-Za-z0-9+/=]+)")
        .unwrap();
    for cap in smtp_login_pattern.captures_iter(&text) {
        if let (Some(user_b64), Some(pass_b64)) = (cap.get(1), cap.get(2)) {
            if let (Ok(user), Ok(pass)) = (
                base64_decode(user_b64.as_str()),
                base64_decode(pass_b64.as_str())
            ) {
                credentials.push(("SMTP".to_string(), user, pass));
            }
        }
    }

    // POP3 credentials
    let pop3_user_pattern = regex::Regex::new(r"USER\s+(\S+)\r?\n").unwrap();
    let pop3_pass_pattern = regex::Regex::new(r"PASS\s+(\S+)\r?\n").unwrap();

    // Telnet credentials (look for login: and Password: prompts)
    let telnet_login_pattern = regex::Regex::new(r"login:\s*(\S+)").unwrap();
    let telnet_pass_pattern = regex::Regex::new(r"[Pp]assword:\s*(\S+)").unwrap();

    for cap in telnet_login_pattern.captures_iter(&text) {
        if let Some(user) = cap.get(1) {
            // Try to find corresponding password
            let pass = telnet_pass_pattern.captures(&text)
                .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
                .unwrap_or_default();
            credentials.push(("Telnet".to_string(), user.as_str().to_string(), pass));
        }
    }

    // HTTP Form credentials (look for common form field patterns)
    let form_patterns = [
        regex::Regex::new(r"username=([^&\s]+)").unwrap(),
        regex::Regex::new(r"user=([^&\s]+)").unwrap(),
        regex::Regex::new(r"login=([^&\s]+)").unwrap(),
        regex::Regex::new(r"email=([^&\s]+)").unwrap(),
    ];
    let password_patterns = [
        regex::Regex::new(r"password=([^&\s]+)").unwrap(),
        regex::Regex::new(r"passwd=([^&\s]+)").unwrap(),
        regex::Regex::new(r"pass=([^&\s]+)").unwrap(),
        regex::Regex::new(r"pwd=([^&\s]+)").unwrap(),
    ];

    for user_pattern in &form_patterns {
        for cap in user_pattern.captures_iter(&text) {
            if let Some(user) = cap.get(1) {
                // Try to find password nearby
                for pass_pattern in &password_patterns {
                    if let Some(pass_cap) = pass_pattern.captures(&text) {
                        if let Some(pass) = pass_cap.get(1) {
                            let decoded_user = url_decode(user.as_str());
                            let decoded_pass = url_decode(pass.as_str());
                            credentials.push(("HTTP Form".to_string(), decoded_user, decoded_pass));
                            break;
                        }
                    }
                }
            }
        }
    }

    // LDAP bind credentials
    let ldap_pattern = regex::Regex::new(r"cn=([^,]+),.*?password=([^\s]+)").unwrap();
    for cap in ldap_pattern.captures_iter(&text) {
        if let (Some(user), Some(pass)) = (cap.get(1), cap.get(2)) {
            credentials.push(("LDAP".to_string(), user.as_str().to_string(), pass.as_str().to_string()));
        }
    }

    // MySQL authentication (look for mysql_native_password packets)
    // This is a simplified check - real implementation would parse the protocol
    if text.contains("mysql_native_password") {
        credentials.push(("MySQL".to_string(), "[detected]".to_string(), "[authentication observed]".to_string()));
    }

    // Deduplicate
    credentials.sort();
    credentials.dedup();

    credentials
}

/// Base64 decode helper
fn base64_decode(input: &str) -> Result<String, ()> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(input)
        .map_err(|_| ())
        .and_then(|bytes| String::from_utf8(bytes).map_err(|_| ()))
}

/// URL decode helper
fn url_decode(input: &str) -> String {
    let mut result = String::new();
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                result.push(byte as char);
            } else {
                result.push('%');
                result.push_str(&hex);
            }
        } else if c == '+' {
            result.push(' ');
        } else {
            result.push(c);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_pattern() {
        let data = b"hello world";
        assert_eq!(find_pattern(data, b"world"), Some(6));
        assert_eq!(find_pattern(data, b"foo"), None);
    }

    #[test]
    fn test_url_decode() {
        assert_eq!(url_decode("hello%20world"), "hello world");
        assert_eq!(url_decode("test%2Bvalue"), "test+value");
        assert_eq!(url_decode("normal"), "normal");
    }

    #[test]
    fn test_base64_decode() {
        assert_eq!(base64_decode("aGVsbG8="), Ok("hello".to_string()));
        assert_eq!(base64_decode("d29ybGQ="), Ok("world".to_string()));
    }

    #[test]
    fn test_extract_credentials_basic() {
        let data = b"Authorization: Basic dXNlcjpwYXNzd29yZA==\r\n";
        let creds = extract_credentials_from_bytes(data);
        assert!(!creds.is_empty());
        assert_eq!(creds[0].0, "HTTP Basic");
        assert_eq!(creds[0].1, "user");
        assert_eq!(creds[0].2, "password");
    }

    #[test]
    fn test_extract_ftp_credentials() {
        let data = b"USER admin\r\nPASS secret123\r\n";
        let creds = extract_credentials_from_bytes(data);
        assert!(!creds.is_empty());
        assert_eq!(creds[0].0, "FTP");
        assert_eq!(creds[0].1, "admin");
    }
}
