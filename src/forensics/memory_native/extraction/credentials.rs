//! Credential extraction from memory
//!
//! Extract passwords, hashes, and authentication tokens from memory dumps.

use anyhow::Result;

use super::CredentialArtifact;
use crate::forensics::memory_native::dump_parser::ParsedDump;
use crate::forensics::memory_native::types::ProcessInfo;

/// Extract all credentials from memory
pub fn extract_all_credentials(
    dump: &ParsedDump,
    processes: &[ProcessInfo],
) -> Result<Vec<CredentialArtifact>> {
    let mut credentials = Vec::new();

    // Extract from specific processes
    for process in processes {
        let name_lower = process.name.to_lowercase();

        if name_lower == "lsass.exe" {
            // LSASS contains Windows credentials
            let lsass_creds = extract_lsass_credentials(dump, process)?;
            credentials.extend(lsass_creds);
        }

        if name_lower.contains("chrome") || name_lower.contains("msedge") {
            // Browser credentials
            let browser_creds = extract_browser_credentials(dump, process)?;
            credentials.extend(browser_creds);
        }

        if name_lower.contains("keepass") || name_lower.contains("1password") {
            // Password manager
            let pm_creds = extract_password_manager(dump, process)?;
            credentials.extend(pm_creds);
        }
    }

    // Generic credential extraction
    let generic = extract_generic_credentials(dump)?;
    credentials.extend(generic);

    // SSH keys
    let ssh = extract_ssh_keys(dump)?;
    credentials.extend(ssh);

    // API keys and tokens
    let tokens = extract_api_tokens(dump)?;
    credentials.extend(tokens);

    Ok(credentials)
}

/// Extract credentials from LSASS process
fn extract_lsass_credentials(dump: &ParsedDump, _process: &ProcessInfo) -> Result<Vec<CredentialArtifact>> {
    let mut credentials = Vec::new();

    // Search for credential patterns in LSASS memory
    // This is simplified - real extraction requires understanding SSP structures

    // Look for NTLM hash patterns (32 hex chars)
    let hex_pattern: Vec<u8> = (0..32).map(|_| 0x00).collect(); // Placeholder

    // Search for primary credential list signature
    let primary_sigs: &[&[u8]] = &[
        b"\x03\x00\x00\x00\x00\x00\x00\x00", // Primary credential marker
        b"Primary",
    ];

    for sig in primary_sigs {
        let matches = dump.search_pattern(sig);

        for &offset in matches.iter().take(100) {
            // Try to parse credential structure
            if let Some(cred) = try_parse_lsass_credential(dump, offset) {
                credentials.push(cred);
            }
        }
    }

    // Search for Kerberos tickets
    let krb_matches = dump.search_pattern(b"krbtgt");
    for &offset in krb_matches.iter().take(50) {
        credentials.push(CredentialArtifact {
            source: "LSASS".to_string(),
            cred_type: "Kerberos".to_string(),
            username: None,
            domain: None,
            value: format!("Kerberos ticket reference at {:#x}", offset),
            is_hash: false,
            process: Some("lsass.exe".to_string()),
            context: Some("TGT/TGS ticket".to_string()),
        });
    }

    Ok(credentials)
}

/// Try to parse an LSASS credential structure
fn try_parse_lsass_credential(dump: &ParsedDump, offset: u64) -> Option<CredentialArtifact> {
    let data = dump.read_bytes(offset, 256)?;

    // Look for username/domain strings
    // Credentials are typically in UNICODE

    // This is a placeholder - real parsing requires detailed structure knowledge
    let _ = data;

    None
}

/// Extract credentials from browser processes
fn extract_browser_credentials(dump: &ParsedDump, process: &ProcessInfo) -> Result<Vec<CredentialArtifact>> {
    let mut credentials = Vec::new();

    // Chrome/Edge store credentials in memory during session
    // Look for login form patterns

    let login_patterns: &[&[u8]] = &[
        b"password\":",
        b"passwd\":",
        b"\"password\"",
        b"login_password",
    ];

    for pattern in login_patterns {
        let matches = dump.search_pattern(pattern);

        for &offset in matches.iter().take(100) {
            if let Some(context) = dump.read_bytes(offset.saturating_sub(64), 256) {
                // Try to extract username and password from JSON-like structure
                if let Some(cred) = parse_json_credential(&context) {
                    credentials.push(CredentialArtifact {
                        source: process.name.clone(),
                        cred_type: "Web Password".to_string(),
                        username: cred.username,
                        domain: None,
                        value: cred.password,
                        is_hash: false,
                        process: Some(process.name.clone()),
                        context: cred.url,
                    });
                }
            }
        }
    }

    Ok(credentials)
}

/// Parsed JSON credential
struct ParsedJsonCredential {
    username: Option<String>,
    password: String,
    url: Option<String>,
}

/// Parse credential from JSON-like structure
fn parse_json_credential(data: &[u8]) -> Option<ParsedJsonCredential> {
    let text = String::from_utf8_lossy(data);

    // Very basic JSON parsing for common patterns
    let password = extract_json_value(&text, "password")?;

    let username = extract_json_value(&text, "username")
        .or_else(|| extract_json_value(&text, "email"))
        .or_else(|| extract_json_value(&text, "user"));

    let url = extract_json_value(&text, "url")
        .or_else(|| extract_json_value(&text, "origin"));

    // Filter out obvious non-credentials
    if password.len() < 4 || password.len() > 64 {
        return None;
    }

    Some(ParsedJsonCredential {
        username,
        password,
        url,
    })
}

/// Extract a value from JSON-like text
fn extract_json_value(text: &str, key: &str) -> Option<String> {
    // Find "key": "value" or "key":"value"
    let key_pattern = format!("\"{}\"", key);
    let pos = text.find(&key_pattern)?;

    let after_key = &text[pos + key_pattern.len()..];
    let colon_pos = after_key.find(':')?;
    let after_colon = after_key[colon_pos + 1..].trim_start();

    if after_colon.starts_with('"') {
        let value_start = 1;
        let value_end = after_colon[value_start..].find('"')?;
        Some(after_colon[value_start..value_start + value_end].to_string())
    } else {
        None
    }
}

/// Extract from password manager processes
fn extract_password_manager(dump: &ParsedDump, process: &ProcessInfo) -> Result<Vec<CredentialArtifact>> {
    let mut credentials = Vec::new();

    // Password managers keep some data in memory
    // Look for entry markers

    let pm_patterns: &[&[u8]] = &[
        b"<Title>",     // KeePass XML format
        b"\"title\":",  // JSON format
        b"password-field",
    ];

    for pattern in pm_patterns {
        let matches = dump.search_pattern(pattern);

        for &offset in matches.iter().take(50) {
            credentials.push(CredentialArtifact {
                source: process.name.clone(),
                cred_type: "Password Manager Entry".to_string(),
                username: None,
                domain: None,
                value: format!("Entry reference at {:#x}", offset),
                is_hash: false,
                process: Some(process.name.clone()),
                context: None,
            });
        }
    }

    Ok(credentials)
}

/// Extract generic credentials from memory
fn extract_generic_credentials(dump: &ParsedDump) -> Result<Vec<CredentialArtifact>> {
    let mut credentials = Vec::new();

    // Common credential patterns
    let patterns = [
        (b"password=".as_slice(), "URL Parameter"),
        (b"passwd=".as_slice(), "URL Parameter"),
        (b"pwd=".as_slice(), "URL Parameter"),
        (b"Authorization: Basic ".as_slice(), "HTTP Basic Auth"),
        (b"Authorization: Bearer ".as_slice(), "Bearer Token"),
    ];

    for (pattern, cred_type) in &patterns {
        let matches = dump.search_pattern(*pattern);

        for &offset in matches.iter().take(100) {
            if let Some(data) = dump.read_bytes(offset, 128) {
                let start = pattern.len();
                let end = data[start..].iter()
                    .position(|&b| b == 0 || b == b'&' || b == b'\n' || b == b'\r' || b == b' ')
                    .unwrap_or(data.len() - start);

                let value = String::from_utf8_lossy(&data[start..start + end]);

                if value.len() >= 4 && value.len() <= 128 {
                    credentials.push(CredentialArtifact {
                        source: "Generic".to_string(),
                        cred_type: cred_type.to_string(),
                        username: None,
                        domain: None,
                        value: value.to_string(),
                        is_hash: false,
                        process: None,
                        context: None,
                    });
                }
            }
        }
    }

    Ok(credentials)
}

/// Extract SSH keys from memory
fn extract_ssh_keys(dump: &ParsedDump) -> Result<Vec<CredentialArtifact>> {
    let mut credentials = Vec::new();

    // SSH private key patterns
    let ssh_patterns: &[&[u8]] = &[
        b"-----BEGIN RSA PRIVATE KEY-----",
        b"-----BEGIN OPENSSH PRIVATE KEY-----",
        b"-----BEGIN EC PRIVATE KEY-----",
        b"-----BEGIN DSA PRIVATE KEY-----",
    ];

    for pattern in ssh_patterns {
        let matches = dump.search_pattern(pattern);

        for &offset in matches.iter().take(10) {
            if let Some(data) = dump.read_bytes(offset, 4096) {
                // Find the end marker
                let end_marker = b"-----END";
                if let Some(end) = data.windows(8).position(|w| w == end_marker) {
                    let key_end = data[end..].iter().position(|&b| b == b'-')
                        .map(|p| end + p + 5)
                        .unwrap_or(end + 50);

                    let key = String::from_utf8_lossy(&data[..key_end.min(data.len())]);

                    credentials.push(CredentialArtifact {
                        source: "Memory".to_string(),
                        cred_type: "SSH Private Key".to_string(),
                        username: None,
                        domain: None,
                        value: format!("[SSH Key at {:#x}, {} bytes]", offset, key.len()),
                        is_hash: false,
                        process: None,
                        context: Some("Private key extracted from memory".to_string()),
                    });
                }
            }
        }
    }

    Ok(credentials)
}

/// Extract API tokens and keys
fn extract_api_tokens(dump: &ParsedDump) -> Result<Vec<CredentialArtifact>> {
    let mut credentials = Vec::new();

    // Common API key patterns
    let api_patterns = [
        (b"aws_access_key_id".as_slice(), "AWS Access Key"),
        (b"aws_secret_access_key".as_slice(), "AWS Secret Key"),
        (b"AKIA".as_slice(), "AWS Key ID"),
        (b"AIza".as_slice(), "Google API Key"),
        (b"sk-".as_slice(), "OpenAI/Stripe Key"),
        (b"ghp_".as_slice(), "GitHub Token"),
        (b"glpat-".as_slice(), "GitLab Token"),
        (b"xox".as_slice(), "Slack Token"),
    ];

    for (pattern, key_type) in &api_patterns {
        let matches = dump.search_pattern(*pattern);

        for &offset in matches.iter().take(50) {
            if let Some(data) = dump.read_bytes(offset, 128) {
                // Extract the key value
                let end = data.iter()
                    .position(|&b| !b.is_ascii_alphanumeric() && b != b'-' && b != b'_')
                    .unwrap_or(data.len());

                let value = String::from_utf8_lossy(&data[..end]);

                if value.len() >= 16 && value.len() <= 100 {
                    credentials.push(CredentialArtifact {
                        source: "Memory".to_string(),
                        cred_type: key_type.to_string(),
                        username: None,
                        domain: None,
                        value: value.to_string(),
                        is_hash: false,
                        process: None,
                        context: None,
                    });
                }
            }
        }
    }

    Ok(credentials)
}
