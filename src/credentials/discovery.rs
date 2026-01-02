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
        // Passwords are encrypted with DPAPI (Windows) or keychain (macOS)

        debug!("Extracting Chrome credentials from {}", profile_path);

        // Placeholder - actual implementation would:
        // 1. Open Login Data SQLite database
        // 2. Query logins table
        // 3. Decrypt passwords using DPAPI/keychain

        Ok(Vec::new())
    }

    fn extract_firefox_credentials(&self, profile_path: &str) -> Result<Vec<BrowserCred>> {
        // Firefox stores credentials in logins.json (encrypted with key4.db)

        debug!("Extracting Firefox credentials from {}", profile_path);

        // Placeholder - actual implementation would:
        // 1. Read logins.json
        // 2. Extract master key from key4.db
        // 3. Decrypt passwords

        Ok(Vec::new())
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
