//! Credential Extraction from Network Traffic
//!
//! Extracts credentials from captured network traffic:
//! - HTTP Basic/Digest/NTLM authentication
//! - FTP/SMTP/POP3/IMAP credentials
//! - Kerberos tickets (AS-REQ, AS-REP, TGS-REQ)
//! - NTLM challenges and responses
//! - LDAP bind credentials
//! - Database connection strings

use base64::Engine;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::net::IpAddr;

/// Credential extracted from network traffic
#[derive(Debug, Clone)]
pub struct NetworkCredential {
    /// Unique identifier
    pub id: String,
    /// PCAP ID this was extracted from
    pub pcap_id: String,
    /// Session ID
    pub session_id: String,
    /// Source IP
    pub src_ip: IpAddr,
    /// Destination IP
    pub dst_ip: IpAddr,
    /// Destination port
    pub dst_port: u16,
    /// Credential type
    pub cred_type: NetworkCredType,
    /// Username/identity
    pub username: Option<String>,
    /// Domain (for Windows auth)
    pub domain: Option<String>,
    /// Password (if plaintext)
    pub password: Option<String>,
    /// Hash (if captured)
    pub hash: Option<String>,
    /// Hash type for cracking
    pub hash_type: Option<String>,
    /// Raw data for further analysis
    pub raw_data: Option<Vec<u8>>,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Type of network credential
#[derive(Debug, Clone, PartialEq)]
pub enum NetworkCredType {
    /// HTTP Basic authentication
    HttpBasic,
    /// HTTP Digest authentication
    HttpDigest,
    /// HTTP NTLM authentication
    HttpNtlm,
    /// FTP credentials
    Ftp,
    /// SMTP credentials
    Smtp,
    /// POP3 credentials
    Pop3,
    /// IMAP credentials
    Imap,
    /// Telnet credentials
    Telnet,
    /// Kerberos AS-REQ (pre-authentication)
    KerberosAsReq,
    /// Kerberos AS-REP (roastable)
    KerberosAsRep,
    /// Kerberos TGS-REQ (service ticket)
    KerberosTgsReq,
    /// NTLM Type 1 (negotiate)
    NtlmType1,
    /// NTLM Type 2 (challenge)
    NtlmType2,
    /// NTLM Type 3 (authenticate - contains hash)
    NtlmType3,
    /// LDAP simple bind
    LdapSimpleBind,
    /// LDAP SASL bind
    LdapSaslBind,
    /// MySQL native password
    MysqlNative,
    /// PostgreSQL MD5 password
    PostgresMd5,
    /// MSSQL TDS login
    MssqlTds,
    /// SMB session setup
    SmbSession,
    /// Other/Unknown
    Other,
}

impl NetworkCredType {
    pub fn name(&self) -> &str {
        match self {
            NetworkCredType::HttpBasic => "HTTP Basic",
            NetworkCredType::HttpDigest => "HTTP Digest",
            NetworkCredType::HttpNtlm => "HTTP NTLM",
            NetworkCredType::Ftp => "FTP",
            NetworkCredType::Smtp => "SMTP",
            NetworkCredType::Pop3 => "POP3",
            NetworkCredType::Imap => "IMAP",
            NetworkCredType::Telnet => "Telnet",
            NetworkCredType::KerberosAsReq => "Kerberos AS-REQ",
            NetworkCredType::KerberosAsRep => "Kerberos AS-REP",
            NetworkCredType::KerberosTgsReq => "Kerberos TGS-REQ",
            NetworkCredType::NtlmType1 => "NTLM Negotiate",
            NetworkCredType::NtlmType2 => "NTLM Challenge",
            NetworkCredType::NtlmType3 => "NTLM Authenticate",
            NetworkCredType::LdapSimpleBind => "LDAP Simple Bind",
            NetworkCredType::LdapSaslBind => "LDAP SASL Bind",
            NetworkCredType::MysqlNative => "MySQL Native",
            NetworkCredType::PostgresMd5 => "PostgreSQL MD5",
            NetworkCredType::MssqlTds => "MSSQL TDS",
            NetworkCredType::SmbSession => "SMB Session",
            NetworkCredType::Other => "Other",
        }
    }

    /// Check if this credential type can be cracked
    pub fn is_crackable(&self) -> bool {
        matches!(self,
            NetworkCredType::HttpDigest |
            NetworkCredType::HttpNtlm |
            NetworkCredType::KerberosAsRep |
            NetworkCredType::KerberosTgsReq |
            NetworkCredType::NtlmType3 |
            NetworkCredType::PostgresMd5 |
            NetworkCredType::MysqlNative
        )
    }

    /// Get hashcat mode for this credential type
    pub fn hashcat_mode(&self) -> Option<i32> {
        match self {
            NetworkCredType::NtlmType3 => Some(5600), // NetNTLMv2
            NetworkCredType::KerberosAsRep => Some(18200),
            NetworkCredType::KerberosTgsReq => Some(13100),
            NetworkCredType::HttpDigest => Some(11400),
            NetworkCredType::PostgresMd5 => Some(12),
            _ => None,
        }
    }
}

/// Credential extractor for network traffic
pub struct CredentialExtractor {
    /// Extracted credentials
    credentials: Vec<NetworkCredential>,
    /// NTLM challenge tracking (for matching Type2 with Type3)
    ntlm_challenges: HashMap<String, NtlmChallenge>,
    /// Configuration
    config: ExtractorConfig,
}

/// NTLM challenge for correlation
#[derive(Debug, Clone)]
struct NtlmChallenge {
    challenge: [u8; 8],
    timestamp: DateTime<Utc>,
    src_ip: IpAddr,
    dst_ip: IpAddr,
}

/// Extractor configuration
#[derive(Debug, Clone)]
pub struct ExtractorConfig {
    /// Extract cleartext credentials
    pub extract_cleartext: bool,
    /// Extract hashes
    pub extract_hashes: bool,
    /// Extract Kerberos tickets
    pub extract_kerberos: bool,
    /// Maximum credentials to store
    pub max_credentials: usize,
}

impl Default for ExtractorConfig {
    fn default() -> Self {
        Self {
            extract_cleartext: true,
            extract_hashes: true,
            extract_kerberos: true,
            max_credentials: 10000,
        }
    }
}

impl CredentialExtractor {
    /// Create new credential extractor
    pub fn new() -> Self {
        Self::with_config(ExtractorConfig::default())
    }

    /// Create with custom config
    pub fn with_config(config: ExtractorConfig) -> Self {
        Self {
            credentials: Vec::new(),
            ntlm_challenges: HashMap::new(),
            config,
        }
    }

    /// Analyze packet for credentials
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
        if self.credentials.len() >= self.config.max_credentials {
            return;
        }

        // Check by port
        match dst_port {
            80 | 8080 | 8000 | 8888 => {
                self.extract_http_credentials(pcap_id, session_id, src_ip, dst_ip, dst_port, payload, timestamp);
            }
            21 => {
                self.extract_ftp_credentials(pcap_id, session_id, src_ip, dst_ip, dst_port, payload, timestamp);
            }
            25 | 465 | 587 => {
                self.extract_smtp_credentials(pcap_id, session_id, src_ip, dst_ip, dst_port, payload, timestamp);
            }
            110 | 995 => {
                self.extract_pop3_credentials(pcap_id, session_id, src_ip, dst_ip, dst_port, payload, timestamp);
            }
            143 | 993 => {
                self.extract_imap_credentials(pcap_id, session_id, src_ip, dst_ip, dst_port, payload, timestamp);
            }
            23 => {
                self.extract_telnet_credentials(pcap_id, session_id, src_ip, dst_ip, dst_port, payload, timestamp);
            }
            88 => {
                if self.config.extract_kerberos {
                    self.extract_kerberos_data(pcap_id, session_id, src_ip, dst_ip, dst_port, payload, timestamp);
                }
            }
            389 | 636 => {
                self.extract_ldap_credentials(pcap_id, session_id, src_ip, dst_ip, dst_port, payload, timestamp);
            }
            445 | 139 => {
                self.extract_smb_credentials(pcap_id, session_id, src_ip, dst_ip, dst_port, payload, timestamp);
            }
            3306 => {
                self.extract_mysql_credentials(pcap_id, session_id, src_ip, dst_ip, dst_port, payload, timestamp);
            }
            5432 => {
                self.extract_postgres_credentials(pcap_id, session_id, src_ip, dst_ip, dst_port, payload, timestamp);
            }
            1433 => {
                self.extract_mssql_credentials(pcap_id, session_id, src_ip, dst_ip, dst_port, payload, timestamp);
            }
            _ => {
                // Check for NTLM in any traffic
                if payload.starts_with(b"NTLMSSP") || payload.windows(7).any(|w| w == b"NTLMSSP") {
                    self.extract_ntlm_from_payload(pcap_id, session_id, src_ip, dst_ip, dst_port, payload, timestamp);
                }
            }
        }
    }

    /// Extract HTTP credentials (Basic, Digest, NTLM)
    fn extract_http_credentials(
        &mut self,
        pcap_id: &str,
        session_id: &str,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        dst_port: u16,
        payload: &[u8],
        timestamp: DateTime<Utc>,
    ) {
        let text = String::from_utf8_lossy(payload);

        // Look for Authorization header
        for line in text.lines() {
            if line.to_lowercase().starts_with("authorization:") {
                let auth_value = line[14..].trim();

                if auth_value.to_lowercase().starts_with("basic ") {
                    // HTTP Basic auth
                    let encoded = &auth_value[6..];
                    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) {
                        if let Ok(creds) = String::from_utf8(decoded) {
                            if let Some((user, pass)) = creds.split_once(':') {
                                if self.config.extract_cleartext {
                                    self.credentials.push(NetworkCredential {
                                        id: uuid::Uuid::new_v4().to_string(),
                                        pcap_id: pcap_id.to_string(),
                                        session_id: session_id.to_string(),
                                        src_ip,
                                        dst_ip,
                                        dst_port,
                                        cred_type: NetworkCredType::HttpBasic,
                                        username: Some(user.to_string()),
                                        domain: None,
                                        password: Some(pass.to_string()),
                                        hash: None,
                                        hash_type: None,
                                        raw_data: None,
                                        timestamp,
                                        metadata: HashMap::new(),
                                    });
                                }
                            }
                        }
                    }
                } else if auth_value.to_lowercase().starts_with("digest ") {
                    // HTTP Digest auth
                    if self.config.extract_hashes {
                        if let Some(cred) = self.parse_digest_auth(pcap_id, session_id, src_ip, dst_ip, dst_port, &auth_value[7..], timestamp) {
                            self.credentials.push(cred);
                        }
                    }
                } else if auth_value.to_lowercase().starts_with("ntlm ") {
                    // HTTP NTLM auth
                    let encoded = &auth_value[5..];
                    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) {
                        self.extract_ntlm_from_payload(pcap_id, session_id, src_ip, dst_ip, dst_port, &decoded, timestamp);
                    }
                } else if auth_value.to_lowercase().starts_with("negotiate ") {
                    // SPNEGO/NTLM
                    let encoded = &auth_value[10..];
                    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) {
                        self.extract_ntlm_from_payload(pcap_id, session_id, src_ip, dst_ip, dst_port, &decoded, timestamp);
                    }
                }
            }
        }
    }

    /// Parse HTTP Digest authentication
    fn parse_digest_auth(
        &self,
        pcap_id: &str,
        session_id: &str,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        dst_port: u16,
        auth_data: &str,
        timestamp: DateTime<Utc>,
    ) -> Option<NetworkCredential> {
        let mut params: HashMap<String, String> = HashMap::new();

        // Parse key="value" pairs
        for part in auth_data.split(',') {
            let part = part.trim();
            if let Some((key, value)) = part.split_once('=') {
                let value = value.trim_matches('"');
                params.insert(key.trim().to_lowercase(), value.to_string());
            }
        }

        let username = params.get("username")?.clone();
        let realm = params.get("realm").cloned().unwrap_or_default();
        let nonce = params.get("nonce").cloned().unwrap_or_default();
        let uri = params.get("uri").cloned().unwrap_or_default();
        let response = params.get("response").cloned()?;
        let qop = params.get("qop").cloned();
        let nc = params.get("nc").cloned();
        let cnonce = params.get("cnonce").cloned();

        // Build hashcat format: $digest$<hash_type>$<user>$<realm>$<nonce>$<method>$<uri>$<qop>$<nc>$<cnonce>$<response>
        let hash = format!(
            "$digest${}${}${}${}${}${}${}${}${}${}",
            "2", // MD5
            username,
            realm,
            nonce,
            "GET", // Would need to extract from request
            uri,
            qop.as_deref().unwrap_or(""),
            nc.as_deref().unwrap_or(""),
            cnonce.as_deref().unwrap_or(""),
            response
        );

        let mut metadata = HashMap::new();
        metadata.insert("realm".to_string(), realm);
        metadata.insert("uri".to_string(), uri);

        Some(NetworkCredential {
            id: uuid::Uuid::new_v4().to_string(),
            pcap_id: pcap_id.to_string(),
            session_id: session_id.to_string(),
            src_ip,
            dst_ip,
            dst_port,
            cred_type: NetworkCredType::HttpDigest,
            username: Some(username),
            domain: None,
            password: None,
            hash: Some(hash),
            hash_type: Some("HTTP-Digest".to_string()),
            raw_data: Some(auth_data.as_bytes().to_vec()),
            timestamp,
            metadata,
        })
    }

    /// Extract FTP credentials
    fn extract_ftp_credentials(
        &mut self,
        pcap_id: &str,
        session_id: &str,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        dst_port: u16,
        payload: &[u8],
        timestamp: DateTime<Utc>,
    ) {
        if !self.config.extract_cleartext {
            return;
        }

        let text = String::from_utf8_lossy(payload);

        for line in text.lines() {
            let line = line.trim();

            if line.starts_with("USER ") {
                let username = line[5..].trim();
                if !username.is_empty() {
                    self.credentials.push(NetworkCredential {
                        id: uuid::Uuid::new_v4().to_string(),
                        pcap_id: pcap_id.to_string(),
                        session_id: session_id.to_string(),
                        src_ip,
                        dst_ip,
                        dst_port,
                        cred_type: NetworkCredType::Ftp,
                        username: Some(username.to_string()),
                        domain: None,
                        password: None, // Will be correlated with PASS
                        hash: None,
                        hash_type: None,
                        raw_data: None,
                        timestamp,
                        metadata: HashMap::new(),
                    });
                }
            } else if line.starts_with("PASS ") {
                let password = line[5..].trim();
                // Update the last FTP credential with password
                if let Some(cred) = self.credentials.iter_mut().rev()
                    .find(|c| c.cred_type == NetworkCredType::Ftp &&
                              c.session_id == session_id &&
                              c.password.is_none())
                {
                    cred.password = Some(password.to_string());
                }
            }
        }
    }

    /// Extract SMTP credentials
    fn extract_smtp_credentials(
        &mut self,
        pcap_id: &str,
        session_id: &str,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        dst_port: u16,
        payload: &[u8],
        timestamp: DateTime<Utc>,
    ) {
        if !self.config.extract_cleartext {
            return;
        }

        let text = String::from_utf8_lossy(payload);

        // Check for AUTH command responses (base64 encoded)
        for line in text.lines() {
            // AUTH PLAIN with credentials inline
            if line.starts_with("AUTH PLAIN ") {
                let encoded = line[11..].trim();
                if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) {
                    // Format: \0username\0password
                    let parts: Vec<&[u8]> = decoded.split(|&b| b == 0).collect();
                    if parts.len() >= 3 {
                        let username = String::from_utf8_lossy(parts[1]);
                        let password = String::from_utf8_lossy(parts[2]);

                        self.credentials.push(NetworkCredential {
                            id: uuid::Uuid::new_v4().to_string(),
                            pcap_id: pcap_id.to_string(),
                            session_id: session_id.to_string(),
                            src_ip,
                            dst_ip,
                            dst_port,
                            cred_type: NetworkCredType::Smtp,
                            username: Some(username.to_string()),
                            domain: None,
                            password: Some(password.to_string()),
                            hash: None,
                            hash_type: None,
                            raw_data: None,
                            timestamp,
                            metadata: HashMap::new(),
                        });
                    }
                }
            }
            // AUTH LOGIN (base64 encoded separately)
            else if line.starts_with("AUTH LOGIN") {
                // Next lines will be base64 username and password
                // This would need session state tracking for full implementation
            }
        }
    }

    /// Extract POP3 credentials
    fn extract_pop3_credentials(
        &mut self,
        pcap_id: &str,
        session_id: &str,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        dst_port: u16,
        payload: &[u8],
        timestamp: DateTime<Utc>,
    ) {
        if !self.config.extract_cleartext {
            return;
        }

        let text = String::from_utf8_lossy(payload);

        for line in text.lines() {
            let line = line.trim();

            if line.starts_with("USER ") {
                let username = line[5..].trim();
                if !username.is_empty() {
                    self.credentials.push(NetworkCredential {
                        id: uuid::Uuid::new_v4().to_string(),
                        pcap_id: pcap_id.to_string(),
                        session_id: session_id.to_string(),
                        src_ip,
                        dst_ip,
                        dst_port,
                        cred_type: NetworkCredType::Pop3,
                        username: Some(username.to_string()),
                        domain: None,
                        password: None,
                        hash: None,
                        hash_type: None,
                        raw_data: None,
                        timestamp,
                        metadata: HashMap::new(),
                    });
                }
            } else if line.starts_with("PASS ") {
                let password = line[5..].trim();
                if let Some(cred) = self.credentials.iter_mut().rev()
                    .find(|c| c.cred_type == NetworkCredType::Pop3 &&
                              c.session_id == session_id &&
                              c.password.is_none())
                {
                    cred.password = Some(password.to_string());
                }
            }
        }
    }

    /// Extract IMAP credentials
    fn extract_imap_credentials(
        &mut self,
        pcap_id: &str,
        session_id: &str,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        dst_port: u16,
        payload: &[u8],
        timestamp: DateTime<Utc>,
    ) {
        if !self.config.extract_cleartext {
            return;
        }

        let text = String::from_utf8_lossy(payload);

        // IMAP LOGIN command: tag LOGIN username password
        for line in text.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 && parts[1].to_uppercase() == "LOGIN" {
                let username = parts[2].trim_matches('"');
                let password = parts[3..].join(" ").trim_matches('"').to_string();

                self.credentials.push(NetworkCredential {
                    id: uuid::Uuid::new_v4().to_string(),
                    pcap_id: pcap_id.to_string(),
                    session_id: session_id.to_string(),
                    src_ip,
                    dst_ip,
                    dst_port,
                    cred_type: NetworkCredType::Imap,
                    username: Some(username.to_string()),
                    domain: None,
                    password: Some(password),
                    hash: None,
                    hash_type: None,
                    raw_data: None,
                    timestamp,
                    metadata: HashMap::new(),
                });
            }
        }
    }

    /// Extract Telnet credentials
    fn extract_telnet_credentials(
        &mut self,
        pcap_id: &str,
        session_id: &str,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        dst_port: u16,
        payload: &[u8],
        timestamp: DateTime<Utc>,
    ) {
        if !self.config.extract_cleartext {
            return;
        }

        // Telnet is tricky - credentials are often character by character
        // This is a simplified version looking for complete strings
        let text = String::from_utf8_lossy(payload);
        let text = text.trim();

        // Heuristic: short strings after login/password prompts
        if text.len() > 0 && text.len() < 64 && text.chars().all(|c| c.is_ascii() && !c.is_ascii_control()) {
            // Would need session state to correlate with prompts
            // For now, just note there's telnet traffic
        }
    }

    /// Extract Kerberos data (AS-REQ, AS-REP, TGS-REQ)
    fn extract_kerberos_data(
        &mut self,
        pcap_id: &str,
        session_id: &str,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        dst_port: u16,
        payload: &[u8],
        timestamp: DateTime<Utc>,
    ) {
        if payload.len() < 10 {
            return;
        }

        // Check for Kerberos ASN.1 application tags
        // AS-REQ: 0x6a (Application 10)
        // AS-REP: 0x6b (Application 11)
        // TGS-REQ: 0x6c (Application 12)
        // TGS-REP: 0x6d (Application 13)

        let msg_type = payload[0];

        match msg_type {
            0x6a => {
                // AS-REQ - extract principal name and potentially encrypted timestamp
                if let Some(cred) = self.parse_kerberos_asreq(pcap_id, session_id, src_ip, dst_ip, dst_port, payload, timestamp) {
                    self.credentials.push(cred);
                }
            }
            0x6b => {
                // AS-REP - roastable if no pre-auth
                if let Some(cred) = self.parse_kerberos_asrep(pcap_id, session_id, src_ip, dst_ip, dst_port, payload, timestamp) {
                    self.credentials.push(cred);
                }
            }
            0x6c => {
                // TGS-REQ - can extract SPN
                if let Some(cred) = self.parse_kerberos_tgsreq(pcap_id, session_id, src_ip, dst_ip, dst_port, payload, timestamp) {
                    self.credentials.push(cred);
                }
            }
            _ => {}
        }
    }

    /// Parse Kerberos AS-REQ
    fn parse_kerberos_asreq(
        &self,
        pcap_id: &str,
        session_id: &str,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        dst_port: u16,
        payload: &[u8],
        timestamp: DateTime<Utc>,
    ) -> Option<NetworkCredential> {
        // Simplified ASN.1 parsing for AS-REQ
        // Would need full DER parser for production

        let mut metadata = HashMap::new();
        metadata.insert("message_type".to_string(), "AS-REQ".to_string());

        // Try to extract cname (principal name)
        // This is a simplified extraction
        let username = self.extract_kerberos_principal(payload);
        let realm = self.extract_kerberos_realm(payload);

        if username.is_some() || realm.is_some() {
            Some(NetworkCredential {
                id: uuid::Uuid::new_v4().to_string(),
                pcap_id: pcap_id.to_string(),
                session_id: session_id.to_string(),
                src_ip,
                dst_ip,
                dst_port,
                cred_type: NetworkCredType::KerberosAsReq,
                username,
                domain: realm,
                password: None,
                hash: None,
                hash_type: None,
                raw_data: Some(payload.to_vec()),
                timestamp,
                metadata,
            })
        } else {
            None
        }
    }

    /// Parse Kerberos AS-REP (for AS-REP roasting)
    fn parse_kerberos_asrep(
        &self,
        pcap_id: &str,
        session_id: &str,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        dst_port: u16,
        payload: &[u8],
        timestamp: DateTime<Utc>,
    ) -> Option<NetworkCredential> {
        // AS-REP contains encrypted data that can be cracked
        // Format: $krb5asrep$23$user@REALM:hash

        let username = self.extract_kerberos_principal(payload);
        let realm = self.extract_kerberos_realm(payload);

        // Extract encrypted part for hash
        // Would need full ASN.1 parsing for production
        let enc_data = self.extract_kerberos_enc_data(payload);

        let hash = if let (Some(user), Some(realm_str), Some(enc)) = (&username, &realm, enc_data.as_ref()) {
            Some(format!("$krb5asrep$23${}@{}:{}", user, realm_str, hex::encode(enc)))
        } else {
            None
        };

        let mut metadata = HashMap::new();
        metadata.insert("message_type".to_string(), "AS-REP".to_string());
        metadata.insert("roastable".to_string(), "true".to_string());

        Some(NetworkCredential {
            id: uuid::Uuid::new_v4().to_string(),
            pcap_id: pcap_id.to_string(),
            session_id: session_id.to_string(),
            src_ip,
            dst_ip,
            dst_port,
            cred_type: NetworkCredType::KerberosAsRep,
            username,
            domain: realm,
            password: None,
            hash,
            hash_type: Some("Kerberos AS-REP".to_string()),
            raw_data: Some(payload.to_vec()),
            timestamp,
            metadata,
        })
    }

    /// Parse Kerberos TGS-REQ
    fn parse_kerberos_tgsreq(
        &self,
        pcap_id: &str,
        session_id: &str,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        dst_port: u16,
        payload: &[u8],
        timestamp: DateTime<Utc>,
    ) -> Option<NetworkCredential> {
        // TGS-REQ contains the SPN being requested

        let sname = self.extract_kerberos_sname(payload);
        let realm = self.extract_kerberos_realm(payload);

        let mut metadata = HashMap::new();
        metadata.insert("message_type".to_string(), "TGS-REQ".to_string());
        if let Some(ref s) = sname {
            metadata.insert("spn".to_string(), s.clone());
        }

        Some(NetworkCredential {
            id: uuid::Uuid::new_v4().to_string(),
            pcap_id: pcap_id.to_string(),
            session_id: session_id.to_string(),
            src_ip,
            dst_ip,
            dst_port,
            cred_type: NetworkCredType::KerberosTgsReq,
            username: sname,
            domain: realm,
            password: None,
            hash: None,
            hash_type: None,
            raw_data: Some(payload.to_vec()),
            timestamp,
            metadata,
        })
    }

    /// Extract principal name from Kerberos message (simplified)
    fn extract_kerberos_principal(&self, data: &[u8]) -> Option<String> {
        // Look for GeneralString patterns in ASN.1
        // This is a heuristic - would need full parser for accuracy
        let text = String::from_utf8_lossy(data);

        // Look for username-like strings
        for i in 0..data.len().saturating_sub(4) {
            if data[i] == 0x1b { // GeneralString tag
                let len = data.get(i + 1)?;
                if *len > 0 && *len < 64 {
                    let end = i + 2 + *len as usize;
                    if end <= data.len() {
                        if let Ok(s) = String::from_utf8(data[i + 2..end].to_vec()) {
                            if s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.') {
                                return Some(s);
                            }
                        }
                    }
                }
            }
        }

        None
    }

    /// Extract realm from Kerberos message (simplified)
    fn extract_kerberos_realm(&self, data: &[u8]) -> Option<String> {
        // Look for realm - typically uppercase domain name
        for i in 0..data.len().saturating_sub(4) {
            if data[i] == 0x1b { // GeneralString tag
                let len = data.get(i + 1)?;
                if *len > 3 && *len < 64 {
                    let end = i + 2 + *len as usize;
                    if end <= data.len() {
                        if let Ok(s) = String::from_utf8(data[i + 2..end].to_vec()) {
                            // Realm is typically uppercase with dots
                            if s.contains('.') && s.chars().all(|c| c.is_ascii_uppercase() || c == '.') {
                                return Some(s);
                            }
                        }
                    }
                }
            }
        }

        None
    }

    /// Extract encrypted data from Kerberos message
    fn extract_kerberos_enc_data(&self, data: &[u8]) -> Option<Vec<u8>> {
        // Look for encrypted data - typically large blob after enc-part tag
        // This is simplified - would need full ASN.1 parsing

        // Look for OctetString with substantial length
        for i in 0..data.len().saturating_sub(100) {
            if data[i] == 0x04 { // OctetString tag
                // Check for multi-byte length
                if data.get(i + 1)? & 0x80 != 0 {
                    let len_bytes = (data[i + 1] & 0x7f) as usize;
                    if len_bytes > 0 && len_bytes <= 4 && i + 2 + len_bytes < data.len() {
                        let mut length = 0usize;
                        for j in 0..len_bytes {
                            length = (length << 8) | (data[i + 2 + j] as usize);
                        }

                        if length >= 50 && length < 5000 {
                            let start = i + 2 + len_bytes;
                            let end = (start + length).min(data.len());
                            return Some(data[start..end].to_vec());
                        }
                    }
                }
            }
        }

        None
    }

    /// Extract sname (service name) from TGS-REQ
    fn extract_kerberos_sname(&self, data: &[u8]) -> Option<String> {
        // Similar to principal extraction but for service names
        self.extract_kerberos_principal(data)
    }

    /// Extract NTLM from raw payload
    fn extract_ntlm_from_payload(
        &mut self,
        pcap_id: &str,
        session_id: &str,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        dst_port: u16,
        payload: &[u8],
        timestamp: DateTime<Utc>,
    ) {
        // Find NTLMSSP signature
        let sig = b"NTLMSSP\x00";

        for i in 0..payload.len().saturating_sub(sig.len()) {
            if &payload[i..i + sig.len()] == sig {
                let ntlm_data = &payload[i..];

                if ntlm_data.len() < 12 {
                    continue;
                }

                let msg_type = u32::from_le_bytes([ntlm_data[8], ntlm_data[9], ntlm_data[10], ntlm_data[11]]);

                match msg_type {
                    1 => {
                        // Type 1 (Negotiate)
                        self.credentials.push(NetworkCredential {
                            id: uuid::Uuid::new_v4().to_string(),
                            pcap_id: pcap_id.to_string(),
                            session_id: session_id.to_string(),
                            src_ip,
                            dst_ip,
                            dst_port,
                            cred_type: NetworkCredType::NtlmType1,
                            username: None,
                            domain: None,
                            password: None,
                            hash: None,
                            hash_type: None,
                            raw_data: Some(ntlm_data.to_vec()),
                            timestamp,
                            metadata: HashMap::new(),
                        });
                    }
                    2 => {
                        // Type 2 (Challenge)
                        if ntlm_data.len() >= 24 {
                            let mut challenge = [0u8; 8];
                            challenge.copy_from_slice(&ntlm_data[24..32]);

                            // Store for correlation
                            let key = format!("{}:{}:{}:{}", src_ip, dst_ip, src_ip, dst_port);
                            self.ntlm_challenges.insert(key, NtlmChallenge {
                                challenge,
                                timestamp,
                                src_ip,
                                dst_ip,
                            });

                            let mut metadata = HashMap::new();
                            metadata.insert("challenge".to_string(), hex::encode(challenge));

                            self.credentials.push(NetworkCredential {
                                id: uuid::Uuid::new_v4().to_string(),
                                pcap_id: pcap_id.to_string(),
                                session_id: session_id.to_string(),
                                src_ip,
                                dst_ip,
                                dst_port,
                                cred_type: NetworkCredType::NtlmType2,
                                username: None,
                                domain: None,
                                password: None,
                                hash: None,
                                hash_type: None,
                                raw_data: Some(ntlm_data.to_vec()),
                                timestamp,
                                metadata,
                            });
                        }
                    }
                    3 => {
                        // Type 3 (Authenticate) - contains NTLMv2 hash
                        if let Some(cred) = self.parse_ntlm_type3(pcap_id, session_id, src_ip, dst_ip, dst_port, ntlm_data, timestamp) {
                            self.credentials.push(cred);
                        }
                    }
                    _ => {}
                }

                break; // Only process first NTLMSSP in payload
            }
        }
    }

    /// Parse NTLM Type 3 message to extract NTLMv2 hash
    fn parse_ntlm_type3(
        &self,
        pcap_id: &str,
        session_id: &str,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        dst_port: u16,
        data: &[u8],
        timestamp: DateTime<Utc>,
    ) -> Option<NetworkCredential> {
        if data.len() < 64 {
            return None;
        }

        // NTLM Type 3 structure offsets
        let lm_len = u16::from_le_bytes([data[12], data[13]]) as usize;
        let lm_offset = u32::from_le_bytes([data[16], data[17], data[18], data[19]]) as usize;

        let nt_len = u16::from_le_bytes([data[20], data[21]]) as usize;
        let nt_offset = u32::from_le_bytes([data[24], data[25], data[26], data[27]]) as usize;

        let domain_len = u16::from_le_bytes([data[28], data[29]]) as usize;
        let domain_offset = u32::from_le_bytes([data[32], data[33], data[34], data[35]]) as usize;

        let user_len = u16::from_le_bytes([data[36], data[37]]) as usize;
        let user_offset = u32::from_le_bytes([data[40], data[41], data[42], data[43]]) as usize;

        let host_len = u16::from_le_bytes([data[44], data[45]]) as usize;
        let host_offset = u32::from_le_bytes([data[48], data[49], data[50], data[51]]) as usize;

        // Extract fields
        let username = if user_offset + user_len <= data.len() {
            String::from_utf16_lossy(
                &data[user_offset..user_offset + user_len]
                    .chunks(2)
                    .filter_map(|c| if c.len() == 2 { Some(u16::from_le_bytes([c[0], c[1]])) } else { None })
                    .collect::<Vec<u16>>()
            )
        } else {
            return None;
        };

        let domain = if domain_offset + domain_len <= data.len() {
            String::from_utf16_lossy(
                &data[domain_offset..domain_offset + domain_len]
                    .chunks(2)
                    .filter_map(|c| if c.len() == 2 { Some(u16::from_le_bytes([c[0], c[1]])) } else { None })
                    .collect::<Vec<u16>>()
            )
        } else {
            String::new()
        };

        // Extract NT response (NTLMv2 hash)
        let nt_response = if nt_offset + nt_len <= data.len() && nt_len > 0 {
            data[nt_offset..nt_offset + nt_len].to_vec()
        } else {
            return None;
        };

        // Try to find matching challenge
        let key = format!("{}:{}:{}:{}", dst_ip, src_ip, dst_ip, dst_port);
        let challenge = self.ntlm_challenges.get(&key).map(|c| c.challenge);

        // Build NetNTLMv2 hash for hashcat
        // Format: user::domain:challenge:response:blob
        let hash = if let Some(challenge) = challenge {
            if nt_response.len() >= 24 {
                let response = &nt_response[..16];
                let blob = &nt_response[16..];
                format!(
                    "{}::{}:{}:{}:{}",
                    username,
                    domain,
                    hex::encode(challenge),
                    hex::encode(response),
                    hex::encode(blob)
                )
            } else {
                hex::encode(&nt_response)
            }
        } else {
            // No challenge found, store raw response
            format!(
                "{}::{}:unknown:{}:{}",
                username,
                domain,
                hex::encode(&nt_response[..16.min(nt_response.len())]),
                if nt_response.len() > 16 { hex::encode(&nt_response[16..]) } else { String::new() }
            )
        };

        let mut metadata = HashMap::new();
        metadata.insert("nt_len".to_string(), nt_len.to_string());
        if let Some(challenge) = challenge {
            metadata.insert("challenge".to_string(), hex::encode(challenge));
        }

        Some(NetworkCredential {
            id: uuid::Uuid::new_v4().to_string(),
            pcap_id: pcap_id.to_string(),
            session_id: session_id.to_string(),
            src_ip,
            dst_ip,
            dst_port,
            cred_type: NetworkCredType::NtlmType3,
            username: Some(username),
            domain: Some(domain),
            password: None,
            hash: Some(hash),
            hash_type: Some("NetNTLMv2".to_string()),
            raw_data: Some(data.to_vec()),
            timestamp,
            metadata,
        })
    }

    /// Extract LDAP credentials
    fn extract_ldap_credentials(
        &mut self,
        pcap_id: &str,
        session_id: &str,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        dst_port: u16,
        payload: &[u8],
        timestamp: DateTime<Utc>,
    ) {
        if !self.config.extract_cleartext || payload.len() < 10 {
            return;
        }

        // LDAP uses BER/DER encoding
        // Simple bind request has auth choice 0 (simple)

        // Look for bind request pattern (simplified)
        // This would need full LDAP ASN.1 parsing for production

        // Heuristic: look for DN followed by password
        if let Some(dn_end) = payload.iter().position(|&b| b == 0x80) {
            // 0x80 = context tag 0 (simple auth)
            if dn_end + 2 < payload.len() {
                let pass_len = payload[dn_end + 1] as usize;
                if dn_end + 2 + pass_len <= payload.len() {
                    if let Ok(password) = String::from_utf8(payload[dn_end + 2..dn_end + 2 + pass_len].to_vec()) {
                        // Try to extract DN
                        let dn = String::from_utf8_lossy(&payload[..dn_end])
                            .chars()
                            .filter(|c| c.is_ascii() && !c.is_ascii_control())
                            .collect::<String>();

                        if !password.is_empty() && dn.len() > 3 {
                            self.credentials.push(NetworkCredential {
                                id: uuid::Uuid::new_v4().to_string(),
                                pcap_id: pcap_id.to_string(),
                                session_id: session_id.to_string(),
                                src_ip,
                                dst_ip,
                                dst_port,
                                cred_type: NetworkCredType::LdapSimpleBind,
                                username: Some(dn),
                                domain: None,
                                password: Some(password),
                                hash: None,
                                hash_type: None,
                                raw_data: None,
                                timestamp,
                                metadata: HashMap::new(),
                            });
                        }
                    }
                }
            }
        }
    }

    /// Extract SMB credentials
    fn extract_smb_credentials(
        &mut self,
        pcap_id: &str,
        session_id: &str,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        dst_port: u16,
        payload: &[u8],
        timestamp: DateTime<Utc>,
    ) {
        // SMB session setup contains NTLM messages
        // Look for NTLMSSP in the payload
        self.extract_ntlm_from_payload(pcap_id, session_id, src_ip, dst_ip, dst_port, payload, timestamp);
    }

    /// Extract MySQL credentials
    fn extract_mysql_credentials(
        &mut self,
        pcap_id: &str,
        session_id: &str,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        dst_port: u16,
        payload: &[u8],
        timestamp: DateTime<Utc>,
    ) {
        // MySQL native password authentication
        // The hash is SHA1(password) XOR SHA1(random_from_server + SHA1(SHA1(password)))

        if payload.len() < 36 {
            return;
        }

        // Check for handshake response packet
        // This is a simplified version - would need full protocol parsing

        // Look for username in the packet
        let mut metadata = HashMap::new();
        metadata.insert("protocol".to_string(), "MySQL".to_string());

        // Try to extract username (null-terminated after fixed header)
        if let Some(user_end) = payload[32..].iter().position(|&b| b == 0) {
            if let Ok(username) = String::from_utf8(payload[32..32 + user_end].to_vec()) {
                if !username.is_empty() {
                    self.credentials.push(NetworkCredential {
                        id: uuid::Uuid::new_v4().to_string(),
                        pcap_id: pcap_id.to_string(),
                        session_id: session_id.to_string(),
                        src_ip,
                        dst_ip,
                        dst_port,
                        cred_type: NetworkCredType::MysqlNative,
                        username: Some(username),
                        domain: None,
                        password: None,
                        hash: None,
                        hash_type: Some("MySQL native".to_string()),
                        raw_data: Some(payload.to_vec()),
                        timestamp,
                        metadata,
                    });
                }
            }
        }
    }

    /// Extract PostgreSQL credentials
    fn extract_postgres_credentials(
        &mut self,
        pcap_id: &str,
        session_id: &str,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        dst_port: u16,
        payload: &[u8],
        timestamp: DateTime<Utc>,
    ) {
        if payload.len() < 5 {
            return;
        }

        // Check for password message (type 'p')
        if payload[0] == b'p' {
            let msg_len = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]) as usize;
            if msg_len > 5 && 5 + msg_len - 4 <= payload.len() {
                let password_data = &payload[5..5 + msg_len - 4 - 1]; // -1 for null terminator

                if let Ok(password) = String::from_utf8(password_data.to_vec()) {
                    // Check if it's MD5 format
                    let (hash, is_md5) = if password.starts_with("md5") {
                        (Some(password.clone()), true)
                    } else if self.config.extract_cleartext {
                        (None, false)
                    } else {
                        return;
                    };

                    let mut metadata = HashMap::new();
                    metadata.insert("auth_type".to_string(), if is_md5 { "MD5" } else { "cleartext" }.to_string());

                    self.credentials.push(NetworkCredential {
                        id: uuid::Uuid::new_v4().to_string(),
                        pcap_id: pcap_id.to_string(),
                        session_id: session_id.to_string(),
                        src_ip,
                        dst_ip,
                        dst_port,
                        cred_type: NetworkCredType::PostgresMd5,
                        username: None, // Would need to correlate with startup message
                        domain: None,
                        password: if is_md5 { None } else { Some(password) },
                        hash,
                        hash_type: if is_md5 { Some("PostgreSQL MD5".to_string()) } else { None },
                        raw_data: Some(payload.to_vec()),
                        timestamp,
                        metadata,
                    });
                }
            }
        }
    }

    /// Extract MSSQL credentials
    fn extract_mssql_credentials(
        &mut self,
        pcap_id: &str,
        session_id: &str,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        dst_port: u16,
        payload: &[u8],
        timestamp: DateTime<Utc>,
    ) {
        if payload.len() < 8 {
            return;
        }

        // TDS login packet type is 0x10
        if payload[0] == 0x10 {
            // TDS LOGIN7 packet
            // Extract username and password (they're UTF-16LE encoded and password is XOR'd)

            let mut metadata = HashMap::new();
            metadata.insert("protocol".to_string(), "TDS".to_string());

            self.credentials.push(NetworkCredential {
                id: uuid::Uuid::new_v4().to_string(),
                pcap_id: pcap_id.to_string(),
                session_id: session_id.to_string(),
                src_ip,
                dst_ip,
                dst_port,
                cred_type: NetworkCredType::MssqlTds,
                username: None, // Would need full TDS parsing
                domain: None,
                password: None,
                hash: None,
                hash_type: None,
                raw_data: Some(payload.to_vec()),
                timestamp,
                metadata,
            });
        }
    }

    /// Get all extracted credentials
    pub fn get_credentials(&self) -> &[NetworkCredential] {
        &self.credentials
    }

    /// Get crackable credentials
    pub fn get_crackable(&self) -> Vec<&NetworkCredential> {
        self.credentials.iter()
            .filter(|c| c.cred_type.is_crackable() && c.hash.is_some())
            .collect()
    }

    /// Get cleartext credentials
    pub fn get_cleartext(&self) -> Vec<&NetworkCredential> {
        self.credentials.iter()
            .filter(|c| c.password.is_some())
            .collect()
    }

    /// Get credentials by type
    pub fn get_by_type(&self, cred_type: NetworkCredType) -> Vec<&NetworkCredential> {
        self.credentials.iter()
            .filter(|c| c.cred_type == cred_type)
            .collect()
    }

    /// Get statistics
    pub fn get_stats(&self) -> CredentialStats {
        let mut by_type: HashMap<String, usize> = HashMap::new();
        let mut cleartext = 0;
        let mut hashes = 0;

        for cred in &self.credentials {
            *by_type.entry(cred.cred_type.name().to_string()).or_insert(0) += 1;
            if cred.password.is_some() {
                cleartext += 1;
            }
            if cred.hash.is_some() {
                hashes += 1;
            }
        }

        CredentialStats {
            total: self.credentials.len(),
            cleartext,
            hashes,
            by_type,
        }
    }

    /// Clear all credentials
    pub fn clear(&mut self) {
        self.credentials.clear();
        self.ntlm_challenges.clear();
    }
}

/// Credential extraction statistics
#[derive(Debug, Clone)]
pub struct CredentialStats {
    pub total: usize,
    pub cleartext: usize,
    pub hashes: usize,
    pub by_type: HashMap<String, usize>,
}

impl Default for CredentialExtractor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_basic_extraction() {
        let mut extractor = CredentialExtractor::new();

        let payload = b"GET / HTTP/1.1\r\nHost: test.com\r\nAuthorization: Basic YWRtaW46cGFzc3dvcmQ=\r\n\r\n";

        extractor.analyze_packet(
            "test",
            "sess1",
            "192.168.1.100".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            12345,
            80,
            payload,
            Utc::now(),
        );

        assert_eq!(extractor.credentials.len(), 1);
        assert_eq!(extractor.credentials[0].username, Some("admin".to_string()));
        assert_eq!(extractor.credentials[0].password, Some("password".to_string()));
    }

    #[test]
    fn test_ftp_extraction() {
        let mut extractor = CredentialExtractor::new();

        // USER command
        extractor.analyze_packet(
            "test",
            "sess1",
            "192.168.1.100".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            12345,
            21,
            b"USER anonymous\r\n",
            Utc::now(),
        );

        // PASS command
        extractor.analyze_packet(
            "test",
            "sess1",
            "192.168.1.100".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            12345,
            21,
            b"PASS email@example.com\r\n",
            Utc::now(),
        );

        assert_eq!(extractor.credentials.len(), 1);
        assert_eq!(extractor.credentials[0].username, Some("anonymous".to_string()));
        assert_eq!(extractor.credentials[0].password, Some("email@example.com".to_string()));
    }
}
