//! Honeypot system for deception technology (Sprint 7)
//!
//! Provides honeypot capabilities for threat detection including:
//! - Multiple honeypot types (SSH, HTTP, FTP, Database, Email)
//! - Interaction logging and analysis
//! - Attacker fingerprinting
//! - Alert generation

use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use log::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Honeypot {
    pub id: String,
    pub name: String,
    pub honeypot_type: HoneypotType,
    pub ip_address: String,
    pub port: u16,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HoneypotType {
    SSH,
    HTTP,
    FTP,
    Database,
    Email,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneypotInteraction {
    pub id: String,
    pub honeypot_id: String,
    pub source_ip: String,
    pub timestamp: DateTime<Utc>,
    pub interaction_type: String,
    pub details: String,
}

/// Global honeypot state
static HONEYPOT_STATE: once_cell::sync::Lazy<Arc<RwLock<HoneypotState>>> =
    once_cell::sync::Lazy::new(|| Arc::new(RwLock::new(HoneypotState::default())));

#[derive(Debug, Default)]
struct HoneypotState {
    honeypots: HashMap<String, Honeypot>,
    interactions: HashMap<String, Vec<HoneypotInteraction>>,
    attacker_profiles: HashMap<String, AttackerProfile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackerProfile {
    pub ip_address: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub interaction_count: usize,
    pub targeted_honeypots: Vec<String>,
    pub threat_level: ThreatLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ThreatLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Create a new honeypot
pub async fn create_honeypot(name: &str, honeypot_type: HoneypotType, ip: &str, port: u16) -> Result<Honeypot> {
    let honeypot = Honeypot {
        id: uuid::Uuid::new_v4().to_string(),
        name: name.to_string(),
        honeypot_type,
        ip_address: ip.to_string(),
        port,
        is_active: true,
        created_at: Utc::now(),
    };

    let mut state = HONEYPOT_STATE.write().await;
    state.honeypots.insert(honeypot.id.clone(), honeypot.clone());
    state.interactions.insert(honeypot.id.clone(), Vec::new());

    info!("Created honeypot: {} ({}:{})", name, ip, port);
    Ok(honeypot)
}

/// Log an interaction with a honeypot
pub async fn log_interaction(honeypot_id: &str, source_ip: &str, details: &str) -> Result<HoneypotInteraction> {
    let interaction = HoneypotInteraction {
        id: uuid::Uuid::new_v4().to_string(),
        honeypot_id: honeypot_id.to_string(),
        source_ip: source_ip.to_string(),
        timestamp: Utc::now(),
        interaction_type: "connection_attempt".to_string(),
        details: details.to_string(),
    };

    let mut state = HONEYPOT_STATE.write().await;

    // Add to interactions list
    if let Some(interactions) = state.interactions.get_mut(honeypot_id) {
        interactions.push(interaction.clone());
    } else {
        state.interactions.insert(honeypot_id.to_string(), vec![interaction.clone()]);
    }

    // Update attacker profile
    update_attacker_profile(&mut state, source_ip, honeypot_id);

    info!("Logged honeypot interaction from {} on honeypot {}", source_ip, honeypot_id);
    Ok(interaction)
}

/// Update attacker profile based on interaction
fn update_attacker_profile(state: &mut HoneypotState, ip: &str, honeypot_id: &str) {
    let now = Utc::now();

    if let Some(profile) = state.attacker_profiles.get_mut(ip) {
        profile.last_seen = now;
        profile.interaction_count += 1;
        if !profile.targeted_honeypots.contains(&honeypot_id.to_string()) {
            profile.targeted_honeypots.push(honeypot_id.to_string());
        }
        // Escalate threat level based on activity
        if profile.interaction_count > 50 || profile.targeted_honeypots.len() > 3 {
            profile.threat_level = ThreatLevel::Critical;
        } else if profile.interaction_count > 20 || profile.targeted_honeypots.len() > 2 {
            profile.threat_level = ThreatLevel::High;
        } else if profile.interaction_count > 5 {
            profile.threat_level = ThreatLevel::Medium;
        }
    } else {
        state.attacker_profiles.insert(ip.to_string(), AttackerProfile {
            ip_address: ip.to_string(),
            first_seen: now,
            last_seen: now,
            interaction_count: 1,
            targeted_honeypots: vec![honeypot_id.to_string()],
            threat_level: ThreatLevel::Low,
        });
    }
}

/// Get all interactions for a honeypot
pub async fn get_interactions(honeypot_id: &str) -> Result<Vec<HoneypotInteraction>> {
    let state = HONEYPOT_STATE.read().await;
    Ok(state.interactions.get(honeypot_id).cloned().unwrap_or_default())
}

/// Get a honeypot by ID
pub async fn get_honeypot(honeypot_id: &str) -> Result<Honeypot> {
    let state = HONEYPOT_STATE.read().await;
    state.honeypots.get(honeypot_id)
        .cloned()
        .ok_or_else(|| anyhow!("Honeypot not found: {}", honeypot_id))
}

/// List all honeypots
pub async fn list_honeypots() -> Vec<Honeypot> {
    let state = HONEYPOT_STATE.read().await;
    state.honeypots.values().cloned().collect()
}

/// Deactivate a honeypot
pub async fn deactivate_honeypot(honeypot_id: &str) -> Result<()> {
    let mut state = HONEYPOT_STATE.write().await;
    if let Some(honeypot) = state.honeypots.get_mut(honeypot_id) {
        honeypot.is_active = false;
        info!("Deactivated honeypot: {}", honeypot_id);
        Ok(())
    } else {
        Err(anyhow!("Honeypot not found: {}", honeypot_id))
    }
}

/// Get attacker profile
pub async fn get_attacker_profile(ip: &str) -> Option<AttackerProfile> {
    let state = HONEYPOT_STATE.read().await;
    state.attacker_profiles.get(ip).cloned()
}

/// List all attacker profiles
pub async fn list_attacker_profiles() -> Vec<AttackerProfile> {
    let state = HONEYPOT_STATE.read().await;
    state.attacker_profiles.values().cloned().collect()
}

/// Get high-threat attackers
pub async fn get_high_threat_attackers() -> Vec<AttackerProfile> {
    let state = HONEYPOT_STATE.read().await;
    state.attacker_profiles.values()
        .filter(|p| p.threat_level == ThreatLevel::High || p.threat_level == ThreatLevel::Critical)
        .cloned()
        .collect()
}

/// Get honeypot statistics
pub async fn get_honeypot_stats() -> HoneypotStats {
    let state = HONEYPOT_STATE.read().await;

    let total_interactions: usize = state.interactions.values().map(|i| i.len()).sum();
    let active_honeypots = state.honeypots.values().filter(|h| h.is_active).count();
    let unique_attackers = state.attacker_profiles.len();
    let high_threat_count = state.attacker_profiles.values()
        .filter(|p| p.threat_level == ThreatLevel::High || p.threat_level == ThreatLevel::Critical)
        .count();

    let interactions_by_type: HashMap<String, usize> = state.honeypots.values()
        .map(|h| {
            let type_str = format!("{:?}", h.honeypot_type);
            let count = state.interactions.get(&h.id).map(|i| i.len()).unwrap_or(0);
            (type_str, count)
        })
        .fold(HashMap::new(), |mut acc, (t, c)| {
            *acc.entry(t).or_insert(0) += c;
            acc
        });

    HoneypotStats {
        total_honeypots: state.honeypots.len(),
        active_honeypots,
        total_interactions,
        unique_attackers,
        high_threat_attackers: high_threat_count,
        interactions_by_type,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneypotStats {
    pub total_honeypots: usize,
    pub active_honeypots: usize,
    pub total_interactions: usize,
    pub unique_attackers: usize,
    pub high_threat_attackers: usize,
    pub interactions_by_type: HashMap<String, usize>,
}

// =============================================================================
// TCP/UDP HONEYPOT LISTENERS
// =============================================================================

use tokio::net::{TcpListener, UdpSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::atomic::{AtomicBool, Ordering};

/// Global shutdown signal for honeypot listeners
static SHUTDOWN: once_cell::sync::Lazy<Arc<AtomicBool>> =
    once_cell::sync::Lazy::new(|| Arc::new(AtomicBool::new(false)));

/// Start a honeypot listener for the given honeypot configuration.
/// Returns a JoinHandle that can be used to stop the listener.
pub async fn start_listener(honeypot_id: &str) -> Result<tokio::task::JoinHandle<()>> {
    let state = HONEYPOT_STATE.read().await;
    let honeypot = state.honeypots.get(honeypot_id)
        .ok_or_else(|| anyhow!("Honeypot not found: {}", honeypot_id))?
        .clone();
    drop(state);

    if !honeypot.is_active {
        return Err(anyhow!("Honeypot {} is not active", honeypot_id));
    }

    let hp_id = honeypot.id.clone();
    let log_addr = honeypot.ip_address.clone();
    let handle = match honeypot.honeypot_type {
        HoneypotType::SSH => {
            tokio::spawn(run_ssh_honeypot(hp_id, honeypot.ip_address, honeypot.port))
        }
        HoneypotType::HTTP => {
            tokio::spawn(run_http_honeypot(hp_id, honeypot.ip_address, honeypot.port))
        }
        HoneypotType::FTP => {
            tokio::spawn(run_ftp_honeypot(hp_id, honeypot.ip_address, honeypot.port))
        }
        HoneypotType::Database => {
            tokio::spawn(run_database_honeypot(hp_id, honeypot.ip_address, honeypot.port))
        }
        HoneypotType::Email => {
            tokio::spawn(run_smtp_honeypot(hp_id, honeypot.ip_address, honeypot.port))
        }
    };

    info!("Started {:?} honeypot listener on {}:{}", honeypot.honeypot_type, log_addr, honeypot.port);
    Ok(handle)
}

/// Stop all honeypot listeners
pub fn stop_all_listeners() {
    SHUTDOWN.store(true, Ordering::SeqCst);
    info!("Shutdown signal sent to all honeypot listeners");
}

/// Reset shutdown flag (for restarting listeners)
pub fn reset_shutdown() {
    SHUTDOWN.store(false, Ordering::SeqCst);
}

/// SSH honeypot - presents a fake SSH banner and logs credentials
async fn run_ssh_honeypot(honeypot_id: String, bind_addr: String, port: u16) {
    let addr = format!("{}:{}", bind_addr, port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            log::error!("SSH honeypot failed to bind to {}: {}", addr, e);
            return;
        }
    };

    info!("SSH honeypot listening on {}", addr);

    while !SHUTDOWN.load(Ordering::SeqCst) {
        let accept = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            listener.accept(),
        ).await;

        let (mut stream, peer_addr) = match accept {
            Ok(Ok((s, a))) => (s, a),
            Ok(Err(e)) => {
                log::debug!("SSH honeypot accept error: {}", e);
                continue;
            }
            Err(_) => continue, // timeout, check shutdown
        };

        let hp_id = honeypot_id.clone();
        tokio::spawn(async move {
            let source_ip = peer_addr.ip().to_string();

            // Send SSH banner
            let banner = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n";
            let _ = stream.write_all(banner).await;

            // Read client's version string
            let mut buf = [0u8; 512];
            let n = match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                stream.read(&mut buf),
            ).await {
                Ok(Ok(n)) => n,
                _ => 0,
            };

            let client_data = String::from_utf8_lossy(&buf[..n]).to_string();
            let details = format!("SSH connection attempt. Client: {}", client_data.trim());

            let _ = log_interaction(&hp_id, &source_ip, &details).await;

            // Keep connection alive briefly to log more data
            let mut total_read = Vec::new();
            for _ in 0..3 {
                let mut buf2 = [0u8; 1024];
                match tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    stream.read(&mut buf2),
                ).await {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => total_read.extend_from_slice(&buf2[..n]),
                    _ => break,
                }
            }

            if !total_read.is_empty() {
                let extra = format!("Additional SSH data: {} bytes", total_read.len());
                let _ = log_interaction(&hp_id, &source_ip, &extra).await;
            }
        });
    }
}

/// HTTP honeypot - serves fake web pages and logs requests
async fn run_http_honeypot(honeypot_id: String, bind_addr: String, port: u16) {
    let addr = format!("{}:{}", bind_addr, port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            log::error!("HTTP honeypot failed to bind to {}: {}", addr, e);
            return;
        }
    };

    info!("HTTP honeypot listening on {}", addr);

    while !SHUTDOWN.load(Ordering::SeqCst) {
        let accept = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            listener.accept(),
        ).await;

        let (mut stream, peer_addr) = match accept {
            Ok(Ok((s, a))) => (s, a),
            Ok(Err(e)) => {
                log::debug!("HTTP honeypot accept error: {}", e);
                continue;
            }
            Err(_) => continue,
        };

        let hp_id = honeypot_id.clone();
        tokio::spawn(async move {
            let source_ip = peer_addr.ip().to_string();

            // Read HTTP request
            let mut buf = [0u8; 4096];
            let n = match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                stream.read(&mut buf),
            ).await {
                Ok(Ok(n)) => n,
                _ => 0,
            };

            let request = String::from_utf8_lossy(&buf[..n]).to_string();

            // Extract method and path from request
            let first_line = request.lines().next().unwrap_or("");
            let details = format!("HTTP request: {}", first_line);

            let _ = log_interaction(&hp_id, &source_ip, &details).await;

            // Log interesting headers
            for line in request.lines().skip(1) {
                let lower = line.to_lowercase();
                if lower.starts_with("user-agent:") || lower.starts_with("authorization:") || lower.starts_with("cookie:") {
                    let header_detail = format!("HTTP header: {}", line.trim());
                    let _ = log_interaction(&hp_id, &source_ip, &header_detail).await;
                }
                if line.is_empty() { break; }
            }

            // Send fake response
            let response_body = r#"<html><head><title>Login</title></head><body><h1>Admin Panel</h1><form method="POST"><input name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><button>Login</button></form></body></html>"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nServer: Apache/2.4.52\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            let _ = stream.write_all(response.as_bytes()).await;
        });
    }
}

/// FTP honeypot - presents a fake FTP server and logs credentials
async fn run_ftp_honeypot(honeypot_id: String, bind_addr: String, port: u16) {
    let addr = format!("{}:{}", bind_addr, port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            log::error!("FTP honeypot failed to bind to {}: {}", addr, e);
            return;
        }
    };

    info!("FTP honeypot listening on {}", addr);

    while !SHUTDOWN.load(Ordering::SeqCst) {
        let accept = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            listener.accept(),
        ).await;

        let (mut stream, peer_addr) = match accept {
            Ok(Ok((s, a))) => (s, a),
            Ok(Err(e)) => {
                log::debug!("FTP honeypot accept error: {}", e);
                continue;
            }
            Err(_) => continue,
        };

        let hp_id = honeypot_id.clone();
        tokio::spawn(async move {
            let source_ip = peer_addr.ip().to_string();

            // Send FTP banner
            let _ = stream.write_all(b"220 FTP Server Ready\r\n").await;

            let mut username = String::new();

            // Read and respond to FTP commands
            for _ in 0..10 {
                let mut buf = [0u8; 512];
                let n = match tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    stream.read(&mut buf),
                ).await {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => n,
                    _ => break,
                };

                let cmd = String::from_utf8_lossy(&buf[..n]).trim().to_string();
                let cmd_upper = cmd.to_uppercase();

                if cmd_upper.starts_with("USER ") {
                    username = cmd[5..].trim().to_string();
                    let _ = stream.write_all(b"331 Password required\r\n").await;
                } else if cmd_upper.starts_with("PASS ") {
                    let password = cmd[5..].trim().to_string();
                    let details = format!("FTP login attempt: user='{}' pass='{}'", username, password);
                    let _ = log_interaction(&hp_id, &source_ip, &details).await;
                    let _ = stream.write_all(b"530 Login incorrect\r\n").await;
                } else if cmd_upper.starts_with("QUIT") {
                    let _ = stream.write_all(b"221 Goodbye\r\n").await;
                    break;
                } else {
                    let details = format!("FTP command: {}", cmd);
                    let _ = log_interaction(&hp_id, &source_ip, &details).await;
                    let _ = stream.write_all(b"502 Command not implemented\r\n").await;
                }
            }
        });
    }
}

/// Database honeypot - emulates MySQL/PostgreSQL protocol handshake
async fn run_database_honeypot(honeypot_id: String, bind_addr: String, port: u16) {
    let addr = format!("{}:{}", bind_addr, port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            log::error!("Database honeypot failed to bind to {}: {}", addr, e);
            return;
        }
    };

    info!("Database honeypot listening on {}", addr);

    while !SHUTDOWN.load(Ordering::SeqCst) {
        let accept = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            listener.accept(),
        ).await;

        let (mut stream, peer_addr) = match accept {
            Ok(Ok((s, a))) => (s, a),
            Ok(Err(e)) => {
                log::debug!("Database honeypot accept error: {}", e);
                continue;
            }
            Err(_) => continue,
        };

        let hp_id = honeypot_id.clone();
        let is_mysql = port == 3306;
        tokio::spawn(async move {
            let source_ip = peer_addr.ip().to_string();

            if is_mysql {
                // MySQL greeting packet (simplified)
                let greeting = b"\x4a\x00\x00\x00\x0a5.7.42\x00\x01\x00\x00\x00\x3a\x64\x4c\x52\x2f\x43\x60\x68\x00\xff\xf7\x21\x02\x00\x7f\x80\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x76\x3a\x52\x2a\x33\x56\x6e\x42\x22\x48\x74\x55\x00mysql_native_password\x00";
                let _ = stream.write_all(greeting).await;
            } else {
                // PostgreSQL-like - wait for startup message
            }

            // Read client response (auth attempt)
            let mut buf = [0u8; 2048];
            let n = match tokio::time::timeout(
                std::time::Duration::from_secs(15),
                stream.read(&mut buf),
            ).await {
                Ok(Ok(n)) => n,
                _ => 0,
            };

            if n > 0 {
                let details = format!(
                    "Database connection attempt ({} protocol): {} bytes received",
                    if is_mysql { "MySQL" } else { "PostgreSQL" },
                    n
                );
                let _ = log_interaction(&hp_id, &source_ip, &details).await;

                // Try to extract username from the packet
                let data = &buf[..n];
                let printable: String = data.iter()
                    .filter(|&&b| b >= 0x20 && b < 0x7f)
                    .map(|&b| b as char)
                    .collect();
                if !printable.is_empty() {
                    let cred_detail = format!("Database auth data (printable): {}", &printable[..printable.len().min(200)]);
                    let _ = log_interaction(&hp_id, &source_ip, &cred_detail).await;
                }
            }

            // Send access denied
            if is_mysql {
                let error = b"\x17\x00\x00\x02\xff\x15\x04#28000Access denied for user";
                let _ = stream.write_all(error).await;
            }
        });
    }
}

/// SMTP honeypot - fake mail server that logs email relay attempts
async fn run_smtp_honeypot(honeypot_id: String, bind_addr: String, port: u16) {
    let addr = format!("{}:{}", bind_addr, port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            log::error!("SMTP honeypot failed to bind to {}: {}", addr, e);
            return;
        }
    };

    info!("SMTP honeypot listening on {}", addr);

    while !SHUTDOWN.load(Ordering::SeqCst) {
        let accept = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            listener.accept(),
        ).await;

        let (mut stream, peer_addr) = match accept {
            Ok(Ok((s, a))) => (s, a),
            Ok(Err(e)) => {
                log::debug!("SMTP honeypot accept error: {}", e);
                continue;
            }
            Err(_) => continue,
        };

        let hp_id = honeypot_id.clone();
        tokio::spawn(async move {
            let source_ip = peer_addr.ip().to_string();

            // Send SMTP banner
            let _ = stream.write_all(b"220 mail.example.com ESMTP Postfix\r\n").await;

            let mut mail_from = String::new();
            let mut rcpt_to = Vec::new();

            for _ in 0..20 {
                let mut buf = [0u8; 1024];
                let n = match tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    stream.read(&mut buf),
                ).await {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => n,
                    _ => break,
                };

                let cmd = String::from_utf8_lossy(&buf[..n]).trim().to_string();
                let cmd_upper = cmd.to_uppercase();

                if cmd_upper.starts_with("EHLO") || cmd_upper.starts_with("HELO") {
                    let _ = stream.write_all(b"250-mail.example.com\r\n250-SIZE 10240000\r\n250 OK\r\n").await;
                } else if cmd_upper.starts_with("MAIL FROM:") {
                    mail_from = cmd[10..].trim().to_string();
                    let _ = stream.write_all(b"250 OK\r\n").await;
                } else if cmd_upper.starts_with("RCPT TO:") {
                    let recipient = cmd[8..].trim().to_string();
                    rcpt_to.push(recipient);
                    let _ = stream.write_all(b"250 OK\r\n").await;
                } else if cmd_upper.starts_with("DATA") {
                    let _ = stream.write_all(b"354 Start mail input\r\n").await;

                    // Read email body until ".\r\n"
                    let mut email_body = Vec::new();
                    loop {
                        let mut data_buf = [0u8; 4096];
                        let dn = match tokio::time::timeout(
                            std::time::Duration::from_secs(30),
                            stream.read(&mut data_buf),
                        ).await {
                            Ok(Ok(0)) => break,
                            Ok(Ok(n)) => n,
                            _ => break,
                        };
                        email_body.extend_from_slice(&data_buf[..dn]);
                        if email_body.len() >= 5 {
                            let tail = &email_body[email_body.len()-5..];
                            if tail == b"\r\n.\r\n" {
                                break;
                            }
                        }
                        if email_body.len() > 100_000 { break; } // Limit
                    }

                    let details = format!(
                        "SMTP relay attempt: FROM={} TO={:?} body_size={}",
                        mail_from, rcpt_to, email_body.len()
                    );
                    let _ = log_interaction(&hp_id, &source_ip, &details).await;

                    let _ = stream.write_all(b"250 OK: Message queued\r\n").await;
                } else if cmd_upper.starts_with("QUIT") {
                    let _ = stream.write_all(b"221 Bye\r\n").await;
                    break;
                } else if cmd_upper.starts_with("AUTH") {
                    let details = format!("SMTP auth attempt: {}", cmd);
                    let _ = log_interaction(&hp_id, &source_ip, &details).await;
                    let _ = stream.write_all(b"535 Authentication failed\r\n").await;
                } else {
                    let _ = stream.write_all(b"502 Command not recognized\r\n").await;
                }
            }

            if !mail_from.is_empty() || !rcpt_to.is_empty() {
                let summary = format!("SMTP session: from={} recipients={}", mail_from, rcpt_to.len());
                let _ = log_interaction(&hp_id, &source_ip, &summary).await;
            }
        });
    }
}

/// Start a UDP honeypot (for DNS, SNMP, or other UDP services)
pub async fn start_udp_listener(honeypot_id: &str, bind_addr: &str, port: u16) -> Result<tokio::task::JoinHandle<()>> {
    let hp_id = honeypot_id.to_string();
    let addr = format!("{}:{}", bind_addr, port);

    let socket = UdpSocket::bind(&addr).await
        .map_err(|e| anyhow!("UDP honeypot failed to bind to {}: {}", addr, e))?;

    info!("UDP honeypot listening on {}", addr);

    let handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];

        loop {
            if SHUTDOWN.load(Ordering::SeqCst) {
                break;
            }

            let recv = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                socket.recv_from(&mut buf),
            ).await;

            let (n, peer_addr) = match recv {
                Ok(Ok((n, a))) => (n, a),
                Ok(Err(e)) => {
                    log::debug!("UDP honeypot recv error: {}", e);
                    continue;
                }
                Err(_) => continue,
            };

            let source_ip = peer_addr.ip().to_string();
            let data = &buf[..n];

            // Detect protocol based on content
            let protocol = if n >= 12 && (data[2] & 0x80 == 0) {
                "DNS" // DNS query (QR bit = 0)
            } else if n >= 2 && data[0] == 0x30 {
                "SNMP" // ASN.1 SEQUENCE
            } else {
                "Unknown UDP"
            };

            let details = format!("{} packet: {} bytes from port {}", protocol, n, peer_addr.port());
            let _ = log_interaction(&hp_id, &source_ip, &details).await;

            // Send minimal response to encourage further interaction
            if protocol == "DNS" && n >= 12 {
                // Send DNS NXDOMAIN response
                let mut response = data[..n].to_vec();
                if response.len() >= 4 {
                    response[2] |= 0x80; // Set QR bit (response)
                    response[3] = (response[3] & 0xF0) | 0x03; // NXDOMAIN
                    let _ = socket.send_to(&response, peer_addr).await;
                }
            }
        }
    });

    Ok(handle)
}
