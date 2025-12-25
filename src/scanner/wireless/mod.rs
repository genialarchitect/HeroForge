//! Wireless Security Module
//!
//! WiFi security assessment capabilities including network discovery,
//! handshake capture, and password cracking.

pub mod types;
pub mod scanner;
pub mod handshake;
pub mod aircrack;

#[allow(unused_imports)]
pub use types::*;
pub use scanner::WirelessScanner;
pub use handshake::{HandshakeCapturer, DeauthAttack};
#[allow(unused_imports)]
pub use aircrack::{AircrackCracker, WpsAttack, CrackProgress, CrackResult, WordlistInfo, WpsResult};

use sqlx::SqlitePool;
use anyhow::Result;
use chrono::Utc;
use std::collections::HashMap;

/// Wireless security manager
pub struct WirelessManager {
    pool: SqlitePool,
}

impl WirelessManager {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Get dashboard statistics
    pub async fn get_dashboard_stats(&self, user_id: &str) -> Result<WirelessDashboardStats> {
        // Total scans
        let total_scans: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM wireless_scans WHERE user_id = ?"
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await
        .unwrap_or((0,));

        // Active scans
        let active_scans: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM wireless_scans WHERE user_id = ? AND status = 'running'"
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await
        .unwrap_or((0,));

        // Networks discovered
        let networks_discovered: (i64,) = sqlx::query_as(
            "SELECT COUNT(DISTINCT bssid) FROM wireless_networks WHERE user_id = ?"
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await
        .unwrap_or((0,));

        // Handshakes captured
        let handshakes_captured: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM wireless_handshakes WHERE user_id = ? AND is_complete = 1"
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await
        .unwrap_or((0,));

        // PMKIDs captured
        let pmkids_captured: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM wireless_pmkids WHERE user_id = ?"
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await
        .unwrap_or((0,));

        // Passwords cracked
        let passwords_cracked: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM wireless_handshakes WHERE user_id = ? AND cracked = 1"
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await
        .unwrap_or((0,));

        // Networks by encryption
        let mut networks_by_encryption = HashMap::new();
        let rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT encryption, COUNT(*) as count FROM wireless_networks
             WHERE user_id = ? GROUP BY encryption"
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        for (enc, count) in rows {
            networks_by_encryption.insert(enc, count as u32);
        }

        // Top vulnerable networks (open or WEP)
        let top_vulnerable: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT ssid, bssid, encryption FROM wireless_networks
             WHERE user_id = ? AND encryption IN ('open', 'wep')
             ORDER BY signal_strength DESC LIMIT 10"
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        let top_vulnerable_networks: Vec<VulnerableNetwork> = top_vulnerable
            .into_iter()
            .map(|(ssid, bssid, enc)| {
                let (vulnerability, severity) = match enc.as_str() {
                    "open" => ("Open network - no encryption", "critical"),
                    "wep" => ("WEP encryption - easily crackable", "high"),
                    _ => ("Unknown vulnerability", "medium"),
                };
                VulnerableNetwork {
                    ssid,
                    bssid,
                    encryption: WirelessEncryption::Open, // Simplified
                    vulnerability: vulnerability.to_string(),
                    severity: severity.to_string(),
                }
            })
            .collect();

        Ok(WirelessDashboardStats {
            total_scans: total_scans.0 as u32,
            active_scans: active_scans.0 as u32,
            networks_discovered: networks_discovered.0 as u32,
            handshakes_captured: handshakes_captured.0 as u32,
            pmkids_captured: pmkids_captured.0 as u32,
            passwords_cracked: passwords_cracked.0 as u32,
            networks_by_encryption,
            top_vulnerable_networks,
        })
    }

    /// Create a new wireless scan
    pub async fn create_scan(
        &self,
        user_id: &str,
        config: WirelessScanConfig,
    ) -> Result<WirelessScan> {
        let scan = WirelessScan {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            interface: config.interface.clone(),
            config: config.clone(),
            status: AttackStatus::Pending,
            networks_found: 0,
            clients_found: 0,
            handshakes_captured: 0,
            started_at: Utc::now(),
            completed_at: None,
        };

        sqlx::query(
            "INSERT INTO wireless_scans (id, user_id, interface, config, status, started_at)
             VALUES (?, ?, ?, ?, ?, ?)"
        )
        .bind(&scan.id)
        .bind(&scan.user_id)
        .bind(&scan.interface)
        .bind(serde_json::to_string(&scan.config)?)
        .bind("pending")
        .bind(scan.started_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(scan)
    }

    /// Save discovered network
    pub async fn save_network(&self, user_id: &str, network: &WirelessNetwork) -> Result<()> {
        sqlx::query(
            "INSERT OR REPLACE INTO wireless_networks
             (bssid, user_id, ssid, channel, frequency, signal_strength, encryption,
              cipher, auth, wps_enabled, first_seen, last_seen)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&network.bssid)
        .bind(user_id)
        .bind(&network.ssid)
        .bind(network.channel as i32)
        .bind(network.frequency as i32)
        .bind(network.signal_strength as i32)
        .bind(format!("{}", network.encryption))
        .bind(network.cipher.as_ref().map(|c| format!("{:?}", c)))
        .bind(network.auth.as_ref().map(|a| format!("{:?}", a)))
        .bind(network.wps_enabled)
        .bind(network.first_seen.to_rfc3339())
        .bind(network.last_seen.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Save handshake capture
    pub async fn save_handshake(
        &self,
        user_id: &str,
        handshake: &HandshakeCapture,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO wireless_handshakes
             (id, user_id, bssid, ssid, client_mac, capture_file, eapol_messages,
              is_complete, cracked, password, captured_at, cracked_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&handshake.id)
        .bind(user_id)
        .bind(&handshake.bssid)
        .bind(&handshake.ssid)
        .bind(&handshake.client_mac)
        .bind(&handshake.capture_file)
        .bind(handshake.eapol_messages as i32)
        .bind(handshake.is_complete)
        .bind(handshake.cracked)
        .bind(&handshake.password)
        .bind(handshake.captured_at.to_rfc3339())
        .bind(handshake.cracked_at.map(|dt| dt.to_rfc3339()))
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Save PMKID capture
    pub async fn save_pmkid(&self, user_id: &str, pmkid: &PmkidCapture) -> Result<()> {
        sqlx::query(
            "INSERT INTO wireless_pmkids
             (id, user_id, bssid, ssid, pmkid, capture_file, cracked, password, captured_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&pmkid.id)
        .bind(user_id)
        .bind(&pmkid.bssid)
        .bind(&pmkid.ssid)
        .bind(&pmkid.pmkid)
        .bind(&pmkid.capture_file)
        .bind(pmkid.cracked)
        .bind(&pmkid.password)
        .bind(pmkid.captured_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// List wireless scans
    pub async fn list_scans(&self, user_id: &str) -> Result<Vec<WirelessScan>> {
        let rows: Vec<(String, String, String, String, String, i32, i32, i32, String, Option<String>)> = sqlx::query_as(
            "SELECT id, user_id, interface, config, status, networks_found, clients_found,
                    handshakes_captured, started_at, completed_at
             FROM wireless_scans WHERE user_id = ? ORDER BY started_at DESC"
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        let mut scans = Vec::new();
        for row in rows {
            let status = match row.4.as_str() {
                "running" => AttackStatus::Running,
                "success" => AttackStatus::Success,
                "failed" => AttackStatus::Failed,
                "cancelled" => AttackStatus::Cancelled,
                _ => AttackStatus::Pending,
            };

            scans.push(WirelessScan {
                id: row.0,
                user_id: row.1,
                interface: row.2,
                config: serde_json::from_str(&row.3).unwrap_or_default(),
                status,
                networks_found: row.5 as u32,
                clients_found: row.6 as u32,
                handshakes_captured: row.7 as u32,
                started_at: chrono::DateTime::parse_from_rfc3339(&row.8)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                completed_at: row.9.and_then(|s|
                    chrono::DateTime::parse_from_rfc3339(&s)
                        .map(|dt| dt.with_timezone(&Utc))
                        .ok()
                ),
            });
        }

        Ok(scans)
    }

    /// List discovered networks
    pub async fn list_networks(&self, user_id: &str) -> Result<Vec<WirelessNetwork>> {
        let rows: Vec<(String, String, i32, i32, i32, String, Option<String>, Option<String>, bool, String, String)> = sqlx::query_as(
            "SELECT bssid, ssid, channel, frequency, signal_strength, encryption,
                    cipher, auth, wps_enabled, first_seen, last_seen
             FROM wireless_networks WHERE user_id = ? ORDER BY last_seen DESC"
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        let mut networks = Vec::new();
        for row in rows {
            let encryption = match row.5.as_str() {
                "Open" => WirelessEncryption::Open,
                "WEP" => WirelessEncryption::Wep,
                "WPA" => WirelessEncryption::Wpa,
                "WPA2" => WirelessEncryption::Wpa2,
                "WPA3" => WirelessEncryption::Wpa3,
                _ => WirelessEncryption::Unknown,
            };

            networks.push(WirelessNetwork {
                bssid: row.0,
                ssid: row.1,
                channel: row.2 as u8,
                frequency: row.3 as u32,
                signal_strength: row.4 as i8,
                encryption,
                cipher: None, // Simplified
                auth: None,
                wps_enabled: row.8,
                wps_locked: false,
                clients: Vec::new(),
                beacons: 0,
                data_packets: 0,
                first_seen: chrono::DateTime::parse_from_rfc3339(&row.9)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                last_seen: chrono::DateTime::parse_from_rfc3339(&row.10)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            });
        }

        Ok(networks)
    }

    /// List handshake captures
    pub async fn list_handshakes(&self, user_id: &str) -> Result<Vec<HandshakeCapture>> {
        let rows: Vec<(String, String, String, String, String, i32, bool, bool, Option<String>, String, Option<String>)> = sqlx::query_as(
            "SELECT id, bssid, ssid, client_mac, capture_file, eapol_messages,
                    is_complete, cracked, password, captured_at, cracked_at
             FROM wireless_handshakes WHERE user_id = ? ORDER BY captured_at DESC"
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        let mut handshakes = Vec::new();
        for row in rows {
            handshakes.push(HandshakeCapture {
                id: row.0,
                bssid: row.1,
                ssid: row.2,
                client_mac: row.3,
                capture_file: row.4,
                eapol_messages: row.5 as u8,
                is_complete: row.6,
                cracked: row.7,
                password: row.8,
                captured_at: chrono::DateTime::parse_from_rfc3339(&row.9)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                cracked_at: row.10.and_then(|s|
                    chrono::DateTime::parse_from_rfc3339(&s)
                        .map(|dt| dt.with_timezone(&Utc))
                        .ok()
                ),
            });
        }

        Ok(handshakes)
    }

    /// Update handshake with cracked password
    pub async fn update_handshake_cracked(
        &self,
        handshake_id: &str,
        password: &str,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE wireless_handshakes
             SET cracked = 1, password = ?, cracked_at = ?
             WHERE id = ?"
        )
        .bind(password)
        .bind(Utc::now().to_rfc3339())
        .bind(handshake_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}
